"""Public and host-service observer timing settings routes."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import sqlalchemy as sa
from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse

from uvm.operations.backup_host import parse_utc
from uvm.auth.schema import AUTHORITY_CONTEXT
from uvm.persistence.assessment_schema import (
    assessment_command_receipts, assessment_policy,
)
from uvm.persistence.observer_settings_schema import (
    g7_observer_application_intents, g7_observer_host_reports,
    g7_observer_settings_revisions, g7_observer_status,
)
from uvm.operations.observer_settings import (
    ObserverSettingsConflict, ObserverSettingsError, ObserverSettingsUnavailable,
    TIMING_FIELDS, command_digest, commit_desired_revision, deployment_audit_id,
    deployment_grants,
)

_UTC = timezone.utc
_REPORT_FIELDS = {"schema_version", "deployment_id", "report_id", "sequence",
    "controller_instance", "requested_revision", "requested_digest",
    "active_revision", "active_digest", "consumers", "host_policy", "outcome",
    "observed_at", "failure_code", "signature"}


def _error(status: int, code: str, message: str, request: Request,
           *, outcome="not_committed", expected=None, current=None, lookup=None):
    raise HTTPException(status, {"code": code, "message": message,
        "details": {"outcome": outcome, "expected_revisions": expected,
            "current_revisions": current, "lookup_url": lookup}})


def _now_text(value: datetime | None) -> str | None:
    if value is None:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=_UTC)
    return value.astimezone(_UTC).isoformat().replace("+00:00", "Z")


def _digest(value: str | None) -> str | None:
    return "sha256:" + value if value else None


def _cursor_part(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _discovery_cursor(secret: bytes, *, principal: str, authority_revision: int,
        registry_digest: str, visible_digest: str, after: int, limit: int,
        expires_at: int, policy_revision: int | None = None) -> str:
    payload = {"version": 1, "principal": principal,
        "authority_revision": authority_revision, "registry_digest": registry_digest,
        "visible_digest": visible_digest, "after": after, "limit": limit,
        "expires_at": expires_at}
    if policy_revision is not None:
        payload["policy_revision"] = policy_revision
    body = json.dumps(payload, sort_keys=True, separators=(",", ":"),
        ensure_ascii=False, allow_nan=False).encode("utf-8")
    return _cursor_part(body) + "." + _cursor_part(hmac.new(secret, body, hashlib.sha256).digest())


def _read_discovery_cursor(secret: bytes, token: str, *, principal: str,
        authority_revision: int, registry_digest: str, visible_digest: str,
        limit: int, now_epoch: int, policy_revision: int | None = None) -> int:
    try:
        if not isinstance(token, str) or len(token) > 4096 or token.count(".") != 1:
            raise ValueError
        body_part, signature_part = token.split(".", 1)
        body = base64.b64decode(body_part + "=" * (-len(body_part) % 4),
            altchars=b"-_", validate=True)
        signature = base64.b64decode(signature_part + "=" * (-len(signature_part) % 4),
            altchars=b"-_", validate=True)
        if not hmac.compare_digest(signature, hmac.new(secret, body, hashlib.sha256).digest()):
            raise ValueError
        payload = json.loads(body)
        expected = {"version": 1, "principal": principal,
            "authority_revision": authority_revision, "registry_digest": registry_digest,
            "visible_digest": visible_digest, "limit": limit}
        if policy_revision is not None:
            expected["policy_revision"] = policy_revision
        if any(payload.get(key) != value for key, value in expected.items()):
            raise ValueError
        if (type(payload.get("after")) is not int or payload["after"] < 0
                or type(payload.get("expires_at")) is not int or payload["expires_at"] < now_epoch):
            raise ValueError
        return payload["after"]
    except (ValueError, TypeError, KeyError, json.JSONDecodeError):
        raise HTTPException(400, {"code": "invalid_cursor",
            "message": "Deployment discovery cursor is invalid or stale"}) from None


def _registry() -> dict[str, dict]:
    path = os.environ.get("UVM_OBSERVER_DEPLOYMENT_REGISTRY_FILE")
    if not path:
        return {}
    try:
        parsed = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise RuntimeError("observer deployment registry is unavailable") from exc
    if not isinstance(parsed, list):
        raise RuntimeError("observer deployment registry must be a list")
    if len(parsed) > 10000:
        raise RuntimeError("observer deployment registry exceeds its configured bound")
    result = {}
    for item in parsed:
        if (not isinstance(item, dict)
                or set(item) != {"deployment_id", "label", "host_principal_id", "verification_key_file"}
                or not isinstance(item["deployment_id"], str) or not item["deployment_id"]
                or not isinstance(item["label"], str)
                or not isinstance(item["host_principal_id"], str)
                or not isinstance(item["verification_key_file"], str)
                or item["deployment_id"] in result):
            raise RuntimeError("observer deployment registry entry is invalid")
        result[item["deployment_id"]] = item
    return result


def _policy(connection):
    row = connection.execute(sa.select(assessment_policy).where(
        assessment_policy.c.policy_id == 1)).mappings().one_or_none()
    if row is None:
        raise HTTPException(503, {"code": "dependency_unavailable",
            "message": "Observer settings authority is unavailable"})
    return row


def _read_allowed(policy, principal, deployment, context):
    return bool(deployment_grants(policy, principal, "observer.timing.read", deployment, context))


def _authorized_deployment(policy, principal, deployment, context, registry):
    if deployment not in registry or not _read_allowed(policy, principal, deployment, context):
        raise HTTPException(404, {"code": "not_found", "message": "Deployment not found"})


def _current_revisions(connection, policy_row, deployment):
    configuration = connection.execute(sa.select(sa.func.coalesce(
        sa.func.max(g7_observer_settings_revisions.c.revision), 0)).where(
        g7_observer_settings_revisions.c.deployment_id == deployment)).scalar_one()
    from uvm.auth.native_authority import native_state
    authority = int(native_state(policy_row["document"]).get("revision", 0))
    status = connection.execute(sa.select(g7_observer_status).where(
        g7_observer_status.c.deployment_id == deployment)).mappings().one_or_none()
    return {"configuration": int(configuration), "policy": int(policy_row["revision"]),
        "authority": authority,
        "host_policy": int(status["host_policy_revision"] or 0) if status else 0}, status


def _audit_view_allowed(policy, principal, deployment, context):
    from uvm.assessment.api import _scoped_grants
    token = AUTHORITY_CONTEXT.set(context) if context is not None else None
    try:
        return bool(_scoped_grants(policy, principal, "audit.read",
            deployment_audit_id(deployment), None))
    finally:
        if token is not None:
            AUTHORITY_CONTEXT.reset(token)


def _root_dto(connection, policy_row, deployment, principal, context):
    revisions, status = _current_revisions(connection, policy_row, deployment)
    desired_row = None
    if revisions["configuration"]:
        desired_row = connection.execute(sa.select(g7_observer_settings_revisions).where(
            g7_observer_settings_revisions.c.deployment_id == deployment,
            g7_observer_settings_revisions.c.revision == revisions["configuration"])).mappings().one()
    intent = connection.execute(sa.select(g7_observer_application_intents).where(
        g7_observer_application_intents.c.deployment_id == deployment).order_by(
            g7_observer_application_intents.c.created_at.desc()).limit(1)).mappings().one_or_none()
    host_policy = None
    if status and status["host_policy_revision"] and status["host_policy_digest"]:
        observed = status["host_policy_observed_at"]
        age = (datetime.now(_UTC) - (observed.replace(tzinfo=_UTC) if observed.tzinfo is None else observed)).total_seconds()
        freshness = int(status["host_policy_freshness_seconds"] or 0)
        state = "fresh" if 0 <= age <= freshness else "stale" if age >= 0 else "unknown"
        host_policy = {"revision": int(status["host_policy_revision"]),
            "digest": _digest(status["host_policy_digest"]),
            "bounds": status["host_policy_bounds"], "observed_at": _now_text(observed),
            "fresh_until": _now_text((observed.replace(tzinfo=_UTC) if observed.tzinfo is None else observed)
                + timedelta(seconds=freshness)),
            "freshness": state}
    effective = None
    if status and status["effective_revision"] is not None:
        effective = {"revision": int(status["effective_revision"]),
            "digest": _digest(status["effective_digest"]),
            "verified_at": _now_text(status["latest_report_at"])}
    application = None
    # A signed policy-only report can precede the first desired configuration.
    # It establishes host policy/report evidence, but has no application intent
    # to which an application outcome can be attributed.
    if intent:
        matching_report = None
        if status and status["latest_report_id"]:
            matching_report = connection.execute(sa.select(g7_observer_host_reports).where(
                g7_observer_host_reports.c.report_id == status["latest_report_id"],
                g7_observer_host_reports.c.deployment_id == deployment)).mappings().one_or_none()
        report_matches_intent = bool(matching_report
            and matching_report["requested_revision"] == int(intent["revision"])
            and matching_report["requested_digest"] == intent["digest"])
        application = {"status": intent["status"],
            "operation_id": intent["intent_id"],
            "latest_report_id": status["latest_report_id"] if report_matches_intent else None,
            "failure_code": status["latest_failure_code"] if report_matches_intent else None}
    desired = None
    if desired_row:
        desired = {"revision": int(desired_row["revision"]),
            "digest": _digest(desired_row["digest"]), "values": desired_row["values"],
            "command_id": desired_row["command_id"],
            "committed_at": _now_text(desired_row["created_at"])}
    can_configure = bool(deployment_grants(policy_row["document"], principal,
        "observer.timing.configure", deployment, context))
    return {"schema_version": 1, "deployment_id": deployment,
        "revisions": revisions, "desired": desired, "effective": effective,
        "application": application, "host_policy": host_policy,
        "can_configure": can_configure}


def install_observer_settings_routes(app: FastAPI) -> None:
    engine, principals = app.state.engine, app.state.principals

    def authenticate(request: Request, authorization: str | None = Header(default=None)):
        auth_service = getattr(app.state, "oidc_auth", None)
        if auth_service is not None:
            return auth_service.resolve_request(request).principal_id
        if not authorization or not authorization.startswith("Bearer "):
            raise HTTPException(401, {"code": "authentication_required", "message": "Authentication required"})
        supplied = authorization[7:]
        for name, principal in principals.items():
            token = principal.get("token", "")
            if supplied.isascii() and len(supplied) <= 512 and __import__("hmac").compare_digest(supplied, token):
                return name
        raise HTTPException(401, {"code": "authentication_required", "message": "Authentication required"})

    # Backup v1 initially exposes a stable, sanitized readback while host policy
    # and first desired revision are unknown. Configuration is installed below
    # the same current-authority and global-policy lock used by observer settings.
    @app.get("/api/v1/operations/backup-settings/{deployment_id}")
    def read_backup_settings(deployment_id: str, request: Request,
                             principal: str = Depends(authenticate)):
        context, registry = getattr(request.state, "authority_context", None), _registry()
        with engine.begin() as connection:
            from uvm.assessment.policy_lock import lock_policy
            from uvm.persistence.assessment_schema import assessment_policy
            from uvm.persistence.backup_settings_schema import (
                g7_backup_settings_revisions, g7_backup_state,
            )
            from uvm.auth.native_authority import native_state
            lock_policy(connection, shared=True)
            policy_row = connection.execute(sa.select(assessment_policy).where(
                assessment_policy.c.policy_id == 1)).mappings().one_or_none()
            if policy_row is None or deployment_id not in registry or not deployment_grants(
                    policy_row["document"], principal, "backup.settings.read", deployment_id, context):
                raise HTTPException(404, {"code": "not_found", "message": "Deployment not found"})
            policy = policy_row["document"]
            authority = int(native_state(policy).get("revision", 0))
            revision = connection.execute(sa.select(sa.func.coalesce(
                sa.func.max(g7_backup_settings_revisions.c.revision), 0)).where(
                    g7_backup_settings_revisions.c.deployment_id == deployment_id)).scalar_one()
            desired_row = None
            if revision:
                desired_row = connection.execute(sa.select(g7_backup_settings_revisions).where(
                    g7_backup_settings_revisions.c.deployment_id == deployment_id,
                    g7_backup_settings_revisions.c.revision == int(revision))).mappings().one()
            state = connection.execute(sa.select(g7_backup_state).where(
                g7_backup_state.c.deployment_id == deployment_id)).mappings().one_or_none()
            def digest(value): return "sha256:" + value if value else None
            def stamp(value):
                if value is None: return None
                if value.tzinfo is None: value = value.replace(tzinfo=timezone.utc)
                return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
            desired = None if desired_row is None else {"revision": int(revision),
                "digest": digest(desired_row["digest"]), "values": desired_row["values"],
                "command_id": desired_row["command_id"], "committed_at": stamp(desired_row["created_at"])}
            policy_doc = None
            if state and state["host_policy_document"]:
                policy_doc = dict(state["host_policy_document"])
                observed = state["host_policy_observed_at"]
                if observed is not None and observed.tzinfo is None:
                    observed = observed.replace(tzinfo=timezone.utc)
                age = (app.state.utc_now() - observed).total_seconds() if observed else None
                max_age = int(policy_doc["maximum_report_age_seconds"])
                policy_doc.update(observed_at=stamp(observed),
                    fresh_until=stamp(observed + timedelta(seconds=max_age)) if observed else None,
                    freshness=("fresh" if age is not None and 0 <= age <= max_age
                        else "stale" if age is not None and age > max_age else "unknown"))
            # Application evidence has its own signed timestamp. Policy and
            # archive/status traffic cannot retime an existing application.
            application_at = effective_at = application_policy = None
            if state:
                from uvm.persistence.backup_settings_schema import g7_backup_host_records
                history = connection.execute(sa.select(g7_backup_host_records).where(
                    g7_backup_host_records.c.deployment_id == deployment_id,
                    g7_backup_host_records.c.record_kind.in_(["ack", "status"])
                    ).order_by(g7_backup_host_records.c.sequence.desc())).mappings()
                for record in history:
                    doc = record["document"]
                    evidence = ({"state": doc["outcome"], "requested_revision": doc["requested_revision"],
                        "intent_id": doc["intent_id"], "host_policy_revision": doc["host_policy_revision"], "active_revision": doc["active_revision"],
                        "active_digest": doc["active_digest"], "reported_at": doc["observed_at"]}
                        if record["record_kind"] == "ack" else doc.get("settings_application"))
                    if not evidence or not evidence.get("reported_at"):
                        continue
                    if (application_at is None and evidence["requested_revision"] == state["requested_revision"] and
                            evidence["intent_id"] == state["application_intent_id"] and
                            evidence["state"] == state["application_status"]):
                        application_at = parse_utc(evidence["reported_at"])
                        application_policy = evidence["host_policy_revision"]
                    if (effective_at is None and evidence["state"] == "applied" and
                            evidence["active_revision"] == state["effective_revision"] and
                            evidence["active_digest"] == digest(state["effective_digest"])):
                        effective_at = parse_utc(evidence["reported_at"])
            evaluated_at = app.state.utc_now()
            active = None if not state or state["effective_revision"] is None else {
                "revision": state["effective_revision"], "digest": digest(state["effective_digest"]),
                "verified_at": stamp(effective_at)}
            application = None
            if state and state["requested_revision"] is not None:
                application = {"state": state["application_status"] or "unknown",
                    "requested_revision": state["requested_revision"],
                    "requested_digest": digest(state["requested_digest"]),
                    "intent_id": state["application_intent_id"],
                    "host_policy_revision": application_policy or state["host_policy_revision"],
                    "active_revision": active["revision"] if active else None,
                    "active_digest": active["digest"] if active else None,
                    "reported_at": stamp(application_at),
                    "failure_code": state["latest_failure_code"]}
            policy_observed = state["host_policy_observed_at"] if state else None
            if policy_observed is not None and policy_observed.tzinfo is None:
                policy_observed = policy_observed.replace(tzinfo=timezone.utc)
            host_policy_fresh = bool(policy_doc and policy_observed and
                0 <= (app.state.utc_now() - policy_observed).total_seconds() <=
                int(policy_doc["maximum_report_age_seconds"]))
            archive_age, archive_maximum, archive_freshness = None, None, "unknown"
            if state and state["effective_revision"] is not None and state["archive_outcome"] == "complete" and state["archive_completed_at"]:
                effective_settings = connection.execute(sa.select(g7_backup_settings_revisions.c["values"]).where(
                    g7_backup_settings_revisions.c.deployment_id == deployment_id,
                    g7_backup_settings_revisions.c.revision == state["effective_revision"])).scalar_one_or_none()
                completed = state["archive_completed_at"]
                if completed.tzinfo is None:
                    completed = completed.replace(tzinfo=timezone.utc)
                age = int((evaluated_at - completed).total_seconds())
                if effective_settings and age >= 0:
                    archive_age, archive_maximum = age, effective_settings["maximum_backup_age_seconds"]
                    archive_freshness = "fresh" if age <= archive_maximum else "stale"
            return {"schema_version": 1, "deployment_id": deployment_id,
                "revisions": {"configuration": int(revision), "policy": int(policy_row["revision"]),
                    "authority": authority, "host_policy": int(state["host_policy_revision"] or 0) if state else 0,
                    "recovery_epoch": int(state["recovery_epoch"] or 0) if state else 0},
                "desired": desired, "effective": active,
                "status": {"settings_application": application,
                    "completed_archive": {"archive_id": state["archive_id"] if state else None,
                        "completed_at": stamp(state["archive_completed_at"]) if state else None,
                        "manifest_digest": digest(state["archive_manifest_digest"]) if state else None,
                        "outcome": state["archive_outcome"] if state else None},
                    "freshness": {"state": archive_freshness,
                        "evaluated_at": stamp(evaluated_at) if archive_age is not None else None,
                        "age_seconds": archive_age,
                        "basis_completed_at": stamp(state["archive_completed_at"]) if state else None,
                        "maximum_backup_age_seconds": archive_maximum},
                    # ``restored`` is an internal transition after volume restore,
                    # before supported-API verification has passed. It must not be
                    # exposed as a successful verification state.
                    "restore_verification": {"state": (state["restore_state"]
                        if state and state["restore_state"] in {"verified", "failed", "uncertain"}
                        else "verified" if state and state["restore_state"] == "released" else "unknown"),
                        "archive_id": state["restore_archive_id"] if state else None,
                        "recovery_epoch": int(state["recovery_epoch"] or 0) if state else 0,
                        "verified_at": stamp(state["restore_verified_at"]) if state else None,
                        "failure_code": state["restore_failure_code"] if state else None}},
                "host_policy": policy_doc, "can_configure": host_policy_fresh and bool(deployment_grants(
                    policy, principal, "backup.settings.configure", deployment_id, context))}

    @app.post("/api/v1/operations/backup-settings/{deployment_id}/commands")
    def publish_backup_settings(deployment_id: str, body: dict, request: Request,
                                principal: str = Depends(authenticate)):
        context, registry = getattr(request.state, "authority_context", None), _registry()
        allowed = {"schema_version", "command_id", "action", "expected_revisions",
            "rationale", "evidence_ref", "values", "rollback_revision"}
        if (not isinstance(body, dict) or set(body) - allowed
                or type(body.get("schema_version")) is not int or body.get("schema_version") != 1
                or not isinstance(body.get("expected_revisions"), dict)
                or not isinstance(body.get("rationale"), str) or not body["rationale"].strip()
                or ("evidence_ref" in body and body["evidence_ref"] is not None
                    and not isinstance(body["evidence_ref"], str))):
            raise HTTPException(400, {"code": "invalid_request", "message": "Backup command is invalid"})
        action = body.get("action")
        if action not in {"backup.settings.publish", "backup.settings.rollback"}:
            raise HTTPException(400, {"code": "invalid_request", "message": "Backup action is invalid"})
        required = {"schema_version", "command_id", "action", "expected_revisions",
            "rationale", "evidence_ref", "values" if action.endswith("publish") else "rollback_revision"}
        if (set(body) != required
                or set(body["expected_revisions"]) != {"configuration", "policy", "authority", "host_policy"}
                or any(type(body["expected_revisions"][key]) is not int or body["expected_revisions"][key] < 0
                    for key in body["expected_revisions"])):
            raise HTTPException(400, {"code": "invalid_request", "message": "Backup command members or revision tokens are invalid"})
        if (action.endswith("publish") and ("values" not in body or "rollback_revision" in body)
                or action.endswith("rollback") and ("values" in body or "rollback_revision" not in body)):
            raise HTTPException(400, {"code": "invalid_request", "message": "Backup action and values do not match"})
        try:
            command_id = str(uuid.UUID(body.get("command_id", "")))
        except (ValueError, TypeError, AttributeError):
            raise HTTPException(400, {"code": "invalid_request", "message": "Command ID must be a UUID"}) from None
        if command_id != body["command_id"]:
            raise HTTPException(400, {"code": "invalid_request", "message": "Command ID must be canonical"})
        fixture_failpoint = request.headers.get("x-uvm-g7-fixture-failpoint")
        if fixture_failpoint is not None and (os.environ.get("UVM_G7_DISPOSABLE_MODE") != "1"
                or fixture_failpoint not in {"audit", "intent", "receipt"}):
            raise HTTPException(404, {"code": "not_found", "message": "Fixture endpoint is unavailable"})
        transaction_body_completed = False
        try:
            with engine.begin() as connection:
                from uvm.assessment.policy_lock import lock_policy
                from uvm.persistence.assessment_schema import assessment_policy
                lock_policy(connection)
                policy_row = connection.execute(sa.select(assessment_policy).where(
                    assessment_policy.c.policy_id == 1).with_for_update()).mappings().one_or_none()
                if policy_row is None or deployment_id not in registry or not deployment_grants(
                        policy_row["document"], principal, "backup.settings.read", deployment_id, context):
                    raise HTTPException(404, {"code": "not_found", "message": "Deployment not found"})
                if not deployment_grants(policy_row["document"], principal,
                        "backup.settings.configure", deployment_id, context):
                    raise HTTPException(403, {"code": "forbidden", "message": "Current configuration authority is required"})
                from uvm.operations.backup_settings import commit_backup_settings
                try:
                    receipt, replay = commit_backup_settings(connection,
                        deployment_id=deployment_id, principal=principal,
                        command_id=command_id, action=action, body=body,
                        now=app.state.utc_now(),
                        authorization_context=context.document() if context else None,
                        disposable_failpoint=fixture_failpoint)
                except Exception as exc:
                    from uvm.operations.observer_settings import (ObserverSettingsConflict,
                        ObserverSettingsError, ObserverSettingsUnavailable)
                    if isinstance(exc, ObserverSettingsConflict):
                        raise HTTPException(409, {"code": "revision_conflict", "message": str(exc)}) from None
                    if isinstance(exc, ObserverSettingsError):
                        raise HTTPException(409, {"code": "validation_required", "message": str(exc)}) from None
                    if isinstance(exc, ObserverSettingsUnavailable):
                        raise HTTPException(503, {"code": "host_policy_unavailable", "message": str(exc),
                            "details": {"outcome": "not_committed"}}) from None
                    raise
                transaction_body_completed = True
        except sa.exc.SQLAlchemyError as exc:
            # COMMIT acknowledgement loss is resolved through the receipt.
            sqlstate = getattr(getattr(exc, "orig", None), "sqlstate", None)
            proved_abort = (not transaction_body_completed and
                (isinstance(exc, sa.exc.IntegrityError) or
                 (sqlstate and not getattr(exc, "connection_invalidated", True))))
            return JSONResponse(status_code=503, content={"schema_version": 1, "error": {
                "code": "dependency_unavailable" if proved_abort else "outcome_unknown",
                "message": "Backup settings could not be committed" if proved_abort else
                    "Backup settings commit outcome could not be established",
                "correlation_id": str(uuid.uuid4()), "details": {
                    "outcome": "not_committed" if proved_abort else "unknown",
                    "expected_revisions": body["expected_revisions"], "current_revisions": None,
                    "lookup_url": None if proved_abort else
                        f"/api/v1/operations/backup-settings/{deployment_id}/receipts/{command_id}"}}})
        return JSONResponse(status_code=200 if replay else 201, content=receipt)

    @app.get("/api/v1/operations/backup-settings/{deployment_id}/revisions/{revision}")
    def read_backup_revision(deployment_id: str, revision: int, request: Request,
                             principal: str = Depends(authenticate)):
        context, registry = getattr(request.state, "authority_context", None), _registry()
        from uvm.persistence.backup_settings_schema import g7_backup_settings_revisions
        with engine.begin() as connection:
            from uvm.assessment.policy_lock import lock_policy
            from uvm.persistence.assessment_schema import assessment_policy
            lock_policy(connection, shared=True)
            policy_row = connection.execute(sa.select(assessment_policy).where(
                assessment_policy.c.policy_id == 1)).mappings().one_or_none()
            if policy_row is None or deployment_id not in registry or not deployment_grants(
                    policy_row["document"], principal, "backup.settings.read", deployment_id, context):
                raise HTTPException(404, {"code": "not_found", "message": "Revision not found"})
            row = connection.execute(sa.select(g7_backup_settings_revisions).where(
                g7_backup_settings_revisions.c.deployment_id == deployment_id,
                g7_backup_settings_revisions.c.revision == revision)).mappings().one_or_none()
            if row is None:
                raise HTTPException(404, {"code": "not_found", "message": "Revision not found"})
            from uvm.persistence.assessment_schema import assessment_audit_events
            audit = connection.execute(sa.select(assessment_audit_events.c.event_id).where(
                assessment_audit_events.c.command_id == row["command_id"],
                assessment_audit_events.c.target_id == deployment_audit_id(deployment_id),
                assessment_audit_events.c.origin == "backup_settings_api")).scalar_one_or_none()
            return {"schema_version": 1, "deployment_id": deployment_id,
                "revision": int(row["revision"]), "digest": "sha256:" + row["digest"],
                "values": row["values"], "publication_revisions": {
                    "configuration": int(row["revision"]),
                    "policy": int(row["policy_revision"]),
                    "authority": int(row["authority_revision"]),
                    "host_policy": int(row["host_policy_revision"])},
                "command_id": row["command_id"], "actor_id": row["actor_id"],
                "rationale": row["rationale"], "evidence_ref": row["evidence_ref"],
                "committed_at": row["created_at"].isoformat().replace("+00:00", "Z"),
                "audit_id": audit}

    @app.get("/api/v1/operations/backup-settings/{deployment_id}/receipts/{command_id}")
    def read_backup_receipt(deployment_id: str, command_id: str, request: Request,
                            principal: str = Depends(authenticate)):
        context, registry = getattr(request.state, "authority_context", None), _registry()
        try:
            if str(uuid.UUID(command_id)) != command_id:
                raise ValueError
        except (ValueError, TypeError, AttributeError):
            raise HTTPException(404, {"code": "not_found", "message": "Receipt not found"}) from None
        with engine.begin() as connection:
            from uvm.assessment.policy_lock import lock_policy
            from uvm.persistence.assessment_schema import assessment_policy, assessment_command_receipts
            lock_policy(connection, shared=True)
            policy_row = connection.execute(sa.select(assessment_policy).where(
                assessment_policy.c.policy_id == 1)).mappings().one_or_none()
            if policy_row is None or deployment_id not in registry or not deployment_grants(
                    policy_row["document"], principal, "backup.settings.read", deployment_id, context):
                raise HTTPException(404, {"code": "not_found", "message": "Receipt not found"})
            row = connection.execute(sa.select(assessment_command_receipts).where(
                assessment_command_receipts.c.command_id == command_id,
                assessment_command_receipts.c.target_id == deployment_audit_id(deployment_id),
                assessment_command_receipts.c.action.in_(("backup.settings.publish", "backup.settings.rollback")))).mappings().one_or_none()
            if row is None or (row["principal_id"] != principal and not _audit_view_allowed(
                    policy_row["document"], principal, deployment_id, context)):
                raise HTTPException(404, {"code": "not_found", "message": "Receipt not found"})
            return row["result"]

    def host_auth(request: Request, authorization: str | None = Header(default=None)):
        principal = authenticate(request, authorization)
        context = getattr(request.state, "authority_context", None)
        if context is not None and context.credential_mode in {"oidc_session", "github_link"}:
            raise HTTPException(403, {"code": "forbidden", "message": "Host service identity required"})
        candidates = [entry for entry in _registry().values()
            if entry["host_principal_id"] == principal and principals.get(principal, {}).get("actor_kind") == "service"]
        if len(candidates) != 1:
            raise HTTPException(403, {"code": "forbidden", "message": "Host service identity required"})
        return principal, candidates[0]

    @app.get("/recovery-control/v1/{deployment_id}/desired")
    def recovery_desired(deployment_id: str, request: Request,
                         identity=Depends(host_auth)):
        _principal, entry = identity
        if entry["deployment_id"] != deployment_id:
            raise HTTPException(404, {"code": "not_found", "message": "Deployment not found"})
        from uvm.persistence.backup_settings_schema import g7_backup_settings_revisions, g7_backup_state
        from uvm.persistence.assessment_schema import assessment_policy
        from uvm.auth.native_authority import native_state
        with engine.begin() as connection:
            from uvm.assessment.policy_lock import lock_policy
            lock_policy(connection, shared=True)
            policy_row = connection.execute(sa.select(assessment_policy).where(
                assessment_policy.c.policy_id == 1)).mappings().one_or_none()
            if policy_row is None:
                raise HTTPException(503, {"code": "dependency_unavailable", "message": "Policy is unavailable"})
            policy = policy_row["document"]
            authority = int(native_state(policy).get("revision", 0))
            revision = connection.execute(sa.select(sa.func.coalesce(
                sa.func.max(g7_backup_settings_revisions.c.revision), 0)).where(
                    g7_backup_settings_revisions.c.deployment_id == deployment_id)).scalar_one()
            state = connection.execute(sa.select(g7_backup_state).where(
                g7_backup_state.c.deployment_id == deployment_id)).mappings().one_or_none()
            desired = None
            if revision:
                row = connection.execute(sa.select(g7_backup_settings_revisions).where(
                    g7_backup_settings_revisions.c.deployment_id == deployment_id,
                    g7_backup_settings_revisions.c.revision == int(revision))).mappings().one()
                desired = {"revision": int(row["revision"]), "digest": "sha256:" + row["digest"],
                    "values": row["values"], "command_id": row["command_id"],
                    "intent_id": state["application_intent_id"] if state else None,
                    "issued_at": (row["created_at"] if row["created_at"].tzinfo else row["created_at"].replace(tzinfo=timezone.utc)).isoformat().replace("+00:00", "Z")}
            return {"schema_version": 1, "deployment_id": deployment_id,
                "revisions": {"configuration": int(revision), "policy": int(policy_row["revision"]),
                    "authority": authority,
                    "host_policy": int(state["host_policy_revision"] or 0) if state else 0},
                "desired": desired}

    @app.post("/recovery-control/v1/{deployment_id}/reports")
    def recovery_report(deployment_id: str, body: dict, request: Request,
                        identity=Depends(host_auth)):
        """Admit the first signed policy report; status reports stay separate."""
        _principal, entry = identity
        if entry["deployment_id"] != deployment_id:
            raise HTTPException(404, {"code": "not_found", "message": "Deployment not found"})
        if body.get("report_kind") == "status":
            from uvm.operations.backup_status import admit_status
            return admit_status(engine, deployment_id, body, entry, app.state.utc_now())
        fields = {"schema_version", "deployment_id", "report_id", "sequence",
            "controller_instance_id", "report_kind", "host_policy", "desired",
            "settings_application", "completed_archive", "freshness", "restore_verification",
            "recovery_epoch", "observed_at", "fresh_until", "signature"}
        if (not isinstance(body, dict) or set(body) != fields
                or type(body.get("schema_version")) is not int or body["schema_version"] != 1
                or body.get("deployment_id") != deployment_id or body.get("report_kind") != "policy"
                or any(body.get(key) is not None for key in ("desired", "settings_application",
                    "completed_archive", "freshness", "restore_verification", "recovery_epoch"))
                or type(body.get("sequence")) is not int or body["sequence"] < 1):
            raise HTTPException(400, {"code": "invalid_request", "message": "Policy report shape is invalid"})
        try:
            report_id = str(uuid.UUID(body["report_id"]))
            controller_instance = str(uuid.UUID(body["controller_instance_id"]))
            if report_id != body["report_id"] or controller_instance != body["controller_instance_id"]:
                raise ValueError
            if controller_instance != os.getenv("UVM_G7_CONTROLLER_INSTANCE_ID"):
                raise ValueError
            from uvm.operations.backup_host import canonical_json, digest, parse_utc, validate_policy, verify_signature
            observed_at = parse_utc(body["observed_at"])
            fresh_until = parse_utc(body["fresh_until"])
            policy = validate_policy(body["host_policy"])
            pinned_key_id = os.getenv("UVM_G7_HOST_KEY_ID")
            if not pinned_key_id:
                raise ValueError("host signing key ID is not pinned")
            raw, signature = verify_signature(body, entry["verification_key_file"], pinned_key_id)
            if body["fresh_until"] != (observed_at + timedelta(seconds=policy["maximum_report_age_seconds"])).isoformat().replace("+00:00", "Z"):
                # Accept equivalent UTC spellings only after parsing both instants.
                if fresh_until != observed_at + timedelta(seconds=policy["maximum_report_age_seconds"]):
                    raise ValueError("fresh_until does not match signed report age")
        except (ValueError, TypeError, KeyError):
            raise HTTPException(400, {"code": "invalid_request", "message": "Signed host policy report is invalid"}) from None
        report_digest = hashlib.sha256(raw).hexdigest()
        now = app.state.utc_now()
        from uvm.persistence.backup_settings_schema import g7_backup_host_records, g7_backup_state
        try:
            with engine.begin() as connection:
                from uvm.assessment.policy_lock import lock_policy
                from uvm.persistence.assessment_schema import assessment_policy
                from uvm.auth.native_authority import native_state
                lock_policy(connection)
                current_policy = connection.execute(sa.select(assessment_policy).where(
                    assessment_policy.c.policy_id == 1).with_for_update()).mappings().one_or_none()
                if current_policy is None:
                    raise HTTPException(503, {"code": "dependency_unavailable", "message": "Policy is unavailable"})
                authority_revision = int(native_state(current_policy["document"]).get("revision", 0))
                state = connection.execute(sa.select(g7_backup_state).where(
                    g7_backup_state.c.deployment_id == deployment_id).with_for_update()).mappings().one_or_none()
                prior = connection.execute(sa.select(g7_backup_host_records).where(
                    g7_backup_host_records.c.record_id == report_id).with_for_update()).mappings().one_or_none()
                if prior:
                    if prior["record_digest"] != report_digest or prior["document"] != body:
                        raise HTTPException(409, {"code": "command_conflict", "message": "Report ID conflicts"})
                    return prior["response"]
                old_revision = int(state["host_policy_revision"] or 0) if state else 0
                old_sequence = int(state["latest_sequence"] or 0) if state else 0
                if old_revision:
                    old_skew = int(state["host_policy_future_skew_seconds"] or 0)
                else:
                    initial_skew = os.getenv("UVM_G7_INITIAL_MAXIMUM_FUTURE_SKEW_SECONDS")
                    if initial_skew is None or not initial_skew.isdecimal():
                        raise HTTPException(503, {"code": "host_policy_unavailable",
                            "message": "Initial host clock trust is not configured"})
                    old_skew = int(initial_skew)
                if (policy["revision"] <= old_revision or body["sequence"] != old_sequence + 1
                        or observed_at > now + timedelta(seconds=old_skew) or now > fresh_until):
                    raise HTTPException(409, {"code": "revision_conflict", "message": "Policy revision, sequence or trusted time is invalid"})
                policy_digest = policy["digest"].removeprefix("sha256:")
                response = {"schema_version": 1, "deployment_id": deployment_id,
                    "report_id": report_id, "sequence": body["sequence"], "accepted": True,
                    "report_kind": "policy", "policy_revision": int(current_policy["revision"]),
                    "authority_revision": authority_revision,
                    "host_policy_revision": policy["revision"], "policy_digest": policy["digest"],
                    "desired_revision": None, "desired_digest": None,
                    "accepted_at": now.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")}
                connection.execute(g7_backup_host_records.insert().values(
                    record_id=report_id, deployment_id=deployment_id, record_kind="policy",
                    sequence=body["sequence"], record_digest=report_digest,
                    signature=signature, document=body, response=response, received_at=now))
                values = {"deployment_id": deployment_id,
                    "host_policy_revision": policy["revision"], "host_policy_digest": policy_digest,
                    "host_policy_document": policy, "host_policy_key_id": body["signature"]["key_id"],
                    "host_policy_observed_at": observed_at,
                    "host_policy_max_age_seconds": policy["maximum_report_age_seconds"],
                    "host_policy_future_skew_seconds": policy["maximum_future_skew_seconds"],
                    "latest_report_id": report_id, "latest_sequence": body["sequence"],
                    "latest_report_at": observed_at, "updated_at": now}
                if state is None:
                    connection.execute(g7_backup_state.insert().values(**values))
                else:
                    connection.execute(g7_backup_state.update().where(
                        g7_backup_state.c.deployment_id == deployment_id).values(**values))
                return response
        except sa.exc.SQLAlchemyError:
            raise HTTPException(503, {"code": "dependency_unavailable", "message": "Policy report was not committed"}) from None

    @app.post("/recovery-control/v1/{deployment_id}/acks")
    def recovery_ack(deployment_id: str, body: dict, request: Request,
                    identity=Depends(host_auth)):
        _principal, entry = identity
        if entry["deployment_id"] != deployment_id:
            raise HTTPException(404, {"code": "not_found", "message": "Deployment not found"})
        fields = {"schema_version", "deployment_id", "ack_id", "sequence",
            "controller_instance_id", "intent_id", "requested_revision", "requested_digest",
            "active_revision", "active_digest", "host_policy_revision", "outcome",
            "failure_code", "observed_at", "signature"}
        if (not isinstance(body, dict) or set(body) != fields
                or type(body.get("schema_version")) is not int or body["schema_version"] != 1
                or body.get("deployment_id") != deployment_id
                or body.get("outcome") not in {"applied", "failed", "uncertain"}
                or (body.get("failure_code") is not None and not re.fullmatch(
                    r"[a-z][a-z0-9_]{0,63}", body["failure_code"]))):
            raise HTTPException(400, {"code": "invalid_request", "message": "Application acknowledgement shape is invalid"})
        try:
            from uvm.operations.backup_host import parse_utc, verify_signature
            ack_id = str(uuid.UUID(body["ack_id"]))
            controller_instance = str(uuid.UUID(body["controller_instance_id"]))
            intent_id = str(uuid.UUID(body["intent_id"]))
            if any(value != body[field] for value, field in ((ack_id, "ack_id"),
                    (controller_instance, "controller_instance_id"), (intent_id, "intent_id"))):
                raise ValueError
            if controller_instance != os.getenv("UVM_G7_CONTROLLER_INSTANCE_ID"):
                raise ValueError
            if (type(body["sequence"]) is not int or body["sequence"] < 1
                    or type(body["requested_revision"]) is not int or body["requested_revision"] < 1
                    or (body["active_revision"] is not None and
                        (type(body["active_revision"]) is not int or body["active_revision"] < 1))
                    or type(body["host_policy_revision"]) is not int or body["host_policy_revision"] < 1):
                raise ValueError
            parse_digest = lambda value: isinstance(value, str) and re.fullmatch(r"sha256:[0-9a-f]{64}", value)
            if (not parse_digest(body["requested_digest"]) or
                    (body["active_revision"] is None and body["active_digest"] is not None) or
                    (body["active_revision"] is not None and not parse_digest(body["active_digest"]))):
                raise ValueError
            observed = parse_utc(body["observed_at"])
            if not os.getenv("UVM_G7_HOST_KEY_ID"):
                raise ValueError
            raw, signature = verify_signature(body, entry["verification_key_file"], os.getenv("UVM_G7_HOST_KEY_ID"))
        except (ValueError, TypeError, KeyError):
            raise HTTPException(400, {"code": "invalid_request", "message": "Signed application acknowledgement is invalid"}) from None
        now = app.state.utc_now()
        record_digest = hashlib.sha256(raw).hexdigest()
        from uvm.persistence.backup_settings_schema import g7_backup_host_records, g7_backup_state, g7_backup_settings_revisions
        from uvm.persistence.assessment_schema import assessment_policy
        try:
            with engine.begin() as connection:
                from uvm.assessment.policy_lock import lock_policy
                from uvm.auth.native_authority import native_state
                lock_policy(connection)
                policy_row = connection.execute(sa.select(assessment_policy).where(
                    assessment_policy.c.policy_id == 1).with_for_update()).mappings().one_or_none()
                if policy_row is None:
                    raise HTTPException(503, {"code": "dependency_unavailable", "message": "Policy is unavailable"})
                authority = int(native_state(policy_row["document"]).get("revision", 0))
                state = connection.execute(sa.select(g7_backup_state).where(
                    g7_backup_state.c.deployment_id == deployment_id).with_for_update()).mappings().one_or_none()
                prior = connection.execute(sa.select(g7_backup_host_records).where(
                    g7_backup_host_records.c.record_id == ack_id).with_for_update()).mappings().one_or_none()
                if prior:
                    if prior["record_digest"] != record_digest or prior["document"] != body:
                        raise HTTPException(409, {"code": "command_conflict", "message": "Acknowledgement ID conflicts"})
                    return prior["response"]
                if (not state or not state["host_policy_document"]
                        or state["host_policy_revision"] != body["host_policy_revision"]
                        or body["sequence"] != int(state["latest_sequence"] or 0) + 1):
                    raise HTTPException(409, {"code": "revision_conflict", "message": "Host policy or sequence changed"})
                external_floor = connection.execute(sa.select(sa.func.max(
                    g7_backup_host_records.c.recovery_epoch)).where(
                        g7_backup_host_records.c.deployment_id == deployment_id,
                        g7_backup_host_records.c.record_kind == "resync")).scalar_one() or 0
                if int(state["recovery_epoch"] or 0) < external_floor:
                    raise HTTPException(409, {"code": "revision_conflict", "message": "Application acknowledgement is below the external epoch floor"})
                hp = state["host_policy_document"]
                policy_observed = state["host_policy_observed_at"]
                if policy_observed and policy_observed.tzinfo is None:
                    policy_observed = policy_observed.replace(tzinfo=timezone.utc)
                if (not policy_observed or now > policy_observed + timedelta(
                        seconds=int(hp["maximum_report_age_seconds"]))
                        or observed > now + timedelta(seconds=int(hp["maximum_future_skew_seconds"]))):
                    raise HTTPException(503, {"code": "host_policy_unavailable", "message": "Trusted host policy is stale"})
                if now - observed > timedelta(seconds=int(hp["maximum_report_age_seconds"])):
                    raise HTTPException(409, {"code": "revision_conflict", "message": "Application acknowledgement expired before first delivery"})
                desired = connection.execute(sa.select(g7_backup_settings_revisions).where(
                    g7_backup_settings_revisions.c.deployment_id == deployment_id,
                    g7_backup_settings_revisions.c.revision == body["requested_revision"])).mappings().one_or_none()
                if (desired is None or desired["digest"] != body["requested_digest"].removeprefix("sha256:")
                        or body["requested_revision"] != state["requested_revision"]
                        or body["intent_id"] != state["application_intent_id"]):
                    raise HTTPException(409, {"code": "revision_conflict", "message": "Acknowledgement does not match current intent"})
                if body["outcome"] == "applied" and (
                        body["active_revision"] != body["requested_revision"]
                        or body["active_digest"] != body["requested_digest"]):
                    raise HTTPException(409, {"code": "revision_conflict", "message": "Applied acknowledgement must match desired settings"})
                response = {"schema_version": 1, "deployment_id": deployment_id,
                    "ack_id": ack_id, "sequence": body["sequence"], "accepted": True,
                    "application_state": body["outcome"],
                    "requested_revision": body["requested_revision"],
                    "requested_digest": body["requested_digest"],
                    "active_revision": body["active_revision"], "active_digest": body["active_digest"],
                    "revisions": {"configuration": int(state["requested_revision"]),
                        "policy": int(policy_row["revision"]), "authority": authority,
                        "host_policy": int(state["host_policy_revision"])},
                    "accepted_at": now.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")}
                connection.execute(g7_backup_host_records.insert().values(
                    record_id=ack_id, deployment_id=deployment_id, record_kind="ack",
                    sequence=body["sequence"], record_digest=record_digest,
                    signature=signature, document=body, response=response, received_at=now))
                values = {"application_status": body["outcome"], "latest_report_id": ack_id,
                    "latest_sequence": body["sequence"], "latest_report_at": observed,
                    "latest_failure_code": body["failure_code"], "updated_at": now}
                if body["outcome"] == "applied":
                    values.update(effective_revision=body["active_revision"],
                        effective_digest=body["active_digest"].removeprefix("sha256:"))
                connection.execute(g7_backup_state.update().where(
                    g7_backup_state.c.deployment_id == deployment_id).values(**values))
                return response
        except sa.exc.SQLAlchemyError:
            raise HTTPException(503, {"code": "dependency_unavailable", "message": "Acknowledgement was not committed"}) from None

    @app.post("/recovery-control/v1/{deployment_id}/sequence-resync")
    def recovery_sequence_resync(deployment_id: str, body: dict, request: Request,
                                 identity=Depends(host_auth)):
        _principal, entry = identity
        if entry["deployment_id"] != deployment_id:
            raise HTTPException(404, {"code": "not_found", "message": "Deployment not found"})
        fields = {"schema_version", "deployment_id", "resync_id", "controller_instance_id",
            "database_epoch_seen", "database_sequence_seen", "checkpoint_epoch_floor",
            "checkpoint_last_sequence", "issued_at"}
        if (not isinstance(body, dict) or set(body) != fields
                or type(body.get("schema_version")) is not int or body["schema_version"] != 1
                or body.get("deployment_id") != deployment_id):
            raise HTTPException(400, {"code": "invalid_request", "message": "Resync request shape is invalid"})
        try:
            resync_id = str(uuid.UUID(body["resync_id"]))
            instance_id = str(uuid.UUID(body["controller_instance_id"]))
            if (resync_id != body["resync_id"] or instance_id != body["controller_instance_id"]
                    or instance_id != os.getenv("UVM_G7_CONTROLLER_INSTANCE_ID")):
                raise ValueError
            counters = ("database_epoch_seen", "database_sequence_seen",
                "checkpoint_epoch_floor", "checkpoint_last_sequence")
            if any(type(body[key]) is not int or body[key] < 0 or body[key] > 9007199254740991 for key in counters):
                raise ValueError
            issued_at = datetime.fromisoformat(body["issued_at"].replace("Z", "+00:00"))
            if issued_at.tzinfo is None or issued_at.utcoffset() != timezone.utc.utcoffset(issued_at):
                raise ValueError
            issued_at = issued_at.astimezone(timezone.utc)
            canonical = json.dumps(body, ensure_ascii=False, sort_keys=True,
                separators=(",", ":"), allow_nan=False).encode("utf-8")
        except (ValueError, TypeError, KeyError, AttributeError):
            raise HTTPException(400, {"code": "invalid_request", "message": "Resync request identity or counters are invalid"}) from None
        now = app.state.utc_now()
        request_digest = hashlib.sha256(canonical).hexdigest()
        from uvm.persistence.backup_settings_schema import g7_backup_host_records, g7_backup_state
        from uvm.persistence.assessment_schema import assessment_policy
        try:
            with engine.begin() as connection:
                from uvm.assessment.policy_lock import lock_policy
                from uvm.auth.native_authority import native_state
                lock_policy(connection)
                policy_row = connection.execute(sa.select(assessment_policy).where(
                    assessment_policy.c.policy_id == 1).with_for_update()).mappings().one_or_none()
                if policy_row is None:
                    raise HTTPException(503, {"code": "dependency_unavailable", "message": "Policy is unavailable"})
                state = connection.execute(sa.select(g7_backup_state).where(
                    g7_backup_state.c.deployment_id == deployment_id).with_for_update()).mappings().one_or_none()
                prior = connection.execute(sa.select(g7_backup_host_records).where(
                    g7_backup_host_records.c.record_id == resync_id).with_for_update()).mappings().one_or_none()
                if prior:
                    if prior["record_digest"] != request_digest or prior["document"] != body:
                        raise HTTPException(409, {"code": "command_conflict", "message": "Resync ID conflicts"})
                    return prior["response"]
                if not state or not state["host_policy_document"]:
                    raise HTTPException(503, {"code": "host_policy_unavailable", "message": "Trusted host policy is unavailable"})
                policy_doc = state["host_policy_document"]
                observed = state["host_policy_observed_at"]
                if observed and observed.tzinfo is None:
                    observed = observed.replace(tzinfo=timezone.utc)
                if (issued_at > now + timedelta(seconds=int(policy_doc["maximum_future_skew_seconds"]))
                        or now - issued_at > timedelta(seconds=int(policy_doc["maximum_report_age_seconds"]))):
                    raise HTTPException(503, {"code": "host_policy_unavailable", "message": "Resync clock or policy is stale"})
                if (body["database_epoch_seen"] > body["checkpoint_epoch_floor"]
                        or body["database_sequence_seen"] > body["checkpoint_last_sequence"]
                        or body["checkpoint_epoch_floor"] < int(state["recovery_epoch"] or 0)
                        or body["checkpoint_last_sequence"] < int(state["latest_sequence"] or 0)):
                    raise HTTPException(409, {"code": "revision_conflict", "message": "External checkpoint is lower or inconsistent"})
                policy_revision = int(policy_row["revision"])
                authority = int(native_state(policy_row["document"]).get("revision", 0))
                host_policy_revision = int(state["host_policy_revision"] or 0)
                response = {"schema_version": 1, "deployment_id": deployment_id,
                    "resync_id": resync_id, "recovery_epoch_floor": body["checkpoint_epoch_floor"],
                    "next_sequence": body["checkpoint_last_sequence"] + 1, "accepted": True,
                    "revisions": {"configuration": int(state["requested_revision"] or 0),
                        "policy": policy_revision, "authority": authority,
                        "host_policy": host_policy_revision},
                    "accepted_at": now.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")}
                connection.execute(g7_backup_host_records.insert().values(
                    record_id=resync_id, deployment_id=deployment_id, record_kind="resync",
                    sequence=None,
                    recovery_epoch=body["checkpoint_epoch_floor"], record_digest=request_digest,
                    document=body, response=response, received_at=now))
                connection.execute(g7_backup_state.update().where(
                    g7_backup_state.c.deployment_id == deployment_id).values(
                        latest_sequence=body["checkpoint_last_sequence"],
                        updated_at=now))
                return response
        except sa.exc.SQLAlchemyError:
            raise HTTPException(503, {"code": "dependency_unavailable", "message": "Resync acknowledgement was not retained"}) from None

    @app.post("/recovery-control/v1/{deployment_id}/connector-quarantine")
    def recovery_connector_quarantine(deployment_id: str, body: dict, request: Request,
                                      identity=Depends(host_auth)):
        """Persist the exact host-authorized uncertain-intent quarantine set."""
        _principal, entry = identity
        if entry["deployment_id"] != deployment_id:
            raise HTTPException(404, {"code": "not_found", "message": "Deployment not found"})
        fields = {"schema_version", "deployment_id", "event_id", "recovery_epoch",
            "connector_recovery_id", "connector_id", "intent_ids", "reason_code",
            "observed_at", "signature"}
        if (not isinstance(body, dict) or set(body) != fields
                or type(body.get("schema_version")) is not int or body["schema_version"] != 1
                or body.get("deployment_id") != deployment_id
                or body.get("reason_code") != "restore_uncertain_effect"
                or not isinstance(body.get("connector_id"), str)
                or not re.fullmatch(r"[A-Za-z0-9._:-]{1,256}", body["connector_id"])
                or not isinstance(body.get("intent_ids"), list) or not body["intent_ids"]
                or len(body["intent_ids"]) > 1000):
            raise HTTPException(400, {"code": "invalid_request", "message": "Quarantine request shape is invalid"})
        try:
            from uvm.operations.backup_host import parse_utc, verify_signature
            event_id = str(uuid.UUID(body["event_id"]))
            connector_recovery_id = str(uuid.UUID(body["connector_recovery_id"]))
            intent_ids = [str(uuid.UUID(value)) for value in body["intent_ids"]]
            if (event_id != body["event_id"] or connector_recovery_id != body["connector_recovery_id"]
                    or len(set(intent_ids)) != len(intent_ids)
                    or any(value != original for value, original in zip(intent_ids, body["intent_ids"]))
                    or type(body["recovery_epoch"]) is not int or body["recovery_epoch"] < 1
                    or not os.getenv("UVM_G7_HOST_KEY_ID")):
                raise ValueError
            observed = parse_utc(body["observed_at"])
            raw, signature = verify_signature(body, entry["verification_key_file"],
                os.getenv("UVM_G7_HOST_KEY_ID"))
        except (ValueError, TypeError, KeyError):
            raise HTTPException(400, {"code": "invalid_request", "message": "Signed quarantine request is invalid"}) from None
        now = app.state.utc_now()
        record_digest = hashlib.sha256(raw).hexdigest()
        from uvm.persistence.backup_settings_schema import (g7_backup_connector_quarantine,
            g7_backup_host_records, g7_backup_state)
        from uvm.persistence.assessment_schema import assessment_policy
        from uvm.auth.native_authority import native_state
        try:
            with engine.begin() as connection:
                from uvm.assessment.policy_lock import lock_policy
                lock_policy(connection)
                policy_row = connection.execute(sa.select(assessment_policy).where(
                    assessment_policy.c.policy_id == 1).with_for_update()).mappings().one_or_none()
                if policy_row is None:
                    raise HTTPException(503, {"code": "dependency_unavailable", "message": "Policy is unavailable"})
                state = connection.execute(sa.select(g7_backup_state).where(
                    g7_backup_state.c.deployment_id == deployment_id).with_for_update()).mappings().one_or_none()
                prior = connection.execute(sa.select(g7_backup_host_records).where(
                    g7_backup_host_records.c.record_id == event_id).with_for_update()).mappings().one_or_none()
                if prior:
                    if prior["record_digest"] != record_digest or prior["document"] != body:
                        raise HTTPException(409, {"code": "command_conflict", "message": "Quarantine event conflicts"})
                    return prior["response"]
                if not state or not state["host_policy_document"]:
                    raise HTTPException(503, {"code": "host_policy_unavailable", "message": "Trusted host policy is unavailable"})
                host_policy = state["host_policy_document"]
                policy_observed = state["host_policy_observed_at"]
                if policy_observed and policy_observed.tzinfo is None:
                    policy_observed = policy_observed.replace(tzinfo=timezone.utc)
                if (not policy_observed or now > policy_observed + timedelta(
                        seconds=int(host_policy["maximum_report_age_seconds"]))
                        or observed > now + timedelta(seconds=int(host_policy["maximum_future_skew_seconds"]))
                        or now - observed > timedelta(seconds=int(host_policy["maximum_report_age_seconds"]))):
                    raise HTTPException(503, {"code": "host_policy_unavailable", "message": "Quarantine policy or clock is stale"})
                if body["recovery_epoch"] != int(state["recovery_epoch"] or 0):
                    raise HTTPException(409, {"code": "revision_conflict", "message": "Quarantine recovery epoch is stale"})
                started = connection.execute(sa.select(g7_backup_host_records.c.document).where(
                    g7_backup_host_records.c.deployment_id == deployment_id,
                    g7_backup_host_records.c.record_kind == "recovery",
                    g7_backup_host_records.c.recovery_epoch == body["recovery_epoch"]).order_by(
                        g7_backup_host_records.c.sequence)).scalars().first()
                if not started or started["connector_recovery_id"] != connector_recovery_id:
                    raise HTTPException(409, {"code": "revision_conflict", "message": "Quarantine restore identity differs"})
                response = {"schema_version": 1, "deployment_id": deployment_id,
                    "event_id": event_id, "accepted": True,
                    "recovery_epoch": body["recovery_epoch"],
                    "revisions": {"configuration": int(state["requested_revision"] or 0),
                        "policy": int(policy_row["revision"]),
                        "authority": int(native_state(policy_row["document"]).get("revision", 0)),
                        "host_policy": int(state["host_policy_revision"] or 0)},
                    "accepted_at": now.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")}
                connection.execute(g7_backup_host_records.insert().values(
                    record_id=event_id, deployment_id=deployment_id, record_kind="quarantine",
                    recovery_epoch=body["recovery_epoch"], record_digest=record_digest,
                    signature=signature, document=body, response=response, received_at=now))
                for intent_id in intent_ids:
                    existing = connection.execute(sa.select(g7_backup_connector_quarantine).where(
                        g7_backup_connector_quarantine.c.deployment_id == deployment_id,
                        g7_backup_connector_quarantine.c.intent_id == intent_id).with_for_update()).mappings().first()
                    values = {"deployment_id": deployment_id, "intent_id": intent_id,
                        "connector_id": body["connector_id"], "recovery_epoch": body["recovery_epoch"],
                        "connector_recovery_id": connector_recovery_id, "event_id": event_id,
                        "reason_code": body["reason_code"], "created_at": now}
                    if existing:
                        if (existing["connector_id"] != body["connector_id"] or
                                existing["recovery_epoch"] >= body["recovery_epoch"]):
                            raise HTTPException(409, {"code": "revision_conflict", "message": "Intent already has a conflicting recovery hold"})
                        connection.execute(g7_backup_connector_quarantine.update().where(
                            g7_backup_connector_quarantine.c.deployment_id == deployment_id,
                            g7_backup_connector_quarantine.c.intent_id == intent_id).values(**values))
                    else:
                        connection.execute(g7_backup_connector_quarantine.insert().values(**values))
                return response
        except sa.exc.IntegrityError:
            raise HTTPException(409, {"code": "command_conflict", "message": "Quarantine intent conflicts"}) from None
        except sa.exc.SQLAlchemyError:
            raise HTTPException(503, {"code": "dependency_unavailable", "message": "Quarantine was not retained"}) from None

    @app.post("/recovery-control/v1/{deployment_id}/recovery-events")
    def recovery_event(deployment_id: str, body: dict, identity=Depends(host_auth)):
        """Admit signed, monotonic restore transitions; never release dispatch."""
        _principal, entry = identity
        if entry["deployment_id"] != deployment_id:
            raise HTTPException(404, {"code": "not_found", "message": "Deployment not found"})
        fields = {"schema_version", "deployment_id", "event_id", "sequence",
            "controller_instance_id", "recovery_epoch", "connector_recovery_id",
            "previous_epoch", "event_type", "archive_id", "manifest_digest",
            "source_image_digest", "target_image_digest", "new_volume_ids",
            "verification", "queue_inventory_digest", "public_readback_digest",
            "failure_code", "observed_at", "signature"}
        if (not isinstance(body, dict) or set(body) != fields
                or type(body.get("schema_version")) is not int or body["schema_version"] != 1
                or body.get("deployment_id") != deployment_id):
            raise HTTPException(400, {"code": "invalid_request", "message": "Recovery event shape is invalid"})
        try:
            from uvm.operations.backup_host import parse_utc, verify_signature
            event_id = str(uuid.UUID(body["event_id"]))
            instance_id = str(uuid.UUID(body["controller_instance_id"]))
            connector_recovery_id = str(uuid.UUID(body["connector_recovery_id"]))
            archive_id = str(uuid.UUID(body["archive_id"]))
            if (event_id != body["event_id"] or instance_id != body["controller_instance_id"]
                    or connector_recovery_id != body["connector_recovery_id"]
                    or archive_id != body["archive_id"]
                    or instance_id != os.getenv("UVM_G7_CONTROLLER_INSTANCE_ID")
                    or any(type(body.get(key)) is not int or body[key] < 0
                        for key in ("sequence", "recovery_epoch", "previous_epoch"))
                    or not all(isinstance(body.get(key), str) and re.fullmatch(
                        r"sha256:[0-9a-f]{64}", body[key]) for key in
                        ("manifest_digest", "source_image_digest", "queue_inventory_digest"))):
                raise ValueError
            observed = parse_utc(body["observed_at"])
            raw, signature = verify_signature(body, entry["verification_key_file"],
                os.getenv("UVM_G7_HOST_KEY_ID"))
            verification = body["verification"]
            verify_keys = {"uvm_public_api", "ce_public_api", "media_readback",
                "queue_reconciliation", "migration", "details_digest"}
            if (not isinstance(verification, dict) or set(verification) != verify_keys
                    or any(verification[key] not in {"not_run", "passed", "failed"}
                        for key in verify_keys - {"details_digest"})
                    or (verification["details_digest"] is not None and not re.fullmatch(
                        r"sha256:[0-9a-f]{64}", verification["details_digest"]))):
                raise ValueError
            volumes = body["new_volume_ids"]
            if volumes is not None and (not isinstance(volumes, dict)
                    or set(volumes) != {"postgres_cluster", "ce_media", "uvm_state"}
                    or any(not isinstance(value, str) or not value or len(value) > 256
                        for value in volumes.values()) or len(set(volumes.values())) != 3):
                raise ValueError
            for key in ("target_image_digest", "public_readback_digest"):
                if body[key] is not None and not re.fullmatch(r"sha256:[0-9a-f]{64}", body[key]):
                    raise ValueError
            if body["failure_code"] is not None and (not isinstance(body["failure_code"], str)
                    or not re.fullmatch(r"[a-z][a-z0-9_]{0,63}", body["failure_code"])):
                raise ValueError
            if body["event_type"] not in {"restore_started", "preflight_rejected",
                    "volumes_restored", "verification_passed", "verification_failed", "fence_released"}:
                raise ValueError
        except (ValueError, TypeError, KeyError):
            raise HTTPException(400, {"code": "invalid_request", "message": "Recovery event is invalid"}) from None
        now = app.state.utc_now()
        record_digest = hashlib.sha256(raw).hexdigest()
        from uvm.persistence.backup_settings_schema import g7_backup_host_records, g7_backup_state
        from uvm.persistence.assessment_schema import assessment_policy
        from uvm.auth.native_authority import native_state
        try:
            with engine.begin() as connection:
                from uvm.assessment.policy_lock import lock_policy
                lock_policy(connection)
                policy_row = connection.execute(sa.select(assessment_policy).where(
                    assessment_policy.c.policy_id == 1).with_for_update()).mappings().one_or_none()
                if policy_row is None:
                    raise HTTPException(503, {"code": "dependency_unavailable", "message": "Policy is unavailable"})
                state = connection.execute(sa.select(g7_backup_state).where(
                    g7_backup_state.c.deployment_id == deployment_id).with_for_update()).mappings().one_or_none()
                prior = connection.execute(sa.select(g7_backup_host_records).where(
                    g7_backup_host_records.c.record_id == event_id).with_for_update()).mappings().one_or_none()
                if prior:
                    if prior["record_digest"] != record_digest or prior["document"] != body:
                        raise HTTPException(409, {"code": "command_conflict", "message": "Recovery event conflicts"})
                    return prior["response"]
                if not state or not state["host_policy_document"]:
                    raise HTTPException(503, {"code": "host_policy_unavailable", "message": "Trusted host policy is unavailable"})
                host_policy = state["host_policy_document"]
                policy_observed = state["host_policy_observed_at"]
                if policy_observed and policy_observed.tzinfo is None:
                    policy_observed = policy_observed.replace(tzinfo=timezone.utc)
                if (not policy_observed or now > policy_observed + timedelta(
                        seconds=int(host_policy["maximum_report_age_seconds"]))
                        or observed > now + timedelta(seconds=int(host_policy["maximum_future_skew_seconds"]))
                        or now - observed > timedelta(seconds=int(host_policy["maximum_report_age_seconds"]))):
                    raise HTTPException(503, {"code": "host_policy_unavailable", "message": "Recovery event clock or policy is stale"})
                old_epoch = int(state["recovery_epoch"] or 0)
                old_state = state["restore_state"] or "unknown"
                event = body["event_type"]
                transitions = {("unknown", "restore_started"): "started",
                    ("failed", "restore_started"): "started",
                    ("released", "restore_started"): "started",
                    ("started", "preflight_rejected"): "failed",
                    ("started", "volumes_restored"): "restored",
                    ("restored", "verification_passed"): "verified",
                    ("restored", "verification_failed"): "failed",
                    ("verified", "fence_released"): "released"}
                checkpoint_floor = connection.execute(sa.select(
                    sa.func.max(g7_backup_host_records.c.recovery_epoch)).where(
                        g7_backup_host_records.c.deployment_id == deployment_id,
                        g7_backup_host_records.c.record_kind == "resync")).scalar_one() or 0
                expected_epoch = max(old_epoch + 1, int(checkpoint_floor)) if event == "restore_started" else old_epoch
                if body["recovery_epoch"] < int(checkpoint_floor):
                    raise HTTPException(409, {"code": "revision_conflict", "message": "Recovery epoch is below the external floor"})
                if (body["sequence"] != int(state["latest_sequence"] or 0) + 1
                        or body["previous_epoch"] != (expected_epoch - 1 if event == "restore_started" else old_epoch)
                        or body["recovery_epoch"] != expected_epoch
                        or (old_state, event) not in transitions):
                    raise HTTPException(409, {"code": "revision_conflict", "message": "Recovery transition or epoch is stale"})
                if event != "restore_started":
                    retained = connection.execute(sa.select(g7_backup_host_records.c.document).where(
                        g7_backup_host_records.c.deployment_id == deployment_id,
                        g7_backup_host_records.c.record_kind == "recovery",
                        g7_backup_host_records.c.recovery_epoch == old_epoch).order_by(
                            g7_backup_host_records.c.sequence)).scalars().all()
                    started = next((doc for doc in retained if doc["event_type"] == "restore_started"), None)
                    restored = next((doc for doc in retained if doc["event_type"] == "volumes_restored"), None)
                    binding = ("connector_recovery_id", "archive_id", "manifest_digest",
                        "source_image_digest", "queue_inventory_digest")
                    if (started is None or any(body[key] != started[key] for key in binding)
                            or (restored is not None and any(body[key] != restored[key]
                                for key in ("target_image_digest", "new_volume_ids")))):
                        raise HTTPException(409, {"code": "revision_conflict",
                            "message": "Recovery event changes the admitted restore identity"})
                if event in {"verification_passed", "fence_released"}:
                    from uvm.persistence.backup_settings_schema import g7_backup_settings_revisions
                    effective_values = connection.execute(sa.select(g7_backup_settings_revisions.c["values"]).where(
                        g7_backup_settings_revisions.c.deployment_id == deployment_id,
                        g7_backup_settings_revisions.c.revision == state["effective_revision"])).scalar_one_or_none()
                    if (not effective_values or now > parse_utc(started["observed_at"]) + timedelta(
                            seconds=effective_values["restore_verification_timeout_seconds"])):
                        raise HTTPException(409, {"code": "revision_conflict", "message": "Restore verification operation deadline expired"})
                if event == "volumes_restored" and (body["new_volume_ids"] is None
                        or body["target_image_digest"] is None):
                    raise HTTPException(400, {"code": "invalid_request", "message": "Restored volumes and target image are required"})
                if event == "verification_passed" and (body["public_readback_digest"] is None
                        or any(body["verification"][key] != "passed" for key in
                            ("uvm_public_api", "ce_public_api", "media_readback", "queue_reconciliation", "migration"))
                        or body["verification"]["details_digest"] is None):
                    raise HTTPException(409, {"code": "revision_conflict", "message": "Public verification evidence is incomplete"})
                if event == "fence_released":
                    verified = next((doc for doc in retained if doc["event_type"] == "verification_passed"), None)
                    if (verified is None or body["verification"] != verified["verification"] or
                            body["public_readback_digest"] != verified["public_readback_digest"] or
                            body["failure_code"] is not None):
                        raise HTTPException(409, {"code": "revision_conflict", "message": "Fence release changes the verified recovery proof"})
                policy_doc = policy_row["document"]
                revisions = {"configuration": int(state["requested_revision"] or 0),
                    "policy": int(policy_row["revision"]),
                    "authority": int(native_state(policy_doc).get("revision", 0)),
                    "host_policy": int(state["host_policy_revision"] or 0)}
                response = {"schema_version": 1, "deployment_id": deployment_id,
                    "event_id": event_id, "sequence": body["sequence"],
                    "recovery_epoch": body["recovery_epoch"], "accepted": True,
                    "current_state": transitions[(old_state, event)], "revisions": revisions,
                    "accepted_at": now.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")}
                if event == "volumes_restored":
                    from uvm.connectors.api import apply_restore_quarantine_connection
                    apply_restore_quarantine_connection(connection, connector_recovery_id)
                connection.execute(g7_backup_host_records.insert().values(
                    record_id=event_id, deployment_id=deployment_id, record_kind="recovery",
                    sequence=body["sequence"], recovery_epoch=body["recovery_epoch"],
                    record_digest=record_digest, signature=signature, document=body,
                    response=response, received_at=now))
                connection.execute(g7_backup_state.update().where(
                    g7_backup_state.c.deployment_id == deployment_id).values(
                        latest_sequence=body["sequence"], recovery_epoch=body["recovery_epoch"],
                        restore_state=transitions[(old_state, event)],
                        restore_archive_id=archive_id,
                        restore_verified_at=now if event == "verification_passed" else state["restore_verified_at"],
                        restore_failure_code=body["failure_code"], updated_at=now))
                return response
        except sa.exc.IntegrityError:
            raise HTTPException(409, {"code": "command_conflict", "message": "Recovery sequence conflicts"}) from None
        except sa.exc.SQLAlchemyError:
            raise HTTPException(503, {"code": "dependency_unavailable", "message": "Recovery event was not retained"}) from None

    @app.get("/api/v1/operations/observer-settings")
    def discover_observer_deployments(request: Request, limit: int = 50,
            cursor: str | None = None, principal: str = Depends(authenticate)):
        if type(limit) is not int or not 1 <= limit <= 100:
            raise HTTPException(400, {"code": "invalid_request",
                "message": "Deployment discovery limit must be between 1 and 100"})
        context = getattr(request.state, "authority_context", None)
        registry = _registry()
        with engine.begin() as connection:
            from uvm.assessment.policy_lock import lock_policy
            lock_policy(connection, shared=True)
            policy_row = _policy(connection)
            native = policy_row["document"]
            from uvm.auth.native_authority import native_state
            authority_revision = int(native_state(native).get("revision", 0))
            deployments = []
            for deployment, item in sorted(registry.items()):
                grants = deployment_grants(native, principal, "observer.timing.read", deployment, context)
                if grants:
                    deployments.append({"deployment_id": deployment, "label": item["label"],
                        "can_configure": bool(deployment_grants(native, principal,
                            "observer.timing.configure", deployment, context))})
            registry_state = []
            for deployment, item in sorted(registry.items()):
                key_digest = hashlib.sha256(Path(item["verification_key_file"]).read_bytes()).hexdigest()
                registry_state.append({"deployment_id": deployment, "label": item["label"],
                    "host_principal_id": item["host_principal_id"],
                    "verification_key_digest": key_digest})
            registry_digest = hashlib.sha256(json.dumps(registry_state, sort_keys=True,
                separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()
            visible_digest = hashlib.sha256(json.dumps(deployments, sort_keys=True,
                separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()
            offset = 0
            if cursor is not None:
                offset = _read_discovery_cursor(app.state.cursor_secret, cursor,
                    principal=principal, authority_revision=authority_revision,
                    registry_digest=registry_digest, visible_digest=visible_digest,
                    limit=limit, now_epoch=int(app.state.utc_now().timestamp()))
        page = deployments[offset:offset + limit]
        next_cursor = None
        if offset + len(page) < len(deployments):
            next_cursor = _discovery_cursor(app.state.cursor_secret,
                principal=principal, authority_revision=authority_revision,
                registry_digest=registry_digest, visible_digest=visible_digest,
                after=offset + len(page), limit=limit,
                expires_at=int(app.state.utc_now().timestamp()) + 300)
        return {"schema_version": 1, "deployments": page, "next_cursor": next_cursor}

    @app.get("/api/v1/operations/backup-settings")
    def discover_backup_deployments(request: Request, cursor: str | None = None,
            principal: str = Depends(authenticate)):
        """Enumerate only currently readable trusted backup deployments."""
        page_size = 50
        context = getattr(request.state, "authority_context", None)
        registry = _registry()
        with engine.begin() as connection:
            from uvm.assessment.policy_lock import lock_policy
            lock_policy(connection, shared=True)
            policy_row = _policy(connection)
            native = policy_row["document"]
            from uvm.auth.native_authority import native_state
            policy_revision = int(policy_row["revision"])
            authority_revision = int(native_state(native).get("revision", 0))
            # Build the complete authorized projection under current authority before
            # computing page bounds or interpreting a continuation cursor.
            visible = []
            for deployment, item in sorted(registry.items(), key=lambda pair: pair[0].encode("utf-8")):
                if deployment_grants(native, principal, "backup.settings.read", deployment, context):
                    visible.append({"deployment_id": deployment, "label": item["label"],
                        "can_configure": bool(deployment_grants(native, principal,
                            "backup.settings.configure", deployment, context))})
            registry_state = [{"deployment_id": deployment, "label": item["label"],
                "host_principal_id": item["host_principal_id"],
                "verification_key_digest": hashlib.sha256(
                    Path(item["verification_key_file"]).read_bytes()).hexdigest()}
                for deployment, item in sorted(registry.items(), key=lambda pair: pair[0].encode("utf-8"))]
            registry_digest = hashlib.sha256(json.dumps(registry_state, sort_keys=True,
                separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()
            visible_digest = hashlib.sha256(json.dumps(visible, sort_keys=True,
                separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()
            offset = 0
            if cursor is not None:
                try:
                    offset = _read_discovery_cursor(app.state.cursor_secret, cursor,
                        principal=principal, policy_revision=policy_revision,
                        authority_revision=authority_revision, registry_digest=registry_digest,
                        visible_digest=visible_digest, limit=page_size,
                        now_epoch=int(app.state.utc_now().timestamp()))
                except HTTPException:
                    raise HTTPException(409, {"code": "revision_conflict",
                        "message": "Deployment discovery context changed"}) from None
        page = visible[offset:offset + page_size]
        next_cursor = None
        if offset + len(page) < len(visible):
            next_cursor = _discovery_cursor(app.state.cursor_secret,
                principal=principal, policy_revision=policy_revision,
                authority_revision=authority_revision, registry_digest=registry_digest,
                visible_digest=visible_digest, after=offset + len(page), limit=page_size,
                expires_at=int(app.state.utc_now().timestamp()) + 300)
        return {"schema_version": 1, "deployments": page, "next_cursor": next_cursor}

    @app.get("/api/v1/operations/observer-settings/{deployment_id}")
    def read_observer_settings(deployment_id: str, request: Request,
                               principal: str = Depends(authenticate)):
        context, registry = getattr(request.state, "authority_context", None), _registry()
        with engine.begin() as connection:
            from uvm.assessment.policy_lock import lock_policy
            lock_policy(connection, shared=True)
            policy_row = _policy(connection)
            _authorized_deployment(policy_row["document"], principal, deployment_id, context, registry)
            return _root_dto(connection, policy_row, deployment_id, principal, context)

    @app.get("/api/v1/operations/observer-settings/{deployment_id}/revisions/{revision}")
    def read_observer_revision(deployment_id: str, revision: int, request: Request,
                               principal: str = Depends(authenticate)):
        context, registry = getattr(request.state, "authority_context", None), _registry()
        if type(revision) is not int or revision < 1:
            raise HTTPException(400, {"code": "invalid_request", "message": "Revision must be positive"})
        with engine.begin() as connection:
            from uvm.assessment.policy_lock import lock_policy
            lock_policy(connection, shared=True)
            policy_row = _policy(connection)
            _authorized_deployment(policy_row["document"], principal, deployment_id, context, registry)
            row = connection.execute(sa.select(g7_observer_settings_revisions).where(
                g7_observer_settings_revisions.c.deployment_id == deployment_id,
                g7_observer_settings_revisions.c.revision == revision)).mappings().one_or_none()
            if row is None:
                raise HTTPException(404, {"code": "not_found", "message": "Revision not found"})
            return {"schema_version": 1, "deployment_id": deployment_id,
                "revision": int(row["revision"]), "digest": _digest(row["digest"]),
                "values": row["values"], "action": row["action"],
                "command_id": row["command_id"], "actor_id": row["actor_id"],
                "rationale": row["rationale"], "evidence_ref": row["evidence_ref"],
                "committed_at": _now_text(row["created_at"]),
                "copied_from_revision": row["copied_from_revision"]}

    @app.post("/api/v1/operations/observer-settings/{deployment_id}/commands")
    def publish_observer_settings(deployment_id: str, body: dict, request: Request,
                                  principal: str = Depends(authenticate)):
        context, registry = getattr(request.state, "authority_context", None), _registry()
        allowed = {"schema_version", "command_id", "action", "expected_revisions",
            "rationale", "evidence_ref", "values", "rollback_revision"}
        if (not isinstance(body, dict) or set(body) - allowed
                or type(body.get("schema_version")) is not int or body.get("schema_version") != 1
                or ("values" in body) == ("rollback_revision" in body)
                or not isinstance(body.get("expected_revisions"), dict)
                or not isinstance(body.get("rationale"), str) or not body["rationale"].strip()
                or ("evidence_ref" in body and body["evidence_ref"] is not None
                    and not isinstance(body["evidence_ref"], str))):
            raise HTTPException(400, {"code": "invalid_request", "message": "Observer settings command is invalid"})
        action = body.get("action")
        if action not in {"observer.timing.publish", "observer.timing.rollback"}:
            raise HTTPException(400, {"code": "invalid_request", "message": "Observer settings action is invalid"})
        if (action == "observer.timing.publish") != ("values" in body):
            raise HTTPException(400, {"code": "invalid_request", "message": "Command action and body do not match"})
        try:
            command_id = str(uuid.UUID(body.get("command_id", "")))
        except (ValueError, TypeError, AttributeError):
            raise HTTPException(400, {"code": "invalid_request", "message": "Command ID must be a UUID"}) from None
        if command_id != body["command_id"]:
            raise HTTPException(400, {"code": "invalid_request", "message": "Command ID must be canonical"})
        request_digest = command_digest(principal, deployment_id, body)
        fixture_failpoint = None
        supplied_failpoint = request.headers.get("x-uvm-g7-fixture-failpoint")
        if supplied_failpoint is not None:
            if (os.environ.get("UVM_G7_DISPOSABLE_MODE") != "1"
                    or supplied_failpoint not in {"audit", "intent", "receipt"}):
                raise HTTPException(404, {"code": "not_found", "message": "Fixture endpoint is unavailable"})
            fixture_failpoint = supplied_failpoint
        try:
            with engine.begin() as connection:
                from uvm.assessment.policy_lock import lock_policy
                lock_policy(connection)
                policy_row = _policy(connection)
                _authorized_deployment(policy_row["document"], principal, deployment_id, context, registry)
                if not deployment_grants(policy_row["document"], principal,
                        "observer.timing.configure", deployment_id, context):
                    raise HTTPException(403, {"code": "forbidden", "message": "Current configuration authority is required"})
                prior = connection.execute(sa.select(assessment_command_receipts).where(
                    assessment_command_receipts.c.command_id == command_id)).mappings().one_or_none()
                replay = bool(prior and prior["principal_id"] == principal
                    and prior["action"] == action
                    and prior["target_id"] == deployment_audit_id(deployment_id)
                    and prior["request_digest"] == request_digest)
                try:
                    receipt = commit_desired_revision(connection, deployment_id=deployment_id,
                        command_id=command_id, actor_id=principal,
                        actor_kind=principals.get(principal, {}).get("actor_kind", "principal"),
                        action=action, request_digest=request_digest,
                        expected_revisions=body["expected_revisions"], rationale=body["rationale"].strip(),
                        evidence_ref=body.get("evidence_ref"), values=body.get("values"),
                        rollback_revision=body.get("rollback_revision"), now=app.state.utc_now(),
                        authorization_context=context.document() if context else None,
                        disposable_failpoint=fixture_failpoint)
                except ObserverSettingsConflict as exc:
                    code = "command_conflict" if str(exc).startswith("command_id") else "revision_conflict"
                    raise HTTPException(409, {"code": code, "message": str(exc),
                        "details": {"outcome": "not_committed", "expected_revisions": body["expected_revisions"],
                            "current_revisions": None, "lookup_url": None}}) from None
                except ObserverSettingsError as exc:
                    raise HTTPException(400, {"code": "invalid_request", "message": str(exc)}) from None
                except ObserverSettingsUnavailable as exc:
                    raise HTTPException(503, {"code": "dependency_unavailable", "message": str(exc)}) from None
        except sa.exc.IntegrityError:
            # A statement-level integrity rejection is known to have rolled
            # back with this transaction; it cannot have committed a partial
            # settings/audit/receipt/intent bundle.
            error = {"schema_version": 1, "error": {"code": "dependency_unavailable",
                "message": "Observer settings could not be committed",
                "correlation_id": str(uuid.uuid4()), "details": {"outcome": "not_committed",
                    "expected_revisions": body["expected_revisions"],
                    "current_revisions": None, "lookup_url": None}}}
            return JSONResponse(status_code=503, content=error)
        except sa.exc.DBAPIError as exc:
            # PostgreSQL raises a statement error (for example an injected
            # audit/intent/receipt trigger rejection) before COMMIT and aborts
            # the transaction. A returned SQLSTATE with a live connection is
            # a proved non-commit; transport loss without that proof remains
            # uncertain and must be resolved through receipt lookup.
            sqlstate = getattr(getattr(exc, "orig", None), "sqlstate", None)
            if sqlstate and not exc.connection_invalidated:
                error = {"schema_version": 1, "error": {"code": "dependency_unavailable",
                    "message": "Observer settings could not be committed",
                    "correlation_id": str(uuid.uuid4()), "details": {"outcome": "not_committed",
                        "expected_revisions": body["expected_revisions"],
                        "current_revisions": None, "lookup_url": None}}}
                return JSONResponse(status_code=503, content=error)
            error = {"schema_version": 1, "error": {"code": "outcome_unknown",
                "message": "Observer settings commit outcome could not be established",
                "correlation_id": str(uuid.uuid4()), "details": {"outcome": "unknown",
                    "expected_revisions": body["expected_revisions"], "current_revisions": None,
                    "lookup_url": f"/api/v1/operations/observer-settings/{deployment_id}/receipts/{command_id}"}}}
            return JSONResponse(status_code=503, content=error)
        except sa.exc.SQLAlchemyError:
            error = {"schema_version": 1, "error": {"code": "outcome_unknown",
                "message": "Observer settings commit outcome could not be established",
                "correlation_id": str(uuid.uuid4()), "details": {"outcome": "unknown",
                    "expected_revisions": body["expected_revisions"],
                    "current_revisions": None,
                    "lookup_url": f"/api/v1/operations/observer-settings/{deployment_id}/receipts/{command_id}"}}}
            return JSONResponse(status_code=503, content=error)
        return JSONResponse(status_code=200 if replay else 201, content=receipt)

    @app.get("/api/v1/operations/observer-settings/{deployment_id}/receipts/{command_id}")
    def read_observer_receipt(deployment_id: str, command_id: str, request: Request,
                              principal: str = Depends(authenticate)):
        context, registry = getattr(request.state, "authority_context", None), _registry()
        try:
            canonical_id = str(uuid.UUID(command_id))
        except (ValueError, TypeError, AttributeError):
            raise HTTPException(404, {"code": "not_found", "message": "Receipt not found"}) from None
        if canonical_id != command_id:
            raise HTTPException(404, {"code": "not_found", "message": "Receipt not found"})
        with engine.begin() as connection:
            from uvm.assessment.policy_lock import lock_policy
            lock_policy(connection, shared=True)
            policy_row = _policy(connection)
            _authorized_deployment(policy_row["document"], principal, deployment_id, context, registry)
            row = connection.execute(sa.select(assessment_command_receipts).where(
                assessment_command_receipts.c.command_id == command_id,
                assessment_command_receipts.c.target_id == deployment_audit_id(deployment_id),
                assessment_command_receipts.c.action.in_(("observer.timing.publish", "observer.timing.rollback")))).mappings().one_or_none()
            if row is None or (row["principal_id"] != principal and not _audit_view_allowed(
                    policy_row["document"], principal, deployment_id, context)):
                raise HTTPException(404, {"code": "not_found", "message": "Receipt not found"})
            return row["result"]

    @app.get("/api/v1/operations/observer-settings/{deployment_id}/host/desired")
    def host_desired(deployment_id: str, request: Request, identity=Depends(host_auth)):
        principal, entry = identity
        if entry["deployment_id"] != deployment_id:
            raise HTTPException(404, {"code": "not_found", "message": "Deployment not found"})
        with engine.begin() as connection:
            revisions, status = _current_revisions(connection, _policy(connection), deployment_id)
            desired = None
            if revisions["configuration"]:
                row = connection.execute(sa.select(g7_observer_settings_revisions).where(
                    g7_observer_settings_revisions.c.deployment_id == deployment_id,
                    g7_observer_settings_revisions.c.revision == revisions["configuration"])).mappings().one()
                intent = connection.execute(sa.select(g7_observer_application_intents).where(
                    g7_observer_application_intents.c.deployment_id == deployment_id,
                    g7_observer_application_intents.c.revision == revisions["configuration"]).order_by(
                        g7_observer_application_intents.c.created_at.desc()).limit(1)).mappings().one()
                desired = {"revision": int(row["revision"]), "digest": _digest(row["digest"]),
                    "values": row["values"], "command_id": row["command_id"],
                    "intent_id": intent["intent_id"], "expected_host_policy_revision": revisions["host_policy"]}
        return {"schema_version": 1, "deployment_id": deployment_id, "desired": desired}

    @app.get("/api/v1/operations/observer-settings/{deployment_id}/host/telemetry")
    def host_telemetry(deployment_id: str, request: Request,
                       limit: int = 250, sink_id: str = "g7-siem",
                       identity=Depends(host_auth)):
        """Return a bounded read-only lag summary to the registered host observer.

        Audit entries are restricted to this deployment's observer-settings
        target and reduced to digests, receipts and timestamps. Incident rows
        are filtered by their exact deployment key. No audit body or finding
        data crosses this private service boundary.
        """
        _principal, entry = identity
        if entry["deployment_id"] != deployment_id:
            raise HTTPException(404, {"code": "not_found", "message": "Deployment not found"})
        if (type(limit) is not int or not 1 <= limit <= 1000
                or not isinstance(sink_id, str) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,100}", sink_id)):
            raise HTTPException(400, {"code": "invalid_request", "message": "Telemetry bounds are invalid"})
        from uvm.audit_export.exporter import EVENT_FIELDS, _event_payload
        from uvm.audit_export.integrity import event_digest
        from uvm.persistence.assessment_schema import (
            assessment_audit_events, assessment_sink_export_receipts,
        )
        from uvm.persistence.incident_schema import (
            g7_incident_projection_receipts, g7_incident_transitions,
        )
        target_id = deployment_audit_id(deployment_id)
        with engine.connect() as connection:
            event_query = (sa.select(assessment_audit_events,
                assessment_sink_export_receipts.c.sink_id,
                assessment_sink_export_receipts.c.sink_receipt,
                assessment_sink_export_receipts.c.acknowledged_at)
                .select_from(assessment_audit_events.outerjoin(
                    assessment_sink_export_receipts, sa.and_(
                        assessment_sink_export_receipts.c.event_id == assessment_audit_events.c.event_id,
                        assessment_sink_export_receipts.c.sink_id == sink_id)))
                .where(assessment_audit_events.c.target_id == target_id)
                .order_by(assessment_audit_events.c.event_sequence.desc()).limit(limit + 1))
            event_rows = connection.execute(event_query).mappings().all()
            incident_query = (sa.select(g7_incident_transitions.c.observed_at,
                g7_incident_projection_receipts.c.received_at.label("projected_at"))
                .select_from(g7_incident_transitions.outerjoin(
                    g7_incident_projection_receipts,
                    g7_incident_projection_receipts.c.transition_id ==
                        g7_incident_transitions.c.transition_id))
                .where(g7_incident_transitions.c.deployment_id == deployment_id)
                .order_by(g7_incident_transitions.c.observed_at.desc()).limit(limit + 1))
            incident_rows = connection.execute(incident_query).mappings().all()
        event_complete = len(event_rows) <= limit
        incident_complete = len(incident_rows) <= limit
        events = []
        for row in event_rows[:limit]:
            event = _event_payload({key: row[key] for key in EVENT_FIELDS})
            events.append({"event_id": str(event["event_id"]),
                "event_sequence": int(event["event_sequence"]),
                "event_digest": event_digest(event),
                "received_at": _now_text(row["received_at"]),
                "sink_receipt": row["sink_receipt"],
                "acknowledged_at": _now_text(row["acknowledged_at"])})
        incidents = [{"observed_at": _now_text(row["observed_at"]),
            "projected_at": _now_text(row["projected_at"])}
            for row in incident_rows[:limit]]
        return {"schema_version": 1, "deployment_id": deployment_id,
            "sink_id": sink_id, "audit_events": events,
            "audit_complete": event_complete, "incidents": incidents,
            "incidents_complete": incident_complete}

    @app.post("/api/v1/operations/observer-settings/{deployment_id}/host/reports")
    def host_report(deployment_id: str, body: dict, request: Request, identity=Depends(host_auth)):
        principal, entry = identity
        if (entry["deployment_id"] != deployment_id or not isinstance(body, dict)
                or set(body) != _REPORT_FIELDS or type(body.get("schema_version")) is not int
                or body.get("schema_version") != 1 or body.get("deployment_id") != deployment_id):
            raise HTTPException(403, {"code": "forbidden", "message": "Host report does not match registered deployment"})
        try:
            canonical_body = dict(body)
            observed_at = datetime.fromisoformat(body["observed_at"].replace("Z", "+00:00"))
            if observed_at.tzinfo is None:
                raise ValueError
            observed_at = observed_at.astimezone(_UTC)
            canonical_body["observed_at"] = _now_text(observed_at)
            consumers = body["consumers"]
            if not isinstance(consumers, dict) or set(consumers) != {"observer", "supervisor"}:
                raise ValueError
            canonical_consumers = {}
            for name, consumer in consumers.items():
                if not isinstance(consumer, dict) or set(consumer) != {"revision", "digest", "observed_at"}:
                    raise ValueError
                stamp = datetime.fromisoformat(consumer["observed_at"].replace("Z", "+00:00"))
                if (stamp.tzinfo is None or (consumer["revision"] is not None
                        and (type(consumer["revision"]) is not int or consumer["revision"] < 0))
                        or ((consumer["revision"] is None) != (consumer["digest"] is None))):
                    raise ValueError
                canonical_consumers[name] = {**consumer, "observed_at": _now_text(stamp.astimezone(_UTC))}
            canonical_body["consumers"] = canonical_consumers
            from cryptography.hazmat.primitives import serialization
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
            raw = json.dumps({key: value for key, value in canonical_body.items() if key != "signature"},
                sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                allow_nan=False).encode("utf-8")
            if not isinstance(body["signature"], str):
                raise ValueError
            padded_signature = body["signature"] + "=" * (-len(body["signature"]) % 4)
            signature = base64.b64decode(padded_signature, altchars=b"-_", validate=True)
            key_data = Path(entry["verification_key_file"]).read_bytes()
            try:
                public_key = serialization.load_pem_public_key(key_data)
            except ValueError:
                public_key = Ed25519PublicKey.from_public_bytes(key_data)
            public_key.verify(signature, raw)
        except Exception:
            raise HTTPException(401, {"code": "forbidden", "message": "Host report authentication failed"}) from None
        try:
            report_id = str(uuid.UUID(body["report_id"]))
            sequence = body["sequence"]
            policy = body["host_policy"]
            if (report_id != body["report_id"] or type(sequence) is not int or sequence < 1
                    or body["outcome"] not in {"applied", "failed", "uncertain"}
                    or not isinstance(policy, dict) or set(policy) != {"revision", "bounds", "digest", "freshness_seconds"}
                    or type(policy["revision"]) is not int or policy["revision"] < 1
                    or type(policy["freshness_seconds"]) is not int or policy["freshness_seconds"] < 1):
                raise ValueError
            bounds = policy["bounds"]
            if not isinstance(bounds, dict) or set(bounds) != set(TIMING_FIELDS):
                raise ValueError
            for field, limit in bounds.items():
                if (not isinstance(limit, dict) or set(limit) != {"min", "max"}
                        or type(limit["min"]) is not int or type(limit["max"]) is not int
                        or limit["min"] < (0 if field == "maximum_future_skew_seconds" else 1)
                        or limit["max"] < limit["min"]):
                    raise ValueError
            if body["outcome"] == "applied":
                if (body["requested_revision"] is None or body["requested_digest"] is None
                        or body["active_revision"] != body["requested_revision"]
                        or body["active_digest"] != body["requested_digest"]):
                    raise ValueError
                consumers = body["consumers"]
                if any(consumers[name].get("revision") != body["active_revision"]
                        or consumers[name].get("digest") != body["active_digest"] for name in consumers):
                    raise ValueError
            for field in ("requested_revision", "active_revision"):
                value = body[field]
                if value is not None and (type(value) is not int or value < 1):
                    raise ValueError
            for field in ("requested_digest", "active_digest"):
                value = body[field]
                if value is not None and (not isinstance(value, str)
                        or not re.fullmatch(r"sha256:[0-9a-f]{64}", value)):
                    raise ValueError
            if ((body["requested_revision"] is None) != (body["requested_digest"] is None)
                    or (body["active_revision"] is None) != (body["active_digest"] is None)):
                raise ValueError
            if not re.fullmatch(r"sha256:[0-9a-f]{64}", policy["digest"]):
                raise ValueError
            if not isinstance(body["controller_instance"], str) or not body["controller_instance"] or len(body["controller_instance"]) > 128:
                raise ValueError
            failure_code = body["failure_code"]
            if failure_code is not None and (not isinstance(failure_code, str)
                    or not re.fullmatch(r"[a-z][a-z0-9_.-]{0,63}", failure_code)):
                raise ValueError
            signature_bytes = signature
            report_digest = hashlib.sha256(raw).hexdigest()
        except (ValueError, KeyError, TypeError, AttributeError):
            raise HTTPException(400, {"code": "invalid_request", "message": "Host report is invalid"}) from None
        now = app.state.utc_now()
        with engine.begin() as connection:
            from uvm.assessment.policy_lock import lock_policy
            lock_policy(connection)
            status = connection.execute(sa.select(g7_observer_status).where(
                g7_observer_status.c.deployment_id == deployment_id).with_for_update()).mappings().one_or_none()
            prior = connection.execute(sa.select(g7_observer_host_reports).where(
                g7_observer_host_reports.c.report_id == report_id)).mappings().one_or_none()
            if prior:
                if prior["deployment_id"] == deployment_id and prior["report_digest"] == report_digest:
                    return {"schema_version": 1, "report_id": report_id,
                        "sequence": int(prior["sequence"]), "accepted": True, "duplicate": True}
                raise HTTPException(409, {"code": "command_conflict", "message": "Report ID conflicts with retained content"})
            # Exact retained replay is checked before freshness. It repeats no
            # state transition, so an acknowledgement recovery remains valid
            # after the originally admitted report ages out.
            now = app.state.utc_now().astimezone(_UTC)
            consumer_stamps = [datetime.fromisoformat(item["observed_at"].replace("Z", "+00:00")).astimezone(_UTC)
                for item in consumers.values()]
            applied_consumers_stale = (body["outcome"] == "applied" and any(
                now - stamp > timedelta(seconds=policy["freshness_seconds"])
                    or stamp > now + timedelta(seconds=1) for stamp in consumer_stamps))
            if (now - observed_at > timedelta(seconds=policy["freshness_seconds"])
                    or observed_at > now + timedelta(seconds=1)
                    or applied_consumers_stale):
                raise HTTPException(400, {"code": "report_expired",
                    "message": "Host report was not admitted before its freshness deadline"})
            latest_sequence = int(status["latest_report_sequence"] or 0) if status else 0
            if sequence <= latest_sequence:
                raise HTTPException(409, {"code": "revision_conflict", "message": "Host report sequence is stale"})
            if status and status["host_policy_revision"] is not None:
                prior_policy_revision = int(status["host_policy_revision"])
                if policy["revision"] < prior_policy_revision:
                    raise HTTPException(409, {"code": "revision_conflict", "message": "Host policy revision is stale"})
                if (policy["revision"] == prior_policy_revision
                        and (status["host_policy_digest"] != policy["digest"].removeprefix("sha256:")
                            or status["host_policy_bounds"] != policy["bounds"])):
                    raise HTTPException(409, {"code": "command_conflict", "message": "Host policy changed without a revision"})
            requested_revision = body["requested_revision"]
            requested_digest = body["requested_digest"]
            outcome = body["outcome"]
            intent = None
            if requested_revision is not None:
                current_revision = connection.execute(sa.select(sa.func.coalesce(
                    sa.func.max(g7_observer_settings_revisions.c.revision), 0)).where(
                    g7_observer_settings_revisions.c.deployment_id == deployment_id)).scalar_one()
                desired_digest = connection.execute(sa.select(g7_observer_settings_revisions.c.digest).where(
                    g7_observer_settings_revisions.c.deployment_id == deployment_id,
                    g7_observer_settings_revisions.c.revision == requested_revision)).scalar_one_or_none()
                intent = connection.execute(sa.select(g7_observer_application_intents).where(
                    g7_observer_application_intents.c.deployment_id == deployment_id,
                    g7_observer_application_intents.c.revision == requested_revision).with_for_update()
                    .order_by(g7_observer_application_intents.c.created_at.desc()).limit(1)).mappings().one_or_none()
                if requested_revision < int(current_revision):
                    raise HTTPException(409, {"code": "report_superseded",
                        "message": "Unadmitted host report targets an older desired revision"})
                if (requested_revision != int(current_revision) or desired_digest is None
                        or desired_digest != requested_digest.removeprefix("sha256:") or intent is None):
                    raise HTTPException(409, {"code": "revision_conflict",
                        "message": "Host report does not bind to the current application intent"})
                if intent["status"] not in {"pending", "uncertain", outcome}:
                    raise HTTPException(409, {"code": "revision_conflict",
                        "message": "Host report conflicts with the retained intent outcome"})
            if outcome != "applied" and status is not None:
                if (body["active_revision"] != status["effective_revision"]
                        or body["active_digest"] != ("sha256:" + status["effective_digest"]
                            if status["effective_digest"] else None)):
                    raise HTTPException(409, {"code": "revision_conflict",
                        "message": "Failed or uncertain report cannot advance effective settings"})
            if outcome == "applied":
                current_revision = connection.execute(sa.select(sa.func.coalesce(
                    sa.func.max(g7_observer_settings_revisions.c.revision), 0)).where(
                    g7_observer_settings_revisions.c.deployment_id == deployment_id)).scalar_one()
                row = connection.execute(sa.select(g7_observer_settings_revisions.c.digest).where(
                    g7_observer_settings_revisions.c.deployment_id == deployment_id,
                    g7_observer_settings_revisions.c.revision == requested_revision)).scalar_one_or_none()
                if int(current_revision) != requested_revision or row != requested_digest.removeprefix("sha256:"):
                    raise HTTPException(409, {"code": "revision_conflict", "message": "Report does not match current desired revision"})
            report = {key: value for key, value in canonical_body.items() if key != "signature"}
            connection.execute(g7_observer_host_reports.insert().values(
                report_id=report_id, deployment_id=deployment_id, sequence=sequence,
                controller_instance=body["controller_instance"],
                requested_revision=requested_revision, requested_digest=requested_digest.removeprefix("sha256:") if requested_digest else None,
                active_revision=body["active_revision"], active_digest=body["active_digest"].removeprefix("sha256:") if body["active_digest"] else None,
                policy_revision=policy["revision"], policy_bounds=bounds,
                policy_digest=policy["digest"].removeprefix("sha256:"), policy_key_id=Path(entry["verification_key_file"]).name,
                policy_freshness_seconds=policy["freshness_seconds"], observed_at=observed_at,
                outcome=outcome, failure_code=body["failure_code"], report_digest=report_digest,
                signature=signature_bytes, report=report, received_at=now))
            values = {"deployment_id": deployment_id,
                "effective_revision": body["active_revision"],
                "effective_digest": body["active_digest"].removeprefix("sha256:") if body["active_digest"] else None,
                "application_status": outcome, "latest_report_id": report_id,
                "latest_report_sequence": sequence, "latest_report_at": observed_at,
                "latest_failure_code": body["failure_code"],
                "host_policy_revision": policy["revision"], "host_policy_bounds": bounds,
                "host_policy_digest": policy["digest"].removeprefix("sha256:"),
                "host_policy_key_id": Path(entry["verification_key_file"]).name,
                "host_policy_observed_at": observed_at,
                "host_policy_freshness_seconds": policy["freshness_seconds"]}
            if status is None:
                connection.execute(g7_observer_status.insert().values(**values))
            else:
                connection.execute(g7_observer_status.update().where(
                    g7_observer_status.c.deployment_id == deployment_id).values(**values))
            if intent is not None:
                connection.execute(g7_observer_application_intents.update().where(
                    g7_observer_application_intents.c.intent_id == intent["intent_id"]).values(
                        status=outcome, result={"report_id": report_id, "sequence": sequence}, updated_at=now))
        return {"schema_version": 1, "report_id": report_id,
            "sequence": sequence, "accepted": True, "duplicate": False}
