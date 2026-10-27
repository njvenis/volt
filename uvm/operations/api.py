"""Public and host-service observer timing settings routes."""
from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import sqlalchemy as sa
from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse

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
    if status and status["application_status"] and intent:
        application = {"status": status["application_status"],
            "operation_id": intent["intent_id"] if intent else None,
            "latest_report_id": status["latest_report_id"],
            "failure_code": status["latest_failure_code"]}
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

    @app.get("/api/v1/operations/observer-settings")
    def discover_observer_deployments(request: Request, principal: str = Depends(authenticate)):
        context = getattr(request.state, "authority_context", None)
        registry = _registry()
        with engine.begin() as connection:
            from uvm.assessment.policy_lock import lock_policy
            lock_policy(connection, shared=True)
            policy_row = _policy(connection)
            native = policy_row["document"]
            deployments = []
            for deployment, item in sorted(registry.items()):
                grants = deployment_grants(native, principal, "observer.timing.read", deployment, context)
                if grants:
                    deployments.append({"deployment_id": deployment, "label": item["label"],
                        "can_configure": bool(deployment_grants(native, principal,
                            "observer.timing.configure", deployment, context))})
        return {"schema_version": 1, "deployments": deployments, "next_cursor": None}

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
                        authorization_context=context.document() if context else None)
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
            if (now - observed_at > timedelta(seconds=policy["freshness_seconds"])
                    or observed_at > now + timedelta(seconds=1)
                    or any(now - stamp > timedelta(seconds=policy["freshness_seconds"])
                        or stamp > now + timedelta(seconds=1) for stamp in consumer_stamps)):
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
