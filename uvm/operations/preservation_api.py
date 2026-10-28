"""Permission-scoped, read-only G7 preservation API routes."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import stat
import uuid
from datetime import datetime, timezone
from pathlib import Path

import sqlalchemy as sa
from fastapi import Depends, HTTPException, Query, Request
from fastapi.responses import Response

from uvm.operations.preservation import (CLASSES, _read_regular, class_map,
    load_report, tuple_digest, unknown_class, utc_timestamp)
from uvm.persistence.assessment_schema import assessment_policy, assessment_audit_events
from uvm.persistence.ingestion_schema import (collection_runs, run_attempts,
    run_pages, ingestion_evidence, expected_run_events)

UTC = timezone.utc
_CLASS_IDS = {class_id for class_id, _ in CLASSES}
_ACTION = "preservation.read"
_EVIDENCE_ACTION = "preservation.evidence.read"
_AUDIT_ACTION = "audit.read"
_DEPLOYMENT_AUDIT_ACTION = "audit.read.deployment"


def _now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _error(status: int, code: str, message: str):
    raise HTTPException(status, {"code": code, "message": message})


def _scope(value: dict) -> tuple[str, str, str]:
    if (not isinstance(value, dict) or set(value) != {"source_family", "source_account_id", "scope_key"}
            or any(not isinstance(value.get(k), str) or not value[k] or len(value[k]) > 256
                   or any(ord(c) < 32 for c in value[k]) for k in value)):
        _error(400, "invalid_request", "Exact source scope is required")
    return tuple(value[k] for k in ("source_family", "source_account_id", "scope_key"))


def _authority(engine, principal: dict, scope: tuple[str, str, str], action: str,
               *, deployment_id: str | None = None, target_id: str | None = None,
               connection=None, service_adapter: bool = False, attribution_proven: bool = False) -> tuple[bool, str | None]:
    connection = connection if connection is not None else principal.get("preservation_policy_connection")
    if connection is None:
        from uvm.assessment.policy_lock import lock_policy
        with engine.begin() as current:
            lock_policy(current, shared=True)
            return _authority(engine, principal, scope, action, deployment_id=deployment_id,
                target_id=target_id, connection=current, service_adapter=service_adapter, attribution_proven=attribution_proven)
    context = principal.get("context")
    configured_service = os.environ.get("UVM_G7_SOURCE_ADAPTER_PRINCIPAL")
    service_context = context is not None and context.credential_mode == "service_bearer"
    if context is None:
        if (not service_adapter or not configured_service
                or principal.get("name") != configured_service
                or scope not in set(tuple(item) for item in principal.get("scopes", ()))):
            return False, None
    elif service_context:
        if (not service_adapter or not configured_service
                or principal.get("name") != configured_service
                or context.principal_id != configured_service
                or scope not in set(context.source_scopes)):
            return False, None
    elif (context.credential_mode not in {"oidc_session", "github_link"}
            or scope not in set(tuple(item) for item in context.source_scopes)):
        return False, None
    try:
        if connection is None:
            with engine.connect() as authority_connection:
                row = authority_connection.execute(sa.select(assessment_policy.c.document,
                    assessment_policy.c.revision).where(assessment_policy.c.policy_id == 1)).mappings().one_or_none()
        else:
            row = connection.execute(sa.select(assessment_policy.c.document,
                assessment_policy.c.revision).where(assessment_policy.c.policy_id == 1)).mappings().one_or_none()
        if row is None:
            return False, None
        from uvm.auth.native_authority import NATIVE_MODE, effective_access, native_state
        policy = row["document"]
        state = native_state(policy)
        principal_id = context.principal_id if context is not None else configured_service
        if policy.get("principals", {}).get(principal_id, {}).get("enabled") is False:
            return False, None
        if service_context:
            service_access = effective_access(policy, principal_id)
            service_groups = set(service_access[0]) if service_access is not None else set()
            service_deny_ids = {principal_id, *service_groups, "*"}
            configured_grants = principal.get("service_grants", ())
            matching_service = []
            for grant in configured_grants:
                if (not isinstance(grant, dict) or grant.get("action") != action
                        or scope not in {tuple(item.get(k) for k in
                            ("source_family", "source_account_id", "scope_key"))
                            for item in grant.get("source_scopes", ()) if isinstance(item, dict)}
                        or (deployment_id is not None
                            and deployment_id not in grant.get("deployment_scopes", []))
                        or (deployment_id is None and action in {
                            _DEPLOYMENT_AUDIT_ACTION, "audit.export.deployment"})):
                    continue
                matching_service.append(grant)
            if not matching_service:
                return False, None
            service_denies = []
            for denial in policy.get("denies", []):
                if (not isinstance(denial, dict)
                        or denial.get("principal_id") not in service_deny_ids
                        or ("*" not in denial.get("actions", [])
                            and action not in denial.get("actions", []))):
                    continue
                target_ids = denial.get("target_ids", [])
                denied_scopes = {tuple(item.get(k) for k in
                    ("source_family", "source_account_id", "scope_key"))
                    for item in denial.get("source_scopes", ()) if isinstance(item, dict)}
                if ("*" in target_ids or (deployment_id is not None and deployment_id in target_ids)
                        or (target_id is not None and target_id in target_ids)
                        or scope in denied_scopes):
                    service_denies.append(denial)
            if service_denies:
                return False, None
            authority = {"principal": principal_id, "credential": "service_bearer",
                "service_grants": sorted((grant.get("grant_id"), grant.get("action"),
                    grant.get("source_scopes"), grant.get("deployment_scopes"))
                    for grant in matching_service),
                "scopes": sorted([list(item) for item in context.source_scopes]),
                "policy": int(row["revision"]), "authority": int(state.get("revision", 0)),
                "denies": sorted((item.get("deny_id"), item.get("principal_id"),
                    item.get("actions"), item.get("target_ids"), item.get("source_scopes"))
                    for item in policy.get("denies", []) if isinstance(item, dict)
                    and item.get("principal_id") in service_deny_ids
                    and ("*" in item.get("actions", []) or action in item.get("actions", [])))}
            fingerprint = hashlib.sha256(json.dumps(authority, sort_keys=True,
                separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()
            return True, fingerprint
        access = effective_access(policy, principal_id)
        if access is None:
            return False, None
        groups = set(access[0])
        if context is not None:
            groups &= set(context.access_groups)
        principal_record = policy.get("principals", {}).get(principal_id, {})
        if principal_record.get("enabled") is False:
            return False, None
        matching = []
        for group_id in groups:
            group = state.get("access_groups", {}).get(group_id, {})
            scopes = {tuple(item.get(k) for k in ("source_family", "source_account_id", "scope_key"))
                for item in group.get("source_scopes", []) if isinstance(item, dict)}
            if scope not in scopes or (context is not None and scope not in set(context.scopes_for_group(group_id))):
                continue
            roles = (set(context.roles_for_group(group_id)) if context is not None else
                set(dict(access[1]).get(group_id, ())))
            for permission in group.get("permissions", []):
                if (not isinstance(permission, dict) or permission.get("action") != action
                        or permission.get("role_id") not in roles):
                    continue
                if deployment_id is not None and deployment_id not in permission.get("deployment_scopes", []):
                    continue
                selectors = permission.get("target_scope", {})
                families = selectors.get("source_families", [])
                if families and "*" not in families and scope[0] not in families:
                    continue
                if target_id is not None:
                    from uvm.assessment.api import _complete_target_grants, _scoped_grants, _target_scoped_grants
                    from uvm.auth.schema import AUTHORITY_CONTEXT
                    token = AUTHORITY_CONTEXT.set(context)
                    try:
                        native_grants = (_target_scoped_grants(connection, _scoped_grants(policy,
                            principal_id, action, target_id, scope[0], include_unresolved=True), target_id)
                            if attribution_proven else _complete_target_grants(connection, policy, principal_id,
                                action, target_id, scope[0]))
                    finally:
                        AUTHORITY_CONTEXT.reset(token)
                    if permission.get("role_id") not in {g.get("role_id") for g in native_grants}:
                        continue
                else:
                    limits = permission.get("limits", {})
                    # A tuple/deployment supplies no environment/service facts.
                    # Restricted selectors cannot be widened by treating missing facts as a match.
                    if any(values and "*" not in values for values in (
                            selectors.get("environments", []), selectors.get("service_ids", []),
                            limits.get("allowed_environments", []), limits.get("allowed_service_ids", []))):
                        continue
                matching.append((group_id, permission))
        if target_id is not None:
            matching = [(gid, item) for gid, item in matching
                if target_id in item.get("target_scope", {}).get("group_ids", [])
                or "*" in item.get("target_scope", {}).get("group_ids", [])]
        deny_ids = {principal_id, *groups, "*"}
        denies = policy.get("denies", [])
        for denial in denies:
            if (isinstance(denial, dict) and denial.get("principal_id") in deny_ids
                    and ("*" in denial.get("actions", []) or action in denial.get("actions", []))
                    and ("*" in denial.get("target_ids", [])
                         or any(gid in denial.get("target_ids", []) for gid, _ in matching)
                         or (deployment_id and deployment_id in denial.get("target_ids", []))
                         or (target_id and target_id in denial.get("target_ids", []))
                         or scope in {tuple(value.get(k) for k in ("source_family", "source_account_id", "scope_key"))
                             for value in denial.get("source_scopes", []) if isinstance(value, dict)})):
                return False, None
        if not matching:
            return False, None
        authority = {"principal": principal_id,
            "credential": context.credential_mode if context is not None else "configured_service",
            "issuer": context.issuer if context is not None else None,
            "subject": context.subject if context is not None else None,
            "link": context.link_id if context is not None else None,
            "link_revision": context.link_revision if context is not None else None,
            "session": context.session_id if context is not None else None,
            "session_revision": context.session_revision if context is not None else None,
            "policy": int(row["revision"]), "context_policy": context.policy_revision if context is not None else None,
            "authority": int(state.get("revision", 0)), "group_revision": context.group_revision if context is not None else int(state.get("revision", 0)),
            "mapping_revision": context.mapping_revision if context is not None else int(state.get("mapping_revision", 0)), "groups": sorted(groups),
            "scopes": sorted([list(item) for item in (context.source_scopes if context is not None else principal.get("scopes", ())) ]),
            "group_scopes": sorted((group_id, sorted([list(item) for item in
                (context.scopes_for_group(group_id) if context is not None else
                 [tuple(value.get(k) for k in ("source_family", "source_account_id", "scope_key"))
                  for value in policy.get("native_authority", {}).get("access_groups", {}).get(group_id, {}).get("source_scopes", [])])]))
                for group_id in groups),
            "grants": sorted((gid, item.get("permission_id"), item.get("role_id"), item.get("action"),
                item.get("deployment_scopes"), item.get("target_scope"), item.get("limits"),
                item.get("separation_of_duties")) for gid, item in matching)}
        authority["denies"] = sorted((item.get("deny_id"), item.get("principal_id"),
            item.get("actions"), item.get("target_ids"), item.get("source_scopes")) for item in denies
            if isinstance(item, dict) and item.get("principal_id") in deny_ids
            and ("*" in item.get("actions", []) or action in item.get("actions", [])))
        fingerprint = hashlib.sha256(json.dumps(authority, sort_keys=True,
            separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()
        return True, fingerprint
    except HTTPException:
        raise
    except Exception:
        _error(503, "dependency_unavailable", "Current permission authority is unavailable")


def _report_files() -> list[Path]:
    root = os.environ.get("UVM_G7_PRESERVATION_REPORT_DIR")
    if not root:
        return []
    try:
        return [entry for entry in Path(root).iterdir()
            if entry.name.endswith(".json") and len(entry.name) == 69] + list((Path(root) / "snapshots").glob("*.json"))
    except OSError:
        return []


def _find_snapshot(snapshot_id: str):
    if not re_uuid(snapshot_id):
        return None, None
    for path in _report_files():
        try:
            raw = json.loads(_read_regular(path, 32 * 1024 * 1024))
            scope = tuple(raw.get("payload", {}).get("scope", ()))
            if len(scope) != 3:
                continue
            payload, _ = load_report(scope, allow_expired=True, report_path=path, allow_previous=True)
            if payload is not None and payload.get("snapshot_id") == snapshot_id:
                return payload, scope
        except (OSError, ValueError, TypeError):
            continue
    return None, None


def re_uuid(value: str) -> bool:
    try:
        return str(uuid.UUID(value)) == value
    except (ValueError, TypeError, AttributeError):
        return False


def _digest(authority: str, request: Request) -> str:
    secret = request.app.state.cursor_secret
    return hmac.new(secret, authority.encode(), hashlib.sha256).hexdigest()


def _cursor(secret: bytes, payload: dict) -> str:
    body = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    sig = hmac.new(secret, body, hashlib.sha256).digest()
    return base64.urlsafe_b64encode(body + b"." + sig).decode().rstrip("=")


def _read_cursor(secret: bytes, token: str):
    try:
        if not isinstance(token, str) or len(token) > 4096:
            raise ValueError
        raw = base64.urlsafe_b64decode(token + "=" * (-len(token) % 4))
        if len(raw) < 33 or raw[-33:-32] != b".":
            raise ValueError
        body, signature = raw[:-33], raw[-32:]
        if not hmac.compare_digest(signature, hmac.new(secret, body, hashlib.sha256).digest()):
            raise ValueError
        payload = json.loads(body)
        if not isinstance(payload, dict) or set(payload) != {"snapshot_id", "class_id", "limit", "after", "scope", "authority", "report_digest", "expires_at"}:
            raise ValueError
        if (not isinstance(payload["snapshot_id"], str) or not re_uuid(payload["snapshot_id"])
                or not isinstance(payload["class_id"], str) or payload["class_id"] not in _CLASS_IDS
                or type(payload["limit"]) is not int or not 1 <= payload["limit"] <= 100
                or not isinstance(payload["after"], str) or payload["after"].count("\0") != 1
                or any(not isinstance(payload[name], str) or len(payload[name]) != 64
                    or any(char not in "0123456789abcdef" for char in payload[name])
                    for name in ("scope", "authority", "report_digest"))
                or type(payload["expires_at"]) is not int):
            raise ValueError
        return payload
    except (ValueError, TypeError, json.JSONDecodeError):
        _error(400, "invalid_cursor", "Cursor is invalid")


def install_preservation_routes(app, engine, auth, cursor_secret: bytes):
    def current_authority(principal=Depends(auth)):
        from uvm.assessment.policy_lock import lock_policy
        try:
            with engine.begin() as connection:
                lock_policy(connection, shared=True)
                yield {**principal, "preservation_policy_connection": connection}
        except sa.exc.SQLAlchemyError:
            _error(503, "dependency_unavailable", "Current permission authority is unavailable")

    @app.post("/internal/g7/preservation/source-snapshot")
    async def preservation_source_snapshot(request: Request, principal=Depends(current_authority)):
        """Internal host adapter; never a browser DTO or a raw evidence route."""
        expected_subject = os.environ.get("UVM_G7_SOURCE_ADAPTER_SUBJECT")
        expected_issuer = os.environ.get("UVM_G7_SOURCE_ADAPTER_ISSUER")
        expected_principal = os.environ.get("UVM_G7_SOURCE_ADAPTER_PRINCIPAL")
        context = principal.get("context") if isinstance(principal, dict) else None
        session_identity_ok = bool(context is not None and expected_subject and expected_issuer
            and context.credential_mode == "oidc_session"
            and context.subject == expected_subject and context.issuer == expected_issuer)
        service_identity_ok = bool(context is not None and expected_principal
            and context.credential_mode == "service_bearer"
            and context.principal_id == expected_principal
            and principal.get("name") == expected_principal)
        if not (session_identity_ok or service_identity_ok):
            _error(404, "not_found", "Source snapshot is unavailable")
        try:
            body = await request.json()
        except Exception:
            _error(400, "invalid_request", "Source snapshot request is invalid")
        if (not isinstance(body, dict) or set(body) != {"schema_version", "scope", "class_ids"}
                or type(body.get("schema_version")) is not int or body["schema_version"] != 1):
            _error(400, "invalid_request", "Source snapshot request is invalid")
        scope = _scope(body.get("scope"))
        class_ids = body.get("class_ids")
        if (not isinstance(class_ids, list) or not class_ids
                or any(not isinstance(item, str) for item in class_ids)
                or len(set(class_ids)) != len(class_ids)):
            _error(400, "invalid_request", "Source snapshot request is invalid")
        if set(class_ids) != _CLASS_IDS or len(class_ids) != len(_CLASS_IDS):
            _error(400, "invalid_request", "All reviewed classes are required")
        deployment_id = os.environ.get("UVM_G7_DEPLOYMENT_ID")
        if not deployment_id:
            _error(503, "dependency_unavailable", "Deployment binding is unavailable")
        try:
            connection = engine.connect()
            if connection.dialect.name == "postgresql":
                connection = connection.execution_options(isolation_level="REPEATABLE READ")
            with connection:
                with connection.begin():
                    if connection.dialect.name == "postgresql":
                        connection.exec_driver_sql("SET TRANSACTION READ ONLY")
                    allowed, _ = _authority(engine, principal, scope, _ACTION,
                        connection=connection, service_adapter=True)
                    if not allowed:
                        _error(404, "not_found", "Source snapshot is unavailable")
                    if "product.audit_history" in class_ids:
                        audit_allowed, _ = _authority(engine, principal, scope,
                            _DEPLOYMENT_AUDIT_ACTION, deployment_id=deployment_id,
                            connection=connection, service_adapter=True)
                        export_allowed = True
                        if service_identity_ok:
                            export_allowed, _ = _authority(engine, principal, scope,
                                "audit.export.deployment", deployment_id=deployment_id,
                                connection=connection, service_adapter=True)
                        if not audit_allowed or not export_allowed:
                            _error(404, "not_found", "Source snapshot is unavailable")
                    from uvm.operations.preservation_source import source_snapshot
                    result = source_snapshot(connection, scope, class_ids, deployment_id)
            return result
        except HTTPException:
            raise
        except (sa.exc.SQLAlchemyError, OSError, ValueError, TypeError):
            _error(503, "dependency_unavailable", "Source snapshot is unavailable")

    @app.get("/api/v1/operations/preservation")
    def preservation_summary(request: Request, source_family: str = Query(...),
            source_account_id: str = Query(...), scope_key: str = Query(...),
            principal=Depends(current_authority)):
        if set(request.query_params) != {"source_family", "source_account_id", "scope_key"}:
            _error(400, "invalid_request", "Unknown query parameter")
        scope = (source_family, source_account_id, scope_key)
        if _scope(dict(zip(("source_family", "source_account_id", "scope_key"), scope))) != scope:
            _error(400, "invalid_request", "Exact source scope is required")
        allowed, fingerprint = _authority(engine, principal, scope, _ACTION)
        if not allowed:
            _error(404, "not_found", "Preservation report not found")
        payload, trust_reason = load_report(scope)
        classes = class_map(payload, scope, trust_reason or "baseline_missing")
        deployment_id = (payload or {}).get("deployment_id") or os.environ.get("UVM_G7_DEPLOYMENT_ID", "")
        audit_ok = payload is not None
        audit_authorities = []
        audit_fingerprint = hashlib.sha256(b"no-audit-members").hexdigest()
        if payload:
            for item in payload.get("classes", []):
                if not isinstance(item, dict) or item.get("class_id") != "product.audit_history":
                    continue
                audit_targets = item.get("audit_targets")
                if not isinstance(audit_targets, list):
                    audit_ok = False
                    break
                dto = item.get("dto", {})
                if not isinstance(dto, dict):
                    audit_ok = False
                    break
                if (type(dto.get("expected_records")) is int and dto["expected_records"] > 0
                        and not audit_targets):
                    audit_ok = False
                    break
                for target in audit_targets:
                    if not isinstance(target, dict) or target.get("kind") not in {"source", "deployment"}:
                        audit_ok = False; break
                    if target.get("kind") == "deployment":
                        permitted, grant_fingerprint = _authority(engine, principal, scope,
                            _DEPLOYMENT_AUDIT_ACTION, deployment_id=deployment_id)
                    elif target.get("kind") == "source" and target.get("scope") == list(scope):
                        permitted, grant_fingerprint = _authority(engine, principal, scope,
                            _AUDIT_ACTION, target_id=str(target.get("target_id", "")), attribution_proven=True)
                    else:
                        audit_ok = False; break
                    if not permitted:
                        audit_ok = False; break
                    audit_authorities.append(grant_fingerprint)
        if not audit_ok:
            classes["product.audit_history"] = unknown_class(
                "product.audit_history", "P1Y", "audit_scope_incomplete")
            audit_fingerprint = None
        elif payload:
            audit_fingerprint = hashlib.sha256(json.dumps(sorted(audit_authorities),
                separators=(",", ":")).encode()).hexdigest()
        for class_id, _ in CLASSES:
            if class_id not in classes:
                classes[class_id] = unknown_class(class_id, dict(CLASSES)[class_id], trust_reason or "baseline_untrusted")
        environment = (payload or {}).get("environment") or os.environ.get("UVM_G7_PRESERVATION_ENVIRONMENT")
        if not environment:
            for dto in classes.values():
                dto["reasons"] = sorted(set(dto["reasons"]) | {"environment_unlabelled"})
                if isinstance(dto.get("audit_copy"), dict):
                    dto["audit_copy"]["reasons"] = sorted(set(dto["audit_copy"]["reasons"]) | {"environment_unlabelled"})
        result = {"schema_version": 1, "scope": {"source_family": scope[0],
            "source_account_id": scope[1], "scope_key": scope[2]},
            "snapshot_id": (payload or {}).get("snapshot_id"),
            "checked_at": utc_timestamp((payload or {}).get("checked_at"))
                if (payload or {}).get("checked_at") is not None else None,
            "response_at": _now(),
            "valid_until": utc_timestamp((payload or {}).get("valid_until"))
                if (payload or {}).get("valid_until") is not None else None,
            "authority_fingerprint": fingerprint, "audit_authority_fingerprint": audit_fingerprint,
            "mask_reasons": [] if audit_ok else ["audit_scope_incomplete"],
            "environment": environment or None,
            "classes": [classes[key] for key, _ in CLASSES],
            "uncovered_classes": sorted(key for key, _ in CLASSES if classes[key]["state"] != "verified"),
            "elapsed_preservation": "unverified"}
        return result

    @app.get("/api/v1/operations/preservation/records")
    def preservation_records(request: Request, snapshot_id: str = Query(...),
            class_id: str = Query(...), limit: int = Query(50), cursor: str | None = None,
            principal=Depends(current_authority)):
        if set(request.query_params) - {"snapshot_id", "class_id", "limit", "cursor"}:
            _error(400, "invalid_request", "Unknown query parameter")
        if not re_uuid(snapshot_id) or class_id not in _CLASS_IDS or not 1 <= limit <= 100:
            _error(400, "invalid_request", "Snapshot, class or limit is invalid")
        payload, scope = _find_snapshot(snapshot_id)
        if payload is None:
            _error(404, "not_found", "Preservation snapshot not found")
        allowed, authority = _authority(engine, principal, scope, _ACTION)
        if not allowed:
            _error(404, "not_found", "Preservation snapshot not found")
        entry = next((item for item in payload.get("classes", [])
            if isinstance(item, dict) and item.get("class_id") == class_id), None)
        validated = class_map(payload, scope).get(class_id, {})
        if validated.get("state") not in {"verified", "gap"}:
            _error(404, "not_found", "Preservation class not found")
        if entry is None or not isinstance(entry.get("members"), list):
            _error(404, "not_found", "Preservation class not found")
        if not isinstance(entry.get("dto"), dict) or entry["dto"].get("state") not in {"verified", "gap"}:
            _error(404, "not_found", "Preservation class not found")
        try:
            snapshot_expiry = datetime.fromisoformat(payload["valid_until"].replace("Z", "+00:00"))
            if snapshot_expiry.tzinfo is None:
                raise ValueError
        except (KeyError, ValueError, AttributeError, TypeError):
            _error(404, "not_found", "Preservation snapshot not found")
        if class_id == "product.audit_history":
            targets = entry.get("audit_targets")
            dto = entry.get("dto", {})
            if (not isinstance(targets, list) or not isinstance(dto, dict)
                    or (not targets and dto.get("expected_records") != 0)
                    or not all(isinstance(t, dict) and (t.get("kind") == "deployment"
                            or t.get("kind") == "source" and t.get("scope") == list(scope))
                        and _authority(engine, principal, scope,
                        _DEPLOYMENT_AUDIT_ACTION if t.get("kind") == "deployment" else _AUDIT_ACTION,
                        deployment_id=payload.get("deployment_id") if t.get("kind") == "deployment" else None,
                        target_id=str(t.get("target_id", "")) if t.get("kind") != "deployment" else None,
                        attribution_proven=t.get("kind") == "source")[0]
                        for t in targets)):
                _error(404, "not_found", "Preservation class not found")
        current_report, _ = load_report(scope)
        if current_report is not None and current_report.get("snapshot_id") != snapshot_id:
            _error(409, "snapshot_expired", "Preservation snapshot has been replaced")
        if current_report is None and snapshot_expiry > datetime.now(UTC):
            _error(404, "not_found", "Preservation snapshot not found")
        if snapshot_expiry <= datetime.now(UTC):
            _error(409, "snapshot_expired", "Preservation snapshot has expired")
        report_digest = hashlib.sha256(json.dumps(payload, sort_keys=True,
            separators=(",", ":")).encode()).hexdigest()
        after = ""
        if cursor is not None:
            state = _read_cursor(cursor_secret, cursor)
            if (state.get("snapshot_id") != snapshot_id or state.get("class_id") != class_id
                    or state.get("limit") != limit or state.get("scope") != tuple_digest(scope)
                    or state.get("authority") != authority or state.get("report_digest") != report_digest):
                _error(400, "invalid_cursor", "Cursor is invalid")
            if (type(state.get("expires_at")) is not int
                    or state["expires_at"] <= int(datetime.now(UTC).timestamp())):
                _error(409, "cursor_expired", "Cursor has expired")
            after = state["after"]
        evidence_ok = _authority(engine, principal, scope, _EVIDENCE_ACTION,
            service_adapter=True)[0]
        items = [_record_item(member, class_id, evidence_ok) for member in entry["members"]]
        if any(item is None for item in items):
            _error(404, "not_found", "Preservation class not found")
        items = sorted(items, key=lambda item: (item["record_kind"].encode(), item["record_key"].encode()))
        page = [item for item in items if (item["record_kind"].encode(), item["record_key"].encode()) > tuple(x.encode() for x in after.split("\0", 1))][:limit + 1]
        more = len(page) > limit
        page = page[:limit]
        next_cursor = None
        if more and page:
            last = page[-1]
            next_cursor = _cursor(cursor_secret, {"snapshot_id": snapshot_id,
                "class_id": class_id, "limit": limit,
                "after": last["record_kind"] + "\0" + last["record_key"],
                "scope": tuple_digest(scope), "authority": authority,
                "report_digest": report_digest,
                "expires_at": int(datetime.now(UTC).timestamp()) + 600})
        return {"schema_version": 1, "snapshot_id": snapshot_id,
            "class_id": class_id, "items": page, "next_cursor": next_cursor}

    @app.get("/api/v1/ingestion/runs/{run_id}/revisions/{revision}")
    def preservation_run_revision(run_id: str, revision: int, principal=Depends(current_authority)):
        if not re_uuid(run_id) or revision < 1:
            _error(400, "invalid_request", "Run revision is invalid")
        with engine.connect() as connection:
            run = connection.execute(sa.select(collection_runs).where(
                collection_runs.c.run_id == run_id,
                collection_runs.c.revision == revision)).mappings().one_or_none()
            if run is None:
                _error(404, "not_found", "Run revision not found")
            scope = (run["source_family"], run["source_account_id"], run["scope_key"])
        authorized, fingerprint = _authority(engine, principal, scope, _ACTION)
        if not authorized:
            _error(404, "not_found", "Run revision not found")
        with engine.connect() as connection:
            run = connection.execute(sa.select(collection_runs).where(
                collection_runs.c.run_id == run_id,
                collection_runs.c.revision == revision)).mappings().one_or_none()
            if run is None:
                _error(404, "not_found", "Run revision not found")
            attempts = connection.execute(sa.select(run_attempts).where(
                run_attempts.c.run_id == run_id, run_attempts.c.run_revision == revision)
                .order_by(run_attempts.c.attempt_no)).mappings().all()
            pages = connection.execute(sa.select(run_pages).where(
                run_pages.c.run_id == run_id, run_pages.c.run_revision == revision)
                .order_by(run_pages.c.ordinal)).mappings().all()
            evidence = connection.execute(sa.select(ingestion_evidence).where(
                ingestion_evidence.c.run_id == run_id, ingestion_evidence.c.run_revision == revision)
                .order_by(ingestion_evidence.c.evidence_id)).mappings().all()
            transitions = []
            if run["expected_run_id"]:
                transitions = connection.execute(sa.select(expected_run_events).where(
                    expected_run_events.c.expected_run_id == run["expected_run_id"],
                    expected_run_events.c.run_id == run_id,
                    expected_run_events.c.run_revision <= revision).order_by(expected_run_events.c.revision)).mappings().all()
        return _run_dto(dict(run), [dict(x) for x in attempts], [dict(x) for x in pages],
            [dict(x) for x in evidence], [dict(x) for x in transitions], fingerprint,
            cursor_secret)

    @app.get("/api/v1/operations/preservation/evidence/{evidence_id}")
    def preservation_evidence(evidence_id: str, principal=Depends(current_authority)):
        if not re_uuid(evidence_id):
            _error(404, "not_found", "Evidence not found")
        try:
            with engine.connect() as connection:
                row = connection.execute(sa.select(ingestion_evidence, collection_runs.c.source_family,
                        collection_runs.c.source_account_id, collection_runs.c.scope_key)
                    .join(collection_runs, sa.and_(collection_runs.c.run_id == ingestion_evidence.c.run_id,
                        collection_runs.c.revision == ingestion_evidence.c.run_revision))
                    .where(ingestion_evidence.c.evidence_id == evidence_id)).mappings().one_or_none()
        except sa.exc.SQLAlchemyError:
            _error(503, "evidence_store_unavailable", "Evidence registration is unavailable")
        if row is None:
            _error(404, "not_found", "Evidence not found")
        scope = (row["source_family"], row["source_account_id"], row["scope_key"])
        # A host-side verifier uses the separately configured source adapter
        # credential; it is still bound to the exact configured tuple and the
        # independent current evidence-read grant/deny check. Browser sessions
        # continue through their evaluated OIDC authority context.
        read_allowed, _ = _authority(engine, principal, scope, _ACTION,
            service_adapter=True)
        evidence_allowed, _ = _authority(engine, principal, scope, _EVIDENCE_ACTION,
            service_adapter=True)
        if not read_allowed or not evidence_allowed:
            _error(404, "not_found", "Evidence not found")
        try:
            from uvm.operations.preservation_streams import admitted_evidence
            trust_root = os.environ.get("UVM_G7_PRESERVATION_TRUST_DIR")
            verifier = os.environ.get("UVM_G7_PRESERVATION_PUBLIC_KEY_FILE")
            expected = admitted_evidence(trust_root, verifier, os.environ["UVM_G7_DEPLOYMENT_ID"],
                scope, evidence_id, key_id=os.environ.get("UVM_G7_PRESERVATION_KEY_ID")) if trust_root and verifier else None
        except (OSError, ValueError, KeyError, TypeError):
            _error(503, "evidence_store_unavailable", "Independent evidence inventory is unavailable")
        # The dedicated independent capture credential may inspect a new object
        # before admission. Public callers require prior independent membership.
        context = principal.get("context")
        capture_credential = (principal.get("name") == os.environ.get("UVM_G7_SOURCE_ADAPTER_PRINCIPAL")
            and context is not None and context.credential_mode == "service_bearer")
        if expected is None and not capture_credential:
            _error(404, "not_found", "Evidence not found")
        if expected is not None:
            try:
                from uvm.operations.preservation import _verify
                controller_doc = json.loads(_read_regular(Path(trust_root) / "controller.json", 65536))
                controller = _verify(controller_doc, Path(verifier), "deployment-controller-v1")
                now = datetime.now(UTC)
                if (controller_doc["signature"]["key_id"] != os.environ.get("UVM_G7_PRESERVATION_KEY_ID")
                        or controller.get("deployment_id") != os.environ.get("UVM_G7_DEPLOYMENT_ID")
                        or controller.get("storage_generation") != os.environ.get("UVM_G7_STORAGE_GENERATION")
                        or controller.get("volume_set_digest") != os.environ.get("UVM_G7_VOLUME_SET_DIGEST")
                        or controller.get("recovery_epoch") != int(os.environ["UVM_G7_RECOVERY_EPOCH"])
                        or not datetime.fromisoformat(controller["key_valid_from"].replace("Z", "+00:00")) <= now
                            < datetime.fromisoformat(controller["key_valid_until"].replace("Z", "+00:00"))):
                    raise ValueError("independent_inventory_trust_invalid")
            except Exception:
                _error(503, "evidence_store_unavailable", "Independent evidence trust is unavailable")
        if expected is not None and expected != (row["sha256"], row["byte_size"]):
            _error(409, "evidence_changed", "Registered evidence differs from independent inventory")
        root_value = os.environ.get("UVM_G7_SOURCE_EVIDENCE_ROOT", "/opt/uvm/state/source-evidence")
        try:
            root = Path(root_value)
            root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        except OSError:
            _error(503, "evidence_store_unavailable", "Evidence storage is unavailable")
        try:
            root_info = os.fstat(root_fd)
            if (root_info.st_uid != os.getuid() or stat.S_IMODE(root_info.st_mode) != 0o700):
                _error(409, "evidence_unreadable", "Registered evidence cannot be read safely")
            object_name = hashlib.sha256(row["evidence_ref"].encode("utf-8")).hexdigest()
            try:
                object_fd = os.open(object_name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=root_fd)
            except FileNotFoundError:
                _error(409, "evidence_missing", "Registered evidence bytes are missing")
            except OSError:
                _error(409, "evidence_unreadable", "Registered evidence cannot be read safely")
            try:
                info = os.fstat(object_fd)
                if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                        or stat.S_IMODE(info.st_mode) != 0o600 or info.st_size > 16 * 1024 * 1024):
                    _error(409, "evidence_unreadable", "Registered evidence cannot be read safely")
                if row["byte_size"] is None or info.st_size != int(row["byte_size"]):
                    _error(409, "evidence_changed", "Registered evidence bytes changed")
                chunks, remaining = [], info.st_size + 1
                while remaining:
                    part = os.read(object_fd, min(65536, remaining))
                    if not part:
                        break
                    chunks.append(part)
                    remaining -= len(part)
                raw = b"".join(chunks)
                if len(raw) != info.st_size or hashlib.sha256(raw).hexdigest() != row["sha256"]:
                    _error(409, "evidence_changed", "Registered evidence bytes changed")
            finally:
                os.close(object_fd)
        finally:
            os.close(root_fd)
        digest_value = base64.b64encode(bytes.fromhex(row["sha256"])).decode("ascii")
        return Response(content=raw, media_type="application/octet-stream", headers={
            "Content-Length": str(len(raw)), "Content-Digest": f"sha-256=:{digest_value}:",
            "Content-Disposition": f'attachment; filename="evidence-{evidence_id}"',
            "X-Content-Type-Options": "nosniff", "Cache-Control": "no-store"})


def _run_dto(run, attempts, pages, evidence, transitions, authority, alias_key):
    def instant(value):
        return utc_timestamp(value) if value is not None else None
    key = bytes(alias_key)
    if len(key) < 32:
        _error(503, "dependency_unavailable", "Run disclosure key is unavailable")
    def alias(value):
        if value is None:
            return None
        return hmac.new(key, ("g7-alias\0" + str(value)).encode(), hashlib.sha256).hexdigest()
    sanitized = dict(run)
    for field in ("facts_snapshot", "provenance_snapshot", "manual_origin", "schedule_id", "source_report_id"):
        sanitized.pop(field, None)
    result = {"schema_version": 1, "run_id": run["run_id"], "revision": run["revision"],
        "scope": {"source_family": run["source_family"], "source_account_id": run["source_account_id"], "scope_key": run["scope_key"]},
        "expected_run_id": run["expected_run_id"], "manual_origin_code": "scheduled" if run["expected_run_id"] else "manual" if run.get("manual_origin") else "unknown",
        "schedule_id_ref": alias(run["schedule_id"]), "schedule_revision": run["schedule_revision"],
        "source_report_ref": alias(run.get("source_report_id")), "expected_at": instant(run["expected_at"]),
        "started_at": instant(run["started_at"]), "ended_at": instant(run["ended_at"]), "state": run["state"],
        "retrieval_status": run["retrieval_status"], "retrieval_reasons": list(run["retrieval_reasons"]),
        "coverage_status": run["coverage_status"], "coverage_reasons": list(run["coverage_reasons"]),
        "freshness_status": run["freshness_status"], "freshness_reasons": list(run["freshness_reasons"]),
        "created_at": instant(run["created_at"]), "attempts": [], "pages": [], "evidence": [],
        "expected_transitions": []}
    def response_class(value):
        if isinstance(value, str) and len(value) == 3 and value.isdigit() and 100 <= int(value) <= 599:
            return "http_" + value[0] + "xx"
        return value if value in {"http_1xx", "http_2xx", "http_3xx", "http_4xx", "http_5xx", "transport_error", "other"} else "other"
    def error_code(value):
        if value is None or value == "": return "none"
        keyvalue = str(value).casefold()
        for code, aliases in {"rate_limit": ("rate_limit",), "timeout": ("timeout", "timeouterror", "readtimeout"),
                "connection": ("connection", "connectionerror", "connectionreset"),
                "tls": ("tls", "tlserror", "certificateerror"), "parse": ("parse", "parseerror")}.items():
            if keyvalue in aliases: return code
        return "other"
    result["attempts"] = [{"attempt_no": row["attempt_no"], "started_at": instant(row["started_at"]),
        "finished_at": instant(row["finished_at"]), "response_class": response_class(row["response_class"]),
        "success": row["success"], "retry_after_microseconds": row["retry_after_microseconds"],
        "error_code": error_code(row["error_code"])} for row in attempts]
    result["pages"] = [{"ordinal": row["ordinal"], "cursor_ref": alias(row["cursor"]),
        "page_ref": alias(row["page_ref"]), "attempt_no": row["attempt_no"],
        "response_class": response_class(row["response_class"]), "record_count": row["record_count"],
        "next_cursor_ref": alias(row["next_cursor"]), "is_terminal": row["is_terminal"],
        "failed": row["failed"], "request_identity_digest": alias(row["request_identity"]),
        "report_ref": alias(row["report_id"]), "query_scope_digest": alias(row["query_scope"]),
        "evidence_ref": alias(row["evidence_ref"])} for row in pages]
    result["evidence"] = [{"evidence_id": row["evidence_id"], "schema_version": row["schema_version"],
        "evidence_ref": alias(row["evidence_ref"]), "sha256": row["sha256"],
        "kind": row["kind"], "registered_at": instant(row["registered_at"])} for row in evidence]
    result["expected_transitions"] = [{"revision": row["revision"], "state": row["state"],
        "run_revision": row["run_revision"], "effective_at": instant(row["effective_at"]),
        "recorded_at": instant(row["recorded_at"])} for row in transitions]
    return result


def _record_item(member: dict, class_id: str, evidence_allowed: bool) -> dict | None:
    """Project signed observer members to the fixed, non-payload item DTO."""
    if not isinstance(member, dict):
        return None
    required = {"record_key", "record_kind", "retained_at", "state", "reasons",
        "expected_sha256", "actual_sha256", "record_sha256"}
    if not required <= member.keys():
        return None
    key, kind = member["record_key"], member["record_kind"]
    allowed_kinds = {
        "product.source_evidence": {"observation", "observation_linkage", "retention_receipt", "evidence_registration"},
        "product.audit_history": {"audit_event", "audit_attribution", "audit_copy_receipt_established", "audit_anchor"},
        "operational.scanner_collection": {"expected_run", "run_revision", "attempt", "page", "expected_transition", "evidence_registration"},
    }
    try:
        key_size = len(key.encode("utf-8")) if isinstance(key, str) else 0
    except UnicodeError:
        return None
    if (not isinstance(key, str) or not key or not isinstance(kind, str)
            or key_size > 512 or any(ord(char) < 32 for char in key)
            or kind not in allowed_kinds.get(class_id, set())):
        return None
    if (not isinstance(member["state"], str)
            or member["state"] not in {"verified", "missing", "changed", "unreadable", "unexpected"}):
        return None
    reasons = member["reasons"]
    if (not isinstance(reasons, list) or any(not isinstance(reason, str) for reason in reasons)
            or reasons != sorted(set(reasons))):
        return None
    from uvm.operations.preservation import _REASONS, _HEX
    if any(reason not in _REASONS for reason in reasons):
        return None
    expected, actual, record = (member[name] for name in
        ("expected_sha256", "actual_sha256", "record_sha256"))
    for value in (expected, actual, record):
        if value is not None and (not isinstance(value, str) or not _HEX.fullmatch(value)):
            return None
    byte_bearing = member.get("byte_bearing") is True
    if not byte_bearing and (expected is not None or actual is not None):
        return None
    if member["state"] == "missing" and (actual is not None or record is not None):
        return None
    if member["state"] == "missing" and byte_bearing and expected is None:
        return None
    if member["state"] == "verified" and byte_bearing and (expected is None or actual != expected):
        return None
    if member["state"] == "unreadable" and byte_bearing and (expected is None or actual is not None):
        return None
    if member["state"] == "unexpected" and expected is not None:
        return None
    if member["state"] == "changed" and "bytes_changed" in reasons and expected == actual:
        return None
    retained = member.get("retained_at")
    if retained is not None:
        try:
            retained = utc_timestamp(retained)
        except (ValueError, AttributeError, TypeError):
            return None
    readback = None
    if (evidence_allowed and kind == "evidence_registration" and byte_bearing
            and isinstance(member.get("evidence_id"), str)):
        try:
            uuid.UUID(member["evidence_id"])
            readback = "/api/v1/operations/preservation/evidence/" + member["evidence_id"]
        except ValueError:
            return None
    return {"record_key": key, "record_kind": kind, "retained_at": retained,
        "state": member["state"], "reasons": reasons,
        "expected_sha256": expected, "actual_sha256": actual,
        "record_sha256": record, "readback_url": readback}
