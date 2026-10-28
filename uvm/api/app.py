from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import os
import secrets
import threading
import time
import uuid
from pathlib import Path
from datetime import datetime, timezone
from typing import Any

import sqlalchemy as sa
from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, FileResponse
from sqlalchemy.engine import Engine

from uvm.persistence.engine_operation_schema import (engine_operation_requests,
    engine_operation_states, engine_occurrence_links, manifest_ledger_headers,
    manifest_ledger_rows)
from uvm.persistence.health_schema import health_events, health_condition_episodes, notification_intents, notification_deliveries
from uvm.persistence.ingestion_schema import collection_runs, collection_schedules, expected_runs, ingestion_evidence, run_attempts, run_pages
from uvm.persistence.lineage_schema import identity_resolutions, resolution_temporal_assessments
from uvm.persistence.observation_schema import source_observations

UTC = timezone.utc
_PAGE_MAX = 100
_SNAPSHOT_ROW_MAX = 10_000
_SNAPSHOT_COUNT_MAX = 64
_SNAPSHOT_TTL_SECONDS = 600
_LOG = logging.getLogger("uvm.api")


class _OAuthAccessLogFilter(logging.Filter):
    """Keep OIDC and GitHub OAuth state and authorization codes out of access logs."""
    def filter(self, record: logging.LogRecord) -> bool:
        rendered = " ".join(str(value) for value in (record.msg, *record.args))
        return not ("/api/v1/auth/callback" in rendered or
                    "/installation/setup" in rendered or
                    "/installation/callback" in rendered)


logging.getLogger("uvicorn.access").addFilter(_OAuthAccessLogFilter())


class _ReadSnapshots:
    """Bounded process-local fixed-membership snapshots for cursor traversal."""

    def __init__(self):
        self._lock = threading.Lock()
        self._values: dict[str, tuple[float, tuple[tuple[str, tuple[Any, ...], str | None], ...], str, str]] = {}

    def _prune(self, now: float) -> None:
        self._values = {key: value for key, value in self._values.items()
                        if value[0] > now}
        while len(self._values) > _SNAPSHOT_COUNT_MAX:
            self._values.pop(next(iter(self._values)))

    def create(self, entries, principal: str, grants_fingerprint: str) -> str:
        if len(entries) > _SNAPSHOT_ROW_MAX:
            raise HTTPException(503, {"code": "read_snapshot_too_large",
                                      "message": "The result is too large for stable pagination"})
        now = time.monotonic()
        snapshot_id = secrets.token_urlsafe(18)
        with self._lock:
            self._prune(now)
            self._values[snapshot_id] = (now + _SNAPSHOT_TTL_SECONDS, tuple(entries), principal, grants_fingerprint)
            self._prune(now)
        return snapshot_id

    def get(self, snapshot_id: str, principal: str, grants_fingerprint: str):
        now = time.monotonic()
        with self._lock:
            self._prune(now)
            value = self._values.get(snapshot_id)
        if value is None or value[2] != principal or value[3] != grants_fingerprint:
            raise HTTPException(400, {"code": "invalid_cursor",
                                      "message": "Cursor is invalid"})
        return value[1]


def _instant(value: datetime | None) -> str | None:
    if value is None:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=UTC)
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _cursor_key_value(value: Any) -> str:
    if isinstance(value, datetime):
        if value.tzinfo is None:
            value = value.replace(tzinfo=UTC)
        return value.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    return str(value)


def _snapshot_key_value(value: Any) -> Any:
    if isinstance(value, datetime):
        if value.tzinfo is None:
            value = value.replace(tzinfo=UTC)
        return value.astimezone(UTC)
    return str(value)


def _canonical_id(value: str) -> str:
    try:
        parsed = uuid.UUID(value)
    except (ValueError, TypeError, AttributeError):
        raise HTTPException(400, {"code": "invalid_identifier", "message": "Identifier must be a canonical UUID"}) from None
    if str(parsed) != value:
        raise HTTPException(400, {"code": "invalid_identifier", "message": "Identifier must be a canonical UUID"})
    return value


def _jsonable(row: Any) -> Any:
    if isinstance(row, datetime):
        return _instant(row)
    if isinstance(row, dict):
        return {k: _jsonable(v) for k, v in row.items()}
    if isinstance(row, (list, tuple)):
        return [_jsonable(v) for v in row]
    return row


def _decode_config(raw: str | None) -> dict[str, dict[str, Any]]:
    if not raw:
        return {}
    parsed = json.loads(raw)
    if not isinstance(parsed, dict):
        raise RuntimeError("UVM_API_PRINCIPALS must be a JSON object")
    result: dict[str, dict[str, Any]] = {}
    for principal, config in parsed.items():
        if (not isinstance(principal, str) or not principal or not isinstance(config, dict)
                or not isinstance(config.get("token"), str) or not config["token"]
                or not isinstance(config.get("scopes"), list)):
            raise RuntimeError("invalid UVM_API_PRINCIPALS entry")
        if not config["token"].isascii() or config["token"] in (item["token"] for item in result.values()):
            raise RuntimeError("API principal tokens must be unique ASCII strings")
        scopes = []
        for grant in config["scopes"]:
            if (not isinstance(grant, dict) or not all(isinstance(grant.get(k), str) and grant[k]
                                                       for k in ("source_family", "source_account_id", "scope_key"))):
                raise RuntimeError("invalid API scope grant")
            scopes.append(tuple(grant[k] for k in ("source_family", "source_account_id", "scope_key")))
        actor_kind = config.get("actor_kind", "principal")
        origin = config.get("origin", "local_api")
        if actor_kind not in {"principal", "service"} or not isinstance(origin, str) or not origin:
            raise RuntimeError("invalid API actor metadata")
        if actor_kind == "service" and origin == "local_api":
            raise RuntimeError("service API principals require a named origin")
        role_ids = config.get("role_ids", [])
        if (not isinstance(role_ids, list)
                or any(not isinstance(role_id, str) or not role_id for role_id in role_ids)
                or len(set(role_ids)) != len(role_ids)
                or (actor_kind != "service" and role_ids)):
            raise RuntimeError("role_ids must be unique non-empty strings on service principals only")
        result[principal] = {"token": config["token"], "scopes": tuple(scopes),
            "actor_kind": actor_kind, "origin": origin, "role_ids": tuple(role_ids)}
    return result


def _grant_clause(table, scopes):
    return sa.or_(*(sa.and_(table.c.source_family == family,
                            table.c.source_account_id == account,
                            table.c.scope_key == scope)
                    for family, account, scope in scopes))


def _cursor(secret: bytes, endpoint: str, payload: dict[str, Any]) -> str:
    body = json.dumps({"endpoint": endpoint, **payload}, separators=(",", ":"), sort_keys=True).encode()
    signature = hmac.new(secret, body, hashlib.sha256).digest()
    return base64.urlsafe_b64encode(body + b"." + signature).decode().rstrip("=")


def _read_cursor(secret: bytes, endpoint: str, value: str | None):
    if value is None:
        return None
    if len(value) > 4096:
        raise HTTPException(400, detail={"code": "invalid_cursor", "message": "Cursor is invalid"})
    try:
        raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
        if len(raw) < 33 or raw[-33:-32] != b".":
            raise ValueError
        body, signature = raw[:-33], raw[-32:]
        expected = hmac.new(secret, body, hashlib.sha256).digest()
        payload = json.loads(body)
        if (not isinstance(payload, dict)
                or set(payload) not in ({"endpoint", "as_of", "after", "principal", "grants"},
                                        {"endpoint", "as_of", "after", "principal", "grants", "snapshot_id"})
                or payload["endpoint"] != endpoint or not isinstance(payload["as_of"], str)
                or not isinstance(payload["after"], list) or len(payload["after"]) != 2
                or not all(isinstance(value, str) for value in payload["after"])
                or not isinstance(payload["principal"], str) or not isinstance(payload["grants"], str)
                or ("snapshot_id" in payload and not isinstance(payload["snapshot_id"], str))
                or not hmac.compare_digest(signature, expected)):
            raise ValueError
        datetime.fromisoformat(payload["as_of"].replace("Z", "+00:00"))
        return {key: value for key, value in payload.items() if key != "endpoint"}
    except (ValueError, TypeError, KeyError, json.JSONDecodeError):
        raise HTTPException(400, detail={"code": "invalid_cursor", "message": "Cursor is invalid"}) from None


def _as_of_for_cursor(secret: bytes, endpoint: str, cursor: str | None) -> datetime:
    state = _read_cursor(secret, endpoint, cursor)
    if state is None:
        return datetime.now(UTC)
    return datetime.fromisoformat(state["as_of"].replace("Z", "+00:00"))


def _grant_fingerprint(scopes) -> str:
    canonical = sorted({tuple(scope) for scope in scopes})
    return hashlib.sha256(json.dumps(canonical, separators=(",", ":")).encode()).hexdigest()


def _page(*, endpoint, request, limit, cursor, secret, query, ordering, key_fields, as_of_field,
          serialise, snapshot_time=None, where_as_of=True, membership_key=None,
          membership_predicates=(), snapshots=None, principal_name, grant_fingerprint,
          membership_revision=None, render_query=None):
    state = _read_cursor(secret, endpoint, cursor)
    if state and (state["principal"] != principal_name or state["grants"] != grant_fingerprint):
        raise HTTPException(400, {"code": "invalid_cursor", "message": "Cursor is invalid"})
    as_of = (datetime.fromisoformat(state["as_of"].replace("Z", "+00:00")) if state
             else snapshot_time or datetime.now(UTC))
    if where_as_of:
        query = query.where(as_of_field <= as_of)
    snapshot_id = None
    if membership_key is not None:
        if snapshots is None:
            raise RuntimeError("snapshot store is required for stable membership")
        if state:
            snapshot_id = state.get("snapshot_id")
            if not snapshot_id:
                raise HTTPException(400, {"code": "invalid_cursor", "message": "Cursor is invalid"})
            entries = snapshots.get(snapshot_id, principal_name, grant_fingerprint)
        else:
            selected = [membership_key, *ordering]
            if membership_revision is not None:
                selected.append(membership_revision)
            membership_query = query.where(*membership_predicates).with_only_columns(*selected).order_by(None).limit(
                _SNAPSHOT_ROW_MAX + 1)
            with request.app.state.engine.connect() as connection:
                captured = connection.execute(membership_query).all()
            if len(captured) > _SNAPSHOT_ROW_MAX:
                raise HTTPException(503, {"code": "read_snapshot_too_large",
                                          "message": "The result is too large for stable pagination"})
            entries = []
            for row in captured:
                sort_key = tuple(_snapshot_key_value(value)
                                 for value in row[1:1 + len(ordering)])
                revision = str(row[-1]) if membership_revision is not None else None
                entries.append((str(row[0]), sort_key, revision))
            snapshot_id = snapshots.create(entries, principal_name, grant_fingerprint)
        identifiers = [entry[0] for entry in entries]
        query = render_query if render_query is not None else query
        if where_as_of:
            query = query.where(as_of_field <= as_of)
        if not entries:
            query = query.where(sa.false())
        elif membership_revision is not None:
            query = query.where(sa.or_(*(sa.and_(membership_key == identifier,
                                                 membership_revision == int(revision))
                                         for identifier, _key, revision in entries)))
        else:
            query = query.where(membership_key.in_(identifiers))
        # Ordering and continuation always use captured keys, never mutable current row values.
        with request.app.state.engine.connect() as connection:
            current_rows = connection.execute(query).mappings().all()
        by_identifier = {str(row[membership_key.name]): dict(row) for row in current_rows}
        after = (tuple(datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(UTC)
                       if column.type.python_type is datetime else value
                       for column, value in zip(ordering, state["after"], strict=True))
                 if state else None)
        ordered = [(sort_key, by_identifier[identifier]) for identifier, sort_key, _revision in entries
                   if identifier in by_identifier and (after is None or sort_key > after)]
        ordered.sort(key=lambda item: item[0])
        page = [row for _sort_key, row in ordered[:limit + 1]]
        more = len(page) > limit
        page = page[:limit]
        next_cursor = None
        if more and page:
            last_identifier = str(page[-1][membership_key.name])
            last_key = next(key for identifier, key, _revision in entries if identifier == last_identifier)
            next_cursor = _cursor(secret, endpoint, {"as_of": _instant(as_of),
                "after": [_cursor_key_value(value) for value in last_key],
                "snapshot_id": snapshot_id, "principal": principal_name, "grants": grant_fingerprint})
        return {"schema_version": 1, "as_of": _instant(as_of),
                "items": [serialise(row) for row in page], "next_cursor": next_cursor}
    rows = request.app.state.engine.connect()
    try:
        page = rows.execute(query.order_by(*ordering).limit(limit + 1)).mappings().all()
    finally:
        rows.close()
    more = len(page) > limit
    page = page[:limit]
    next_cursor = None
    if more and page:
        last = page[-1]
        payload = {"as_of": _instant(as_of),
                   "after": [str(last[k]) if isinstance(last[k], datetime) else last[k]
                             for k in key_fields]}
        if snapshot_id is not None:
            payload["snapshot_id"] = snapshot_id
        next_cursor = _cursor(secret, endpoint, payload)
    return {"schema_version": 1, "as_of": _instant(as_of),
            "items": [serialise(dict(row)) for row in page], "next_cursor": next_cursor}


def create_app(engine: Engine | None = None, *, principals=None, cursor_secret: str | bytes | None = None,
               utc_now=None) -> FastAPI:
    if engine is None:
        database_url = os.environ.get("UVM_DB_URL")
        if not database_url:
            raise RuntimeError("UVM_DB_URL is required")
        engine = sa.create_engine(database_url, pool_pre_ping=True)
    principals = principals if principals is not None else _decode_config(os.getenv("UVM_API_PRINCIPALS"))
    secret = cursor_secret or os.getenv("UVM_API_CURSOR_SECRET")
    if not secret:
        raise RuntimeError("UVM_API_CURSOR_SECRET is required")
    if isinstance(secret, str):
        secret = secret.encode()
    app = FastAPI(title="UVM Read API", version="1.0.0")
    @app.middleware("http")
    async def oauth_response_security_headers(request: Request, call_next):
        recovery_port = int(os.getenv("UVM_G7_RECOVERY_CONTROL_PORT", "8002"))
        server = request.scope.get("server")
        listening_port = server[1] if isinstance(server, tuple) and len(server) == 2 else None
        recovery_path = request.url.path.startswith("/recovery-control/v1/")
        if ((listening_port == recovery_port and not recovery_path)
                or (recovery_path and listening_port != recovery_port)):
            return JSONResponse(status_code=404, content={"schema_version": 1,
                "error": {"code": "not_found", "message": "Route not found"}})
        response = await call_next(request)
        if "/installation/" in request.url.path:
            response.headers["Referrer-Policy"] = "no-referrer"
            response.headers["Cache-Control"] = "no-store"
        return response
    app.state.engine = engine
    # Trusted construction-time seam for deterministic disposable journeys.
    # Network requests cannot override this clock; production defaults to UTC now.
    def runtime_utc_now():
        # A writable-by-host clock file is available only to the labelled G7
        # disposable fixture so long clock transitions can be verified
        # without weakening the production clock authority.
        clock_file = os.environ.get("UVM_G7_TEST_CLOCK_FILE")
        if os.environ.get("UVM_G7_DISPOSABLE_MODE") == "1" and clock_file:
            try:
                value = datetime.fromisoformat(Path(clock_file).read_text().strip().replace("Z", "+00:00"))
                if value.tzinfo is not None and value.utcoffset() == UTC.utcoffset(value):
                    return value.astimezone(UTC)
            except (OSError, ValueError):
                pass
        return datetime.now(UTC)
    app.state.utc_now = utc_now or runtime_utc_now
    app.state.principals = principals
    app.state.cursor_secret = secret
    app.state.assessment_bootstrap_principal = os.getenv("UVM_G3_BOOTSTRAP_PRINCIPAL")
    snapshot_directory = os.getenv("UVM_API_READ_SNAPSHOT_DIR")
    if snapshot_directory:
        from uvm.api.read_snapshots import SharedReadSnapshots
        snapshots = SharedReadSnapshots(snapshot_directory, row_max=_SNAPSHOT_ROW_MAX,
            count_max=_SNAPSHOT_COUNT_MAX, ttl_seconds=_SNAPSHOT_TTL_SECONDS)
    else:
        snapshots = _ReadSnapshots()
    from uvm.auth.service import install_auth
    auth_service = install_auth(app)
    # FastAPI/Starlette places newly added user middleware at the outside of
    # its stack. Install ingress after authentication so peer and Host policy
    # runs before credentials or identity state are inspected.
    from uvm.api.ingress import install as install_ingress_guard
    install_ingress_guard(app)

    if os.getenv("UVM_G7_VERIFICATION_ONLY") == "1":
        if os.getenv("UVM_AUTH_MODE", "bearer") not in {"bearer", "oidc"}:
            raise RuntimeError("verification-only API requires bearer or restored OIDC session authentication")

        @app.middleware("http")
        async def recovery_read_only_fence(request: Request, call_next):
            # The distinct mTLS control listener shares this app factory but
            # has its own route allowlist and accepts authenticated recovery
            # POSTs. Let that listener-specific fence evaluate its paths;
            # the product listener never sets RECOVERY_CONTROL_ONLY.
            if (os.getenv("UVM_G7_RECOVERY_CONTROL_ONLY") == "1"
                    and request.url.path.startswith("/recovery-control/v1/")):
                return await call_next(request)
            from uvm.api.recovery_readonly import recovery_request_decision
            decision = recovery_request_decision(request.method, request.url.path)
            if decision == "not_found":
                return JSONResponse(status_code=404, content={"detail": {
                    "code": "not_found", "message": "Route not found"}})
            if decision == "method_not_allowed":
                return JSONResponse(status_code=405, content={"detail": {
                    "code": "recovery_read_only", "message": "Recovery verification is read-only"}},
                    headers={"Allow": "GET, HEAD"})
            return await call_next(request)

    if os.getenv("UVM_G7_RECOVERY_CONTROL_ONLY") == "1":
        @app.middleware("http")
        async def recovery_control_route_fence(request: Request, call_next):
            from uvm.api.recovery_readonly import recovery_control_request_decision
            if recovery_control_request_decision(request.url.path) == "not_found":
                return JSONResponse(status_code=404, content={"detail": {
                    "code": "not_found", "message": "Route not found"}})
            return await call_next(request)

    @app.exception_handler(HTTPException)
    async def http_error(request, exc):
        detail = exc.detail if isinstance(exc.detail, dict) else {"code": "request_error", "message": str(exc.detail)}
        code = detail.get("code", "request_error")
        status = exc.status_code
        connector_wire = (request.url.path.startswith("/api/v1/connectors")
            or request.url.path == "/api/v1/assessment/commands"
            or request.url.path.startswith("/api/v1/github")
            or request.url.path.startswith("/api/v1/operations/observer-settings"))
        connector_wire = connector_wire or request.url.path.startswith("/api/v1/operations/backup-settings")
        if connector_wire:
            aliases = {"invalid_settings":"invalid_request", "invalid_command":"invalid_request",
                "request_error":"invalid_request", "persistence_unavailable":"dependency_unavailable",
                "connector_fixture_unavailable":"dependency_unavailable",
                "connector_binding_unavailable":"dependency_unavailable",
                "github_unavailable":"dependency_unavailable",
                "webhook_secret_unavailable":"dependency_unavailable",
                "github_actor_unlinked":"forbidden", "github_audience_unknown":"revision_conflict"}
            code = aliases.get(code, code)
            allowed = {"authentication_required", "csrf_failed", "forbidden", "source_scope_forbidden",
                "not_found", "invalid_request", "revision_conflict", "command_conflict",
                "submission_conflict", "credential_revoked", "restore_quarantined",
                "callback_invalid", "validation_required", "dependency_unavailable", "outcome_unknown",
                "report_expired", "report_superseded", "host_policy_unavailable"}
            if code not in allowed:
                code = ("authentication_required" if status == 401 else "forbidden" if status == 403
                    else "not_found" if status == 404 else "dependency_unavailable" if status >= 500
                    else "revision_conflict" if status == 409 else "invalid_request")
            status_by_code = {"authentication_required":401, "csrf_failed":403, "forbidden":403,
                "source_scope_forbidden":403, "not_found":404, "invalid_request":400,
                "revision_conflict":409, "command_conflict":409, "submission_conflict":409,
                "credential_revoked":409, "restore_quarantined":409, "callback_invalid":400,
                "validation_required":409, "dependency_unavailable":503, "outcome_unknown":503,
                "host_policy_unavailable":503,
                "report_expired":400, "report_superseded":409}
            status = status_by_code[code]
            raw_details = detail.get("details") if isinstance(detail.get("details"), dict) else {}
            details = {"outcome": raw_details.get("outcome",
                    "unknown" if code == "outcome_unknown" else "not_committed"),
                "expected_revisions": raw_details.get("expected_revisions"),
                "current_revisions": raw_details.get("current_revisions"),
                "lookup_url": raw_details.get("lookup_url")}
        else:
            details = detail.get("details", {})
        correlation_id = request.headers.get("x-correlation-id")
        try:
            correlation_id = str(uuid.UUID(correlation_id)) if correlation_id else str(uuid.uuid4())
        except ValueError:
            correlation_id = str(uuid.uuid4())
        return JSONResponse(status_code=status,
                            content={"schema_version": 1, "error": {
                                "code": code,
                                "message": detail.get("message", "Request failed"),
                                "correlation_id": correlation_id,
                                "details": details}})

    @app.exception_handler(RequestValidationError)
    async def validation_error(request, _exc):
        connector_wire = (request.url.path.startswith("/api/v1/connectors")
            or request.url.path == "/api/v1/assessment/commands"
            or request.url.path.startswith("/api/v1/github")
            or request.url.path.startswith("/api/v1/operations/observer-settings"))
        connector_wire = connector_wire or request.url.path.startswith("/api/v1/operations/backup-settings")
        error = {"code":"invalid_request","message":"Request parameters are invalid"}
        if connector_wire:
            supplied=request.headers.get("x-correlation-id")
            try: correlation_id=str(uuid.UUID(supplied)) if supplied else str(uuid.uuid4())
            except ValueError: correlation_id=str(uuid.uuid4())
            error.update(correlation_id=correlation_id,details={"outcome":"not_committed",
                "expected_revisions":None,"current_revisions":None,"lookup_url":None})
        return JSONResponse(status_code=400,content={"schema_version":1,"error":error})

    @app.exception_handler(sa.exc.SQLAlchemyError)
    async def database_error(request, exc):
        _LOG.exception("Read API database operation failed", exc_info=exc)
        connector_wire = (request.url.path.startswith("/api/v1/connectors")
            or request.url.path == "/api/v1/assessment/commands"
            or request.url.path.startswith("/api/v1/github")
            or request.url.path.startswith("/api/v1/operations/observer-settings"))
        connector_wire = connector_wire or request.url.path.startswith("/api/v1/operations/backup-settings")
        error={"code":"dependency_unavailable" if connector_wire else "read_dependency_unavailable",
            "message":"The read service is temporarily unavailable"}
        if connector_wire:
            supplied=request.headers.get("x-correlation-id")
            try: correlation_id=str(uuid.UUID(supplied)) if supplied else str(uuid.uuid4())
            except ValueError: correlation_id=str(uuid.uuid4())
            error.update(correlation_id=correlation_id,details={"outcome":"unknown",
                "expected_revisions":None,"current_revisions":None,"lookup_url":None})
        return JSONResponse(status_code=503,content={"schema_version":1,"error":error})

    @app.exception_handler(Exception)
    async def unexpected_error(request, exc):
        _LOG.exception("Unhandled read API failure", exc_info=exc)
        connector_wire = (request.url.path.startswith("/api/v1/connectors")
            or request.url.path == "/api/v1/assessment/commands"
            or request.url.path.startswith("/api/v1/github")
            or request.url.path.startswith("/api/v1/operations/backup-settings"))
        error={"code":"dependency_unavailable" if connector_wire else "internal_error",
            "message":"The read service could not complete the request"}
        if connector_wire:
            supplied=request.headers.get("x-correlation-id")
            try: correlation_id=str(uuid.UUID(supplied)) if supplied else str(uuid.uuid4())
            except ValueError: correlation_id=str(uuid.uuid4())
            error.update(correlation_id=correlation_id,details={"outcome":"unknown",
                "expected_revisions":None,"current_revisions":None,"lookup_url":None})
        return JSONResponse(status_code=503 if connector_wire else 500,
            content={"schema_version":1,"error":error})

    def auth(request: Request, authorization: str | None = Header(default=None)):
        if auth_service is not None:
            context = auth_service.resolve_request(request)
            if not context.source_scopes:
                raise HTTPException(403, {"code": "scope_forbidden", "message": "Access forbidden"})
            return {"name": context.principal_id, "scopes": context.source_scopes,
                    "context": context}
        if not authorization or not authorization.startswith("Bearer "):
            raise HTTPException(401, {"code": "authentication_required", "message": "Authentication required"})
        supplied = authorization[7:]
        if not supplied.isascii() or len(supplied) > 512:
            raise HTTPException(401, {"code": "authentication_required", "message": "Authentication required"})
        for name, principal in principals.items():
            if hmac.compare_digest(supplied, principal["token"]):
                if not principal["scopes"]:
                    raise HTTPException(403, {"code": "scope_forbidden", "message": "Access forbidden"})
                return {"name": name, "scopes": principal["scopes"]}
        raise HTTPException(401, {"code": "authentication_required", "message": "Authentication required"})

    def paging(limit, cursor):
        if limit < 1 or limit > _PAGE_MAX:
            raise HTTPException(400, {"code": "invalid_limit", "message": "limit must be between 1 and 100"})
        return limit, cursor

    def validate_cursor_binding(endpoint, cursor, principal):
        state = _read_cursor(secret, endpoint, cursor)
        if state and (state["principal"] != principal["name"]
                      or state["grants"] != _grant_fingerprint(principal["scopes"])):
            raise HTTPException(400, {"code": "invalid_cursor", "message": "Cursor is invalid"})

    @app.get("/api/v1/ingestion/runs")
    def list_runs(request: Request, limit: int = Query(50), cursor: str | None = None, principal=Depends(auth)):
        paging(limit, cursor)
        as_of = _as_of_for_cursor(secret, "runs", cursor)
        runs = collection_runs.alias("runs")
        scoped_runs = sa.select(runs).where(_grant_clause(runs, principal["scopes"]))
        scoped_runs = scoped_runs.where(runs.c.created_at <= as_of)
        if cursor is None:
            latest = sa.select(runs.c.run_id, sa.func.max(runs.c.revision).label("revision"))\
                .where(runs.c.created_at <= as_of).group_by(runs.c.run_id).subquery()
            q = sa.select(runs).join(latest, sa.and_(runs.c.run_id == latest.c.run_id,
                                                      runs.c.revision == latest.c.revision))
        else:
            # Continuations select the exact immutable revisions captured at page one.
            q = scoped_runs
        q = q.where(_grant_clause(runs, principal["scopes"]))
        q = q.where(runs.c.created_at <= as_of)
        ordering = (runs.c.created_at, runs.c.run_id)
        def summary(r):
            with engine.connect() as c:
                operation = c.execute(sa.select(engine_operation_states.c.operation_id,
                                                  engine_operation_states.c.status)
                    .join(engine_operation_requests, engine_operation_requests.c.operation_id == engine_operation_states.c.operation_id)
                    .join(manifest_ledger_headers, manifest_ledger_headers.c.operation_id == engine_operation_requests.c.operation_id)
                    .where(engine_operation_requests.c.source_run_id == r["run_id"],
                           manifest_ledger_headers.c.run_id == r["run_id"],
                           manifest_ledger_headers.c.source_family == r["source_family"],
                           manifest_ledger_headers.c.source_account_id == r["source_account_id"])
                    .order_by(engine_operation_states.c.changed_at.desc()).limit(1)).mappings().first()
            return {"run_id": r["run_id"], "revision": r["revision"], "schema_version": r["schema_version"],
                    "source_family": r["source_family"], "source_account_id": r["source_account_id"], "scope_key": r["scope_key"],
                    "state": r["state"], "expected_at": _instant(r["expected_at"]), "started_at": _instant(r["started_at"]),
                    "ended_at": _instant(r["ended_at"]), "quality": {"retrieval": {"status": r["retrieval_status"], "reasons": r["retrieval_reasons"]},
                    "coverage": {"status": r["coverage_status"], "reasons": r["coverage_reasons"]},
                    "freshness": {"status": r["freshness_status"], "reasons": r["freshness_reasons"]}},
                    "ce_operation": ({"operation_id": operation["operation_id"], "status": operation["status"]} if operation else None)}
        # Key fields used by keyset pagination are created_at and run_id.
        return _page(endpoint="runs", request=request, limit=limit, cursor=cursor, secret=secret,
                     query=q, ordering=ordering, key_fields=("created_at", "run_id"),
                     as_of_field=runs.c.created_at, serialise=summary, snapshot_time=as_of,
                     membership_key=runs.c.run_id, membership_revision=runs.c.revision,
                     render_query=scoped_runs,
                     snapshots=snapshots, principal_name=principal["name"],
                     grant_fingerprint=_grant_fingerprint(principal["scopes"]))

    @app.get("/api/v1/ingestion/runs/{run_id}")
    def get_run(run_id: str, request: Request, limit: int = Query(50), cursor: str | None = None,
                principal=Depends(auth)):
        paging(limit, cursor)
        run_id = _canonical_id(run_id)
        validate_cursor_binding(f"run-observations:{run_id}", cursor, principal)
        with engine.connect() as c:
            row = c.execute(sa.select(collection_runs).where(collection_runs.c.run_id == run_id)
                            .order_by(collection_runs.c.revision.desc()).limit(1)).mappings().first()
            if row is None:
                raise HTTPException(404, {"code": "not_found", "message": "Run not found"})
            if (row["source_family"], row["source_account_id"], row["scope_key"]) not in principal["scopes"]:
                raise HTTPException(403, {"code": "scope_forbidden", "message": "Access forbidden"})
            rev = row["revision"]
            attempts = c.execute(sa.select(run_attempts).where(run_attempts.c.run_id == run_id,
                                  run_attempts.c.run_revision == rev).order_by(run_attempts.c.attempt_no)).mappings().all()
            pages = c.execute(sa.select(run_pages).where(run_pages.c.run_id == run_id,
                               run_pages.c.run_revision == rev).order_by(run_pages.c.ordinal)).mappings().all()
            evidence = c.execute(sa.select(ingestion_evidence).where(ingestion_evidence.c.run_id == run_id,
                                  ingestion_evidence.c.run_revision == rev).order_by(ingestion_evidence.c.evidence_id)).mappings().all()
            operations = c.execute(sa.select(engine_operation_requests, engine_operation_states)
                .join(engine_operation_states, engine_operation_states.c.operation_id == engine_operation_requests.c.operation_id)
                .join(manifest_ledger_headers, manifest_ledger_headers.c.operation_id == engine_operation_requests.c.operation_id)
                .where(engine_operation_requests.c.source_run_id == run_id)
                .where(manifest_ledger_headers.c.run_id == run_id,
                       manifest_ledger_headers.c.source_family == row["source_family"],
                       manifest_ledger_headers.c.source_account_id == row["source_account_id"])
                .order_by(engine_operation_requests.c.requested_at, engine_operation_requests.c.operation_id)).mappings().all()
            observations = source_observations.alias("run_observations")
            observation_query = sa.select(observations.c.observation_id,
                                          observations.c.source_record_ordinal,
                                          observations.c.observed_at,
                                          observations.c.collected_at).where(
                observations.c.run_id == run_id,
                observations.c.source_family == row["source_family"],
                observations.c.source_account_id == row["source_account_id"])
        observation_page = _page(
            endpoint=f"run-observations:{run_id}", request=request, limit=limit,
            cursor=cursor, secret=secret, query=observation_query,
            ordering=(observations.c.collected_at, observations.c.observation_id),
            key_fields=("collected_at", "observation_id"),
            as_of_field=observations.c.collected_at,
            membership_key=observations.c.observation_id, snapshots=snapshots,
            principal_name=principal["name"],
            grant_fingerprint=_grant_fingerprint(principal["scopes"]),
            serialise=lambda r: {"observation_id": r["observation_id"],
                                 "source_record_ordinal": r["source_record_ordinal"],
                                 "observed_at": _instant(r["observed_at"]),
                                 "collected_at": _instant(r["collected_at"])})
        run_data = dict(row)
        run_data.pop("facts_snapshot", None)
        run_data.pop("provenance_snapshot", None)
        return {"schema_version": 1, "as_of": observation_page["as_of"], "run": _jsonable(run_data),
                "attempts": [_jsonable(dict(x)) for x in attempts], "pages": [_jsonable(dict(x)) for x in pages],
                "evidence": [_jsonable(dict(x)) for x in evidence],
                "observations": observation_page["items"],
                "observations_next_cursor": observation_page["next_cursor"],
                "ce_operations": [{"operation_id": x["operation_id"], "status": x["status"], "revision": x["revision"],
                    "test_id": x["test_id"], "bound_test_id": x["bound_test_id"], "mapping_revision": x["mapping_revision"],
                    "error_code": x["error_code"], "post_issued": x["post_issued"], "reconciled": x["reconciled"]} for x in operations]}

    @app.get("/api/v1/integrations/health")
    def list_health(request: Request, limit: int = Query(50), cursor: str | None = None, principal=Depends(auth)):
        paging(limit, cursor)
        as_of = _as_of_for_cursor(secret, "health", cursor)
        events = health_events.alias("events")
        run = collection_runs.alias("scope_run")
        expected = expected_runs.alias("scope_expected")
        schedule = collection_schedules.alias("scope_schedule")
        q = sa.select(events, health_condition_episodes.c.subject_key.label("subject_key"))
        q = q.join(health_condition_episodes, health_condition_episodes.c.episode_id == events.c.episode_id)
        q = q.outerjoin(run, sa.and_(run.c.run_id == events.c.run_id,
                                     run.c.revision == events.c.run_revision))
        q = q.outerjoin(expected, expected.c.expected_run_id == events.c.expected_run_id)
        q = q.outerjoin(schedule, sa.and_(schedule.c.schedule_id == expected.c.schedule_id,
                                         schedule.c.revision == expected.c.schedule_revision))
        run_grants = []
        expected_grants = []
        for family, account, scope in principal["scopes"]:
            run_grants.append(sa.and_(run.c.source_family == family, run.c.source_account_id == account, run.c.scope_key == scope))
            expected_grants.append(sa.and_(schedule.c.source_family == family, schedule.c.source_account_id == account, schedule.c.scope_key == scope))
        run_allowed = sa.or_(*run_grants)
        expected_allowed = sa.or_(*expected_grants)
        has_run, has_expected = events.c.run_id.is_not(None), events.c.expected_run_id.is_not(None)
        q = q.where(sa.or_(sa.and_(has_run, run_allowed), sa.and_(has_expected, expected_allowed)),
                    sa.or_(~has_run, run_allowed), sa.or_(~has_expected, expected_allowed),
                    events.c.observed_at <= as_of)
        latest_delivery = sa.select(notification_deliveries.c.outcome).where(
            notification_deliveries.c.event_id == events.c.event_id).order_by(
                notification_deliveries.c.attempted_at.desc()).limit(1).scalar_subquery()
        q = q.add_columns(notification_intents.c.state.label("notification_state"), latest_delivery.label("delivery_outcome"))
        q = q.outerjoin(notification_intents, notification_intents.c.event_id == events.c.event_id)
        ordering = (events.c.observed_at, events.c.event_id)
        def serialise(r):
            return {"event_id": r["event_id"], "condition": r["condition"], "severity": r["severity"], "state": r["state"],
                    "detected_at": _instant(r["detected_at"]), "observed_at": _instant(r["observed_at"]),
                    "expected_run_id": r["expected_run_id"], "run_id": r["run_id"], "run_revision": r["run_revision"],
                    "subject_key": r["subject_key"], "notification": {"intent": r["notification_state"], "delivery": r["delivery_outcome"]}}
        return _page(endpoint="health", request=request, limit=limit, cursor=cursor, secret=secret,
                     query=q, ordering=ordering, key_fields=("observed_at", "event_id"),
                     as_of_field=events.c.observed_at, serialise=serialise, snapshot_time=as_of,
                     membership_key=events.c.event_id, snapshots=snapshots,
                     principal_name=principal["name"],
                     grant_fingerprint=_grant_fingerprint(principal["scopes"]))

    @app.get("/api/v1/unresolved")
    def list_unresolved(request: Request, limit: int = Query(50), cursor: str | None = None, principal=Depends(auth)):
        paging(limit, cursor)
        as_of = _as_of_for_cursor(secret, "unresolved", cursor)
        resolutions = identity_resolutions.alias("resolutions")
        observations = source_observations.alias("observations")
        runs = collection_runs.alias("source_runs")
        q = sa.select(resolutions,
                      observations.c.run_id.label("run_id"),
                      observations.c.source_family.label("source_family"),
                      observations.c.source_account_id.label("source_account_id"),
                      resolution_temporal_assessments.c.status.label("temporal_status"))
        q = q.join(observations, observations.c.observation_id == resolutions.c.observation_id)
        # Scope proof uses EXISTS so run revisions cannot multiply resolution rows.
        assess_latest = sa.select(resolution_temporal_assessments.c.resolution_id,
                                  sa.func.max(resolution_temporal_assessments.c.event_sequence).label("seq")).group_by(resolution_temporal_assessments.c.resolution_id).subquery()
        q = q.outerjoin(assess_latest, assess_latest.c.resolution_id == resolutions.c.resolution_id)
        q = q.outerjoin(resolution_temporal_assessments, sa.and_(resolution_temporal_assessments.c.resolution_id == assess_latest.c.resolution_id,
                                                                  resolution_temporal_assessments.c.event_sequence == assess_latest.c.seq))
        superseding = identity_resolutions.alias("superseding_resolutions")
        superseded_at = sa.exists(sa.select(1).select_from(superseding).where(
            superseding.c.supersedes_resolution_id == resolutions.c.resolution_id,
            superseding.c.evaluated_at <= as_of))
        grants = []
        for family, account, scope in principal["scopes"]:
            grants.append(sa.and_(runs.c.source_family == family,
                                  runs.c.source_account_id == account,
                                  runs.c.scope_key == scope))
        scoped_run_exists = sa.exists(sa.select(1).select_from(runs).where(
            sa.cast(runs.c.run_id, sa.String) == observations.c.run_id,
            runs.c.source_family == observations.c.source_family,
            runs.c.source_account_id == observations.c.source_account_id,
            sa.or_(*grants)))
        q = q.where(scoped_run_exists, resolutions.c.outcome.in_(("ambiguous", "unresolved")),
                    resolutions.c.evaluated_at <= as_of)
        ordering = (resolutions.c.evaluated_at, resolutions.c.resolution_id)
        def serialise(r):
            with engine.connect() as c:
                associations = c.execute(
                    sa.select(manifest_ledger_headers.c.manifest_id,
                              manifest_ledger_headers.c.operation_id,
                              manifest_ledger_rows.c.disposition,
                              manifest_ledger_rows.c.resolution_id,
                              manifest_ledger_rows.c.resolution_revision,
                              manifest_ledger_rows.c.occurrence_id,
                              manifest_ledger_rows.c.blocked_reason,
                              engine_operation_states.c.status.label("operation_status"),
                              engine_operation_states.c.revision.label("operation_revision"),
                              engine_operation_states.c.mapping_revision)
                    .select_from(manifest_ledger_rows)
                    .join(manifest_ledger_headers,
                          manifest_ledger_headers.c.manifest_id == manifest_ledger_rows.c.manifest_id)
                    .join(engine_operation_states,
                          engine_operation_states.c.operation_id == manifest_ledger_headers.c.operation_id)
                    .where(manifest_ledger_rows.c.observation_id == r["observation_id"],
                           manifest_ledger_headers.c.run_id == r["run_id"],
                           manifest_ledger_headers.c.source_family == r["source_family"],
                           manifest_ledger_headers.c.source_account_id == r["source_account_id"])
                    .order_by(manifest_ledger_headers.c.sealed_at,
                              manifest_ledger_headers.c.manifest_id)).mappings().all()
                manifest_associations = []
                for association in associations:
                    links = []
                    if (association["disposition"] == "included"
                            and association["occurrence_id"] is not None
                            and association["mapping_revision"] is not None):
                        links = c.execute(sa.select(
                            engine_occurrence_links.c.link_id,
                            engine_occurrence_links.c.occurrence_id,
                            engine_occurrence_links.c.mapping_revision,
                            engine_occurrence_links.c.test_id,
                            engine_occurrence_links.c.finding_id,
                            engine_occurrence_links.c.endpoint_id,
                            engine_occurrence_links.c.recorded_at)
                            .where(engine_occurrence_links.c.operation_id == association["operation_id"],
                                   engine_occurrence_links.c.manifest_id == association["manifest_id"],
                                   engine_occurrence_links.c.occurrence_id == association["occurrence_id"],
                                   engine_occurrence_links.c.mapping_revision == association["mapping_revision"])
                            .order_by(engine_occurrence_links.c.link_id)).mappings().all()
                    manifest_associations.append({
                        "manifest_id": association["manifest_id"],
                        "disposition": association["disposition"],
                        "resolution_id": association["resolution_id"],
                        "resolution_revision": association["resolution_revision"],
                        "occurrence_id": association["occurrence_id"],
                        "blocked_reason": association["blocked_reason"],
                        "source_run_operation": {
                            "operation_id": association["operation_id"],
                            "status": association["operation_status"],
                            "revision": association["operation_revision"]},
                        "occurrence_links": [_jsonable(dict(link)) for link in links]})
            return {"resolution_id": r["resolution_id"], "revision": r["revision"], "schema_version": r["schema_version"],
                    "observation_id": r["observation_id"], "group_id": r["group_id"], "outcome": r["outcome"],
                    "reason": r["reason"], "candidate_workload_ids": r["candidate_workload_ids"],
                    "candidate_explanations": r["candidate_explanations"], "evaluated_at": _instant(r["evaluated_at"]),
                    "temporal_status": "not_applicable" if r["outcome"] in ("ambiguous", "unresolved") else (r["temporal_status"] or "unknown"),
                    "manifest_associations": manifest_associations}
        return _page(endpoint="unresolved", request=request, limit=limit, cursor=cursor, secret=secret,
                     query=q, ordering=ordering, key_fields=("evaluated_at", "resolution_id"),
                     as_of_field=resolutions.c.evaluated_at, serialise=serialise, snapshot_time=as_of,
                     membership_key=resolutions.c.resolution_id,
                     membership_predicates=(~superseded_at,), snapshots=snapshots,
                     principal_name=principal["name"],
                     grant_fingerprint=_grant_fingerprint(principal["scopes"]))

    from uvm.assessment.api import install_assessment_routes
    install_assessment_routes(app)
    from uvm.operations.api import install_observer_settings_routes
    install_observer_settings_routes(app)
    from uvm.connectors.api import install_connector_routes
    install_connector_routes(app)
    from uvm.assessment.metrics_api import install_metrics_routes
    install_metrics_routes(app, auth)
    from uvm.github.api import install_github_routes
    install_github_routes(app)
    from uvm.assessment.read_diagnostics import install as install_read_diagnostics
    install_read_diagnostics(app, engine)
    from uvm.assessment.d08_transport_diagnostics import install as install_d08_transport_diagnostics
    install_d08_transport_diagnostics(app)
    # Registered last: API handlers retain authority, and reserved service paths
    # never resolve to the SPA. Resolve paths before checking the static root.
    ui_root = os.getenv("UVM_UI_ROOT")
    if ui_root:
        root = Path(ui_root).resolve(strict=True)

        @app.api_route("/{ui_path:path}", methods=["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"], include_in_schema=False)
        def browser_shell(ui_path: str, request: Request):
            if request.method not in {"GET", "HEAD"}:
                raise HTTPException(404, "Not found")
            if ui_path.split("/", 1)[0] in {"api", "__fixture", "admin", "healthz", "docs", "redoc", "openapi.json"}:
                raise HTTPException(404, "Not found")
            target = (root / ui_path).resolve()
            if not target.is_relative_to(root):
                raise HTTPException(404, "Not found")
            if not target.is_file():
                if ui_path not in {"", "auth/failure"}:
                    raise HTTPException(404, "Not found")
                target = root / "index.html"
            return FileResponse(target, headers={"Cache-Control": "no-store",
                "Referrer-Policy": "no-referrer", "X-Content-Type-Options": "nosniff"})
    if os.getenv("UVM_G7_VERIFICATION_ONLY") == "1":
        # Restricted processes expose retained readbacks only. Normal hooks
        # include restore mutations, projection recovery and external pollers.
        app.router.on_startup.clear()
        app.router.on_shutdown.clear()
    return app


app = create_app() if os.getenv("UVM_DB_URL") and os.getenv("UVM_API_CURSOR_SECRET") else None
