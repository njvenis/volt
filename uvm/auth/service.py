"""Local OIDC code exchange and shared, current authority resolution.

The configuration is explicit and versioned. No fixture value is selected by
this module as a deployment default.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import time
import uuid
from functools import wraps
from datetime import datetime, timedelta, timezone
from typing import Any
from urllib.parse import urlsplit

import sqlalchemy as sa
from authlib.integrations.httpx_client import AsyncOAuth2Client
from authlib.oidc.core import CodeIDToken
from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse, RedirectResponse, Response
from httpx2 import AsyncClient
from joserfc import jwt
from joserfc.jwk import KeySet
from joserfc.jwt import JWTClaimsRegistry

from uvm.auth.schema import AUTHORITY_CONTEXT, AuthorityContext
from uvm.auth.native_authority import NATIVE_MODE, effective_access, native_state
from uvm.persistence.auth_schema import (auth_group_memberships, auth_identity_events,
    auth_principals, oidc_authorization_states, oidc_sessions, oidc_subject_groups,
    oidc_subject_links, oidc_sync_state)
from uvm.persistence.assessment_schema import assessment_policy
from uvm.persistence.ingestion_schema import collection_runs
from uvm.persistence.observation_schema import source_observations
from uvm.persistence.schema import exposures, groups as vulnerability_groups, occurrences
from uvm.assessment.policy_lock import lock_policy

UTC = timezone.utc
COOKIE_NAME = "uvm_session"
_STATE_TTL = 600


def _now() -> datetime:
    return datetime.now(UTC)


def _sha(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _json_digest(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _origin(value: str) -> str:
    parsed = urlsplit(value)
    if not parsed.scheme or not parsed.netloc or parsed.path not in ("", "/") or parsed.query or parsed.fragment:
        raise RuntimeError("OIDC origin must be a bare origin")
    return f"{parsed.scheme}://{parsed.netloc}"


def load_oidc_config() -> dict[str, Any]:
    raw = os.environ.get("UVM_OIDC_CONFIG", "")
    if not raw:
        raise RuntimeError("UVM_OIDC_CONFIG is required when OIDC mode is enabled")
    try:
        config = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise RuntimeError("UVM_OIDC_CONFIG is invalid JSON") from exc
    required = {"schema_version", "provider_id", "issuer", "discovery_url", "client_id", "callback_url",
        "client_secret_file", "sync_secret_file", "operator_secret_file", "operator_actor_id",
        "allowed_algorithms", "allowed_endpoint_origins", "source_scope_ceilings",
        "group_mappings", "mapping_revision", "session_ttl_seconds", "heartbeat_max_age_seconds"}
    if not isinstance(config, dict) or set(config) != required or config.get("schema_version") != 1:
        raise RuntimeError("OIDC configuration must use the exact version 1 schema")
    if any(not isinstance(config.get(key), str) or not config[key]
           for key in ("provider_id", "issuer", "discovery_url", "client_id", "callback_url",
               "client_secret_file", "sync_secret_file", "operator_secret_file", "operator_actor_id")):
        raise RuntimeError("OIDC provider, issuer, client and callback are required")
    if (not isinstance(config["allowed_algorithms"], list) or not config["allowed_algorithms"]
            or any(not isinstance(item, str) or not item or item.casefold() == "none"
                   for item in config["allowed_algorithms"])):
        raise RuntimeError("OIDC allowed_algorithms must be a non-empty explicit list")
    if (not isinstance(config["allowed_endpoint_origins"], list)
            or not config["allowed_endpoint_origins"]):
        raise RuntimeError("OIDC trusted endpoint origins are required")
    origins = {_origin(item) for item in config["allowed_endpoint_origins"]}
    if not isinstance(config["group_mappings"], dict) or not isinstance(config["source_scope_ceilings"], list):
        raise RuntimeError("OIDC authority mappings and source ceilings are required")
    for scope in config["source_scope_ceilings"]:
        _scope(scope)
    for group_id, mapping in config["group_mappings"].items():
        if (not isinstance(group_id, str) or not group_id or not isinstance(mapping, dict)
                or set(mapping) != {"role_ids", "source_scopes"}
                or not isinstance(mapping["role_ids"], list)
                or not isinstance(mapping["source_scopes"], list)):
            raise RuntimeError("OIDC access-group mapping schema is invalid")
        for scope in mapping["source_scopes"]:
            _scope(scope)
    if (type(config["mapping_revision"]) is not int or config["mapping_revision"] < 1
            or type(config["session_ttl_seconds"]) is not int or config["session_ttl_seconds"] < 1
            or type(config["heartbeat_max_age_seconds"]) is not int
            or config["heartbeat_max_age_seconds"] < 1):
        raise RuntimeError("OIDC revisions and freshness/session durations must be explicit positive integers")
    issuer_origin = _url_origin(config["issuer"])
    if (issuer_origin not in origins or _url_origin(config["discovery_url"]) not in origins
            or _url_origin(config["callback_url"]) not in origins):
        raise RuntimeError("OIDC issuer, discovery and callback origins must be trusted")
    ceilings = {_scope(item) for item in config["source_scope_ceilings"]}
    for mapping in config["group_mappings"].values():
        if any(_scope(item) not in ceilings for item in mapping["source_scopes"]):
            raise RuntimeError("OIDC group source scope exceeds its configured ceiling")
    return {**config, "_digest": _json_digest(config), "_origins": origins}


def _scope(value: Any) -> tuple[str, str, str]:
    keys = ("source_family", "source_account_id", "scope_key")
    if (not isinstance(value, dict) or set(value) != set(keys)
            or any(not isinstance(value.get(key), str) or not value[key] for key in keys)):
        raise RuntimeError("source scope must be the exact non-empty source tuple")
    return tuple(value[key] for key in keys)


def _secret_value(path: str, label: str) -> str:
    try:
        value = open(path, encoding="utf-8").read().strip()
    except OSError as exc:
        raise RuntimeError(f"OIDC {label} secret file is unavailable") from exc
    if not value:
        raise RuntimeError(f"OIDC {label} secret file is empty")
    return value


def _url_origin(value: str) -> str:
    parsed = urlsplit(value)
    if not parsed.scheme or not parsed.netloc:
        raise RuntimeError("OIDC callback URL must be absolute")
    return f"{parsed.scheme}://{parsed.netloc}"


def group_scope_covered(connection, context: AuthorityContext | None, group_ids,
                        *, granting_identity_groups=None) -> bool:
    """Require every retained exact source tuple in a target set to be covered."""
    if context is None:
        return True
    groups = tuple(sorted(set(group_ids)))
    if not groups:
        return False
    known = set(connection.execute(sa.select(vulnerability_groups.c.group_id).where(
        vulnerability_groups.c.group_id.in_(groups))).scalars())
    if len(known) != len(groups):
        return False
    groups = tuple(sorted(known))
    rows = connection.execute(sa.select(exposures.c.group_id,
        source_observations.c.source_family, source_observations.c.source_account_id,
        source_observations.c.run_id, collection_runs.c.run_id.label("retained_run_id"),
        collection_runs.c.scope_key).select_from(
        source_observations.join(occurrences,
            source_observations.c.occurrence_id == occurrences.c.occurrence_id).join(
            exposures, occurrences.c.exposure_id == exposures.c.exposure_id).join(
            collection_runs, sa.and_(sa.cast(collection_runs.c.run_id, sa.String) == source_observations.c.run_id,
                    collection_runs.c.source_family == source_observations.c.source_family,
                    collection_runs.c.source_account_id == source_observations.c.source_account_id),
                    isouter=True))
        .where(exposures.c.group_id.in_(groups))).all()
    if not rows or any(row.retained_run_id is None for row in rows):
        return False
    observed_groups = {row.group_id for row in rows}
    if observed_groups != set(groups):
        return False
    target_occurrences = set(connection.execute(sa.select(occurrences.c.occurrence_id)
        .select_from(occurrences.join(exposures,
            occurrences.c.exposure_id == exposures.c.exposure_id))
        .where(exposures.c.group_id.in_(groups))).scalars())
    observed_occurrences = set(connection.execute(sa.select(source_observations.c.occurrence_id)
        .select_from(source_observations.join(occurrences,
            source_observations.c.occurrence_id == occurrences.c.occurrence_id).join(
            exposures, occurrences.c.exposure_id == exposures.c.exposure_id))
        .where(exposures.c.group_id.in_(groups))).scalars())
    if not target_occurrences or not target_occurrences <= observed_occurrences:
        return False
    required_by_group: dict[str, set[tuple[str, str, str]]] = {}
    for row in rows:
        required_by_group.setdefault(row.group_id, set()).add(
            (row.source_family, row.source_account_id, row.scope_key))
    # Keep a granting role paired with the source ceiling contributed by the
    # same identity access group.  The target IDs above are vulnerability UUIDs
    # and are deliberately not compared with identity-group IDs.
    if context.credential_mode in {"oidc_session", "github_link"}:
        grant_groups = (set(context.access_groups) if granting_identity_groups is None
            else set(granting_identity_groups))
        if not grant_groups:
            return False
        authorised_scopes = context.scopes_for_granting_groups(grant_groups)
    else:
        authorised_scopes = set(context.source_scopes)
    return all(required and required <= authorised_scopes
        for required in required_by_group.values()) and set(required_by_group) == set(groups)


class OIDCAuth:
    def __init__(self, engine, principals: dict[str, dict[str, Any]]):
        self.engine = engine
        self.principals = principals
        self.config = load_oidc_config()
        self.client_secret = _secret_value(self.config["client_secret_file"], "client")
        self.sync_secret = _secret_value(self.config["sync_secret_file"], "sync")
        self.operator_secret = _secret_value(self.config["operator_secret_file"], "operator")

    def _service_context(self, token: str) -> AuthorityContext | None:
        for name, item in self.principals.items():
            if (item.get("actor_kind") == "service" and isinstance(item.get("token"), str)
                    and hmac.compare_digest(token, item["token"])):
                return self.service_context_for_principal(name)
        return None

    def service_context_for_principal(self, principal_id: str) -> AuthorityContext | None:
        """Resolve a configured service identity for an internal background action."""
        item = self.principals.get(principal_id)
        if not item or item.get("actor_kind") != "service":
            return None
        scopes = tuple(tuple(scope) for scope in item.get("scopes", ()))
        now = _now()
        with self.engine.connect() as connection:
            policy_revision = connection.execute(sa.select(assessment_policy.c.revision).where(
                assessment_policy.c.policy_id == 1)).scalar_one_or_none() or 0
        roles = tuple(item.get("role_ids", ()))
        return AuthorityContext(principal_id, "service_bearer", None, None, None, None, None, None,
            (), 0, self.config["mapping_revision"], policy_revision, scopes, roles, now)

    def linked_actor_context(self, connection, principal_id: str) -> AuthorityContext:
        """Resolve a GitHub-linked actor through current OIDC identity state."""
        now = _now()
        link = connection.execute(sa.select(oidc_subject_links).where(
            oidc_subject_links.c.principal_id == principal_id,
            oidc_subject_links.c.enabled.is_(True)).order_by(
                oidc_subject_links.c.updated_at.desc()).limit(1)).mappings().first()
        principal = connection.execute(sa.select(auth_principals).where(
            auth_principals.c.principal_id == principal_id,
            auth_principals.c.enabled.is_(True))).mappings().first()
        sync = connection.execute(sa.select(oidc_sync_state).where(
            oidc_sync_state.c.provider_id == self.config["provider_id"])).mappings().first()
        if link is None or principal is None:
            raise HTTPException(403, {"code": "github_actor_unlinked", "message": "Current linked identity is unavailable"})
        if sync is None or (now - sync["heartbeat_at"]).total_seconds() > self.config["heartbeat_max_age_seconds"]:
            raise HTTPException(503, {"code": "identity_freshness_unavailable", "message": "Current identity state is unavailable"})
        memberships = connection.execute(sa.select(auth_group_memberships.c.group_id,
            auth_group_memberships.c.revision).where(auth_group_memberships.c.principal_id == principal_id,
                auth_group_memberships.c.enabled.is_(True))).all()
        group_roles, group_scopes = {}, {}
        ceiling = {_scope(item) for item in self.config["source_scope_ceilings"]}
        for group, _revision in memberships:
            configured = self.config["group_mappings"].get(group)
            if configured:
                group_roles[group] = tuple(sorted(set(configured["role_ids"])))
                group_scopes[group] = tuple(sorted({_scope(item) for item in configured["source_scopes"]
                    if _scope(item) in ceiling}))
        policy_revision = connection.execute(sa.select(assessment_policy.c.revision).where(
            assessment_policy.c.policy_id == 1)).scalar_one_or_none() or 0
        policy_document = connection.execute(sa.select(assessment_policy.c.document).where(
            assessment_policy.c.policy_id == 1)).scalar_one_or_none() or {}
        native = native_state(policy_document)
        if native.get("mode") == NATIVE_MODE:
            resolved = effective_access(policy_document, principal_id, now)
            groups, group_roles, group_scopes, group_revision = resolved
            return AuthorityContext(principal_id, "github_link", link["issuer"], link["subject"],
                link["link_id"], link["revision"], None, None, groups, group_revision,
                native.get("mapping_revision", 0), policy_revision,
                tuple(sorted({scope for _group, scopes in group_scopes for scope in scopes})),
                tuple(sorted({role for _group, roles in group_roles for role in roles})), now,
                group_roles, group_scopes)
        return AuthorityContext(principal_id, "github_link", link["issuer"], link["subject"],
            link["link_id"], link["revision"], None, None,
            tuple(sorted(group for group, _revision in memberships)),
            max((revision for _group, revision in memberships), default=sync["revision"]),
            self.config["mapping_revision"], policy_revision,
            tuple(sorted({scope for scopes in group_scopes.values() for scope in scopes})),
            tuple(sorted({role for roles in group_roles.values() for role in roles})), now,
            tuple(sorted(group_roles.items())), tuple(sorted(group_scopes.items())))

    def resolve_cookie(self, connection, raw_cookie: str | None, *, csrf_token: str | None = None,
                       require_fresh: bool = True) -> AuthorityContext:
        if not raw_cookie or len(raw_cookie) > 256:
            raise HTTPException(401, {"code": "authentication_required", "message": "Authentication required"})
        return self._resolve_session(connection, session_hash=_sha(raw_cookie), csrf_token=csrf_token,
            require_fresh=require_fresh)

    def resolve_session_id(self, connection, session_id: str, *, require_fresh: bool = True) -> AuthorityContext:
        """Resolve current authority for a durable session reference after a crash."""
        if not session_id:
            raise HTTPException(401, {"code": "session_invalid", "message": "Authentication required"})
        return self._resolve_session(connection, session_id=session_id, require_fresh=require_fresh)

    def _resolve_session(self, connection, *, session_hash=None, session_id=None, csrf_token=None,
                         require_fresh=True) -> AuthorityContext:
        if (session_hash is None) == (session_id is None):
            raise ValueError("resolve exactly one session identity")
        now = _now()
        row = connection.execute(sa.select(
            oidc_sessions.c.session_id, oidc_sessions.c.principal_id, oidc_sessions.c.link_id,
            oidc_sessions.c.link_revision.label("session_link_revision"),
            oidc_sessions.c.revision.label("session_revision"), oidc_sessions.c.csrf_hash,
            oidc_sessions.c.expires_at, oidc_sessions.c.revoked_at,
            oidc_subject_links.c.issuer, oidc_subject_links.c.subject,
            oidc_subject_links.c.revision.label("current_link_revision"),
            oidc_subject_links.c.enabled.label("link_enabled"),
            auth_principals.c.enabled.label("principal_enabled"))
            .select_from(oidc_sessions.join(oidc_subject_links,
                oidc_subject_links.c.link_id == oidc_sessions.c.link_id).join(auth_principals,
                auth_principals.c.principal_id == oidc_sessions.c.principal_id))
            .where(oidc_sessions.c.session_hash == session_hash if session_hash is not None
                else oidc_sessions.c.session_id == session_id)).mappings().first()
        if (row is None or row["revoked_at"] is not None or row["expires_at"] <= now
                or not row["link_enabled"] or not row["principal_enabled"] or row["session_revision"] < 1
                or not row["principal_id"]
                or not row["link_id"] or not row["issuer"] or not row["subject"]):
            raise HTTPException(401, {"code": "session_invalid", "message": "Authentication required"})
        if row["session_link_revision"] != row["current_link_revision"]:
            raise HTTPException(401, {"code": "session_invalid", "message": "Authentication required"})
        if csrf_token is not None and not (
                hmac.compare_digest(csrf_token.encode("utf-8"), row["csrf_hash"].encode("ascii"))
                or hmac.compare_digest(_sha(csrf_token), row["csrf_hash"])):
            raise HTTPException(403, {"code": "csrf_failed", "message": "Request verification failed"})
        sync = connection.execute(sa.select(oidc_sync_state).where(
            oidc_sync_state.c.provider_id == self.config["provider_id"])).mappings().first()
        if sync is None:
            raise HTTPException(503, {"code": "identity_freshness_unavailable", "message": "Current identity state is unavailable"})
        if require_fresh and (now - sync["heartbeat_at"]).total_seconds() > self.config["heartbeat_max_age_seconds"]:
            raise HTTPException(503, {"code": "identity_freshness_expired", "message": "Current identity state is unavailable"})
        policy_row = connection.execute(sa.select(assessment_policy.c.revision,
            assessment_policy.c.document).where(assessment_policy.c.policy_id == 1)).mappings().first()
        policy_revision = policy_row["revision"] if policy_row else 0
        policy_document = policy_row["document"] if policy_row else {}
        native = native_state(policy_document)
        if native.get("mode") == NATIVE_MODE:
            if policy_document.get("principals", {}).get(row["principal_id"], {}).get("enabled") is False:
                raise HTTPException(401, {"code": "session_invalid", "message": "Authentication required"})
            groups, group_roles, group_scopes, group_revision = effective_access(policy_document,
                row["principal_id"], now)
            return AuthorityContext(row["principal_id"], "oidc_session", row["issuer"], row["subject"],
                row["link_id"], row["current_link_revision"], row["session_id"], row["session_revision"],
                groups, group_revision, native.get("mapping_revision", 0), policy_revision,
                tuple(sorted({scope for _group, scopes in group_scopes for scope in scopes})),
                tuple(sorted({role for _group, roles in group_roles for role in roles})), now,
                group_roles, group_scopes)
        memberships = connection.execute(sa.select(auth_group_memberships.c.group_id,
            auth_group_memberships.c.revision).where(auth_group_memberships.c.principal_id == row["principal_id"],
            auth_group_memberships.c.enabled.is_(True))).all()
        groups = tuple(sorted(item.group_id for item in memberships))
        mapping = self.config["group_mappings"]
        role_ids: set[str] = set()
        sources: set[tuple[str, str, str]] = set()
        group_roles: dict[str, tuple[str, ...]] = {}
        group_scopes: dict[str, tuple[tuple[str, str, str], ...]] = {}
        ceilings = {_scope(item) for item in self.config["source_scope_ceilings"]}
        for group_id in groups:
            entry = mapping.get(group_id)
            if entry is None:
                continue
            mapped_scopes = tuple(sorted({_scope(item) for item in entry["source_scopes"]
                if _scope(item) in ceilings}))
            mapped_roles = tuple(sorted(set(entry["role_ids"])))
            group_scopes[group_id] = mapped_scopes
            group_roles[group_id] = mapped_roles
            role_ids.update(mapped_roles)
            sources.update(mapped_scopes)
        return AuthorityContext(row["principal_id"], "oidc_session", row["issuer"], row["subject"],
            row["link_id"], row["current_link_revision"], row["session_id"], row["session_revision"], groups,
            max((item.revision for item in memberships), default=sync["revision"]),
            self.config["mapping_revision"], policy_revision, tuple(sorted(sources)),
            tuple(sorted(role_ids)), now, tuple(sorted(group_roles.items())),
            tuple(sorted(group_scopes.items())))

    def resolve_request(self, request: Request) -> AuthorityContext:
        authorization = request.headers.get("authorization", "")
        if authorization.startswith("Bearer "):
            token = authorization[7:]
            if token.isascii() and len(token) <= 512:
                service = self._service_context(token)
                if service:
                    request.state.authority_context = service
                    AUTHORITY_CONTEXT.set(service)
                    return service
            raise HTTPException(401, {"code": "authentication_required", "message": "Authentication required"})
        raw_cookie = request.cookies.get(COOKIE_NAME)
        with self.engine.connect() as connection:
            context = self.resolve_cookie(connection, raw_cookie)
        request.state.authority_context = context
        request.state.raw_session_cookie = raw_cookie
        AUTHORITY_CONTEXT.set(context)
        return context

    def final_context(self, connection, request: Request) -> AuthorityContext:
        """Resolve again under the caller's final locked write transaction."""
        raw_cookie = getattr(request.state, "raw_session_cookie", None)
        if raw_cookie is None:
            prior = getattr(request.state, "authority_context", None)
            if prior is not None and prior.credential_mode == "service_bearer":
                policy_revision = connection.execute(sa.select(assessment_policy.c.revision).where(
                    assessment_policy.c.policy_id == 1)).scalar_one_or_none() or 0
                current = AuthorityContext(prior.principal_id, prior.credential_mode,
                    prior.issuer, prior.subject, prior.link_id, prior.link_revision,
                    prior.session_id, prior.session_revision, prior.access_groups,
                    prior.group_revision, self.config["mapping_revision"], policy_revision,
                    prior.source_scopes, prior.role_ids, _now(), prior.group_roles, prior.group_scopes)
                request.state.authority_context = current
                AUTHORITY_CONTEXT.set(current)
                return current
            if prior is not None and prior.credential_mode == "github_link":
                current = self.linked_actor_context(connection, prior.principal_id)
                request.state.authority_context = current
                AUTHORITY_CONTEXT.set(current)
                return current
            if prior is not None and prior.credential_mode == "oidc_session":
                current = self.resolve_session_id(connection, prior.session_id)
                if current.principal_id != prior.principal_id or current.link_id != prior.link_id:
                    raise HTTPException(401, {"code": "session_invalid", "message": "Authentication required"})
                request.state.authority_context = current
                AUTHORITY_CONTEXT.set(current)
                return current
            return prior
        current = self.resolve_cookie(connection, raw_cookie)
        request.state.authority_context = current
        AUTHORITY_CONTEXT.set(current)
        return current

    def final_context_after_snapshot_lock(self, connection, request: Request) -> AuthorityContext:
        """Resolve cookie authority from a fresh snapshot after a caller's policy lock.

        Long report materialisation uses REPEATABLE READ. Its snapshot can predate
        a provider sync that this transaction waited behind, so a second read on
        that same connection could still see removed memberships. The caller
        holds the shared policy row lock here; lock the session row as well, then
        resolve through a fresh connection before proceeding with the report.
        """
        raw_cookie = getattr(request.state, "raw_session_cookie", None)
        if raw_cookie is None:
            prior = getattr(request.state, "authority_context", None)
            if prior is None or prior.credential_mode != "oidc_session":
                return self.final_context(connection, request)
            session = connection.execute(sa.select(oidc_sessions.c.session_id).where(
                oidc_sessions.c.session_id == prior.session_id).with_for_update()).first()
            if session is None:
                raise HTTPException(401, {"code": "session_invalid", "message": "Authentication required"})
            with self.engine.connect() as fresh_connection:
                current = self.resolve_session_id(fresh_connection, prior.session_id)
            if current.principal_id != prior.principal_id or current.link_id != prior.link_id:
                raise HTTPException(401, {"code": "session_invalid", "message": "Authentication required"})
            request.state.authority_context = current
            AUTHORITY_CONTEXT.set(current)
            return current
        session = connection.execute(sa.select(oidc_sessions.c.session_id).where(
            oidc_sessions.c.session_hash == _sha(raw_cookie)).with_for_update()).first()
        if session is None:
            raise HTTPException(401, {"code": "session_invalid", "message": "Authentication required"})
        with self.engine.connect() as fresh_connection:
            current = self.resolve_cookie(fresh_connection, raw_cookie)
        request.state.authority_context = current
        AUTHORITY_CONTEXT.set(current)
        return current

    def current(self, request: Request | None = None) -> AuthorityContext | None:
        if request is not None:
            return getattr(request.state, "authority_context", None)
        return AUTHORITY_CONTEXT.get()

    def install_routes(self, app: FastAPI) -> None:
        config = self.config

        def browser_navigation(handler):
            @wraps(handler)
            async def wrapped(request: Request):
                try:
                    response = await handler(request)
                except (HTTPException, sa.exc.SQLAlchemyError) as exc:
                    if "text/html" not in request.headers.get("accept", ""):
                        raise
                    status_code = exc.status_code if isinstance(exc, HTTPException) else 503
                    status = ("forbidden" if status_code == 403 else
                              "unavailable" if status_code >= 500 else "invalid")
                    response = RedirectResponse("/auth/failure?status=" + status, status_code=303)
                    response.delete_cookie("uvm_oidc_browser", path="/api/v1/auth/callback")
                response.headers["Cache-Control"] = "no-store"
                response.headers["Referrer-Policy"] = "no-referrer"
                return response
            return wrapped

        @app.get("/api/v1/auth/login")
        @browser_navigation
        async def login(request: Request):
            metadata = await self._metadata()
            state, nonce = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
            verifier = secrets.token_urlsafe(64)
            browser_binding = secrets.token_urlsafe(32)
            oauth = AsyncOAuth2Client(config["client_id"], self.client_secret,
                redirect_uri=config["callback_url"], scope="openid", code_challenge_method="S256")
            url, _ = oauth.create_authorization_url(metadata["authorization_endpoint"],
                state=state, nonce=nonce, code_verifier=verifier)
            now = _now()
            with self.engine.begin() as connection:
                connection.execute(oidc_authorization_states.delete().where(
                    oidc_authorization_states.c.expires_at <= now))
                connection.execute(oidc_authorization_states.insert().values(
                    state_hash=_sha(state), nonce=nonce, code_verifier=verifier,
                    browser_binding_hash=_sha(browser_binding),
                    created_at=now, expires_at=now + timedelta(seconds=_STATE_TTL)))
            response = RedirectResponse(url, status_code=302)
            response.set_cookie("uvm_oidc_browser", browser_binding, max_age=_STATE_TTL,
                httponly=True, secure=config["callback_url"].startswith("https://"),
                samesite="lax", path="/api/v1/auth/callback")
            return response

        @app.get("/api/v1/auth/callback")
        @browser_navigation
        async def callback(request: Request):
            if request.query_params.get("error") or not request.query_params.get("code"):
                raise HTTPException(401, {"code": "oidc_exchange_failed", "message": "Identity provider exchange failed"})
            state = request.query_params.get("state", "")
            browser_binding = request.cookies.get("uvm_oidc_browser", "")
            if not state or len(state) > 256 or not browser_binding:
                raise HTTPException(401, {"code": "oidc_state_invalid", "message": "Authentication could not be completed"})
            now = _now()
            with self.engine.begin() as connection:
                stored = connection.execute(sa.select(oidc_authorization_states).where(
                    oidc_authorization_states.c.state_hash == _sha(state),
                    oidc_authorization_states.c.browser_binding_hash == _sha(browser_binding)
                    ).with_for_update()).mappings().first()
                if stored is None or stored["expires_at"] <= now:
                    raise HTTPException(401, {"code": "oidc_state_invalid", "message": "Authentication could not be completed"})
                connection.execute(oidc_authorization_states.delete().where(
                    oidc_authorization_states.c.state_hash == _sha(state)))
                expected_nonce, verifier = stored["nonce"], stored["code_verifier"]
            metadata = await self._metadata()
            oauth = AsyncOAuth2Client(config["client_id"], self.client_secret,
                redirect_uri=config["callback_url"], scope="openid", code_challenge_method="S256")
            try:
                token = await oauth.fetch_token(metadata["token_endpoint"],
                    authorization_response=str(request.url), state=state,
                    code_verifier=verifier, redirect_uri=config["callback_url"])
            except Exception as exc:
                raise HTTPException(401, {"code": "oidc_exchange_failed", "message": "Identity provider exchange failed"}) from exc
            finally:
                await oauth.aclose()
            claims = await self._validate_id_token(token.get("id_token"), metadata, expected_nonce,
                token.get("access_token"))
            with self.engine.begin() as connection:
                lock_policy(connection)
                connection.execute(sa.select(assessment_policy.c.policy_id).where(
                    assessment_policy.c.policy_id == 1).with_for_update())
                link = connection.execute(sa.select(
                    oidc_subject_links.c.link_id, oidc_subject_links.c.principal_id,
                    oidc_subject_links.c.revision.label("link_revision"),
                    oidc_subject_links.c.enabled.label("link_enabled"),
                    auth_principals.c.enabled.label("principal_enabled"))
                    .select_from(oidc_subject_links.join(auth_principals,
                        auth_principals.c.principal_id == oidc_subject_links.c.principal_id))
                    .where(oidc_subject_links.c.issuer == claims["iss"],
                           oidc_subject_links.c.subject == claims["sub"])).mappings().first()
                if link is None or not link["link_enabled"]:
                    raise HTTPException(403, {"code": "subject_unlinked", "message": "This identity is not linked"})
                if not link["principal_enabled"]:
                    raise HTTPException(403, {"code": "principal_disabled", "message": "Principal is disabled"})
                raw_session, csrf = secrets.token_urlsafe(48), secrets.token_urlsafe(32)
                session_id = str(uuid.uuid4())
                connection.execute(oidc_sessions.insert().values(
                    session_hash=_sha(raw_session), session_id=session_id,
                    principal_id=link["principal_id"], link_id=link["link_id"],
                    link_revision=link["link_revision"], revision=1, csrf_hash=_sha(csrf),
                    created_at=now, expires_at=now + timedelta(seconds=config["session_ttl_seconds"]),
                    revoked_at=None))
            response = (RedirectResponse("/", status_code=303)
                if "text/html" in request.headers.get("accept", "") else
                JSONResponse({"schema_version": 1, "authenticated": True,
                    "csrf_token": _sha(csrf), "principal_id": link["principal_id"]}))
            response.set_cookie(COOKIE_NAME, raw_session, httponly=True,
                secure=urlsplit(config["callback_url"]).scheme == "https",
                samesite="lax", path="/", max_age=config["session_ttl_seconds"])
            response.delete_cookie("uvm_oidc_browser", path="/api/v1/auth/callback")
            return response

        @app.get("/api/v1/auth/session")
        def session(request: Request):
            context = self.resolve_request(request)
            csrf_token = None
            raw = request.cookies.get(COOKIE_NAME)
            if raw:
                with self.engine.connect() as connection:
                    csrf_token = connection.execute(sa.select(oidc_sessions.c.csrf_hash).where(
                        oidc_sessions.c.session_hash == _sha(raw))).scalar_one()
            return JSONResponse({"schema_version": 1, "authenticated": True,
                "csrf_token": csrf_token, "principal_id": context.principal_id, "credential_mode": context.credential_mode,
                "access_groups": list(context.access_groups), "source_scopes": [list(x) for x in context.source_scopes],
                "authority": context.document()}, headers={"Cache-Control": "no-store"})

        @app.post("/api/v1/auth/logout")
        def logout(request: Request):
            raw = request.cookies.get(COOKIE_NAME)
            if raw:
                with self.engine.begin() as connection:
                    lock_policy(connection)
                    connection.execute(sa.select(assessment_policy.c.policy_id).where(
                        assessment_policy.c.policy_id == 1).with_for_update())
                    connection.execute(oidc_sessions.update().where(
                        oidc_sessions.c.session_hash == _sha(raw), oidc_sessions.c.revoked_at.is_(None))
                        .values(revoked_at=_now(), revision=oidc_sessions.c.revision + 1))
            response = JSONResponse({"schema_version": 1, "authenticated": False},
                headers={"Cache-Control": "no-store"})
            response.delete_cookie(COOKIE_NAME, path="/")
            return response

        @app.post("/api/v1/auth/operator/links")
        def operator_link(body: dict, authorization: str | None = Header(default=None)):
            self._check_secret(authorization, self.operator_secret)
            fields = {"issuer", "subject", "principal_id", "display_label", "rationale", "evidence_ref"}
            if (not isinstance(body, dict) or set(body) != fields
                    or body["issuer"] != config["issuer"]
                    or any(not isinstance(body[key], str) or not body[key].strip()
                        for key in fields - {"issuer"})):
                raise HTTPException(422, {"code": "invalid_link_request", "message": "Link request is invalid"})
            now = _now()
            with self.engine.begin() as connection:
                lock_policy(connection)
                connection.execute(sa.select(assessment_policy.c.policy_id).where(
                    assessment_policy.c.policy_id == 1).with_for_update())
                existing = connection.execute(sa.select(oidc_subject_links).where(
                    oidc_subject_links.c.issuer == body["issuer"],
                    oidc_subject_links.c.subject == body["subject"]).with_for_update()).mappings().first()
                if existing and (existing["principal_id"] != body["principal_id"] or existing["enabled"]):
                    raise HTTPException(409, {"code": "subject_link_conflict", "message": "Subject link already exists"})
                principal = connection.execute(sa.select(auth_principals).where(
                    auth_principals.c.principal_id == body["principal_id"]).with_for_update()).mappings().first()
                if principal is None:
                    connection.execute(auth_principals.insert().values(
                        principal_id=body["principal_id"], display_label=body["display_label"],
                        enabled=True, revision=1, created_at=now))
                elif not principal["enabled"]:
                    raise HTTPException(409, {"code": "principal_disabled", "message": "Principal is disabled"})
                groups = connection.execute(sa.select(oidc_subject_groups).where(
                    oidc_subject_groups.c.issuer == body["issuer"],
                    oidc_subject_groups.c.subject == body["subject"])).mappings().all()
                if existing:
                    link_id, revision = existing["link_id"], existing["revision"] + 1
                    connection.execute(oidc_subject_links.update().where(
                        oidc_subject_links.c.link_id == link_id).values(
                    revision=revision, enabled=True, actor_id=config["operator_actor_id"],
                            rationale=body["rationale"], evidence_ref=body["evidence_ref"], updated_at=now))
                else:
                    link_id, revision = str(uuid.uuid4()), 1
                    connection.execute(oidc_subject_links.insert().values(
                        link_id=link_id, issuer=body["issuer"], subject=body["subject"],
                        principal_id=body["principal_id"], revision=revision, enabled=True,
                    actor_id=config["operator_actor_id"], rationale=body["rationale"], evidence_ref=body["evidence_ref"],
                        created_at=now, updated_at=now))
                connection.execute(auth_group_memberships.delete().where(
                    auth_group_memberships.c.principal_id == body["principal_id"]))
                for item in groups:
                    connection.execute(auth_group_memberships.insert().values(
                        group_id=item["group_id"], principal_id=body["principal_id"], enabled=True,
                        revision=item["provider_revision"], updated_at=now,
                        provider_revision=item["provider_revision"]))
                seq = (connection.execute(sa.select(sa.func.max(auth_identity_events.c.event_sequence))).scalar_one_or_none() or 0) + 1
                connection.execute(auth_identity_events.insert().values(
                    event_id=str(uuid.uuid4()), event_sequence=seq, actor_id=config["operator_actor_id"],
                    action="linked", subject_link_id=link_id, revision=revision,
                    before_value=({"principal_id": existing["principal_id"],
                        "enabled": existing["enabled"], "revision": existing["revision"]}
                        if existing else {}),
                    after_value={"principal_id": body["principal_id"], "issuer": body["issuer"],
                        "subject_digest": _sha(body["subject"]), "enabled": True},
                    rationale=body["rationale"], evidence_ref=body["evidence_ref"], occurred_at=now))
            return {"schema_version": 1, "link_id": link_id, "link_revision": revision,
                "principal_id": body["principal_id"], "enabled": True}

        @app.post("/api/v1/auth/operator/links/{link_id}/revoke")
        def operator_revoke(link_id: str, body: dict,
                            authorization: str | None = Header(default=None)):
            self._check_secret(authorization, self.operator_secret)
            if (not isinstance(body, dict) or set(body) != {"expected_revision", "rationale", "evidence_ref"}
                    or type(body.get("expected_revision")) is not int
                    or any(not isinstance(body.get(key), str) or not body[key].strip()
                        for key in ("rationale", "evidence_ref"))):
                raise HTTPException(422, {"code": "invalid_link_request", "message": "Revocation request is invalid"})
            now = _now()
            with self.engine.begin() as connection:
                lock_policy(connection)
                connection.execute(sa.select(assessment_policy.c.policy_id).where(
                    assessment_policy.c.policy_id == 1).with_for_update())
                link = connection.execute(sa.select(oidc_subject_links).where(
                    oidc_subject_links.c.link_id == link_id).with_for_update()).mappings().first()
                if link is None:
                    raise HTTPException(404, {"code": "subject_link_not_found", "message": "Identity link was not found"})
                if link["revision"] != body["expected_revision"] or not link["enabled"]:
                    raise HTTPException(409, {"code": "revision_conflict", "message": "Identity link revision changed"})
                revision = link["revision"] + 1
                connection.execute(oidc_subject_links.update().where(
                    oidc_subject_links.c.link_id == link_id).values(
                        enabled=False, revision=revision, actor_id=config["operator_actor_id"],
                        rationale=body["rationale"], evidence_ref=body["evidence_ref"], updated_at=now))
                connection.execute(oidc_sessions.update().where(
                    oidc_sessions.c.link_id == link_id, oidc_sessions.c.revoked_at.is_(None)).values(
                        revoked_at=now, revision=oidc_sessions.c.revision + 1))
                seq = (connection.execute(sa.select(sa.func.max(auth_identity_events.c.event_sequence))).scalar_one_or_none() or 0) + 1
                connection.execute(auth_identity_events.insert().values(
                    event_id=str(uuid.uuid4()), event_sequence=seq,
                    actor_id=config["operator_actor_id"],
                    action="revoked", subject_link_id=link_id, revision=revision,
                    before_value={"enabled": True, "revision": link["revision"]},
                    after_value={"enabled": False, "revision": revision},
                    rationale=body["rationale"], evidence_ref=body["evidence_ref"], occurred_at=now))
            return {"schema_version": 1, "link_id": link_id, "link_revision": revision,
                "enabled": False, "sessions_revoked": True}

        def provider_sync(body: dict, authorization: str | None = Header(default=None)):
            self._check_secret(authorization, self.sync_secret)
            if (not isinstance(body, dict) or set(body) != {"schema_version", "provider_id", "revision", "heartbeat_at", "kind", "identities"}
                    or body["schema_version"] != 1 or body["provider_id"] != config["provider_id"]
                    or type(body["revision"]) is not int or body["revision"] < 1
                    or body["kind"] != "full_snapshot" or not isinstance(body["identities"], list)):
                raise HTTPException(422, {"code": "invalid_identity_sync", "message": "Identity snapshot is invalid"})
            parsed = []
            seen = set()
            for item in body["identities"]:
                if (not isinstance(item, dict) or set(item) != {"subject", "groups"}
                        or not isinstance(item["subject"], str) or not item["subject"]
                        or not isinstance(item["groups"], list)
                        or any(not isinstance(group, str) or not group for group in item["groups"])
                        or item["subject"] in seen):
                    raise HTTPException(422, {"code": "invalid_identity_sync", "message": "Identity snapshot is invalid"})
                seen.add(item["subject"])
                parsed.append({"subject": item["subject"], "groups": sorted(set(item["groups"]))})
            try:
                heartbeat_claim = datetime.fromisoformat(body["heartbeat_at"].replace("Z", "+00:00"))
            except (AttributeError, TypeError, ValueError):
                raise HTTPException(422, {"code": "invalid_identity_sync", "message": "Identity heartbeat is invalid"}) from None
            if heartbeat_claim.tzinfo is None:
                raise HTTPException(422, {"code": "invalid_identity_sync", "message": "Identity heartbeat is invalid"})
            if heartbeat_claim.astimezone(UTC) > _now():
                raise HTTPException(422, {"code": "invalid_identity_sync", "message": "Identity heartbeat is invalid"})
            digest = _json_digest(parsed)
            now = _now()
            heartbeat = heartbeat_claim.astimezone(UTC)
            with self.engine.begin() as connection:
                lock_policy(connection)
                connection.execute(sa.select(assessment_policy.c.policy_id).where(
                    assessment_policy.c.policy_id == 1).with_for_update())
                prior = connection.execute(sa.select(oidc_sync_state).where(
                    oidc_sync_state.c.provider_id == config["provider_id"]).with_for_update()).mappings().first()
                if prior and body["revision"] < prior["revision"]:
                    raise HTTPException(409, {"code": "identity_revision_stale", "message": "Identity revision is stale"})
                if prior and body["revision"] == prior["revision"] and digest != prior["snapshot_digest"]:
                    raise HTTPException(409, {"code": "identity_revision_conflict", "message": "Identity revision conflicts"})
                if prior and body["revision"] == prior["revision"]:
                    # A replay is idempotent and cannot refresh the heartbeat.
                    pass
                else:
                    prior_groups = connection.execute(sa.select(oidc_subject_groups).where(
                        oidc_subject_groups.c.issuer == config["issuer"])).mappings().all()
                    old_by_subject: dict[str, set[str]] = {}
                    for item in prior_groups:
                        old_by_subject.setdefault(item["subject"], set()).add(item["group_id"])
                    new_by_subject = {item["subject"]: set(item["groups"]) for item in parsed}
                    connection.execute(oidc_subject_groups.delete().where(
                        oidc_subject_groups.c.issuer == config["issuer"]))
                    for identity in parsed:
                        for group_id in identity["groups"]:
                            connection.execute(oidc_subject_groups.insert().values(
                                issuer=config["issuer"], subject=identity["subject"], group_id=group_id,
                                provider_revision=body["revision"], updated_at=now))
                    links = connection.execute(sa.select(oidc_subject_links).where(
                        oidc_subject_links.c.issuer == config["issuer"],
                        oidc_subject_links.c.enabled.is_(True))).mappings().all()
                    active_subjects = {item["subject"] for item in parsed}
                    for link in links:
                        if (link["subject"] not in active_subjects
                                or old_by_subject.get(link["subject"], set())
                                    != new_by_subject.get(link["subject"], set())):
                            connection.execute(oidc_sessions.update().where(
                                oidc_sessions.c.link_id == link["link_id"],
                                oidc_sessions.c.revoked_at.is_(None)).values(
                                    revoked_at=now, revision=oidc_sessions.c.revision + 1))
                    connection.execute(auth_group_memberships.delete())
                    for identity in parsed:
                        link = next((item for item in links if item["subject"] == identity["subject"]), None)
                        if link:
                            for group_id in identity["groups"]:
                                connection.execute(auth_group_memberships.insert().values(
                                    group_id=group_id, principal_id=link["principal_id"], enabled=True,
                                    revision=body["revision"], updated_at=now,
                                    provider_revision=body["revision"]))
                    statement = oidc_sync_state.insert().values(provider_id=config["provider_id"],
                        revision=body["revision"], heartbeat_at=heartbeat, snapshot_digest=digest)
                    if prior:
                        statement = oidc_sync_state.update().where(
                            oidc_sync_state.c.provider_id == config["provider_id"]).values(
                                revision=body["revision"], heartbeat_at=heartbeat, snapshot_digest=digest)
                    connection.execute(statement)
                    seq = (connection.execute(sa.select(sa.func.max(
                        auth_identity_events.c.event_sequence))).scalar_one_or_none() or 0) + 1
                    connection.execute(auth_identity_events.insert().values(
                        event_id=str(uuid.uuid4()), event_sequence=seq,
                        actor_id=config["provider_id"], action="provider_snapshot_applied",
                        subject_link_id=None, revision=body["revision"], before_value={
                            "provider_revision": prior["revision"] if prior else 0,
                            "snapshot_digest": prior["snapshot_digest"] if prior else None},
                        after_value={"provider_revision": body["revision"],
                            "snapshot_digest": digest, "identity_count": len(parsed)},
                        rationale="Authenticated complete synthetic provider identity snapshot",
                        evidence_ref=f"provider:{config['provider_id']}:revision:{body['revision']}",
                        occurred_at=now))
            return {"schema_version": 1, "provider_id": config["provider_id"],
                "revision": body["revision"], "snapshot_digest": digest, "committed": True}

        self._provider_sync = provider_sync

    def install_sync_route(self, app: FastAPI) -> None:
        @app.get("/healthz")
        def internal_health():
            return {"status": "ready", "boundary": "loopback-only-oidc-sync"}

        @app.post("/api/v1/auth/provider/sync")
        def provider_sync_internal(body: dict, authorization: str | None = Header(default=None)):
            return self._provider_sync(body, authorization)

    def _check_secret(self, authorization: str | None, secret: str) -> None:
        if not authorization or not authorization.startswith("Bearer ") or not hmac.compare_digest(
                authorization[7:], secret):
            raise HTTPException(401, {"code": "authentication_required", "message": "Authentication required"})

    async def _metadata(self) -> dict[str, Any]:
        # Discovery URL derives only from the configured issuer. All returned
        # endpoint origins are checked against trusted configuration.
        url = self.config["discovery_url"]
        try:
            async with AsyncClient(timeout=5, follow_redirects=False) as client:
                response = await client.get(url)
                response.raise_for_status()
                metadata = response.json()
        except Exception as exc:
            raise HTTPException(503, {"code": "oidc_discovery_unavailable", "message": "Identity provider is unavailable"}) from exc
        if metadata.get("issuer") != self.config["issuer"]:
            raise HTTPException(503, {"code": "oidc_discovery_invalid", "message": "Identity provider is unavailable"})
        try:
            for key in ("authorization_endpoint", "token_endpoint", "jwks_uri"):
                endpoint = metadata.get(key)
                if not isinstance(endpoint, str) or _url_origin(endpoint) not in self.config["_origins"]:
                    raise HTTPException(503, {"code": "oidc_discovery_invalid", "message": "Identity provider is unavailable"})
        except RuntimeError as exc:
            raise HTTPException(503, {"code": "oidc_discovery_invalid", "message": "Identity provider is unavailable"}) from exc
        return metadata

    async def _validate_id_token(self, value, metadata, nonce, access_token):
        if not isinstance(value, str) or len(value) > 16384:
            raise HTTPException(401, {"code": "oidc_token_invalid", "message": "Identity provider token is invalid"})
        try:
            async with AsyncClient(timeout=5, follow_redirects=False) as client:
                response = await client.get(metadata["jwks_uri"])
                response.raise_for_status()
                keys = KeySet.import_key_set(response.json())
            parsed = jwt.decode(value, keys, algorithms=self.config["allowed_algorithms"])
            claims = CodeIDToken(parsed.claims, parsed.header, params={
                "client_id": self.config["client_id"], "nonce": nonce,
                "access_token": access_token})
            claims.validate()
            JWTClaimsRegistry(iss={"essential": True, "value": self.config["issuer"]},
                aud={"essential": True, "values": [self.config["client_id"]]}).validate(dict(claims))
            aud = claims.get("aud")
            if isinstance(aud, list) and len(aud) > 1 and claims.get("azp") != self.config["client_id"]:
                raise ValueError("invalid authorized party")
            if not isinstance(claims.get("sub"), str) or not claims["sub"]:
                raise ValueError("invalid subject")
            return dict(claims)
        except Exception as exc:
            raise HTTPException(401, {"code": "oidc_token_invalid", "message": "Identity provider token is invalid"}) from exc

    def middleware(self, app: FastAPI) -> None:
        @app.middleware("http")
        async def oidc_middleware(request: Request, call_next):
            operator_route = request.url.path.startswith("/api/v1/auth/operator/")
            if not request.url.path.startswith("/api/v1/") or request.url.path in {
                    "/api/v1/auth/login", "/api/v1/auth/callback", "/api/v1/auth/provider/sync",
                    "/api/v1/auth/operator/links",
                    "/api/v1/assessment/exception-warning-callback"} or operator_route:
                response = await call_next(request)
                if request.url.path.startswith("/api/v1/auth/"):
                    response.headers["Cache-Control"] = "no-store"
                    response.headers["Referrer-Policy"] = "no-referrer"
                return response
            raw = request.cookies.get(COOKIE_NAME)
            if raw or request.headers.get("authorization", "").startswith("Bearer "):
                try:
                    csrf = request.headers.get("x-csrf-token")
                    write = request.method.upper() not in {"GET", "HEAD", "OPTIONS"}
                    if write and raw:
                        origin = request.headers.get("origin")
                        allowed = _url_origin(self.config["callback_url"])
                        if origin != allowed or not csrf:
                            return JSONResponse(status_code=403, content={"detail": {"code": "csrf_failed", "message": "Request verification failed"}}, headers={"Cache-Control": "no-store"})
                    if raw:
                        with self.engine.connect() as connection:
                            context = self.resolve_cookie(connection, raw, csrf_token=csrf if write else None)
                    else:
                        context = self.resolve_request(request)
                    request.state.authority_context = context
                    if raw:
                        request.state.raw_session_cookie = raw
                    AUTHORITY_CONTEXT.set(context)
                except HTTPException as exc:
                    return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail},
                        headers={"Cache-Control": "no-store"})
            response = await call_next(request)
            if request.url.path.startswith("/api/v1/auth/"):
                response.headers["Cache-Control"] = "no-store"
                response.headers["Referrer-Policy"] = "no-referrer"
            return response


def install_auth(app: FastAPI) -> OIDCAuth | None:
    if os.environ.get("UVM_AUTH_MODE") != "oidc":
        return None
    service = OIDCAuth(app.state.engine, app.state.principals)
    app.state.oidc_auth = service
    service.install_routes(app)
    service.middleware(app)
    return service
