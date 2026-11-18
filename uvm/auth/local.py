"""Persistent Argon2id local authentication for explicitly configured installs."""
from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import os
import re
import secrets
import stat
import threading
import time
import unicodedata
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlsplit
from typing import Any, Literal

import sqlalchemy as sa
from pydantic import BaseModel, ConfigDict
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from cryptography.exceptions import InvalidKey
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse, Response

from uvm.auth.native_authority import effective_access, native_state
from uvm.auth.schema import AUTHORITY_CONTEXT, AuthorityContext
from uvm.persistence.auth_schema import (auth_identity_events, auth_principals,
    local_accounts, local_auth_installation, local_capabilities, local_login_throttles,
    local_sessions)
from uvm.persistence.assessment_schema import (assessment_audit_events,
    assessment_command_receipts, assessment_policy)
from uvm.persistence.connector_schema import connectors
from uvm.assessment.policy_lock import lock_policy

UTC = timezone.utc
COOKIE_NAME = "uvm_session"
_USERNAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._@-]{0,63}$")
_ARGON2ID_PHC_V1 = re.compile(r"^\$argon2id\$v=19\$m=19456,t=2,p=1\$[A-Za-z0-9+/]{22}\$[A-Za-z0-9+/]{43}$")
_DUMMY_SALT = b"volt-local-dummy-salt"
_KDF_SLOTS = threading.BoundedSemaphore(4)
# Versioned local blocklist. Keep this set versioned with password policy so an
# operator can identify which admission rule applies to newly set passwords.
_COMMON_PASSWORDS_V1 = {"passwordpassword", "123456789012345", "qwertyuiopasdfg",
    "letmeinletmein", "iloveyouiloveyou", "welcome12345678", "adminadminadmin",
    "changemechangeme", "correcthorsebatterystaple", "password123456789",
    "qwerty123456789", "111111111111111", "abc123abc123abc", "monkeymonkey123"}


class LocalAuthConfigDTO(BaseModel):
    schema_version: Literal[1] = 1
    mode: Literal["local"]
    setup_state: Literal["required", "claimed", "unavailable"]


class LocalSessionDTO(BaseModel):
    schema_version: Literal[1] = 1
    authenticated: bool
    principal_id: str
    credential_mode: Literal["local_session"]
    csrf_token: str
    protected_admin: bool
    access_groups: list[str]
    source_scopes: list[list[str]]
    authority: dict[str, Any]
    receipt_id: str | None = None


class LocalConnectorSummaryDTO(BaseModel):
    connector_id: str
    lifecycle: str
    connector_revision: int
    configuration_revision: int
    source_revision: int
    environment_label: str
    source: dict[str, str]


class LocalDeploymentDTO(BaseModel):
    schema_version: Literal[1] = 1
    installation_id: str
    connector_registry_revision: int
    can_register_connector: bool
    connectors: list[LocalConnectorSummaryDTO]
    policy_revision: int
    authority_revision: int


def _json_request(properties: dict, required: list[str]) -> dict:
    return {"requestBody": {"required": True, "content": {"application/json": {
        "schema": {"type": "object", "properties": properties,
            "required": required, "additionalProperties": False}}}}}


_STRING = {"type": "string"}


def _now():
    return datetime.now(UTC)


def _sha(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _new_capability(purpose: str, installation_id: str, principal_id,
                    generation: int, credential_revision: int):
    locator = secrets.token_urlsafe(18)
    secret = secrets.token_urlsafe(32)
    material = "\0".join(("volt-local-capability-v1", purpose, installation_id,
        principal_id or "", str(generation), str(credential_revision), secret))
    return locator, secret, f"{locator}.{secret}", _sha(material)


def _capability_digest(token, capability):
    if not isinstance(token, str) or token.count(".") != 1:
        return None
    locator, secret = token.split(".", 1)
    if not locator or not secret or locator != capability["capability_locator"]:
        return None
    material = "\0".join(("volt-local-capability-v1", capability["purpose"],
        capability["installation_id"], capability["principal_id"] or "",
        str(capability["generation"]), str(capability["credential_revision"]), secret))
    return locator, _sha(material)


def _password_hash(password: str) -> str:
    password = unicodedata.normalize("NFC", password)
    with _KDF_SLOTS:
        return Argon2id(salt=secrets.token_bytes(16), length=32, iterations=2,
            lanes=1, memory_cost=19456).derive_phc_encoded(password.encode("utf-8"))


def _password_verify(verifier: str | None, password: str) -> bool:
    password = unicodedata.normalize("NFC", password)
    if not 15 <= len(password) <= 128:
        password = "x" * 32
        verifier = None
    try:
        with _KDF_SLOTS:
            if not isinstance(verifier, str) or not _ARGON2ID_PHC_V1.fullmatch(verifier):
                raise ValueError("unsupported verifier")
            Argon2id.verify_phc_encoded(password.encode("utf-8"), verifier)
            return True
    except InvalidKey:
        # A valid PHC mismatch has already performed one complete derivation.
        return False
    except (AttributeError, ValueError, TypeError):
        # Equalize the dominant KDF work for unknown usernames and malformed rows.
        with _KDF_SLOTS:
            Argon2id(salt=_DUMMY_SALT[:16], length=32, iterations=2,
                lanes=1, memory_cost=19456).derive(password.encode("utf-8", errors="ignore"))
        return False


def load_local_config() -> dict:
    path = os.environ.get("UVM_LOCAL_AUTH_CONFIG_FILE", "/etc/volt/local-auth.json")
    try:
        info = os.stat(path, follow_symlinks=False)
        if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600:
            raise RuntimeError("local authentication configuration must be a regular 0600 file")
        config = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise RuntimeError("local authentication configuration is unavailable or invalid") from exc
    keys = {"schema_version", "installation_id", "public_origin", "secret_source",
        "bootstrap_delivery", "session_policy", "trusted_ingress"}
    if not isinstance(config, dict) or set(config) != keys or config.get("schema_version") != 1:
        raise RuntimeError("local authentication configuration schema is invalid")
    try:
        config["installation_id"] = str(uuid.UUID(config["installation_id"]))
        origin = urlsplit(config["public_origin"])
        if (origin.scheme not in {"http", "https"} or not origin.hostname or not origin.netloc or origin.path not in ("", "/")
                or origin.query or origin.fragment):
            raise ValueError
        ingress = config["trusted_ingress"]
        if not isinstance(ingress, dict):
            raise ValueError
        loopback = origin.hostname in {"localhost", "127.0.0.1", "::1"}
        if ingress.get("mode") == "loopback" and not (origin.scheme == "http" and loopback):
            raise ValueError
        if ingress.get("mode") == "https" and origin.scheme != "https":
            raise ValueError
        if (not isinstance(config["secret_source"], dict) or set(config["secret_source"]) !=
                {"kind", "secret_source_id", "key_path"} or config["secret_source"]["kind"] != "encrypted_local_v1"):
            raise ValueError
        config["secret_source"]["secret_source_id"] = str(uuid.UUID(config["secret_source"]["secret_source_id"]))
        key_path = config["secret_source"]["key_path"]
        fd = os.open(key_path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            key_info = os.fstat(fd)
            if not stat.S_ISREG(key_info.st_mode) or stat.S_IMODE(key_info.st_mode) != 0o600 or len(os.read(fd, 33)) != 32:
                raise ValueError
        finally:
            os.close(fd)
        os.environ.setdefault("UVM_CONNECTOR_LOCAL_KEY_ID", config["secret_source"]["secret_source_id"])
        os.environ.setdefault("UVM_CONNECTOR_LOCAL_KEY_FILE", key_path)
        delivery = config["bootstrap_delivery"]
        if not isinstance(delivery, dict) or set(delivery) != {"kind", "path"} or delivery["kind"] != "private_file":
            raise ValueError
        if not isinstance(config["session_policy"], dict) or set(config["session_policy"]) != {"ttl_seconds"}:
            raise ValueError
        ttl = config["session_policy"]["ttl_seconds"]
        if type(ttl) is not int or ttl != 3600:
            raise ValueError
        ingress = config["trusted_ingress"]
        if (set(ingress) != {"mode", "allowed_hosts", "allowed_peer_cidrs"}
                or ingress["mode"] not in {"loopback", "https"} or not isinstance(ingress["allowed_hosts"], list)
                or not ingress["allowed_hosts"] or any(not isinstance(host, str) or not host for host in ingress["allowed_hosts"])
                or not isinstance(ingress["allowed_peer_cidrs"], list) or not ingress["allowed_peer_cidrs"]
                or any(not isinstance(cidr, str) or not cidr for cidr in ingress["allowed_peer_cidrs"])):
            raise ValueError
        if origin.hostname not in {host.lower().split(":", 1)[0] for host in ingress["allowed_hosts"]}:
            raise ValueError
        # Preserve the existing socket-peer plus exact-Host ingress guard; do
        # not derive peer trust from Origin, Host, or forwarded headers.
        os.environ.setdefault("UVM_INGRESS_ALLOWED_PEER_CIDRS", ",".join(ingress["allowed_peer_cidrs"]))
        os.environ.setdefault("UVM_INGRESS_ALLOWED_HOSTS", ",".join(ingress["allowed_hosts"]))
    except (ValueError, TypeError, KeyError, OSError):
        raise RuntimeError("local authentication configuration schema is invalid") from None
    return config


class LocalAuth:
    """Shared auth interface used by assessment/read APIs and browser middleware."""
    def __init__(self, engine, config):
        self.engine, self.config = engine, config
        self.mapping_revision = 1
        now = _now()
        with engine.begin() as c:
            mode = os.environ.get("UVM_AUTH_MODE", "")
            existing = c.execute(sa.select(local_auth_installation).where(
                local_auth_installation.c.singleton_id == 1).with_for_update()).mappings().first()
            if existing and existing["installation_id"] != config["installation_id"]:
                raise RuntimeError("configured installation ID does not match persisted local identity")
            links = c.execute(sa.select(sa.func.count()).select_from(
                __import__("uvm.persistence.auth_schema", fromlist=["oidc_subject_links"]).oidc_subject_links)).scalar_one()
            if existing is None:
                established = (links or c.execute(sa.select(sa.func.count()).select_from(auth_principals)).scalar_one()
                    or c.execute(sa.select(sa.func.count()).select_from(assessment_policy)).scalar_one()
                    or c.execute(sa.select(sa.func.count()).select_from(connectors)).scalar_one())
                if established:
                    raise RuntimeError("cannot switch an established identity database to local authentication")
                c.execute(local_auth_installation.insert().values(singleton_id=1,
                    installation_id=config["installation_id"], setup_generation=1, claimed_at=None, created_at=now))
            if mode != "local":
                raise RuntimeError("local authentication requires UVM_AUTH_MODE=local")

    def _context(self, c, session_hash=None, session_id=None, csrf_token=None):
        if (session_hash is None) == (session_id is None):
            raise ValueError("resolve exactly one session identity")
        row = c.execute(sa.select(local_sessions, local_accounts.c.credential_revision.label("account_revision"),
            local_accounts.c.status, auth_principals.c.enabled.label("principal_enabled"))
            .select_from(local_sessions.join(local_accounts, local_accounts.c.principal_id == local_sessions.c.principal_id)
                .join(auth_principals, auth_principals.c.principal_id == local_accounts.c.principal_id))
            .where(local_sessions.c.session_hash == session_hash if session_hash else local_sessions.c.session_id == session_id)).mappings().first()
        now = _now()
        if (row is None or row["revoked_at"] is not None or row["expires_at"] <= now or row["status"] != "enabled"
                or not row["principal_enabled"] or row["credential_revision"] != row["account_revision"]):
            raise HTTPException(401, {"code": "authentication_required", "message": "Authentication required"})
        if csrf_token is not None:
            supplied = csrf_token.encode("utf-8")
            # The browser contract returns the stored SHA-256 digest. Never
            # accept the raw CSRF secret as a second representation.
            if not hmac.compare_digest(supplied, row["csrf_hash"].encode("ascii")):
                raise HTTPException(403, {"code": "csrf_failed", "message": "Request verification failed"})
        policy = c.execute(sa.select(assessment_policy.c.revision, assessment_policy.c.document).where(
            assessment_policy.c.policy_id == 1)).mappings().first()
        document = policy["document"] if policy else {}
        state = native_state(document)
        groups, group_roles, group_scopes, group_revision = effective_access(document, row["principal_id"], now) or ((), (), (), 0)
        roles = tuple(sorted({role for _, values in group_roles for role in values}))
        scopes = tuple(sorted({scope for _, values in group_scopes for scope in values}))
        return AuthorityContext(row["principal_id"], "local_session", None, None, None,
            None, row["session_id"], row["revision"], tuple(groups), int(group_revision), 1,
            int(policy["revision"] if policy else 0), scopes, roles, now, tuple(group_roles), tuple(group_scopes))

    def resolve_cookie(self, c, raw, *, csrf_token=None, require_fresh=True):
        if not raw or len(raw) > 256:
            raise HTTPException(401, {"code": "authentication_required", "message": "Authentication required"})
        return self._context(c, session_hash=_sha(raw), csrf_token=csrf_token)

    def resolve_session_id(self, c, session_id, *, require_fresh=True):
        return self._context(c, session_id=session_id)

    def resolve_request(self, request):
        if request.headers.get("authorization"):
            raise HTTPException(401, {"code": "authentication_required", "message": "Authentication required"})
        raw = request.cookies.get(COOKIE_NAME)
        with self.engine.connect() as c:
            context = self.resolve_cookie(c, raw)
        request.state.authority_context = context
        request.state.raw_session_cookie = raw
        AUTHORITY_CONTEXT.set(context)
        return context

    def final_context(self, c, request):
        raw = getattr(request.state, "raw_session_cookie", None)
        prior = getattr(request.state, "authority_context", None)
        current = self.resolve_cookie(c, raw) if raw else self.resolve_session_id(c, prior.session_id)
        request.state.authority_context = current
        AUTHORITY_CONTEXT.set(current)
        return current

    def current(self, request=None):
        return getattr(request.state, "authority_context", None) if request is not None else AUTHORITY_CONTEXT.get()

    def _session_response(self, request, raw, csrf, principal_id, status_code=200, receipt_id=None):
        with self.engine.connect() as c:
            policy = c.execute(sa.select(assessment_policy.c.document).where(assessment_policy.c.policy_id == 1)).scalar_one_or_none() or {}
            protected_admin = principal_id in set(native_state(policy).get("bootstrap_admins", []))
        value = {"schema_version": 1, "authenticated": True, "csrf_token": _sha(csrf),
            "principal_id": principal_id, "credential_mode": "local_session", "access_groups": [],
            "source_scopes": [], "protected_admin": protected_admin,
            "authority": {"principal_id": principal_id, "credential_mode": "local_session",
                "protected_admin": protected_admin}}
        if receipt_id is not None: value["receipt_id"] = receipt_id
        response = JSONResponse(value, status_code=status_code, headers={"Cache-Control": "no-store"})
        response.set_cookie(COOKIE_NAME, raw, httponly=True,
            secure=self.config["public_origin"].startswith("https://"), samesite="lax", path="/",
            max_age=self.config["session_policy"]["ttl_seconds"])
        return response

    def _session(self, c, principal_id, now):
        raw, csrf, sid = secrets.token_urlsafe(48), secrets.token_urlsafe(32), str(uuid.uuid4())
        account = c.execute(sa.select(local_accounts.c.credential_revision).where(
            local_accounts.c.principal_id == principal_id)).scalar_one()
        c.execute(local_sessions.insert().values(session_hash=_sha(raw), session_id=sid,
            principal_id=principal_id, credential_revision=account, revision=1, csrf_hash=_sha(csrf),
            created_at=now, expires_at=now + timedelta(seconds=self.config["session_policy"]["ttl_seconds"]), revoked_at=None))
        return raw, csrf

    def install_routes(self, app: FastAPI):
        @app.get("/api/v1/auth/config", response_model=LocalAuthConfigDTO)
        def auth_config():
            try:
                with self.engine.connect() as c:
                    row = c.execute(sa.select(local_auth_installation).where(local_auth_installation.c.singleton_id == 1)).mappings().one()
                state = "claimed" if row["claimed_at"] else "required"
            except sa.exc.SQLAlchemyError:
                state = "unavailable"
            return {"schema_version": 1, "mode": "local", "setup_state": state}

        @app.post("/api/v1/auth/local/login", response_model=LocalSessionDTO,
            openapi_extra=_json_request({"username": _STRING, "password": _STRING},
                ["username", "password"]))
        def login(body: dict, request: Request):
            self._origin_check(request)
            if not isinstance(body, dict) or set(body) != {"username", "password"} or not all(isinstance(body.get(k), str) for k in ("username", "password")):
                raise HTTPException(422, {"code": "invalid_credentials", "message": "Sign-in request is invalid"})
            username = body["username"]
            username_key = username[:64].casefold()
            peer = request.client.host if request.client else "unknown"
            buckets = {"user": _sha("user\0" + username_key), "peer": _sha("peer\0" + peer)}
            now = _now()
            denied = False
            retry = 0
            with self.engine.begin() as c:
                lock_policy(c)
                from sqlalchemy.dialects.postgresql import insert as pg_insert
                for bucket in sorted(buckets.values()):
                    c.execute(pg_insert(local_login_throttles).values(bucket_hash=bucket,
                        window_started_at=now, attempts=0, blocked_until=None, failure_times=[]).on_conflict_do_nothing())
                rows = c.execute(sa.select(local_login_throttles).where(
                    local_login_throttles.c.bucket_hash.in_(list(buckets.values()))).order_by(
                    local_login_throttles.c.bucket_hash).with_for_update()).mappings().all()
                by_hash = {row["bucket_hash"]: row for row in rows}
                # Individual failures expire independently in a rolling window.
                now = _now()
                cutoff = (now - timedelta(minutes=15)).timestamp()
                failures = {bucket: [stamp for stamp in row["failure_times"] if stamp > cutoff]
                    for bucket, row in by_hash.items()}
                import math
                for kind, bucket in buckets.items():
                    limit = 5 if kind == "user" else 30
                    if len(failures[bucket]) >= limit:
                        retry = max(retry, max(1, math.ceil(
                            failures[bucket][-limit] + 900 - now.timestamp())))
                if retry:
                    # Reject before account lookup or entering the KDF budget.
                    denied = True
                else:
                    account = c.execute(sa.select(local_accounts).where(
                        local_accounts.c.username_normalized == username.casefold())
                        .with_for_update()).mappings().first()
                    valid = _password_verify(account["verifier"] if account else None, body["password"])
                    if not account or account["status"] != "enabled" or not valid:
                        denied = True
                        for kind, bucket in buckets.items():
                            times = failures[bucket] + [now.timestamp()]
                            limit = 5 if kind == "user" else 30
                            until = datetime.fromtimestamp(times[-limit] + 900, UTC) if len(times) >= limit else None
                            c.execute(local_login_throttles.update().where(
                                local_login_throttles.c.bucket_hash == bucket).values(
                                    failure_times=times, window_started_at=datetime.fromtimestamp(times[0], UTC),
                                    attempts=len(times), blocked_until=until))
                            if until:
                                retry = max(retry, max(1, math.ceil((until - now).total_seconds())))
                    else:
                        # Success cannot erase failures inside either rolling window.
                        raw, csrf = self._session(c, account["principal_id"], now)
            if denied and retry:
                raise HTTPException(429, {"code": "authentication_throttled", "message": "Sign-in is temporarily unavailable"}, headers={"Retry-After": str(retry)})
            if denied:
                raise HTTPException(401, {"code": "authentication_required", "message": "Authentication required"})
            return self._session_response(request, raw, csrf, account["principal_id"])

        @app.post("/api/v1/auth/setup/claim", response_model=LocalSessionDTO,
            openapi_extra=_json_request({"capability": _STRING, "username": _STRING,
                "display_name": _STRING, "password": _STRING},
                ["capability", "username", "display_name", "password"]))
        def claim(body: dict, request: Request):
            self._origin_check(request)
            if not isinstance(body, dict) or set(body) != {"capability", "username", "display_name", "password"}:
                raise HTTPException(422, {"code": "invalid_setup", "message": "Setup request is invalid"})
            self._validate_account(body["username"], body["display_name"], body["password"])
            now = _now(); raw_session = csrf = principal_id = None
            receipt_id = str(uuid.uuid4())
            with self.engine.begin() as c:
                lock_policy(c)
                c.execute(sa.select(local_auth_installation.c.singleton_id).where(local_auth_installation.c.singleton_id == 1).with_for_update())
                install = c.execute(sa.select(local_auth_installation).where(local_auth_installation.c.singleton_id == 1)).mappings().one()
                token_locator = body["capability"].split(".", 1)[0] if isinstance(body.get("capability"), str) and "." in body["capability"] else ""
                cap = c.execute(sa.select(local_capabilities).where(local_capabilities.c.capability_locator == token_locator).with_for_update()).mappings().first()
                presented = _capability_digest(body.get("capability"), cap) if cap else None
                if (not cap or cap["purpose"] != "setup" or cap["principal_id"] is not None or cap["installation_id"] != install["installation_id"]
                        or cap["generation"] != install["setup_generation"] or not presented or not hmac.compare_digest(presented[1], cap["capability_hash"])
                        or cap["expires_at"] <= now or cap["consumed_at"] is not None or install["claimed_at"] is not None):
                    raise HTTPException(401, {"code": "authentication_required", "message": "Authentication required"})
                principal_id = str(uuid.uuid4())
                c.execute(auth_principals.insert().values(principal_id=principal_id, display_label=body["display_name"].strip(), enabled=True, revision=1, created_at=now))
                username = body["username"]
                c.execute(local_accounts.insert().values(principal_id=principal_id, username=username, username_normalized=username.casefold(), verifier=_password_hash(body["password"]), credential_revision=1, capability_generation=1, status="enabled", created_at=now, updated_at=now))
                c.execute(local_capabilities.update().where(local_capabilities.c.capability_hash == cap["capability_hash"]).values(consumed_at=now))
                c.execute(local_auth_installation.update().where(local_auth_installation.c.singleton_id == 1).values(claimed_at=now))
                policy = c.execute(sa.select(assessment_policy).where(assessment_policy.c.policy_id == 1).with_for_update()).mappings().first()
                if policy is None:
                    access_group_id = str(uuid.uuid4())
                    deployment_scope = {"kind": "deployment", "deployment_ids": [install["installation_id"]]}
                    empty_limits = {"maximum_acceptance_days": None, "maximum_severity": None,
                        "whole_group_confirmation": False, "allowed_environments": [],
                        "allowed_service_ids": [], "allowed_sla_clock_bases": [],
                        "allowed_sla_severities": [], "allowed_sla_start_sources": [],
                        "maximum_sla_duration_seconds": None, "allow_sla_backfill": False,
                        "maximum_deadline_extension_seconds": None, "allowed_identity_scalar_fields": {}}
                    duties = {"approval_requires_distinct_actor": True, "prohibit_requester_approval": True,
                        "required_approver_count": 1, "prohibited_action_pairs": []}
                    permissions = [{"permission_id": str(uuid.uuid4()), "role_id": str(uuid.uuid4()),
                        "action": action, "target_scope": deployment_scope, "limits": empty_limits,
                        "separation_of_duties": duties}
                        for action in ("policy.read", "access_group.read", "ownership.team.read")]
                    now_z = now.isoformat().replace("+00:00", "Z")
                    document = {"roles": {}, "grants": [], "principals": {principal_id: {"enabled": True}},
                        "native_authority": {"mode": "uvm_native_v2", "revision": 1, "ownership_revision": 1, "mapping_revision": 1,
                        "bootstrap_admins": [principal_id], "grantable_envelope": {"version": 2,
                        "actions": ["policy.read", "access_group.read", "ownership.team.read", "ownership.team.manage", "connector.read", "connector.configure", "connector.secret.manage", "assessment.read", "audit.read"],
                        "target_scope": {"kind": "deployment", "deployment_ids": [install["installation_id"]]},
                        "connector_ids": [], "connector_sources": [], "source_scopes": [],
                        "source_read_targets": [], "limits": empty_limits,
                        "separation_of_duties": {"approval_requires_distinct_actor": True, "prohibit_requester_approval": True, "required_approver_count": 1, "prohibited_action_pairs": []}},
                        "access_groups": {access_group_id: {"access_group_id": access_group_id,
                            "display_name": "Initial local administration", "description": "",
                            "enabled": True, "revision": 1, "source_scopes": [],
                            "permissions": permissions, "memberships": [{"principal_id": principal_id,
                                "effective_from": now_z, "effective_until": None, "enabled": True,
                                "revision": 1, "recorded_at": now_z, "recorded_by": principal_id}],
                            "created_at": now_z, "updated_at": now_z}},
                        "ownership_teams": {}, "revocations": []}}
                    c.execute(assessment_policy.insert().values(policy_id=1, revision=1, document=document, updated_at=now, updated_by=principal_id))
                else:
                    raise HTTPException(409, {"code": "setup_unavailable", "message": "Initial setup is unavailable"})
                self._audit(c, principal_id, "local.setup.claimed", principal_id, now,
                    command_id=receipt_id, intent_kind="administration.authority.reconcile",
                    intent_target=install["installation_id"], authority_revision=1,
                    before_value={"setup_state": "required", "claimed_at": None},
                    after_value={"setup_state": "claimed", "claimed_at": now.isoformat()})
                raw_session, csrf = self._session(c, principal_id, now)
            return self._session_response(request, raw_session, csrf, principal_id, 201, receipt_id)

        @app.get("/api/v1/auth/session", response_model=LocalSessionDTO)
        def session(request: Request):
            context = self.resolve_request(request)
            raw = request.cookies[COOKIE_NAME]
            with self.engine.connect() as c:
                csrf = c.execute(sa.select(local_sessions.c.csrf_hash).where(local_sessions.c.session_hash == _sha(raw))).scalar_one()
            return JSONResponse({"schema_version": 1, "authenticated": True, "csrf_token": csrf,
                "principal_id": context.principal_id, "credential_mode": "local_session",
                "protected_admin": self._is_bootstrap_admin(context.principal_id),
                "access_groups": list(context.access_groups), "source_scopes": [list(x) for x in context.source_scopes],
                "authority": context.document()}, headers={"Cache-Control": "no-store"})

        @app.get("/api/v1/deployment", response_model=LocalDeploymentDTO)
        def deployment(request: Request):
            context = self.resolve_request(request)
            admin = self._is_bootstrap_admin(context.principal_id)
            if not admin:
                raise HTTPException(403, {"code": "forbidden", "message": "Protected administrator access required"})
            try:
                with self.engine.connect() as c:
                    policy = c.execute(sa.select(assessment_policy.c.revision, assessment_policy.c.document).where(assessment_policy.c.policy_id == 1)).mappings().one()
                    rows = c.execute(sa.select(connectors)).mappings().all()
                    connectors_value = [{"connector_id": r["connector_id"], "lifecycle": r["lifecycle"],
                        "connector_revision": r["connector_revision"],
                        "configuration_revision": r["configuration_revision"],
                        "source_revision": r["source_revision"], "environment_label": r["environment_label"],
                        "source": {"source_id": r["source_id"], "source_family": r["source_family"],
                            "source_account_id": r["source_account_id"], "scope_key": r["scope_key"]}}
                        for r in rows]
            except sa.exc.SQLAlchemyError:
                raise HTTPException(503, {"code": "persistence_unavailable", "message": "Deployment state is unavailable"}) from None
            state = native_state(policy["document"])
            return {"schema_version": 1, "installation_id": self.config["installation_id"],
                "connector_registry_revision": int(policy["document"].get("connector_registry_revision", 0)),
                "can_register_connector": admin, "connectors": connectors_value,
                "policy_revision": policy["revision"], "authority_revision": int(state.get("revision", 0))}

        @app.post("/api/v1/auth/logout")
        def logout(request: Request):
            raw = request.cookies.get(COOKIE_NAME)
            if raw:
                with self.engine.begin() as c:
                    lock_policy(c)
                    c.execute(local_sessions.update().where(local_sessions.c.session_hash == _sha(raw), local_sessions.c.revoked_at.is_(None)).values(revoked_at=_now(), revision=local_sessions.c.revision + 1))
            response = JSONResponse({"schema_version": 1, "authenticated": False}, headers={"Cache-Control": "no-store"})
            response.delete_cookie(COOKIE_NAME, path="/")
            return response

        @app.post("/api/v1/auth/local/password", openapi_extra=_json_request(
            {"current_password": _STRING, "new_password": _STRING},
            ["current_password", "new_password"]))
        def change_password(body: dict, request: Request):
            context = self.resolve_request(request); self._origin_check(request, require_csrf=True)
            if not isinstance(body, dict) or set(body) != {"current_password", "new_password"}:
                raise HTTPException(422, {"code": "invalid_password", "message": "Password request is invalid"})
            self._validate_password(body["new_password"])
            now = _now(); raw = request.cookies[COOKIE_NAME]
            with self.engine.begin() as c:
                lock_policy(c)
                current = self.resolve_cookie(c, raw, csrf_token=request.headers.get("x-csrf-token"))
                if current.principal_id != context.principal_id or current.session_id != context.session_id:
                    raise HTTPException(401, {"code": "authentication_required", "message": "Authentication required"})
                account = c.execute(sa.select(local_accounts).where(local_accounts.c.principal_id == context.principal_id).with_for_update()).mappings().one()
                if not _password_verify(account["verifier"], body["current_password"]):
                    raise HTTPException(401, {"code": "authentication_required", "message": "Authentication required"})
                c.execute(local_accounts.update().where(local_accounts.c.principal_id == context.principal_id).values(verifier=_password_hash(body["new_password"]), credential_revision=account["credential_revision"] + 1, updated_at=now))
                c.execute(local_sessions.update().where(local_sessions.c.principal_id == context.principal_id, local_sessions.c.revoked_at.is_(None)).values(revoked_at=now, revision=local_sessions.c.revision + 1))
                self._audit(c, context.principal_id, "local.password.changed", context.principal_id, now)
            response = Response(status_code=204); response.delete_cookie(COOKIE_NAME, path="/"); return response

        def capability_complete(body, request, purpose):
            self._origin_check(request)
            fields = {"capability", "new_password"}
            if not isinstance(body, dict) or set(body) != fields or not isinstance(body["capability"], str):
                raise HTTPException(422, {"code": "invalid_capability", "message": "Capability request is invalid"})
            self._validate_password(body["new_password"]); now = _now()
            with self.engine.begin() as c:
                lock_policy(c)
                token_locator = body["capability"].split(".", 1)[0] if "." in body["capability"] else ""
                cap = c.execute(sa.select(local_capabilities).where(local_capabilities.c.capability_locator == token_locator).with_for_update()).mappings().first()
                presented = _capability_digest(body["capability"], cap) if cap else None
                install = c.execute(sa.select(local_auth_installation).where(local_auth_installation.c.singleton_id == 1).with_for_update()).mappings().one()
                if (not cap or cap["purpose"] != purpose or cap["installation_id"] != install["installation_id"] or not presented or not hmac.compare_digest(presented[1], cap["capability_hash"]) or cap["expires_at"] <= now or cap["consumed_at"] is not None):
                    raise HTTPException(401, {"code": "authentication_required", "message": "Authentication required"})
                account = c.execute(sa.select(local_accounts).where(local_accounts.c.principal_id == cap["principal_id"]).with_for_update()).mappings().first() if cap["principal_id"] else None
                if (not account or account["credential_revision"] != cap["credential_revision"] or account["capability_generation"] != cap["generation"] or (purpose == "recovery" and account["status"] != "enabled") or (purpose == "enrolment" and account["status"] != "pending")):
                    raise HTTPException(401, {"code": "authentication_required", "message": "Authentication required"})
                c.execute(local_accounts.update().where(local_accounts.c.principal_id == account["principal_id"]).values(verifier=_password_hash(body["new_password"]), credential_revision=account["credential_revision"] + 1, status="enabled", updated_at=now))
                c.execute(local_capabilities.update().where(local_capabilities.c.capability_hash == cap["capability_hash"]).values(consumed_at=now))
                c.execute(local_sessions.update().where(local_sessions.c.principal_id == account["principal_id"], local_sessions.c.revoked_at.is_(None)).values(revoked_at=now, revision=local_sessions.c.revision + 1))
                self._audit(c, "host-maintenance", f"local.{purpose}.completed", account["principal_id"], now)
            return Response(status_code=204)

        @app.post("/api/v1/auth/local/recovery", openapi_extra=_json_request(
            {"capability": _STRING, "new_password": _STRING}, ["capability", "new_password"]))
        def recovery(body: dict, request: Request): return capability_complete(body, request, "recovery")
        @app.post("/api/v1/auth/local/enrol", openapi_extra=_json_request(
            {"capability": _STRING, "new_password": _STRING}, ["capability", "new_password"]))
        def enrol(body: dict, request: Request): return capability_complete(body, request, "enrolment")

    def _origin_check(self, request, *, require_csrf=False):
        if request.headers.get("origin") != self.config["public_origin"]:
            raise HTTPException(403, {"code": "origin_forbidden", "message": "Request origin is not allowed"})
        if require_csrf and request.cookies.get(COOKIE_NAME):
            csrf = request.headers.get("x-csrf-token")
            if not csrf:
                raise HTTPException(403, {"code": "csrf_failed", "message": "Request verification failed"})
            with self.engine.connect() as c:
                current = self.resolve_cookie(c, request.cookies[COOKIE_NAME], csrf_token=csrf)

    def _is_bootstrap_admin(self, principal_id):
        with self.engine.connect() as c:
            document = c.execute(sa.select(assessment_policy.c.document).where(assessment_policy.c.policy_id == 1)).scalar_one_or_none() or {}
        return principal_id in set(native_state(document).get("bootstrap_admins", []))

    @staticmethod
    def _validate_password(value):
        normalized = unicodedata.normalize("NFC", value) if isinstance(value, str) else ""
        if len(normalized) < 15 or len(normalized) > 128 or normalized.casefold() in _COMMON_PASSWORDS_V1:
            raise HTTPException(422, {"code": "invalid_password", "message": "Password must contain 15 to 128 characters and not be commonly used"})

    def _validate_account(self, username, display_name, password):
        if not isinstance(username, str) or not _USERNAME.fullmatch(username) or not isinstance(display_name, str) or not display_name.strip() or len(display_name.strip()) > 120:
            raise HTTPException(422, {"code": "invalid_account", "message": "Account details are invalid"})
        self._validate_password(password)

    @staticmethod
    def _audit(c, actor, action, target, now, *, command_id=None, intent_kind=None,
               intent_target=None, authority_revision=0, before_value=None, after_value=None):
        from uvm.persistence.assessment_schema import assessment_command_receipts
        from uvm.persistence.native_authority_schema import administration_reconciliation_intents
        event = str(uuid.uuid4()); command = command_id or str(uuid.uuid4())
        seq = (c.execute(sa.select(sa.func.max(assessment_audit_events.c.event_sequence))).scalar_one_or_none() or 0) + 1
        context = {"credential_mode": "local_session" if actor != "host-maintenance" else "host_maintenance"}
        policy_revision = c.execute(sa.select(assessment_policy.c.revision).where(
            assessment_policy.c.policy_id == 1)).scalar_one_or_none() or 0
        intent_id = str(uuid.uuid4()) if intent_kind else None
        c.execute(assessment_audit_events.insert().values(event_id=event, event_sequence=seq,
            actor_id=actor, actor_kind="local_account" if actor != "host-maintenance" else "host_maintenance",
            origin="local_auth", action=action, target_id=target,
            before_value=before_value or {}, after_value=after_value or {"principal_id": target}, membership_ids=[], membership_revision=0,
            rationale=action, evidence_ref="local-auth:" + action, policy_revision=policy_revision, identity_revision=0,
            occurred_at=now, received_at=now, correlation_id=str(uuid.uuid4()), command_id=command,
            authorization_context=context))
        if intent_id:
            c.execute(administration_reconciliation_intents.insert().values(intent_id=intent_id,
                audit_event_id=event, kind=intent_kind, target_id=intent_target or target,
                authority_revision=authority_revision, status="pending", attempts=0,
                last_error=None, created_at=now, updated_at=now))
        digest = hashlib.sha256(json.dumps({"actor": actor, "action": action, "target": target},
            sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        decision_id = str(uuid.uuid4())
        result = {"schema_version": 1, "command_id": command, "decision_id": decision_id,
            "audit_event_id": event, "intent_id": intent_id,
            "action": action, "target_id": target}
        c.execute(assessment_command_receipts.insert().values(command_id=command,
            principal_id=actor, action=action, target_id=target, request_digest=digest,
            decision_id=decision_id, audit_event_id=event, intent_id=intent_id,
            result=result, created_at=now, authorization_context=context))
        return result

    def middleware(self, app: FastAPI):
        @app.middleware("http")
        async def local_auth_middleware(request: Request, call_next):
            public = {"/api/v1/auth/config", "/api/v1/auth/setup/claim", "/api/v1/auth/local/login",
                "/api/v1/auth/local/enrol", "/api/v1/auth/local/recovery", "/healthz", "/health"}
            path = request.url.path
            if path.startswith("/api/v1/") and path not in public and path != "/api/v1/auth/session":
                raw = request.cookies.get(COOKIE_NAME)
                if raw:
                    write = request.method.upper() not in {"GET", "HEAD", "OPTIONS"}
                    if write:
                        if request.headers.get("origin") != self.config["public_origin"] or not request.headers.get("x-csrf-token"):
                            return JSONResponse(status_code=403, content={"detail": {"code": "csrf_failed", "message": "Request verification failed"}}, headers={"Cache-Control": "no-store"})
                    try:
                        with self.engine.connect() as c:
                            context = self.resolve_cookie(c, raw, csrf_token=request.headers.get("x-csrf-token") if write else None)
                        request.state.authority_context = context; request.state.raw_session_cookie = raw
                        AUTHORITY_CONTEXT.set(context)
                    except HTTPException as exc:
                        return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail}, headers={"Cache-Control": "no-store"})
            response = await call_next(request)
            if path.startswith("/api/v1/auth/"):
                response.headers["Cache-Control"] = "no-store"; response.headers["Referrer-Policy"] = "no-referrer"
            return response


def install_local_auth(app: FastAPI):
    config = load_local_config()
    service = LocalAuth(app.state.engine, config)
    app.state.oidc_auth = service
    service.install_routes(app)
    service.middleware(app)
    return service
