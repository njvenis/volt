"""Scoped local connector settings API and write-only secret intake."""
from __future__ import annotations

import copy
import hashlib
import hmac
import json
import logging
import os
import re
import secrets
import stat
import uuid
from sqlalchemy.exc import IntegrityError
from datetime import datetime, timezone, timedelta
from urllib.parse import urlencode

import sqlalchemy as sa
from fastapi import HTTPException, Request
from fastapi.responses import RedirectResponse

from uvm.assessment.policy_lock import lock_policy
from uvm.auth.schema import AUTHORITY_CONTEXT
from uvm.persistence.assessment_schema import (assessment_audit_events,
    assessment_command_receipts, assessment_policy)
from uvm.persistence.connector_schema import (connectors, connector_configurations,
    connector_secret_heads, connector_secrets, connector_receipts, connector_intents, connector_submissions,
    connector_nonce_reservations)
from uvm.persistence.connector_schema import connector_setup_flows
from uvm.persistence.auth_schema import oidc_sessions
from uvm.connectors.crypto import encrypt, decrypt
from uvm.connectors.recovery import (issuer_entry, issuer_entry_diagnostic,
    issuer_version, operator_clearance)
from uvm.github.app_auth import app_jwt

ZERO = "00000000-0000-4000-8000-000000000000"
_LOG = logging.getLogger(__name__)
UTC = timezone.utc
PURPOSES = {"private_key", "oauth_client_secret", "webhook_secret", "preview_secret", "rest_token"}
PERMISSIONS = ("connector.read", "connector.configure", "connector.secret.manage",
               "github.repository.configure")
_UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\Z")


def _fail(status: int, code: str, message: str):
    raise HTTPException(status, {"code": code, "message": message})


def _uuid(value, label="id"):
    if not isinstance(value, str) or not _UUID.fullmatch(value):
        _fail(400, "invalid_request", f"{label} must be a canonical UUID")
    return value


def _now(app):
    value = app.state.utc_now()
    return value.astimezone(UTC)


def _reserved_nonce(connection, key_id: str, purpose: str, binding_id: str, now) -> bytes:
    """Reserve a per-key AES-GCM nonce in the same transaction as its ciphertext."""
    for _ in range(32):
        nonce = secrets.token_bytes(12)
        try:
            with connection.begin_nested():
                connection.execute(connector_nonce_reservations.insert().values(
                    key_id=key_id, nonce=nonce, purpose=purpose,
                    binding_id=binding_id, created_at=now))
            return nonce
        except IntegrityError:
            continue
    raise RuntimeError("AES-GCM nonce allocation exhausted")


def _z(value):
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _recovery_epoch(*, allow_not_yet_created: bool = False) -> str | None:
    """Read the infrastructure-supplied restore fence, never a DB-restored value."""
    host_restore_id = os.getenv("UVM_G7_CONNECTOR_RECOVERY_ID")
    if host_restore_id:
        if not _UUID.fullmatch(host_restore_id):
            raise RuntimeError("host connector recovery UUID is invalid")
        return host_restore_id
    path = os.getenv("UVM_CONNECTOR_RECOVERY_EPOCH_FILE")
    if not path:
        return None
    descriptor = None
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600:
            raise ValueError("recovery epoch file must be a regular 0600 file")
        with os.fdopen(descriptor, "r", encoding="ascii") as stream:
            descriptor = None
            value = stream.read().strip()
    except FileNotFoundError:
        if allow_not_yet_created:
            return None
        raise RuntimeError("connector recovery epoch is unavailable or unsafe")
    except (OSError, UnicodeError, ValueError) as exc:
        if descriptor is not None:
            os.close(descriptor)
        raise RuntimeError("connector recovery epoch is unavailable or unsafe") from exc
    if not _UUID.fullmatch(value):
        raise RuntimeError("connector recovery epoch is invalid")
    return value


def apply_restore_quarantine(engine, epoch_id: str) -> int:
    """Fail-close every restored connector before request/worker readiness."""
    with engine.begin() as connection:
        return apply_restore_quarantine_connection(connection, epoch_id)


def apply_restore_quarantine_connection(connection, epoch_id: str) -> int:
    """Bind connector recovery to the authenticated host restore UUID atomically."""
    epoch_id = _uuid(epoch_id, "recovery_epoch_id")
    now = datetime.now(UTC)
    rows = connection.execute(sa.select(connectors).with_for_update()).mappings().all()
    for row in rows:
        if (row["recovery"].get("state") == "quarantined"
                and row["recovery"].get("recovery_epoch_id") == epoch_id):
            continue
        recovery = {"state":"quarantined", "recovery_epoch_id":epoch_id,
            "operator_clearance_present":False, "requires_fresh_credentials":True,
            "reason":"restore_quarantined"}
        connection.execute(connectors.update().where(
            connectors.c.connector_id == row["connector_id"]).values(
                recovery=recovery, lifecycle="disabled", active_configuration_revision=None,
                connector_revision=int(row["connector_revision"])+1,
                validation={"status":"failed","checked_at":_z(now),"intent_id":None,
                    "configuration_revision":row["configuration_revision"],
                    "reason":"restore_quarantined"}, updated_at=now))
        connection.execute(connector_secrets.update().where(
            connector_secrets.c.connector_id == row["connector_id"],
            connector_secrets.c.state != "revoked").values(quarantine="restored_version"))
        # A restored row cannot establish whether an externally issued
        # revocation completed after the backup snapshot. Keep the exact
        # secret/version binding, but expose remote status as uncertain.
        secrets_to_reconcile = connection.execute(sa.select(connector_secrets).where(
            connector_secrets.c.connector_id == row["connector_id"],
            connector_secrets.c.state != "revoked").with_for_update()).mappings().all()
        for secret in secrets_to_reconcile:
            remote = dict(secret["remote_revocation"] or {})
            if remote.get("status") not in {"complete", "confirmed_revoked"}:
                # The v1 nested remote status uses `unknown`; intent
                # settlement uses `outcome_unknown`.
                remote.update(status="unknown", reason="outcome_unknown")
                connection.execute(connector_secrets.update().where(
                    connector_secrets.c.connector_id == row["connector_id"],
                    connector_secrets.c.secret_id == secret["secret_id"],
                    connector_secrets.c.version_id == secret["version_id"]).values(
                        remote_revocation=remote))
                if remote.get("intent_id"):
                    connection.execute(connector_intents.update().where(
                        connector_intents.c.connector_id == row["connector_id"],
                        connector_intents.c.intent_id == remote["intent_id"],
                        connector_intents.c.kind == "connector.remote_revoke",
                        connector_intents.c.status.in_(["pending", "running"])).values(
                            status="uncertain", result={"reason":"database_restore_status_unknown",
                                "secret_id":secret["secret_id"],"version_id":secret["version_id"]},
                            updated_at=now))
    return len(rows)

def _authenticate(app, request: Request) -> str:
    context = getattr(request.state, "authority_context", None)
    if context is not None:
        return context.principal_id
    auth = getattr(app.state, "oidc_auth", None)
    if auth is not None:
        return auth.resolve_request(request).principal_id
    authorization = request.headers.get("authorization", "")
    if authorization.startswith("Bearer "):
        supplied = authorization[7:]
        for name, value in app.state.principals.items():
            if hmac.compare_digest(supplied, value.get("token", "")):
                return name
    _fail(401, "authentication_required", "Authentication required")


def _fixture(connector_id: str) -> dict:
    configured = os.getenv("UVM_CONNECTOR_FIXTURE_ID")
    if not configured:
        _fail(503, "connector_fixture_unavailable", "Connector source binding is unavailable")
    if connector_id != configured:
        _fail(404, "not_found", "Connector does not exist")
    try:
        return {"connector_id": _uuid(configured),
            "source_id": _uuid(os.environ["UVM_CONNECTOR_FIXTURE_SOURCE_ID"]),
            "source_family": os.environ["UVM_CONNECTOR_FIXTURE_SOURCE_FAMILY"],
            "source_account_id": os.environ["UVM_CONNECTOR_FIXTURE_SOURCE_ACCOUNT_ID"],
            "scope_key": os.environ["UVM_CONNECTOR_FIXTURE_SCOPE_KEY"],
            "environment_label": os.environ["UVM_CONNECTOR_ENVIRONMENT_LABEL"]}
    except (KeyError, ValueError):
        _fail(503, "connector_binding_unavailable", "Connector source binding is unavailable")


def _ensure(app, connector_id: str):
    binding = _fixture(connector_id)
    now = _now(app)
    with app.state.engine.begin() as c:
        existing = c.execute(sa.select(connectors).where(
            connectors.c.connector_id == connector_id)).mappings().first()
        if existing is None:
            epoch = _recovery_epoch(allow_not_yet_created=True)
            c.execute(connectors.insert().values(**binding, source_revision=1,
                secret_source_id=None, secret_source_revision=0, connector_revision=1,
                configuration_revision=0, active_configuration_revision=None,
                lifecycle="disabled", validation={"status":"unverified","checked_at":None,
                    "intent_id":None,"configuration_revision":None,"reason":None},
                recovery=({"state":"quarantined","recovery_epoch_id":epoch,
                    "operator_clearance_present":False,"requires_fresh_credentials":True,
                    "reason":"restore_quarantined"} if epoch else
                    {"state":"clear","recovery_epoch_id":None,
                    "operator_clearance_present":False,"requires_fresh_credentials":False,"reason":None}),
                updated_at=now))
        else:
            for key in ("source_id", "source_family", "source_account_id", "scope_key", "environment_label"):
                if existing[key] != binding[key]:
                    _fail(503, "scope_changed", "Provisioned connector binding changed")
        return binding


def _auth_context(app, request, connection):
    service = getattr(app.state, "oidc_auth", None)
    if service is None:
        return getattr(request.state, "authority_context", None)
    try:
        return service.final_context(connection, request)
    except HTTPException:
        raise


def _policy(connection):
    row = connection.execute(sa.select(assessment_policy).where(
        assessment_policy.c.policy_id == 1)).mappings().first()
    if row is None:
        _fail(503, "persistence_unavailable", "Assessment policy is unavailable")
    return row


def _grants(policy, actor, action, binding):
    from uvm.assessment.api import _scoped_grants
    rows = _scoped_grants(policy, actor, action, binding["connector_id"], binding["source_family"])
    result = []
    for grant in rows:
        scopes = grant.get("source_scopes")
        if scopes is not None and binding_scope(binding) not in {
                tuple(x.get(k) for k in ("source_family", "source_account_id", "scope_key"))
                for x in scopes if isinstance(x, dict)}:
            continue
        result.append(grant)
    context = AUTHORITY_CONTEXT.get()
    if context is not None and context.credential_mode in {"oidc_session", "github_link"}:
        eligible = set(context.scopes_for_granting_groups(g.get("principal_id") for g in result))
        if binding_scope(binding) not in eligible:
            return []
    return result


def binding_scope(binding):
    return (binding["source_family"], binding["source_account_id"], binding["scope_key"])


def _require(policy, actor, action, binding):
    if not _grants(policy, actor, action, binding):
        _fail(403, "forbidden", f"Current {action} permission is required")


def _revisions(row, policy, context, secret=None):
    return {"target":int(policy["revision"]),"policy":int(policy["revision"]),
        "identity_membership":0,"owners":0,
        "authority":int(getattr(context, "policy_revision", policy["revision"])),
        "connector":int(row["connector_revision"]),"source":int(row["source_revision"]),
        "secret_source":int(row["secret_source_revision"]),"secret":secret}


def _check_revisions(expected, actual):
    if not isinstance(expected, dict) or set(expected) != set(actual) or expected != actual:
        _fail(409, "revision_conflict", "Connector state changed; refresh before submitting")


def _request_shape(action, payload):
    common={"connector_id","source_id","rationale","evidence_ref"}
    fields={
        "connector.configuration.stage":{"settings"},
        "connector.configuration.validate":{"configuration_revision"},
        "connector.configuration.activate":{"configuration_revision","validation_intent_id"},
        "connector.configuration.disable":set(),
        "connector.configuration.rollback":{"configuration_revision","validation_intent_id"},
        "connector.secret.version.revoke":{"secret_id","version_id"},
        "connector.secret.submission.reconcile":{"submission_id","secret_id","version_id"},
    }
    if action not in fields or set(payload)!=common|fields[action]:
        _fail(422,"invalid_command","Connector command payload has missing or unknown fields")


def _settings(row, connection, connector_id):
    config = None
    if row["configuration_revision"]:
        config = connection.execute(sa.select(connector_configurations.c.settings).where(
            connector_configurations.c.connector_id == connector_id,
            connector_configurations.c.configuration_revision == row["configuration_revision"])).scalar_one_or_none()
    return config or {"environment_label":row["environment_label"],
        "authentication_mode":"legacy_token_file","secret_source":None,
        "credentials":{"private_key":None,"oauth_client_secret":None,"webhook_secret":None,"preview_secret":None,"rest_token":None},
        "github":{"host":"github.com","api_version":"2022-11-28","app":None,
            "installation":None,"repository_ids":[],"audience_revisions":{}}}


def _refresh_secret_heads(connection, connector_id, settings):
    """Allocate current head revisions for eligible historical credential refs."""
    candidate = copy.deepcopy(settings)
    for purpose, ref in (candidate.get("credentials") or {}).items():
        if ref is None:
            continue
        secret = connection.execute(sa.select(connector_secrets).where(
            connector_secrets.c.connector_id == connector_id,
            connector_secrets.c.secret_id == ref.get("secret_id"),
            connector_secrets.c.version_id == ref.get("version_id")).with_for_update()).mappings().first()
        head = connection.execute(sa.select(connector_secret_heads.c.revision).where(
            connector_secret_heads.c.connector_id == connector_id,
            connector_secret_heads.c.secret_id == ref.get("secret_id")).with_for_update()).scalar_one_or_none()
        if (secret is None or secret["purpose"] != purpose
                or secret["state"] not in {"active", "inactive"}
                or secret["quarantine"] != "clear" or head is None):
            _fail(409, "credential_revoked", "Selected historical credential is no longer eligible")
        ref["secret_revision"] = int(head)
    return candidate


def _validation_result(connection, connector_id, settings, configuration_revision, row, now):
    """Validate only a complete, revision-bound local App candidate; never call an external host."""
    recovery = row["recovery"]
    recovery_state = recovery.get("state")
    reason = "restore_quarantined" if recovery_state == "quarantined" else None
    if recovery_state == "awaiting_activation":
        clearance = operator_clearance(connector_id, recovery.get("recovery_epoch_id"))
        if recovery.get("operator_clearance_present") is not True or not clearance:
            reason = "restore_quarantined"
        else:
            for purpose, ref in (settings.get("credentials") or {}).items():
                if ref is None:
                    continue
                if (ref.get("version_id") not in clearance.get("fresh_version_ids", [])
                        or not issuer_version(connector_id, ref.get("secret_id"), ref.get("version_id"),
                                              purpose, recovery.get("recovery_epoch_id"))):
                    reason = "restore_quarantined"
                    break
    is_app = settings.get("authentication_mode") == "github_app_v1"
    if not is_app and not (settings.get("credentials") or {}).get("rest_token"):
        reason = "credentials_unavailable"
    app = (settings.get("github") or {}).get("app")
    installation = (settings.get("github") or {}).get("installation")
    if is_app and reason is None and (not isinstance(app, dict) or not isinstance(installation, dict)
            or not all(isinstance(app.get(k), str) and app[k] for k in ("app_id", "client_id", "slug"))
            or not all(isinstance(installation.get(k), str) and installation[k]
                for k in ("installation_id", "account_id"))):
        reason = "installation_invalid"
    if reason is None:
        ids = settings["github"].get("repository_ids", [])
        approvals = settings["github"].get("audience_revisions", {})
        if not ids or any(not isinstance(item, str) or not item.isdigit() for item in ids):
            reason = "audience_incomplete"
        elif any(type(approvals.get(item)) is not int or approvals[item] < 1 for item in ids):
            reason = "audience_unapproved"
        else:
            # An integer copied into connector settings is not an approval.  Bind
            # each selected repository to its current, separately governed UVM
            # audience snapshot and recompute every included group's readers.
            from uvm.persistence.g4_schema import github_repositories
            from uvm.github.api import _assert_group_audience_binding
            installation_repos = set()
            flow_id = (installation or {}).get("flow_id") if isinstance(installation, dict) else None
            if isinstance(flow_id, str):
                flow = connection.execute(sa.select(connector_setup_flows).where(
                    connector_setup_flows.c.flow_id == flow_id,
                    connector_setup_flows.c.connector_id == connector_id,
                    connector_setup_flows.c.status == "verified")).mappings().first()
                if (flow and flow["installation"]
                        and str(flow["installation"].get("installation_id")) == str(installation.get("installation_id"))
                        and str(flow["installation"].get("account_id")) == str(installation.get("account_id"))):
                    installation_repos = {str(item.get("repository_id"))
                        for item in flow["repositories"]
                        if isinstance(item, dict) and item.get("installation_access") is True}
            for repository_id in ids:
                repository = connection.execute(sa.select(github_repositories).where(
                    github_repositories.c.repository_id == repository_id,
                    github_repositories.c.enabled.is_(True))).mappings().first()
                if repository is None or (is_app and repository_id not in installation_repos):
                    reason = "audience_unapproved"
                    break
                if int(repository["audience_revision"]) != approvals[repository_id]:
                    reason = "audience_unapproved"
                    break
                included = (repository["audience_document"] or {}).get("included_scopes", {})
                if not included:
                    reason = "audience_unapproved"
                    break
                try:
                    for group_id in included:
                        _assert_group_audience_binding(connection, dict(repository), group_id)
                except HTTPException:
                    reason = "audience_unapproved"
                    break
    references = []
    for purpose, ref in (settings.get("credentials") or {}).items():
        if ref is None:
            continue
        secret = connection.execute(sa.select(connector_secrets).where(
            connector_secrets.c.connector_id == connector_id,
            connector_secrets.c.secret_id == ref["secret_id"],
            connector_secrets.c.version_id == ref["version_id"])).mappings().first()
        head = connection.execute(sa.select(connector_secret_heads.c.revision).where(
            connector_secret_heads.c.connector_id == connector_id,
            connector_secret_heads.c.secret_id == ref["secret_id"])).scalar_one_or_none()
        if (secret is None or secret["purpose"] != purpose or secret["state"] == "revoked"
                or secret["quarantine"] != "clear" or int(head or 0) != ref["secret_revision"]):
            reason = reason or "credential_revoked"
        # Purpose is bound by the credential slot in Settings and the
        # immutable secret row; the public SecretRef shape omits it.
        references.append({"secret_id":ref["secret_id"],
            "version_id":ref["version_id"],"secret_revision":ref["secret_revision"]})
    required_purposes = ({"private_key", "oauth_client_secret", "webhook_secret"}
        if settings.get("authentication_mode") == "github_app_v1" else {"rest_token"})
    if not required_purposes <= {purpose for purpose, ref in
                (settings.get("credentials") or {}).items() if ref is not None}:
        reason = reason or "credentials_unavailable"
    return {"configuration_revision":configuration_revision,"source_revision":row["source_revision"],
        "secret_source_revision":row["secret_source_revision"],"credentials":references,
        "installation":installation,"repository_ids":(settings.get("github") or {}).get("repository_ids",[]),
        "audience_revisions":(settings.get("github") or {}).get("audience_revisions",{}),
        "checked_at":_z(now),"valid":reason is None,"reason":reason}


def _lock_intent_commit(app, request, connection, connector_id, intent_id,
        actor, binding, intent, *, secret_required=False):
    """Take DB locks only after provider I/O and fence its result before commit."""
    lock_policy(connection)
    policy = _policy(connection)
    context = _auth_context(app, request, connection)
    _require(policy["document"], actor, "connector.configure", binding)
    if secret_required:
        _require(policy["document"], actor, "connector.secret.manage", binding)
    row = connection.execute(sa.select(connectors).where(
        connectors.c.connector_id == connector_id).with_for_update()).mappings().one()
    current_intent = connection.execute(sa.select(connector_intents).where(
        connector_intents.c.connector_id == connector_id,
        connector_intents.c.intent_id == intent_id).with_for_update()).mappings().one()
    payload = intent["payload"] or {}
    unchanged = (current_intent["status"] == "pending"
        and current_intent["actor_id"] == actor
        and policy["revision"] == payload.get("policy_revision")
        and context is not None
        and getattr(context, "policy_revision", None) == payload.get("authority_revision"))
    if intent["kind"] == "connector.validate":
        settings = _settings(row, connection, connector_id)
        unchanged = unchanged and row["configuration_revision"] == payload.get("configuration_revision")
        unchanged = unchanged and row["source_revision"] == payload.get("source_revision")
        unchanged = unchanged and row["secret_source_revision"] == payload.get("secret_source_revision")
        unchanged = unchanged and row["connector_revision"] == payload.get("connector_revision")
        unchanged = unchanged and row["validation"].get("intent_id") == intent_id
        unchanged = unchanged and settings == payload.get("settings")
        if unchanged:
            try:
                unchanged = _refresh_secret_heads(connection, connector_id, settings) == settings
            except HTTPException:
                unchanged = False
    elif payload.get("reason") == "configuration_rollback":
        unchanged = unchanged and row["configuration_revision"] == payload.get("configuration_revision")
        unchanged = unchanged and row["active_configuration_revision"] == payload.get("configuration_revision")
        unchanged = unchanged and row["lifecycle"] == "active" and row["recovery"].get("state") == "clear"
        unchanged = unchanged and row["connector_revision"] == payload.get("connector_revision")
        unchanged = unchanged and row["source_revision"] == payload.get("source_revision")
        unchanged = unchanged and row["secret_source_revision"] == payload.get("secret_source_revision")
    return policy, context, row, current_intent, bool(unchanged)


def _secret_view(connection, connector_id, secret_id, *, actor=None, binding=None, policy=None):
    rows = connection.execute(sa.select(connector_secrets).where(
        connector_secrets.c.connector_id == connector_id,
        connector_secrets.c.secret_id == secret_id).order_by(connector_secrets.c.created_at)).mappings().all()
    if not rows:
        return None
    versions = []
    for row in rows:
        versions.append({"version_id":row["version_id"],"state":row["state"],"present":True,
            "created_at":_z(row["created_at"]),"revoked_at":None,
            "quarantine":row["quarantine"],"usable":row["state"] == "active" and row["quarantine"] == "clear",
            "validation_eligible":row["state"] == "inactive" and row["quarantine"] == "clear",
            "remote_revocation":row["remote_revocation"]})
    purpose = rows[0]["purpose"]
    head = connection.execute(sa.select(connector_secret_heads.c.revision).where(
        connector_secret_heads.c.connector_id == connector_id,
        connector_secret_heads.c.secret_id == secret_id)).scalar_one_or_none()
    secret_rev = int(head or 0)
    return {"secret_id":secret_id,"revision":secret_rev,"purpose":purpose,"versions":versions}


def _connector_view(connection, row, binding, policy, context):
    settings = _settings(row, connection, row["connector_id"])
    secrets = []
    ids = connection.execute(sa.select(connector_secrets.c.secret_id).where(
        connector_secrets.c.connector_id == row["connector_id"]).distinct()).scalars().all()
    for secret_id in ids:
        view = _secret_view(connection, row["connector_id"], secret_id)
        if view:
            secrets.append(view)
    reconciliation_query = sa.select(connector_intents).where(
        connector_intents.c.connector_id == row["connector_id"],
        connector_intents.c.kind.in_(["connector.remote_revoke", "connector.reconcile"]))
    # A terminal failure is retained for history, but must not shadow newer
    # unresolved work when the disposable/test clock gives intents the same
    # created_at value. Surface active obligations before historical failures.
    pending_reconciliation = connection.execute(reconciliation_query.where(
        connector_intents.c.status.in_(["pending", "running", "uncertain"])
        ).order_by(connector_intents.c.created_at.desc(),
            connector_intents.c.updated_at.desc()).limit(1)).mappings().first()
    if pending_reconciliation is None:
        pending_reconciliation = connection.execute(reconciliation_query.where(
            connector_intents.c.status == "failed"
            ).order_by(connector_intents.c.created_at.desc(),
                connector_intents.c.updated_at.desc()).limit(1)).mappings().first()
    reconciliation_status = pending_reconciliation["status"] if pending_reconciliation else "complete"
    reconciliation_reason = None
    if pending_reconciliation:
        reconciliation_reason = ("outcome_unknown" if reconciliation_status in
            {"pending", "running", "uncertain"} else
            pending_reconciliation["result"].get("reason") if
                isinstance(pending_reconciliation["result"], dict) else None)
    return {"schema_version":1,"connector_id":row["connector_id"],
        "source":{"source_id":row["source_id"],"revision":row["source_revision"],
            "source_family":row["source_family"],"source_account_id":row["source_account_id"],"scope_key":row["scope_key"]},
        "revisions":_revisions(row,policy,context),"configuration_revision":row["configuration_revision"],
        "active_configuration_revision":row["active_configuration_revision"],"lifecycle":row["lifecycle"],
        "settings":settings,"validation":row["validation"],"recovery":row["recovery"],
        "reconciliation":{"status":reconciliation_status,
            "intent_id":pending_reconciliation["intent_id"] if pending_reconciliation else None,
            "reason":reconciliation_reason},
        "secrets":secrets,"updated_at":_z(row["updated_at"])}


def _flow_view(flow, connector_id, source_id):
    """Public, sanitised flow shape. Internal OAuth state and candidate IDs stay private."""
    raw_installation = flow["installation"] if flow["status"] == "verified" else None
    installation = ({key:raw_installation[key] for key in
        ("flow_id", "installation_id", "account_id") if key in raw_installation}
        if isinstance(raw_installation,dict) else None)
    return {"schema_version":1,"flow_id":flow["flow_id"],"connector_id":connector_id,
        "source_id":source_id,"configuration_revision":flow["configuration_revision"],
        "initiating_principal_id":flow["actor_id"],"status":flow["status"],
        "expires_at":_z(flow["expires_at"]),"reason":flow["failure_reason"],
        "app":flow["app"],"installation":installation,
        "granted_permissions":flow["granted_permissions"],"repositories":flow["repositories"],
        "repositories_complete":flow["repositories_complete"],
        "verification_receipt":flow["verification_receipt"]}


def install_connector_routes(app):
    engine = app.state.engine

    def quarantine_restored_instance():
        authority_path = os.getenv("UVM_CONNECTOR_RECOVERY_EPOCH_FILE")
        host_restore_id = os.getenv("UVM_G7_CONNECTOR_RECOVERY_ID")
        if not authority_path and not host_restore_id:
            with engine.connect() as connection:
                configured = connection.execute(sa.select(connectors.c.connector_id).where(
                    connectors.c.configuration_revision > 0).limit(1)).first()
            if configured:
                raise RuntimeError("connector recovery epoch is required for configured state")
            return
        if authority_path and not host_restore_id and not os.path.lexists(authority_path):
            # A clean disposable boot creates its fixture connector after the
            # API starts, then its restore fixture supplies the epoch. A
            # restored database with existing connector rows must never boot
            # without the independent startup fence.
            with engine.connect() as connection:
                existing = connection.execute(sa.select(connectors.c.connector_id).limit(1)).first()
            if existing:
                raise RuntimeError("connector recovery epoch is unavailable for restored state")
            return
        epoch = _recovery_epoch()
        if epoch:
            count = apply_restore_quarantine(engine, epoch)
            _LOG.warning("connector_restore_quarantine_startup_complete connectors=%d pid=%d",
                count, os.getpid())

    # This startup hook is registered before the GitHub poller hook so a
    # restored connector is fenced before any connector worker can run.
    app.router.on_startup.insert(0, quarantine_restored_instance)

    @app.middleware("http")
    async def connector_no_store(request: Request, call_next):
        response = await call_next(request)
        if request.url.path.startswith("/api/v1/connectors/") or request.url.path == "/api/v1/assessment/commands":
            response.headers["Cache-Control"] = "no-store"
        return response

    @app.get("/api/v1/connectors")
    def list_connectors(request: Request, limit: int = 25, cursor: str | None = None):
        if limit < 1 or limit > 100 or cursor is not None:
            _fail(400, "invalid_request", "Connector pagination parameters are invalid")
        actor = _authenticate(app, request)
        configured = os.getenv("UVM_CONNECTOR_FIXTURE_ID")
        if not configured:
            return {"schema_version":1,"items":[],"next_cursor":None}
        binding = _ensure(app, configured)
        with engine.begin() as c:
            context = _auth_context(app, request, c)
            policy = _policy(c)
            _require(policy["document"],actor,"connector.read",binding)
            row = c.execute(sa.select(connectors).where(connectors.c.connector_id == configured)).mappings().one()
            return {"schema_version":1,"items":[_connector_view(c,row,binding,policy,context)],"next_cursor":None}

    @app.get("/api/v1/connectors/{connector_id}/permissions")
    def connector_permissions(connector_id: str, request: Request, source_id: str):
        _uuid(connector_id,"connector_id"); _uuid(source_id,"source_id")
        actor = _authenticate(app,request); binding = _ensure(app,connector_id)
        if source_id != binding["source_id"]: _fail(403,"source_scope_forbidden","Source scope does not match")
        with engine.begin() as c:
            context = _auth_context(app,request,c); policy = _policy(c)
            allowed = {name:bool(_grants(policy["document"],actor,name,binding)) for name in PERMISSIONS}
            if not any(allowed[x] for x in PERMISSIONS[:3]): _fail(403,"forbidden","Connector permission is required")
            row = c.execute(sa.select(connectors).where(connectors.c.connector_id==connector_id)).mappings().one()
            return {"schema_version":1,"connector_id":connector_id,"source":{"source_id":source_id,
                "revision":row["source_revision"],"source_family":row["source_family"],
                "source_account_id":row["source_account_id"],"scope_key":row["scope_key"]},
                "revisions":_revisions(row,policy,context),"principal_id":actor,"allowed":allowed}

    @app.get("/api/v1/connectors/{connector_id}")
    def read_connector(connector_id: str, request: Request, source_id: str):
        _uuid(connector_id,"connector_id"); _uuid(source_id,"source_id")
        actor = _authenticate(app,request); binding = _ensure(app,connector_id)
        if source_id != binding["source_id"]: _fail(403,"source_scope_forbidden","Source scope does not match")
        with engine.begin() as c:
            context = _auth_context(app,request,c); policy = _policy(c)
            _require(policy["document"],actor,"connector.read",binding)
            row = c.execute(sa.select(connectors).where(connectors.c.connector_id==connector_id)).mappings().one()
            return _connector_view(c,row,binding,policy,context)

    @app.post("/api/v1/connectors/{connector_id}/secrets/{secret_id}/versions",status_code=201)
    def submit_secret(connector_id: str, secret_id: str, body: dict, request: Request):
        _uuid(connector_id,"connector_id"); _uuid(secret_id,"secret_id")
        actor = _authenticate(app,request); binding = _ensure(app,connector_id)
        required = {"schema_version","submission_id","version_id","source_id","purpose","expected_revisions","rationale","evidence_ref","input"}
        if not isinstance(body,dict) or set(body)!=required or body.get("schema_version")!=1:
            _fail(400,"invalid_request","Secret submission shape is invalid")
        submission_id = _uuid(body["submission_id"],"submission_id"); version_id = _uuid(body["version_id"],"version_id")
        if body["source_id"] != binding["source_id"]: _fail(403,"source_scope_forbidden","Source scope does not match")
        if body["purpose"] not in PURPOSES or not isinstance(body["rationale"],str) or not body["rationale"].strip() or not isinstance(body["evidence_ref"],str) or not body["evidence_ref"].strip():
            _fail(400,"invalid_request","Secret submission metadata is invalid")
        data = body["input"]
        if not isinstance(data,dict) or set(data)!={"kind","value"} or data.get("kind")!="value" or not isinstance(data.get("value"),str):
            _fail(400,"invalid_request","Only encrypted-local secret values are supported in this fixture")
        raw = data["value"].encode("utf-8")
        body["input"]["value"] = ""
        now = _now(app)
        # Durable admission precedes the commit attempt. An interrupted second
        # transaction remains outcome_unknown and cannot be retried with bytes.
        try:
            with engine.begin() as admission:
                lock_policy(admission); policy0=_policy(admission); context0=_auth_context(app,request,admission)
                _require(policy0["document"],actor,"connector.secret.manage",binding)
                row0=admission.execute(sa.select(connectors).where(connectors.c.connector_id==connector_id).with_for_update()).mappings().one()
                head0=admission.execute(sa.select(connector_secret_heads.c.revision).where(connector_secret_heads.c.connector_id==connector_id,connector_secret_heads.c.secret_id==secret_id)).scalar_one_or_none() or 0
                _check_revisions(body["expected_revisions"],_revisions(row0,policy0,context0,int(head0)))
                existing=admission.execute(sa.select(connector_submissions).where(sa.or_(
                        connector_submissions.c.submission_id==submission_id,
                        sa.and_(connector_submissions.c.connector_id==connector_id,
                            connector_submissions.c.version_id==version_id))).with_for_update()).mappings().first()
                if existing is not None:
                    same_binding=(existing["submission_id"]==submission_id
                        and existing["connector_id"]==connector_id
                        and existing["source_id"]==binding["source_id"]
                        and existing["secret_id"]==secret_id
                        and existing["version_id"]==version_id
                        and existing["actor_id"]==actor)
                    # A confirmed rollback allows the operator to retry the
                    # operation, never to resurrect its admitted identifiers.
                    # retry_allowed means a fresh submission/version pair.
                    _fail(409,"submission_conflict",
                        "Submission and version IDs are terminal; create new IDs")
                else:
                    admission.execute(connector_submissions.insert().values(submission_id=submission_id,connector_id=connector_id,
                        source_id=binding["source_id"],secret_id=secret_id,version_id=version_id,actor_id=actor,
                        outcome="unknown",retry_allowed=False,receipt=None,created_at=now))
        except sa.exc.DBAPIError as exc:
            # Admission rollback is also definitive when PostgreSQL reports a
            # statement error on a live connection. Connection loss at commit
            # keeps its outcome unknown for later reconciliation.
            sqlstate = getattr(getattr(exc, "orig", None), "sqlstate", None)
            if exc.connection_invalidated or not sqlstate:
                raise
            raise HTTPException(status_code=503, detail={"code":"dependency_unavailable",
                "message":"Secret submission was not admitted",
                "details":{"outcome":"not_committed","expected_revisions":None,
                    "current_revisions":None,"lookup_url":None}}) from None
        # Deterministic interruption seam for the labelled disposable public
        # journey. The durable admission has committed; a test may hold this
        # handler while another request settles the row to not_committed, then
        # release it to prove the stale handler cannot resurrect the version.
        pause_dir = os.getenv("UVM_CONNECTOR_TEST_SUBMISSION_PAUSE_DIR")
        if os.getenv("UVM_G7_DISPOSABLE_MODE") == "1" and pause_dir:
            from pathlib import Path
            import time
            directory = Path(pause_dir)
            pause = directory / "pause"
            if pause.exists():
                marker = directory / ("admitted-" + submission_id)
                marker.write_text("admitted\n")
                deadline = time.monotonic() + 30
                while pause.exists() and time.monotonic() < deadline:
                    time.sleep(0.02)
        try:
            with engine.begin() as c:
                lock_policy(c); policy = _policy(c)
                context = _auth_context(app,request,c)
                _require(policy["document"],actor,"connector.secret.manage",binding)
                row = c.execute(sa.select(connectors).where(connectors.c.connector_id==connector_id).with_for_update()).mappings().one()
                recovery = row["recovery"]
                if recovery.get("state") != "clear":
                    proof = issuer_entry(connector_id, secret_id, version_id, body["purpose"],
                                         recovery.get("recovery_epoch_id"), raw)
                    if recovery.get("state") != "quarantined":
                        _fail(409,"restore_quarantined","Recovery state does not permit issuer staging")
                    if not proof or proof.get("issued_after_epoch") is not True:
                        proof_checks = issuer_entry_diagnostic(
                            connector_id, secret_id, version_id, body["purpose"],
                            recovery.get("recovery_epoch_id"), raw)
                        _LOG.warning("connector recovery issuer proof rejected %s", json.dumps({
                            "connector_id":connector_id,"secret_id":secret_id,"version_id":version_id,
                            "recovery_state":recovery.get("state"),"proof_checks":proof_checks}, sort_keys=True))
                        _fail(409,"restore_quarantined","Issuer proof does not match this credential version")
                existing = c.execute(sa.select(connector_submissions).where(connector_submissions.c.submission_id==submission_id).with_for_update()).mappings().first()
                if not existing or existing["actor_id"]!=actor or existing["outcome"]!="unknown": _fail(409,"submission_conflict","Submission ID is already closed")
                if c.execute(sa.select(connector_secrets.c.version_id).where(connector_secrets.c.connector_id==connector_id,connector_secrets.c.version_id==version_id)).first():
                    _fail(409,"submission_conflict","Version ID is already used")
                secret_row = c.execute(sa.select(connector_secrets.c.purpose).where(connector_secrets.c.connector_id==connector_id,connector_secrets.c.secret_id==secret_id).limit(1)).first()
                if secret_row and secret_row[0]!=body["purpose"]: _fail(409,"revision_conflict","Secret purpose is immutable")
                head = c.execute(sa.select(connector_secret_heads).where(connector_secret_heads.c.connector_id==connector_id,connector_secret_heads.c.secret_id==secret_id).with_for_update()).mappings().first()
                if head is None:
                    c.execute(connector_secret_heads.insert().values(connector_id=connector_id,secret_id=secret_id,purpose=body["purpose"],revision=0))
                    head={"revision":0}
                elif head["purpose"]!=body["purpose"]: _fail(409,"revision_conflict","Secret purpose is immutable")
                actual = _revisions(row,policy,context,int(head["revision"]))
                _check_revisions(body["expected_revisions"],actual)
                if len(raw) < 1 or len(raw) > 65536:
                    _fail(400,"invalid_request","Secret value must contain 1 to 65536 UTF-8 bytes")
                active_settings=_settings(row,c,connector_id)
                provider=active_settings.get("secret_source")
                if not isinstance(provider,dict) or provider.get("kind")!="encrypted_local_v1":
                    _fail(409,"credentials_unavailable","Encrypted-local source is not selected")
                # Secret content never participates in audit, receipts, or a request digest.
                try:
                    nonce = _reserved_nonce(c, provider.get("key_binding_id", ""),
                        "secret", version_id, now)
                    encrypted=encrypt(raw,connector_id,secret_id,version_id,nonce=nonce)
                except (ValueError, RuntimeError):
                    _fail(503,"credentials_unavailable","Encrypted-local source is unavailable")
                if encrypted["key_id"]!=provider.get("key_binding_id"):
                    _fail(503,"credentials_unavailable","Encrypted-local key binding changed")
                del raw
                sequence = c.execute(sa.select(sa.func.max(assessment_audit_events.c.event_sequence))).scalar_one() or 0
                event_id = str(uuid.uuid4())
                receipt = {"schema_version":1,"command_id":submission_id,"action":"connector.secret.submit","target_id":ZERO,
                    "policy_revision":policy["revision"],"decision_id":str(uuid.uuid4()),"audit_event_id":event_id,"intents":[],
                    "result":{"effect":"connector_secret_submitted","connector_id":connector_id,"source_id":binding["source_id"],
                        "revisions":_revisions(row,policy,context,int(head["revision"])+1),
                        "configuration_revision":row["configuration_revision"],"active_configuration_revision":row["active_configuration_revision"],
                        "lifecycle":row["lifecycle"],"secret_id":secret_id,"version_id":version_id,"version_state":"inactive",
                        "submission_id":submission_id,"submission_outcome":"committed","flow_id":None,"recovery":row["recovery"]}}
                after = {"connector_id":connector_id,"source_id":binding["source_id"],"secret_id":secret_id,"version_id":version_id,
                    "purpose":body["purpose"],"state":"inactive","ciphertext_present":True}
                c.execute(connector_secrets.insert().values(connector_id=connector_id,secret_id=secret_id,version_id=version_id,
                    purpose=body["purpose"],state="inactive",algorithm=encrypted["algorithm"],key_id=encrypted["key_id"],
                    nonce=encrypted["nonce"],ciphertext=encrypted["ciphertext"],reference=None,quarantine="clear",
                    remote_revocation={"status":"not_requested","intent_id":None,"observed_at":None,"expires_at":None,"reason":None},
                    actor_id=actor,created_at=now))
                c.execute(connector_secret_heads.update().where(connector_secret_heads.c.connector_id==connector_id,
                    connector_secret_heads.c.secret_id==secret_id).values(revision=int(head["revision"])+1))
                c.execute(connector_submissions.update().where(connector_submissions.c.submission_id==submission_id).values(
                    outcome="committed",receipt=receipt))
                c.execute(assessment_audit_events.insert().values(event_id=event_id,event_sequence=sequence+1,
                    actor_id=actor,actor_kind="principal",origin="local_api",action="connector.secret.submit",target_id=ZERO,
                    before_value={"connector_id":connector_id,"secret_id":secret_id},after_value=after,membership_ids=[],
                    membership_revision=0,rationale=body["rationale"],evidence_ref=body["evidence_ref"],
                    policy_revision=policy["revision"],identity_revision=0,occurred_at=now,received_at=now,
                    correlation_id=str(uuid.uuid4()),command_id=submission_id,
                    authorization_context=context.document() if context else None))
                digest = hashlib.sha256(json.dumps({k:v for k,v in body.items() if k!="input"},sort_keys=True,separators=(",",":")).encode()).hexdigest()
                c.execute(connector_receipts.insert().values(connector_id=connector_id,command_id=submission_id,actor_id=actor,
                    action="connector.secret.submit",request_digest=digest,receipt=receipt,created_at=now))
                return receipt
        except HTTPException:
            # Policy/validation failures after durable admission are known not
            # to have committed the secret transaction. Close the ID as a
            # durable tombstone so the client can recover and retry safely.
            with engine.begin() as settlement:
                settlement.execute(connector_submissions.update().where(
                    connector_submissions.c.submission_id == submission_id,
                    connector_submissions.c.outcome == "unknown").values(
                    outcome="not_committed", retry_allowed=True, receipt=None))
            raise
        except sa.exc.DBAPIError as exc:
            # Only a database-reported statement failure proves rollback. A
            # broken connection or other unconfirmed commit remains unknown.
            sqlstate = getattr(getattr(exc, "orig", None), "sqlstate", None)
            if exc.connection_invalidated or not sqlstate:
                raise
            with engine.begin() as settlement:
                settlement.execute(connector_submissions.update().where(
                    connector_submissions.c.submission_id == submission_id,
                    connector_submissions.c.outcome == "unknown").values(
                    outcome="not_committed", retry_allowed=True, receipt=None))
            raise HTTPException(status_code=503, detail={"code":"dependency_unavailable",
                "message":"Secret submission was rolled back",
                "details":{"outcome":"not_committed","expected_revisions":None,
                    "current_revisions":None,"lookup_url":None}}) from None


    @app.get("/api/v1/connectors/{connector_id}/secret-submissions/{submission_id}")
    def lookup_submission(connector_id: str, submission_id: str, request: Request,
                          source_id: str, secret_id: str, version_id: str):
        actor=_authenticate(app,request); binding=_ensure(app,connector_id)
        for value,label in ((connector_id,"connector_id"),(submission_id,"submission_id"),(source_id,"source_id"),(secret_id,"secret_id"),(version_id,"version_id")):_uuid(value,label)
        if source_id!=binding["source_id"]:_fail(403,"source_scope_forbidden","Source scope does not match")
        with engine.begin() as c:
            context=_auth_context(app,request,c);policy=_policy(c);_require(policy["document"],actor,"connector.secret.manage",binding)
            row=c.execute(sa.select(connector_submissions).where(connector_submissions.c.submission_id==submission_id)).mappings().first()
            if row is None:return {"schema_version":1,"submission_id":submission_id,"connector_id":connector_id,"source_id":source_id,"secret_id":secret_id,"version_id":version_id,"outcome":"unknown","receipt":None,"retry_allowed":False,"poll_after_ms":1000}
            if (row["actor_id"]!=actor or row["connector_id"]!=connector_id or row["source_id"]!=source_id or row["secret_id"]!=secret_id or row["version_id"]!=version_id):_fail(404,"not_found","Submission does not exist")
            retry_allowed = True if row["outcome"] == "not_committed" else bool(row["retry_allowed"])
            return {"schema_version":1,"submission_id":submission_id,"connector_id":connector_id,"source_id":source_id,"secret_id":secret_id,"version_id":version_id,"outcome":row["outcome"],"receipt":row["receipt"],"retry_allowed":retry_allowed,"poll_after_ms":1000 if row["outcome"]=="unknown" else None}

    @app.get("/api/v1/connectors/{connector_id}/secrets/{secret_id}")
    def read_secret(connector_id: str, secret_id: str, request: Request, source_id: str):
        actor=_authenticate(app,request);binding=_ensure(app,connector_id)
        for value in (connector_id,secret_id,source_id):_uuid(value)
        if source_id!=binding["source_id"]:_fail(403,"source_scope_forbidden","Source scope does not match")
        with engine.begin() as c:
            context=_auth_context(app,request,c);policy=_policy(c);_require(policy["document"],actor,"connector.read",binding)
            row=c.execute(sa.select(connectors).where(connectors.c.connector_id==connector_id)).mappings().one()
            secret=_secret_view(c,connector_id,secret_id)
            if not secret:_fail(404,"not_found","Secret does not exist")
            return {"schema_version":1,"connector_id":connector_id,"source":{"source_id":source_id,"revision":row["source_revision"],"source_family":row["source_family"],"source_account_id":row["source_account_id"],"scope_key":row["scope_key"]},"revisions":_revisions(row,policy,context,secret["revision"]),"secret":secret,"recovery":row["recovery"]}

    @app.get("/api/v1/connectors/{connector_id}/sources/{source_id}")
    def read_connector_source(connector_id: str, source_id: str, request: Request):
        actor=_authenticate(app,request);binding=_ensure(app,connector_id)
        if source_id!=binding["source_id"]:_fail(403,"source_scope_forbidden","Source scope does not match")
        with engine.begin() as c:
            context=_auth_context(app,request,c);policy=_policy(c);_require(policy["document"],actor,"connector.read",binding)
            row=c.execute(sa.select(connectors).where(connectors.c.connector_id==connector_id)).mappings().one()
            provider=_settings(row,c,connector_id).get("secret_source")
            return {"schema_version":1,"connector_id":connector_id,"source":{"source_id":source_id,"revision":row["source_revision"],"source_family":row["source_family"],"source_account_id":row["source_account_id"],"scope_key":row["scope_key"]},"revisions":_revisions(row,policy,context),"secret_source":provider}

    @app.get("/api/v1/connectors/{connector_id}/configurations/{configuration_revision}")
    def read_configuration(connector_id: str, configuration_revision: int, request: Request, source_id: str):
        actor=_authenticate(app,request);binding=_ensure(app,connector_id)
        if source_id!=binding["source_id"]:_fail(403,"source_scope_forbidden","Source scope does not match")
        with engine.begin() as c:
            context=_auth_context(app,request,c);policy=_policy(c);_require(policy["document"],actor,"connector.read",binding)
            row=c.execute(sa.select(connectors).where(connectors.c.connector_id==connector_id)).mappings().one()
            config=c.execute(sa.select(connector_configurations).where(connector_configurations.c.connector_id==connector_id,connector_configurations.c.configuration_revision==configuration_revision)).mappings().first()
            if config is None:_fail(404,"not_found","Configuration does not exist")
            return {"schema_version":1,"connector_id":connector_id,"source":{"source_id":source_id,"revision":row["source_revision"],"source_family":row["source_family"],"source_account_id":row["source_account_id"],"scope_key":row["scope_key"]},"revisions":_revisions(row,policy,context),"configuration_revision":configuration_revision,"settings":config["settings"],"created_at":_z(config["created_at"])}

    @app.get("/api/v1/connectors/{connector_id}/receipts/{command_id}")
    def read_connector_receipt(connector_id: str, command_id: str, request: Request, source_id: str):
        actor=_authenticate(app,request);binding=_ensure(app,connector_id)
        if source_id!=binding["source_id"]:_fail(403,"source_scope_forbidden","Source scope does not match")
        with engine.begin() as c:
            context=_auth_context(app,request,c);policy=_policy(c)
            receipt=c.execute(sa.select(connector_receipts).where(connector_receipts.c.connector_id==connector_id,connector_receipts.c.command_id==command_id)).mappings().first()
            if receipt is None:_fail(404,"not_found","Receipt does not exist")
            if not _grants(policy["document"],actor,"connector.read",binding) and not (receipt["actor_id"]==actor and _grants(policy["document"],actor,"connector.configure",binding)):_fail(403,"forbidden","Current connector permission is required")
            return receipt["receipt"]

    @app.get("/api/v1/connectors/{connector_id}/intents/{intent_id}")
    def read_connector_intent(connector_id: str, intent_id: str, request: Request, source_id: str):
        actor=_authenticate(app,request);binding=_ensure(app,connector_id)
        if source_id!=binding["source_id"]:_fail(403,"source_scope_forbidden","Source scope does not match")
        # Snapshot authority, candidate credentials and repository bindings in
        # a short transaction. Provider I/O below runs after this transaction
        # closes; the later commit path reacquires ordered locks and rechecks.
        provider_probe = None
        provider_snapshot = None
        with engine.begin() as snapshot_connection:
            lock_policy(snapshot_connection)
            snapshot_context=_auth_context(app,request,snapshot_connection)
            snapshot_policy=_policy(snapshot_connection)
            snapshot_row=snapshot_connection.execute(sa.select(connectors).where(
                connectors.c.connector_id==connector_id)).mappings().first()
            snapshot_intent=snapshot_connection.execute(sa.select(connector_intents).where(
                connector_intents.c.connector_id==connector_id,
                connector_intents.c.intent_id==intent_id)).mappings().first()
            if not _grants(snapshot_policy["document"], actor, "connector.read", binding) and not (
                    snapshot_intent is not None and snapshot_intent["actor_id"] == actor and
                    _grants(snapshot_policy["document"], actor, "connector.configure", binding)):
                _fail(403, "forbidden", "Current connector permission is required")
            if snapshot_row is None or snapshot_intent is None:
                _fail(404, "not_found", "Intent does not exist")
            if (snapshot_intent["status"] == "pending" and (
                    snapshot_intent["kind"] == "connector.validate" or
                    (snapshot_intent["kind"] == "connector.reconcile" and
                        (snapshot_intent["payload"] or {}).get("reason") == "configuration_rollback"))):
                if snapshot_intent["actor_id"] != actor:
                    _fail(403, "forbidden", "Only the initiating connector operator may complete this intent")
                _require(snapshot_policy["document"], actor, "connector.configure", binding)
                _require(snapshot_policy["document"], actor, "connector.secret.manage", binding)
            from uvm.operations.backup_settings import intent_quarantined
            if intent_quarantined(snapshot_connection, intent_id, connector_id):
                _fail(409, "restore_uncertain_effect", "Intent is held for recovery reconciliation")
            if (snapshot_row is not None and snapshot_intent is not None
                    and snapshot_intent["kind"]=="connector.validate"
                    and snapshot_intent["status"]=="pending"):
                if snapshot_intent["actor_id"]!=actor:
                    _fail(403,"forbidden","Only the initiating connector operator may complete validation")
                _require(snapshot_policy["document"],actor,"connector.configure",binding)
                _require(snapshot_policy["document"],actor,"connector.secret.manage",binding)
                payload=snapshot_intent["payload"] or {}
                revision=payload.get("configuration_revision")
                current_scope=(revision==snapshot_row["configuration_revision"]
                    and payload.get("source_revision")==snapshot_row["source_revision"]
                    and payload.get("secret_source_revision")==snapshot_row["secret_source_revision"]
                    and payload.get("connector_revision")==snapshot_row["connector_revision"]
                    and payload.get("policy_revision")==snapshot_policy["revision"]
                    and snapshot_context is not None
                    and payload.get("authority_revision")==getattr(snapshot_context,"policy_revision",None))
                if current_scope:
                    provider_probe=_validation_result(snapshot_connection,connector_id,
                        payload.get("settings",{}),revision,snapshot_row,_now(app))
                    if provider_probe["valid"]:
                        from uvm.connectors.runtime import prepare_provider_candidate
                        provider_snapshot=prepare_provider_candidate(snapshot_connection,
                            snapshot_row,payload.get("settings",{}))
                else:
                    provider_probe={"valid":False,"reason":"scope_changed"}
            elif (snapshot_row is not None and snapshot_intent is not None
                    and snapshot_intent["kind"] == "connector.reconcile"
                    and snapshot_intent["status"] == "pending"
                    and (snapshot_intent["payload"] or {}).get("reason") == "configuration_rollback"):
                if snapshot_intent["actor_id"] != actor:
                    _fail(403,"forbidden","Only the initiating connector operator may complete reconciliation")
                _require(snapshot_policy["document"],actor,"connector.configure",binding)
                _require(snapshot_policy["document"],actor,"connector.secret.manage",binding)
                payload=snapshot_intent["payload"] or {}
                current_scope=(snapshot_row["configuration_revision"]==payload.get("configuration_revision")
                    and snapshot_row["active_configuration_revision"]==payload.get("configuration_revision")
                    and snapshot_row["lifecycle"]=="active"
                    and snapshot_row["recovery"].get("state")=="clear"
                    and payload.get("policy_revision")==snapshot_policy["revision"]
                    and snapshot_context is not None
                    and payload.get("authority_revision")==getattr(snapshot_context,"policy_revision",None))
                if current_scope:
                    from uvm.connectors.runtime import prepare_provider_candidate
                    candidate_settings=_settings(snapshot_row,snapshot_connection,connector_id)
                    provider_probe={"valid":True,"reason":None}
                    provider_snapshot=prepare_provider_candidate(snapshot_connection,
                        snapshot_row,candidate_settings)
                else:
                    provider_probe={"valid":False,"reason":"scope_changed"}
        if provider_snapshot is not None:
            snapshot_values = {
                "configuration_revision": snapshot_row["configuration_revision"],
                "source_revision": snapshot_row["source_revision"],
                "secret_source_revision": snapshot_row["secret_source_revision"],
                "connector_revision": snapshot_row["connector_revision"],
                "policy_revision": snapshot_policy["revision"],
                "authority_revision": getattr(snapshot_context, "policy_revision", None),
                "settings": provider_snapshot["settings"],
                "intent_id": str(snapshot_intent["intent_id"]),
                "active_configuration_revision": snapshot_row["active_configuration_revision"],
                "lifecycle": snapshot_row["lifecycle"],
            }
            def validation_dispatch_fence(_method=None, _path=None):
                from uvm.assessment.policy_lock import lock_policy
                with engine.begin() as fence_connection:
                    lock_policy(fence_connection)
                    current_context = _auth_context(app, request, fence_connection)
                    current_policy = _policy(fence_connection)
                    current_row = fence_connection.execute(sa.select(connectors).where(
                        connectors.c.connector_id == connector_id).with_for_update()
                        ).mappings().first()
                    current_intent = fence_connection.execute(sa.select(connector_intents).where(
                        connector_intents.c.connector_id == connector_id,
                        connector_intents.c.intent_id == snapshot_values["intent_id"]
                        ).with_for_update()).mappings().first()
                    _require(current_policy["document"], actor, "connector.configure", binding)
                    _require(current_policy["document"], actor, "connector.secret.manage", binding)
                    if current_intent is not None and intent_quarantined(fence_connection, intent_id, connector_id):
                        _fail(409, "restore_uncertain_effect", "Intent is held for recovery reconciliation")
                    unchanged = (current_row is not None and current_intent is not None
                        and current_intent["status"] == "pending"
                        and current_intent["actor_id"] == actor
                        and current_policy["revision"] == snapshot_values["policy_revision"]
                        and current_context is not None
                        and getattr(current_context, "policy_revision", None) == snapshot_values["authority_revision"]
                        and all(current_row[key] == snapshot_values[key] for key in (
                            "configuration_revision", "source_revision",
                            "secret_source_revision", "connector_revision"))
                        and current_row["active_configuration_revision"] == snapshot_values["active_configuration_revision"]
                        and current_row["lifecycle"] == snapshot_values["lifecycle"]
                        and _settings(current_row, fence_connection, connector_id) == snapshot_values["settings"])
                    # A revision match alone is insufficient: secret heads can
                    # advance independently. Revalidate purpose, active/staged
                    # eligibility, quarantine and the live approved audience
                    # at every outbound request boundary.
                    if unchanged:
                        current_live = _validation_result(fence_connection, connector_id,
                            snapshot_values["settings"],
                            snapshot_values["configuration_revision"],
                            current_row, _now(app))
                        unchanged = bool(current_live["valid"])
                    if not unchanged:
                        from uvm.connectors.crypto import SecretUnavailable
                        raise SecretUnavailable("connector validation changed before provider dispatch")
            try:
                from uvm.connectors.runtime import validate_provider_candidate_snapshot
                validate_provider_candidate_snapshot(provider_snapshot,
                    before_request=validation_dispatch_fence)
            except Exception as exc:
                from uvm.connectors.crypto import SecretUnavailable
                provider_probe["valid"]=False
                provider_probe["reason"]=("credentials_unavailable" if isinstance(
                    exc,SecretUnavailable) else "provider_unavailable")
        with engine.begin() as c:
            # Authority-first ordering matches dispatch admission and avoids
            # acquiring the policy row while waiting on its advisory fence.
            lock_policy(c)
            context=_auth_context(app,request,c);policy=_policy(c)
            row=c.execute(sa.select(connectors).where(connectors.c.connector_id==connector_id)).mappings().one()
            intent=c.execute(sa.select(connector_intents).where(connector_intents.c.connector_id==connector_id,connector_intents.c.intent_id==intent_id)).mappings().first()
            if intent is None:_fail(404,"not_found","Intent does not exist")
            if not _grants(policy["document"],actor,"connector.read",binding) and not (intent["actor_id"]==actor and _grants(policy["document"],actor,"connector.configure",binding)):_fail(403,"forbidden","Current connector permission is required")
            if intent_quarantined(c, intent_id, connector_id):
                _fail(409, "restore_uncertain_effect", "Intent is held for recovery reconciliation")
            disable_connector=False
            if intent["kind"]=="connector.validate" and intent["status"]=="pending":
                if intent["actor_id"] != actor:
                    _fail(403,"forbidden","Only the initiating connector operator may complete validation")
                _require(policy["document"],actor,"connector.configure",binding)
                # The GET performs provider I/O using the staged credential;
                # legacy REST tokens receive the same write-only authority
                # protection as App credentials.
                _require(policy["document"],actor,"connector.secret.manage",binding)
                revision=intent["payload"].get("configuration_revision")
                if (revision!=row["configuration_revision"] or intent["payload"].get("source_revision")!=row["source_revision"]
                        or intent["payload"].get("secret_source_revision")!=row["secret_source_revision"]
                        or intent["payload"].get("connector_revision")!=row["connector_revision"]
                        or intent["payload"].get("policy_revision")!=policy["revision"]):
                    result={"configuration_revision":revision,"source_revision":intent["payload"].get("source_revision"),
                        "secret_source_revision":intent["payload"].get("secret_source_revision"),"credentials":[],
                        "installation":None,"repository_ids":[],"audience_revisions":{},"checked_at":_z(_now(app)),
                        "valid":False,"reason":"scope_changed"}
                else:
                    result=_validation_result(c,connector_id,intent["payload"].get("settings",{}),revision,row,_now(app))
                    if result["valid"] and provider_probe is not None and not provider_probe.get("valid"):
                        result["valid"]=False
                        result["reason"]=provider_probe.get("reason","provider_unavailable")
                    elif result["valid"] and provider_snapshot is None:
                        result["valid"]=False
                        result["reason"]="scope_changed"
                policy,context,current_row,current_intent,unchanged=_lock_intent_commit(
                    app,request,c,connector_id,intent_id,actor,binding,intent,
                    secret_required=True)
                checked=_now(app)
                if not unchanged:
                    result.update(valid=False,reason="scope_changed",checked_at=_z(checked))
                elif result["valid"]:
                    live=_validation_result(c,connector_id,
                        intent["payload"].get("settings",{}),revision,current_row,checked)
                    if not live["valid"]:
                        result.update(valid=False,reason=live["reason"],checked_at=_z(checked))
                state="valid" if result["valid"] else "failed"
                c.execute(connector_intents.update().where(connector_intents.c.connector_id==connector_id,
                    connector_intents.c.intent_id==intent_id,
                    connector_intents.c.status=="pending").values(
                    status="complete",attempts=current_intent["attempts"]+1,result=result,updated_at=checked))
                if unchanged:
                    c.execute(connectors.update().where(connectors.c.connector_id==connector_id,
                        connectors.c.connector_revision==current_row["connector_revision"]).values(
                        validation={"status":state,"checked_at":_z(checked),"intent_id":intent_id,
                            "configuration_revision":revision,"reason":result["reason"]},
                        connector_revision=current_row["connector_revision"]+1,updated_at=checked))
                intent=c.execute(sa.select(connector_intents).where(connector_intents.c.intent_id==intent_id)).mappings().one()
            elif intent["kind"]=="connector.reconcile" and intent["status"]=="pending":
                if intent["actor_id"]!=actor:
                    _fail(403,"forbidden","Only the initiating connector operator may complete reconciliation")
                _require(policy["document"],actor,"connector.configure",binding)
                payload=intent["payload"] or {};reason=payload.get("reason")
                if (payload.get("policy_revision") is not None and payload["policy_revision"]!=policy["revision"]
                        or payload.get("authority_revision") is not None
                        and payload["authority_revision"]!=getattr(context,"policy_revision",policy["revision"])):
                    result={"reason":"scope_changed","verified":False}
                    state="failed"
                    disable_connector=(reason == "configuration_rollback"
                        and row["lifecycle"] == "active"
                        and row["active_configuration_revision"] == payload.get("configuration_revision"))
                elif reason=="connector_disabled" and row["lifecycle"]=="disabled" and row["active_configuration_revision"] is None:
                    result={"reason":None,"verified":True,"configuration_revision":row["configuration_revision"],
                        "provider_readback":"not_active"}
                    state="complete"
                elif (reason=="configuration_rollback" and row["lifecycle"]=="active"
                        and row["active_configuration_revision"]==payload.get("configuration_revision")
                        and row["configuration_revision"]==payload.get("configuration_revision")
                        and row["recovery"].get("state")=="clear"):
                    _require(policy["document"],actor,"connector.secret.manage",binding)
                    if provider_probe is not None and provider_probe.get("valid"):
                        result={"reason":None,"verified":True,
                            "configuration_revision":row["configuration_revision"],
                            "provider_readback":"complete"}
                        state="complete"
                    else:
                        result={"reason":"reconciliation_failed","verified":False,
                            "configuration_revision":row["configuration_revision"]}
                        state="failed"
                        disable_connector=True
                else:
                    result={"reason":"scope_changed","verified":False,
                        "configuration_revision":row["configuration_revision"]}
                    state="failed"
                policy,context,current_row,current_intent,unchanged=_lock_intent_commit(
                    app,request,c,connector_id,intent_id,actor,binding,intent,
                    secret_required=(reason == "configuration_rollback"))
                if not unchanged:
                    result={"reason":"scope_changed","verified":False,
                        "configuration_revision":current_row["configuration_revision"]}
                    state="failed"
                    disable_connector=(reason == "configuration_rollback"
                        and current_row["lifecycle"] == "active"
                        and current_row["active_configuration_revision"] == payload.get("configuration_revision"))
                elif reason == "configuration_rollback" and result.get("verified"):
                    live = _validation_result(c,connector_id,
                        _settings(current_row,c,connector_id),
                        current_row["configuration_revision"],current_row,_now(app))
                    if not live["valid"]:
                        result={"reason":live.get("reason") or "scope_changed",
                            "verified":False,
                            "configuration_revision":current_row["configuration_revision"]}
                        state="failed"
                        disable_connector=True
                # A changed authority/policy binding is exactly why a failed
                # rollback reconciliation must close runtime. The exact active
                # configuration revision check above prevents disabling a
                # newer operator-selected candidate.
                if disable_connector:
                    c.execute(connectors.update().where(connectors.c.connector_id==connector_id,
                        connectors.c.connector_revision==current_row["connector_revision"],
                        connectors.c.configuration_revision==payload.get("configuration_revision"),
                        connectors.c.active_configuration_revision==payload.get("configuration_revision")).values(
                        lifecycle="disabled",active_configuration_revision=None,
                        connector_revision=current_row["connector_revision"]+1,updated_at=_now(app)))
                checked=_now(app)
                c.execute(connector_intents.update().where(connector_intents.c.connector_id==connector_id,
                    connector_intents.c.intent_id==intent_id,
                    connector_intents.c.status=="pending").values(
                    status=state,attempts=current_intent["attempts"]+1,result=result,updated_at=checked))
                intent=c.execute(sa.select(connector_intents).where(connector_intents.c.intent_id==intent_id)).mappings().one()
            status={"uncertain":"outcome_unknown","running":"pending"}.get(intent["status"],intent["status"])
            result=intent["result"] if isinstance(intent["result"],dict) else None
            return {"schema_version":1,"connector_id":connector_id,"source_id":source_id,"intent_id":intent_id,
                "kind":intent["kind"],"status":status,"attempts":intent["attempts"],
                "last_error":result.get("reason") if result else None,"next_attempt_at":None,
                "completed_at":_z(intent["updated_at"]) if status in {"complete","failed"} else None,
                "validation_result":intent["result"] if intent["kind"]=="connector.validate" else None,
                "observed_remote_revocation":None}

    @app.post("/api/v1/connectors/{connector_id}/installation-flows", status_code=201)
    def start_installation_flow(connector_id: str, body: dict, request: Request):
        _uuid(connector_id, "connector_id"); actor = _authenticate(app, request)
        binding = _ensure(app, connector_id)
        required = {"schema_version", "command_id", "source_id", "configuration_revision",
                    "expected_revisions", "rationale", "evidence_ref"}
        if not isinstance(body, dict) or set(body) != required or body.get("schema_version") != 1:
            _fail(400, "invalid_request", "Installation flow request is invalid")
        command_id = _uuid(body["command_id"], "command_id")
        if body["source_id"] != binding["source_id"]: _fail(403, "source_scope_forbidden", "Source scope does not match")
        if not isinstance(body["rationale"], str) or not body["rationale"].strip() or not isinstance(body["evidence_ref"], str) or not body["evidence_ref"].strip():
            _fail(400, "invalid_request", "Rationale and evidence reference are required")
        now = _now(app); state = secrets.token_urlsafe(32); verifier = secrets.token_urlsafe(48)
        challenge = __import__("base64").urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")
        flow_id = str(uuid.uuid4())
        app_url = os.getenv("UVM_GITHUB_APP_BASE_URL")
        if not app_url:
            app_url = "http://127.0.0.1:19002" if os.getenv("UVM_G7_DISPOSABLE_MODE") == "1" else "https://github.com"
        with engine.begin() as c:
            lock_policy(c); context = _auth_context(app, request, c); policy = _policy(c)
            _require(policy["document"], actor, "connector.configure", binding)
            row = c.execute(sa.select(connectors).where(connectors.c.connector_id == connector_id).with_for_update()).mappings().one()
            _check_revisions(body["expected_revisions"], _revisions(row, policy, context))
            if row["configuration_revision"] != body["configuration_revision"]: _fail(409, "revision_conflict", "Configuration revision is stale")
            if row["recovery"].get("state") != "clear": _fail(409, "restore_quarantined", "Connector recovery fence is closed")
            settings = _settings(row, c, connector_id); github = settings.get("github") or {}; appdata = github.get("app")
            if settings.get("authentication_mode") != "github_app_v1" or not isinstance(appdata, dict): _fail(409, "credentials_unavailable", "A staged GitHub App candidate is required")
            if not context or context.credential_mode != "oidc_session" or not context.session_id: _fail(401, "authentication_required", "A live browser session is required")
            if _grants(policy["document"], actor, "connector.secret.manage", binding) == []: _fail(403, "forbidden", "Secret management permission is required to resolve setup credentials")
            credential_refs = settings.get("credentials") or {}
            for purpose in ("private_key", "oauth_client_secret"):
                ref = credential_refs.get(purpose)
                if not isinstance(ref, dict): _fail(409, "credentials_unavailable", "App setup credentials are not staged")
                secret = c.execute(sa.select(connector_secrets).where(connector_secrets.c.connector_id == connector_id,
                    connector_secrets.c.secret_id == ref["secret_id"], connector_secrets.c.version_id == ref["version_id"])).mappings().first()
                head = c.execute(sa.select(connector_secret_heads.c.revision).where(connector_secret_heads.c.connector_id == connector_id,
                    connector_secret_heads.c.secret_id == ref["secret_id"])).scalar_one_or_none()
                if not secret or secret["purpose"] != purpose or secret["state"] == "revoked" or secret["quarantine"] != "clear" or int(head or 0) != ref["secret_revision"]:
                    _fail(409, "credential_revoked", "An App setup credential is revoked, quarantined or stale")
            key_id = os.getenv("UVM_CONNECTOR_LOCAL_KEY_ID", "")
            nonce = _reserved_nonce(c, key_id, "flow_verifier", flow_id, now)
            encrypted = encrypt(verifier.encode(), connector_id, flow_id, flow_id, nonce=nonce)
            expires = now + timedelta(minutes=10)
            flow_app = {"app_id": appdata["app_id"], "client_id": appdata["client_id"], "slug": appdata["slug"]}
            c.execute(connector_setup_flows.insert().values(flow_id=flow_id, connector_id=connector_id,
                actor_id=actor, session_id=context.session_id, configuration_revision=row["configuration_revision"],
                credential_binding={"configuration_revision":row["configuration_revision"],
                    "source_revision":row["source_revision"],"policy_revision":policy["revision"],
                    "credentials":{purpose:{"secret_id":credential_refs[purpose]["secret_id"],
                        "secret_revision":credential_refs[purpose]["secret_revision"],
                        "version_id":credential_refs[purpose]["version_id"]}
                        for purpose in ("private_key","oauth_client_secret")}},
                state_digest=hashlib.sha256(state.encode()).hexdigest(), verifier_key_id=encrypted["key_id"],
                verifier_nonce=encrypted["nonce"], verifier_ciphertext=encrypted["ciphertext"],
                status="awaiting_installation", failure_reason=None, app=flow_app, installation=None,
                granted_permissions={"issues":"none","metadata":"none","administration":"none","members":"none"},
                repositories=[], repositories_complete=False, verification_receipt=None, expires_at=expires,
                consumed_at=None, created_at=now))
            audit_event_id = str(uuid.uuid4())
            event_sequence = c.execute(sa.select(sa.func.max(assessment_audit_events.c.event_sequence))).scalar_one() or 0
            receipt = {"schema_version":1,"command_id":command_id,"action":"connector.installation.start",
                "target_id":ZERO,"policy_revision":policy["revision"],"decision_id":str(uuid.uuid4()),
                "audit_event_id":audit_event_id,"intents":[],"result":{"effect":"connector_installation_started",
                "connector_id":connector_id,"source_id":binding["source_id"],"revisions":_revisions(row,policy,context),
                "configuration_revision":row["configuration_revision"],
                "active_configuration_revision":row["active_configuration_revision"],"lifecycle":row["lifecycle"],
                "secret_id":None,"version_id":None,"version_state":None,"submission_id":None,
                "submission_outcome":None,"flow_id":flow_id,"recovery":row["recovery"]}}
            digest = hashlib.sha256(json.dumps({k:v for k,v in body.items() if k != "expected_revisions"}, sort_keys=True).encode()).hexdigest()
            c.execute(connector_receipts.insert().values(connector_id=connector_id, command_id=command_id,
                actor_id=actor, action="connector.installation.start", request_digest=digest, receipt=receipt, created_at=now))
            c.execute(assessment_audit_events.insert().values(event_id=audit_event_id,event_sequence=event_sequence+1,
                actor_id=actor,actor_kind="principal",origin="local_api",action="connector.installation.start",target_id=ZERO,
                before_value={"connector_id":connector_id,"configuration_revision":row["configuration_revision"]},
                after_value={"connector_id":connector_id,"flow_id":flow_id,"status":"awaiting_installation"},
                membership_ids=[],membership_revision=0,rationale=body["rationale"],evidence_ref=body["evidence_ref"],
                policy_revision=policy["revision"],identity_revision=0,occurred_at=now,received_at=now,
                correlation_id=str(uuid.uuid4()),command_id=command_id,
                authorization_context=context.document() if context else None))
            flow = c.execute(sa.select(connector_setup_flows).where(connector_setup_flows.c.flow_id == flow_id)).mappings().one()
            redirect = app_url.rstrip("/") + "/apps/" + appdata["slug"] + "/installations/new?" + urlencode({"state":state,"setup_action":"install"})
            return {"schema_version":1,"flow":_flow_view(flow, connector_id, binding["source_id"]),"redirect_url":redirect,"receipt":receipt}

    @app.get("/api/v1/connectors/{connector_id}/installation-flows/{flow_id}")
    def read_installation_flow(connector_id: str, flow_id: str, request: Request, source_id: str):
        _uuid(connector_id, "connector_id"); _uuid(flow_id, "flow_id"); _uuid(source_id, "source_id")
        actor = _authenticate(app, request); binding = _ensure(app, connector_id)
        if source_id != binding["source_id"]: _fail(403, "source_scope_forbidden", "Source scope does not match")
        with engine.begin() as c:
            context = _auth_context(app, request, c); policy = _policy(c)
            _require(policy["document"], actor, "connector.configure", binding)
            flow = c.execute(sa.select(connector_setup_flows).where(connector_setup_flows.c.flow_id == flow_id,
                connector_setup_flows.c.connector_id == connector_id)).mappings().first()
            if flow is None or flow["actor_id"] != actor or not context or context.session_id != flow["session_id"]:
                _fail(404, "not_found", "Installation flow does not exist")
            if flow["status"] not in {"verified", "failed", "expired"} and flow["expires_at"] <= _now(app):
                c.execute(connector_setup_flows.update().where(connector_setup_flows.c.flow_id == flow_id).values(status="expired"))
                flow = dict(flow); flow["status"] = "expired"
            return _flow_view(flow, connector_id, source_id)

    @app.get("/api/v1/connectors/{connector_id}/installation/setup")
    def installation_setup(connector_id: str, request: Request, installation_id: str,
                           setup_action: str, state: str):
        _uuid(connector_id, "connector_id")
        if not installation_id.isdigit() or setup_action not in {"install", "update"} or not state:
            _fail(400, "callback_invalid", "Installation setup parameters are invalid")
        actor = _authenticate(app, request); binding = _ensure(app, connector_id)
        now = _now(app); auth_state = secrets.token_urlsafe(32); verifier = secrets.token_urlsafe(48)
        challenge = __import__("base64").urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")
        with engine.begin() as c:
            context = _auth_context(app, request, c); policy = _policy(c); lock_policy(c)
            _require(policy["document"], actor, "connector.configure", binding)
            _require(policy["document"], actor, "connector.secret.manage", binding)
            connector_row = c.execute(sa.select(connectors).where(
                connectors.c.connector_id == connector_id).with_for_update()).mappings().one()
            if connector_row["recovery"].get("state") != "clear":
                _fail(409, "restore_quarantined", "Connector recovery fence is closed")
            flow = c.execute(sa.select(connector_setup_flows).where(connector_setup_flows.c.connector_id == connector_id,
                connector_setup_flows.c.state_digest == hashlib.sha256(state.encode()).hexdigest()).with_for_update()).mappings().first()
            if not flow or flow["actor_id"] != actor or not context or context.session_id != flow["session_id"] or flow["status"] != "awaiting_installation" or flow["expires_at"] <= now or flow["consumed_at"]:
                _fail(400, "callback_invalid", "Installation flow is invalid")
            candidate = {"candidate_installation_id":installation_id, "setup_action":setup_action}
            key_id = os.getenv("UVM_CONNECTOR_LOCAL_KEY_ID", "")
            nonce = _reserved_nonce(c, key_id, "flow_verifier", flow["flow_id"], now)
            encrypted = encrypt(verifier.encode(), connector_id, flow["flow_id"], flow["flow_id"], nonce=nonce)
            c.execute(connector_setup_flows.update().where(connector_setup_flows.c.flow_id == flow["flow_id"]).values(
                state_digest=hashlib.sha256(auth_state.encode()).hexdigest(), verifier_key_id=encrypted["key_id"],
                verifier_nonce=encrypted["nonce"], verifier_ciphertext=encrypted["ciphertext"],
                status="awaiting_authorization", installation=candidate, consumed_at=now))
            # Public fixed loopback endpoints are configured by deployment, never by the request.
            base = os.getenv("UVM_CONNECTOR_PUBLIC_BASE_URL", "http://127.0.0.1:8081")
            callback = base.rstrip("/") + f"/api/v1/connectors/{connector_id}/installation/callback"
            # Keep the public App install origin distinct from the configured
            # OAuth authorisation origin. Disposable journeys route the first
            # through a browser allowlist and the second directly to loopback.
            if os.getenv("UVM_G7_DISPOSABLE_MODE") == "1":
                fixture_port = os.getenv("UVM_GITHUB_APP_FIXTURE_PORT", "19002")
                if not fixture_port.isdigit() or not 1 <= int(fixture_port) <= 65535:
                    _fail(503,"dependency_unavailable","Loopback GitHub App fixture is unavailable")
                oauth_base = "http://127.0.0.1:" + fixture_port
            else:
                oauth_base = os.getenv("UVM_GITHUB_OAUTH_BASE_URL",
                    os.getenv("UVM_GITHUB_APP_BASE_URL", "https://github.com")).rstrip("/")
            location = oauth_base + "/login/oauth/authorize?" + urlencode({"client_id":flow["app"]["client_id"],
                "redirect_uri":callback,"state":auth_state,"code_challenge":challenge,"code_challenge_method":"S256"})
            return RedirectResponse(location, status_code=303)

    @app.get("/api/v1/connectors/{connector_id}/installation/callback")
    def installation_callback(connector_id: str, request: Request, code: str | None = None,
                              error: str | None = None, state: str | None = None):
        _uuid(connector_id, "connector_id")
        if not state or (code is None) == (error is None): _fail(400, "callback_invalid", "OAuth callback is invalid")
        actor = _authenticate(app, request); binding = _ensure(app, connector_id); now = _now(app)
        with engine.begin() as c:
            lock_policy(c); context = _auth_context(app, request, c); policy = _policy(c)
            _require(policy["document"], actor, "connector.configure", binding)
            connector_row = c.execute(sa.select(connectors).where(
                connectors.c.connector_id == connector_id).with_for_update()).mappings().one()
            if connector_row["recovery"].get("state") != "clear":
                _fail(409, "restore_quarantined", "Connector recovery fence is closed")
            flow = c.execute(sa.select(connector_setup_flows).where(connector_setup_flows.c.connector_id == connector_id,
                connector_setup_flows.c.state_digest == hashlib.sha256(state.encode()).hexdigest()).with_for_update()).mappings().first()
            if not flow or flow["actor_id"] != actor or not context or context.session_id != flow["session_id"] or flow["status"] != "awaiting_authorization" or flow["expires_at"] <= now or flow["consumed_at"] is None:
                _fail(400, "callback_invalid", "OAuth callback is invalid")
            if error is not None:
                c.execute(connector_setup_flows.update().where(connector_setup_flows.c.flow_id == flow["flow_id"]).values(status="failed",failure_reason="provider_denied",installation=None))
                path = f"/administration/connectors/{connector_id}?installation_flow_id={flow['flow_id']}"
                return RedirectResponse(path, status_code=303)
            # Consume before contacting even the loopback provider. Recovery after a crash fails closed.
            c.execute(connector_setup_flows.update().where(connector_setup_flows.c.flow_id == flow["flow_id"]).values(status="verifying"))
            flow = dict(flow)
            settings = _settings(c.execute(sa.select(connectors).where(connectors.c.connector_id == connector_id)).mappings().one(), c, connector_id)
            refs = settings["credentials"]
            binding_snapshot = flow.get("credential_binding") or {}
            if (binding_snapshot.get("configuration_revision") != connector_row["configuration_revision"]
                    or binding_snapshot.get("source_revision") != connector_row["source_revision"]
                    or binding_snapshot.get("policy_revision") != policy["revision"]
                    or any(binding_snapshot.get("credentials", {}).get(purpose) != refs.get(purpose)
                        for purpose in ("private_key", "oauth_client_secret"))):
                _fail(409, "revision_conflict", "Installation credential binding changed")
            oauth_ref = refs["oauth_client_secret"]
            private_ref = refs["private_key"]
            oauth_secret = c.execute(sa.select(connector_secrets).where(connector_secrets.c.connector_id == connector_id,
                connector_secrets.c.secret_id == oauth_ref["secret_id"], connector_secrets.c.version_id == oauth_ref["version_id"])).mappings().one_or_none()
            private_secret = c.execute(sa.select(connector_secrets).where(connector_secrets.c.connector_id == connector_id,
                connector_secrets.c.secret_id == private_ref["secret_id"], connector_secrets.c.version_id == private_ref["version_id"])).mappings().one_or_none()
            for purpose, ref, credential in (("oauth_client_secret", oauth_ref, oauth_secret),
                    ("private_key", private_ref, private_secret)):
                head = c.execute(sa.select(connector_secret_heads.c.revision).where(
                    connector_secret_heads.c.connector_id == connector_id,
                    connector_secret_heads.c.secret_id == ref["secret_id"]).with_for_update()).scalar_one_or_none()
                if (not credential or credential["purpose"] != purpose
                        or credential["state"] == "revoked" or credential["quarantine"] != "clear"
                        or int(head or 0) != ref["secret_revision"]):
                    _fail(409, "credential_revoked", "An installation setup credential is no longer eligible")
            verifier_row = {"algorithm":"AES-256-GCM-v1","key_id":flow["verifier_key_id"],
                "nonce":flow["verifier_nonce"],"ciphertext":flow["verifier_ciphertext"]}
            verifier = decrypt(verifier_row, connector_id, flow["flow_id"], flow["flow_id"]).decode()
            client_secret = decrypt(oauth_secret, connector_id, oauth_ref["secret_id"], oauth_ref["version_id"]).decode()
            private_key = decrypt(private_secret, connector_id, private_ref["secret_id"], private_ref["version_id"])
            candidate = (flow["installation"] or {}).get("candidate_installation_id")
            appdata = flow["app"]
        import urllib.error, urllib.request
        api_base = os.getenv("UVM_GITHUB_API_BASE_URL", "http://127.0.0.1:19001/").rstrip("/") + "/"
        def fixture_call_response(path, method="GET", form=None, token=None, json_body=None):
            headers = {"Accept":"application/json"}
            if form is not None: headers["Content-Type"] = "application/x-www-form-urlencoded"
            if json_body is not None: headers["Content-Type"] = "application/json"
            if token: headers["Authorization"] = "Bearer " + token
            data = (urlencode(form).encode() if form is not None else
                json.dumps(json_body, sort_keys=True, separators=(",", ":")).encode()
                if json_body is not None else None)
            try:
                request_obj = urllib.request.Request(api_base + path, data=data,
                    headers=headers, method=method)
            except ValueError:
                raise ValueError("provider_request_invalid") from None
            try:
                with urllib.request.urlopen(request_obj, timeout=10) as response:
                    raw = response.read()
                    try:
                        return json.loads(raw), response.headers
                    except (ValueError, UnicodeError):
                        raise ValueError("provider_response_invalid") from None
            except urllib.error.HTTPError:
                raise
        def fixture_call(path, method="GET", form=None, token=None, json_body=None):
            return fixture_call_response(path, method, form, token, json_body)[0]
        def fixture_call_pages(path, token):
            pages=[]; current=path; seen=set(); total=None
            while current:
                absolute=urllib.parse.urljoin(api_base, current)
                parsed=urllib.parse.urlsplit(absolute)
                if parsed.netloc != urllib.parse.urlsplit(api_base).netloc or parsed.scheme != "http":
                    raise ValueError("provider_pagination_origin_changed")
                if absolute in seen: raise ValueError("provider_pagination_loop")
                seen.add(absolute)
                relative=urllib.parse.urlunsplit(("", "", parsed.path.lstrip("/"), parsed.query, ""))
                data, headers=fixture_call_response(relative, token=token)
                items=data.get("repositories"); count=data.get("total_count")
                if not isinstance(items,list) or type(count) is not int: raise ValueError("audience_incomplete")
                if total is None: total=count
                elif total != count: raise ValueError("audience_incomplete")
                pages.extend(items); next_url=None
                for part in headers.get("Link", "").split(","):
                    if 'rel="next"' in part:
                        start,end=part.find("<"),part.find(">")
                        if start<0 or end<=start: raise ValueError("audience_incomplete")
                        next_url=part[start+1:end]; break
                current=next_url
            if total is None or len(pages)!=total: raise ValueError("audience_incomplete")
            return pages
        verification_stage = "oauth_exchange"
        try:
            base = os.getenv("UVM_CONNECTOR_PUBLIC_BASE_URL", "http://127.0.0.1:8081").rstrip("/")
            callback = base + f"/api/v1/connectors/{connector_id}/installation/callback"
            oauth = fixture_call("login/oauth/access_token", "POST", {"client_id":appdata["client_id"],
                "client_secret":client_secret,"code":code,"code_verifier":verifier,"state":state,"redirect_uri":callback})
            token = oauth.get("access_token")
            verification_stage = "app_jwt"
            app_token = app_jwt(appdata["app_id"], private_key)
            verification_stage = "user_identity"
            user = fixture_call("user", token=token)
            verification_stage = "installation_identity"
            installations = fixture_call("user/installations", token=token).get("installations", [])
            selected = next((item for item in installations if str(item.get("id")) == str(candidate)), None)
            if not selected: raise ValueError("installation_not_accessible")
            verification_stage = "app_installation_identity"
            app_installation = fixture_call(f"app/installations/{candidate}", token=app_token)
            if str(app_installation.get("app_id")) != str(appdata["app_id"]) or app_installation.get("suspended_at"):
                raise ValueError("installation_identity_mismatch")
            if str(app_installation.get("account", {}).get("id")) != str(selected.get("account", {}).get("id")):
                raise ValueError("installation_account_mismatch")
            expected_permissions={"issues":"write","metadata":"read","administration":"read","members":"read"}
            if app_installation.get("permissions") != expected_permissions:
                raise ValueError("permissions_incomplete")
            verification_stage = "user_repository_readback"
            repositories = fixture_call_pages(f"user/installations/{candidate}/repositories?per_page=100", token)
            if not repositories or any(not str(item.get("id", "")).isdigit() for item in repositories):
                raise ValueError("audience_incomplete")
            scoped_ids = sorted({str(item["id"]) for item in repositories})
            # OAuth user discovery is the source for the initial visible repo list.
            # Selected repositories are checked later using read-only App tokens.
            grants = {"issues":"write","metadata":"read","administration":"read","members":"read"}
            installation = {"flow_id":flow["flow_id"],"installation_id":str(candidate),
                "account_id":str(selected.get("account", {}).get("id", "")),
                # Keep the user-authenticated identity internally for the
                # separately authorised identity-link command. It is never
                # sent to callers; unlike an installation token, this value
                # was read from /user using the OAuth user token above.
                "verified_user_id":str(user.get("id", ""))}
            public_repos = [{"repository_id":str(item["id"]),"owner":item["owner"],"name":item["name"],
                "private":bool(item.get("private")),"installation_access":True,
                "audience_status":"unapproved","audience_revision":None} for item in repositories]
            verification = {"schema_version":1,"command_id":str(uuid.uuid4()),"action":"connector.installation.verify",
                "target_id":ZERO,"policy_revision":policy["revision"],"decision_id":str(uuid.uuid4()),"audit_event_id":str(uuid.uuid4()),"intents":[],
                "result":{"effect":"connector_installation_verified","connector_id":connector_id,
                    "source_id":binding["source_id"],"revisions":None,
                    "configuration_revision":flow["configuration_revision"],
                    "active_configuration_revision":None,"lifecycle":"staged","secret_id":None,
                    "version_id":None,"version_state":None,"submission_id":None,
                    "submission_outcome":None,"flow_id":flow["flow_id"],"recovery":None}}
            verification_stage = "receipt_commit"
            with engine.begin() as c:
                lock_policy(c); current_context = _auth_context(app, request, c); current_policy = _policy(c)
                _require(current_policy["document"], actor, "connector.configure", binding)
                current = c.execute(sa.select(connector_setup_flows).where(connector_setup_flows.c.flow_id == flow["flow_id"]).with_for_update()).mappings().one()
                _require(current_policy["document"], actor, "connector.configure", binding)
                _require(current_policy["document"], actor, "connector.secret.manage", binding)
                current_connector = c.execute(sa.select(connectors).where(
                    connectors.c.connector_id == connector_id).with_for_update()).mappings().one()
                current_settings = _settings(current_connector, c, connector_id)
                binding_snapshot = flow.get("credential_binding") or {}
                if (binding_snapshot.get("configuration_revision") != current_connector["configuration_revision"]
                        or binding_snapshot.get("source_revision") != current_connector["source_revision"]
                        or any(current_settings.get("credentials", {}).get(purpose) != ref
                            for purpose, ref in (binding_snapshot.get("credentials") or {}).items())):
                    raise ValueError("flow_authority_changed")
                for purpose, ref in (binding_snapshot.get("credentials") or {}).items():
                    current_credential = c.execute(sa.select(connector_secrets).where(
                        connector_secrets.c.connector_id == connector_id,
                        connector_secrets.c.secret_id == ref["secret_id"],
                        connector_secrets.c.version_id == ref["version_id"]).with_for_update()).mappings().first()
                    current_head = c.execute(sa.select(connector_secret_heads.c.revision).where(
                        connector_secret_heads.c.connector_id == connector_id,
                        connector_secret_heads.c.secret_id == ref["secret_id"]).with_for_update()).scalar_one_or_none()
                    if (not current_credential or current_credential["purpose"] != purpose
                            or current_credential["state"] == "revoked"
                            or current_credential["quarantine"] != "clear"
                            or int(current_head or 0) != ref["secret_revision"]):
                        raise ValueError("flow_authority_changed")
                if binding_snapshot.get("policy_revision") != current_policy["revision"]:
                    raise ValueError("flow_authority_changed")
                verification["policy_revision"] = current_policy["revision"]
                verification["result"]["revisions"] = _revisions(current_connector,current_policy,current_context)
                verification["result"]["active_configuration_revision"] = current_connector["active_configuration_revision"]
                verification["result"]["lifecycle"] = current_connector["lifecycle"]
                verification["result"]["recovery"] = current_connector["recovery"]
                if (current["status"] != "verifying" or current["actor_id"] != actor or not current_context
                        or current_context.session_id != current["session_id"]
                        or current_connector["configuration_revision"] != current["configuration_revision"]):
                    raise ValueError("flow_authority_changed")
                if current["expires_at"] <= _now(app): raise ValueError("flow_expired")
                c.execute(connector_setup_flows.update().where(connector_setup_flows.c.flow_id == flow["flow_id"]).values(
                    status="verified",installation=installation,granted_permissions=grants,repositories=public_repos,
                    repositories_complete=True,verification_receipt=verification,verifier_ciphertext=b"",verifier_nonce=b""))
                sequence = c.execute(sa.select(sa.func.max(assessment_audit_events.c.event_sequence))).scalar_one() or 0
                c.execute(assessment_audit_events.insert().values(event_id=verification["audit_event_id"],event_sequence=sequence+1,
                    actor_id=actor,actor_kind="principal",origin="local_api",action="connector.installation.verify",target_id=ZERO,
                    before_value={"connector_id":connector_id,"flow_id":flow["flow_id"],"status":"verifying"},
                    after_value=verification["result"],membership_ids=[],membership_revision=0,
                    rationale="Verify local GitHub App installation",evidence_ref="fixture:g7:installation-verification",
                    policy_revision=current_policy["revision"],identity_revision=0,occurred_at=_now(app),received_at=_now(app),
                    correlation_id=str(uuid.uuid4()),command_id=verification["command_id"],
                    authorization_context=current_context.document() if current_context else None))
                c.execute(connector_receipts.insert().values(connector_id=connector_id,command_id=verification["command_id"],
                    actor_id=actor,action="connector.installation.verify",request_digest=hashlib.sha256(flow["flow_id"].encode()).hexdigest(),
                    receipt=verification,created_at=_now(app)))
        except Exception as exc:
            if isinstance(exc, urllib.error.HTTPError):
                failure_reason = "provider_exchange_rejected" if exc.code in {400, 401, 403} else "provider_unavailable"
            elif isinstance(exc, ValueError) and str(exc) in {"installation_not_accessible", "installation_identity_mismatch",
                    "installation_account_mismatch", "permissions_incomplete", "audience_incomplete",
                    "installation_scope_unverified", "scoped_permissions_mismatch",
                    "scoped_repository_set_mismatch", "scoped_token_missing", "provider_pagination_origin_changed",
                    "provider_pagination_loop", "provider_request_invalid", "provider_response_invalid",
                    "flow_authority_changed", "flow_expired"}:
                failure_reason = str(exc)
            elif exc.__class__.__name__ == "SecretUnavailable":
                failure_reason = "credentials_unavailable"
            elif isinstance(exc, (UnicodeError, KeyError, TypeError, AttributeError)):
                failure_reason = "fixture_response_invalid"
            else:
                # Class names are bounded runtime diagnostics; exception text
                # may contain provider response data and is never persisted.
                failure_reason = "provider_unavailable"
            with engine.begin() as c:
                c.execute(connector_setup_flows.update().where(connector_setup_flows.c.flow_id == flow["flow_id"],
                    connector_setup_flows.c.status == "verifying").values(status="failed",failure_reason=failure_reason,installation=None,
                    verifier_ciphertext=b"",verifier_nonce=b""))
        path = f"/administration/connectors/{connector_id}?installation_flow_id={flow['flow_id']}"
        return RedirectResponse(path, status_code=303)


def execute_connector_command(app, body: dict, request: Request, actor: str):
    """Command endpoint dispatch. Metadata commands use its transaction path."""
    action=body.get("action"); payload=body.get("payload")
    if not isinstance(payload,dict):_fail(400,"invalid_command","Connector command payload is invalid")
    connector_id=_uuid(payload.get("connector_id"),"connector_id");source_id=_uuid(payload.get("source_id"),"source_id")
    binding=_fixture(connector_id)
    if source_id!=binding["source_id"]:_fail(403,"source_scope_forbidden","Source scope does not match")
    command_id=_uuid(body.get("command_id"),"command_id")
    if body.get("target_id")!=ZERO or body.get("membership_ids")!=[] or body.get("schema_version")!=1:
        _fail(422,"invalid_command","Connector command envelope is invalid")
    required_keys={"schema_version","command_id","action","target_id","membership_ids","expected_revisions","payload"}
    if set(body)!=required_keys:_fail(422,"invalid_command","Connector command envelope has unknown fields")
    if not isinstance(payload.get("rationale"),str) or not payload["rationale"].strip() or not isinstance(payload.get("evidence_ref"),str) or not payload["evidence_ref"].strip():
        _fail(422,"invalid_command","Rationale and evidence reference are required")
    engine=app.state.engine;now=_now(app)
    with engine.begin() as c:
        lock_policy(c);policy=_policy(c);context=_auth_context(app,request,c)
        row=c.execute(sa.select(connectors).where(connectors.c.connector_id==connector_id).with_for_update()).mappings().one_or_none()
        if row is None:_fail(404,"not_found","Connector does not exist")
        _require(policy["document"],actor,
            "connector.secret.manage" if action in {"connector.secret.version.revoke",
                "connector.secret.submission.reconcile"} else "connector.configure",binding)
        digest=hashlib.sha256(json.dumps({"principal_id":actor,**body},sort_keys=True,separators=(",",":")).encode()).hexdigest()
        replay=c.execute(sa.select(connector_receipts).where(connector_receipts.c.connector_id==connector_id,connector_receipts.c.command_id==command_id)).mappings().first()
        if replay:
            if replay["actor_id"]!=actor or replay["request_digest"]!=digest:_fail(409,"command_conflict","Command ID was used for another request")
            return replay["receipt"]
        secret_id=payload.get("secret_id")
        secret_rev=None
        if secret_id:
            _uuid(secret_id,"secret_id")
            secret_rev=c.execute(sa.select(connector_secret_heads.c.revision).where(connector_secret_heads.c.connector_id==connector_id,connector_secret_heads.c.secret_id==secret_id)).scalar_one_or_none() or 0
        actual=_revisions(row,policy,context,secret_rev)
        _check_revisions(body.get("expected_revisions"),actual)
        _request_shape(action,payload)
        submission_outcome=None
        if action=="connector.configuration.stage":
            settings=payload.get("settings")
            if not isinstance(settings,dict) or settings.get("environment_label")!=row["environment_label"]:_fail(422,"invalid_settings","Settings must use the provisioned environment label")
            if set(settings)!={"environment_label","authentication_mode","secret_source","credentials","github"}:_fail(422,"invalid_settings","Settings shape is invalid")
            if settings["authentication_mode"] not in {"legacy_token_file","github_app_v1"}:_fail(422,"invalid_settings","Authentication mode is invalid")
            if set(settings["credentials"])!=PURPOSES or not isinstance(settings["github"],dict):_fail(422,"invalid_settings","Credential and GitHub settings are invalid")
            github = settings["github"]
            if set(github) != {"host", "api_version", "app", "installation",
                    "repository_ids", "audience_revisions"}:
                _fail(422, "invalid_settings", "GitHub settings shape is invalid")
            appdata = github["app"]
            if appdata is not None and (not isinstance(appdata, dict) or
                    set(appdata) != {"app_id", "client_id", "slug"}):
                _fail(422, "invalid_settings", "GitHub App settings shape is invalid")
            installation = github["installation"]
            if installation is not None and (not isinstance(installation, dict) or
                    set(installation) != {"flow_id", "installation_id", "account_id"}):
                _fail(422, "invalid_settings", "Installation settings shape is invalid")
            if (not isinstance(github["repository_ids"], list) or
                    len(github["repository_ids"]) != len(set(map(str, github["repository_ids"]))) or
                    not isinstance(github["audience_revisions"], dict) or
                    any(type(revision) is not int or revision < 1
                        for revision in github["audience_revisions"].values())):
                _fail(422, "invalid_settings", "GitHub repository scope is invalid")
            for purpose,ref in settings["credentials"].items():
                if ref is not None and (not isinstance(ref,dict) or set(ref)!={"secret_id","secret_revision","version_id"} or not all(_UUID.fullmatch(str(ref.get(k,""))) for k in ("secret_id","version_id")) or type(ref.get("secret_revision")) is not int or ref["secret_revision"]<0):
                    _fail(422,"invalid_settings","Credential reference is invalid")
            settings = _refresh_secret_heads(c, connector_id, settings)
            prior=_settings(row,c,connector_id)
            changed=(settings.get("secret_source")!=prior.get("secret_source") or settings.get("credentials")!=prior.get("credentials"))
            if changed:_require(policy["document"],actor,"connector.secret.manage",binding)
            provider=settings.get("secret_source")
            if provider is not None and (not isinstance(provider,dict) or provider.get("kind")!="encrypted_local_v1" or set(provider)!={"kind","secret_source_id","revision","key_binding_id"} or not _UUID.fullmatch(str(provider.get("secret_source_id",""))) or not _UUID.fullmatch(str(provider.get("key_binding_id",""))) or type(provider.get("revision")) is not int or provider["revision"]<0 or provider["revision"]!=row["secret_source_revision"]):
                _fail(422,"invalid_settings","Fixture supports only a bound encrypted-local source")
            prior_provider=prior.get("secret_source")
            source_changed=(
                (provider is None) != (prior_provider is None)
                or (provider is not None and prior_provider is not None and any(
                    provider.get(key)!=prior_provider.get(key)
                    for key in ("kind","secret_source_id","key_binding_id"))))
            if provider is not None:
                # The browser submits the revision it read (zero on first use).
                # Allocate the next persisted source revision on the server.
                provider["revision"] = row["secret_source_revision"] + int(source_changed)
            if settings["authentication_mode"]=="github_app_v1":
                appdata=settings["github"].get("app")
                if (not isinstance(settings.get("secret_source"),dict) or settings["secret_source"].get("kind")!="encrypted_local_v1"
                        or not isinstance(appdata,dict) or not isinstance(appdata.get("app_id"),str)
                        or not appdata["app_id"].isdigit() or settings["github"].get("host")!="github.com"):
                    _fail(422,"invalid_settings","Local GitHub App settings are incomplete")
            revision=row["configuration_revision"]+1
            c.execute(connector_configurations.insert().values(connector_id=connector_id,configuration_revision=revision,settings=settings,actor_id=actor,created_at=now))
            c.execute(connectors.update().where(connectors.c.connector_id==connector_id).values(configuration_revision=revision,lifecycle="staged",connector_revision=row["connector_revision"]+1,secret_source_id=provider.get("secret_source_id") if provider else None,secret_source_revision=row["secret_source_revision"]+int(source_changed),validation={"status":"unverified","checked_at":None,"intent_id":None,"configuration_revision":None,"reason":None},updated_at=now))
            effect="connector_configuration_committed";intent=None
        elif action=="connector.configuration.validate":
            revision=payload.get("configuration_revision")
            if revision!=row["configuration_revision"]:_fail(409,"revision_conflict","Configuration revision is stale")
            settings=_settings(row,c,connector_id)
            _require(policy["document"],actor,"connector.secret.manage",binding)
            intent_id=str(uuid.uuid4())
            c.execute(connector_intents.insert().values(intent_id=intent_id,connector_id=connector_id,kind="connector.validate",actor_id=actor,status="pending",attempts=0,payload={"configuration_revision":revision,"source_revision":row["source_revision"],"secret_source_revision":row["secret_source_revision"],"connector_revision":row["connector_revision"],"policy_revision":policy["revision"],"authority_revision":actual["authority"],"settings":settings},result=None,created_at=now,updated_at=now))
            c.execute(connectors.update().where(connectors.c.connector_id==connector_id).values(validation={"status":"unverified","checked_at":None,"intent_id":intent_id,"configuration_revision":revision,"reason":None},updated_at=now))
            effect="connector_validation_requested";intent={"intent_id":intent_id,"kind":"connector.validate","target_id":connector_id,"authority_revision":actual["authority"],"status":"pending"}
        elif action=="connector.configuration.disable":
            intent_id=str(uuid.uuid4())
            c.execute(connector_intents.insert().values(intent_id=intent_id,
                connector_id=connector_id,kind="connector.reconcile",actor_id=actor,
                status="pending",attempts=0,payload={"configuration_revision":row["configuration_revision"],
                    "policy_revision":policy["revision"],"authority_revision":actual["authority"],
                    "reason":"connector_disabled"},result=None,created_at=now,updated_at=now))
            c.execute(connectors.update().where(connectors.c.connector_id==connector_id).values(lifecycle="disabled",active_configuration_revision=None,connector_revision=row["connector_revision"]+1,updated_at=now))
            effect="connector_configuration_committed";intent={"intent_id":intent_id,
                "kind":"connector.reconcile","target_id":connector_id,
                "authority_revision":actual["authority"],"status":"pending"};revision=row["configuration_revision"]
        elif action=="connector.configuration.activate":
            _require(policy["document"], actor, "connector.secret.manage", binding)
            if row["recovery"].get("state") not in {"clear", "awaiting_activation"}:
                _fail(409,"restore_quarantined","Connector recovery fence is closed")
            clearance = None
            if row["recovery"].get("state") == "awaiting_activation":
                clearance = operator_clearance(connector_id, row["recovery"].get("recovery_epoch_id"))
                if (not clearance or row["recovery"].get("operator_clearance_present") is not True):
                    _fail(409,"restore_quarantined","Current independent recovery clearance is unavailable")
            revision=payload.get("configuration_revision")
            validation_id=payload.get("validation_intent_id")
            if (revision!=row["configuration_revision"] or row["validation"].get("status")!="valid"
                    or row["validation"].get("intent_id")!=validation_id
                    or row["validation"].get("configuration_revision")!=revision):
                _fail(409,"validation_required","A completed current validation is required before activation")
            intent_row=c.execute(sa.select(connector_intents).where(
                connector_intents.c.connector_id==connector_id,connector_intents.c.intent_id==validation_id).with_for_update()).mappings().first()
            if (intent_row is None or intent_row["status"]!="complete" or not intent_row["result"]
                    or not intent_row["result"].get("valid")
                    or intent_row["actor_id"] != actor
                    or intent_row["payload"].get("policy_revision") != policy["revision"]
                    or intent_row["payload"].get("authority_revision") != actual["authority"]):
                _fail(409,"validation_required","A completed current validation is required before activation")
            settings=_settings(row,c,connector_id)
            last_activated_mode = row.get("last_activated_authentication_mode")
            if (settings.get("authentication_mode") == "legacy_token_file"
                    and last_activated_mode in {"github_app_v1", "unknown"}):
                _fail(409, "rollback_required",
                    "An App-to-legacy transition is available only through validated historical rollback")
            refs=settings.get("credentials",{})
            live_validation = _validation_result(c, connector_id, settings, revision,
                row, now)
            if not live_validation["valid"]:
                _fail(409, "validation_required",
                    "Current connector credentials and repository disclosure approval must be validated")
            current_binding = sorted((ref["secret_id"], ref["version_id"],
                ref["secret_revision"]) for ref in refs.values() if ref is not None)
            validated_binding = sorted((item.get("secret_id"), item.get("version_id"),
                item.get("secret_revision")) for item in intent_row["result"].get("credentials", []))
            if current_binding != validated_binding:
                _fail(409, "validation_required", "Validation does not bind the current credential selection")
            for purpose,ref in refs.items():
                if ref is None:continue
                secret=c.execute(sa.select(connector_secrets).where(
                    connector_secrets.c.connector_id==connector_id,
                    connector_secrets.c.secret_id==ref["secret_id"],
                    connector_secrets.c.version_id==ref["version_id"]).with_for_update()).mappings().first()
                if (secret is None or secret["purpose"]!=purpose or secret["state"]=="revoked"
                        or secret["quarantine"]!="clear"):
                    _fail(409,"credential_revoked","A selected credential is revoked or quarantined")
                if clearance and ref["version_id"] not in clearance.get("fresh_version_ids", []):
                    _fail(409,"restore_quarantined","Recovery activation requires only issuer-proven fresh versions")
                head=c.execute(sa.select(connector_secret_heads).where(
                    connector_secret_heads.c.connector_id==connector_id,
                    connector_secret_heads.c.secret_id==ref["secret_id"]).with_for_update()).mappings().one()
                if int(head["revision"]) != ref["secret_revision"]:
                    _fail(409,"revision_conflict","A selected credential reference is stale")
                c.execute(connector_secrets.update().where(
                    connector_secrets.c.connector_id==connector_id,
                    connector_secrets.c.secret_id==ref["secret_id"],
                    connector_secrets.c.state=="active").values(state="inactive"))
                c.execute(connector_secrets.update().where(
                    connector_secrets.c.connector_id==connector_id,
                    connector_secrets.c.secret_id==ref["secret_id"],
                    connector_secrets.c.version_id==ref["version_id"]).values(state="active"))
            recovered = row["recovery"].get("state") == "awaiting_activation"
            recovery = ({"state":"clear","recovery_epoch_id":row["recovery"].get("recovery_epoch_id"),
                "operator_clearance_present":True,"requires_fresh_credentials":False,"reason":None}
                if recovered else row["recovery"])
            c.execute(connectors.update().where(connectors.c.connector_id==connector_id).values(
                lifecycle="active",active_configuration_revision=revision,
                last_activated_authentication_mode=settings["authentication_mode"],
                recovery=recovery,connector_revision=row["connector_revision"]+1,updated_at=now))
            effect="connector_configuration_committed";intent=None
        elif action=="connector.configuration.rollback":
            _require(policy["document"],actor,"connector.secret.manage",binding)
            target_revision=payload.get("configuration_revision")
            validation_id=_uuid(payload.get("validation_intent_id"),"validation_intent_id")
            if type(target_revision) is not int or target_revision<1 or target_revision>=row["configuration_revision"]:
                _fail(409,"revision_conflict","Rollback must name an immutable historical configuration")
            historical=c.execute(sa.select(connector_configurations).where(
                connector_configurations.c.connector_id==connector_id,
                connector_configurations.c.configuration_revision==target_revision)).mappings().one_or_none()
            validation=c.execute(sa.select(connector_intents).where(
                connector_intents.c.connector_id==connector_id,
                connector_intents.c.intent_id==validation_id).with_for_update()).mappings().one_or_none()
            if (historical is None or validation is None or validation["kind"]!="connector.validate"
                    or validation["status"]!="complete" or not validation["result"]
                    or validation["result"].get("valid") is not True
                    or validation["actor_id"]!=actor
                    or row["validation"].get("status")!="valid"
                    or row["validation"].get("intent_id")!=validation_id
                    or row["validation"].get("configuration_revision")!=row["configuration_revision"]
                    or validation["payload"].get("configuration_revision")!=row["configuration_revision"]
                    or validation["payload"].get("policy_revision")!=policy["revision"]
                    or validation["payload"].get("authority_revision")!=getattr(context,"policy_revision",None)):
                _fail(409,"validation_required","A completed current rollback-candidate validation is required")
            settings=_settings(row,c,connector_id)
            historical_settings=_refresh_secret_heads(c, connector_id, historical["settings"])
            # Historical App settings may carry an audience approval revision
            # that became stale after a policy or reader change. Rollback may
            # refresh only that separately governed binding; all connector and
            # credential selections must still exactly match the immutable
            # historical candidate and the validation intent.
            comparable_settings=copy.deepcopy(settings)
            comparable_historical=copy.deepcopy(historical_settings)
            if (comparable_settings.get("authentication_mode")=="github_app_v1"
                    and comparable_historical.get("authentication_mode")=="github_app_v1"):
                comparable_settings.get("github",{}).pop("audience_revisions",None)
                comparable_historical.get("github",{}).pop("audience_revisions",None)
            if (comparable_settings!=comparable_historical
                    or settings!=validation["payload"].get("settings")):
                _fail(409,"revision_conflict","Validated rollback settings no longer match the historical candidate")
            live=_validation_result(c,connector_id,settings,row["configuration_revision"],row,now)
            if not live["valid"]:
                _fail(409,live.get("reason") or "validation_required",
                    "Rollback candidate no longer satisfies current policy and audience")
            if row["recovery"].get("state")!="clear":
                _fail(409,"restore_quarantined","Rollback is unavailable while recovery is fenced")
            refs=settings.get("credentials",{})
            for purpose,ref in refs.items():
                if ref is None:continue
                secret=c.execute(sa.select(connector_secrets).where(
                    connector_secrets.c.connector_id==connector_id,
                    connector_secrets.c.secret_id==ref["secret_id"],
                    connector_secrets.c.version_id==ref["version_id"]).with_for_update()).mappings().one_or_none()
                head=c.execute(sa.select(connector_secret_heads.c.revision).where(
                    connector_secret_heads.c.connector_id==connector_id,
                    connector_secret_heads.c.secret_id==ref["secret_id"]).with_for_update()).scalar_one_or_none()
                if (secret is None or secret["purpose"]!=purpose or secret["state"]=="revoked"
                        or secret["quarantine"]!="clear" or int(head or 0)!=ref["secret_revision"]):
                    _fail(409,"credential_revoked","Historical rollback credentials are revoked or stale")
                c.execute(connector_secrets.update().where(
                    connector_secrets.c.connector_id==connector_id,
                    connector_secrets.c.secret_id==ref["secret_id"],
                    connector_secrets.c.state=="active").values(state="inactive"))
                c.execute(connector_secrets.update().where(
                    connector_secrets.c.connector_id==connector_id,
                    connector_secrets.c.secret_id==ref["secret_id"],
                    connector_secrets.c.version_id==ref["version_id"],
                    connector_secrets.c.state!="revoked").values(state="active"))
            next_revision=row["configuration_revision"]+1
            c.execute(connector_configurations.insert().values(connector_id=connector_id,
                configuration_revision=next_revision,settings=settings,actor_id=actor,created_at=now))
            intent_id=str(uuid.uuid4())
            c.execute(connector_intents.insert().values(intent_id=intent_id,connector_id=connector_id,
                kind="connector.reconcile",actor_id=actor,status="pending",attempts=0,
                payload={"configuration_revision":next_revision,"restored_from_revision":target_revision,
                    "reason":"configuration_rollback","policy_revision":policy["revision"],
                    "authority_revision":actual["authority"],
                    "connector_revision":row["connector_revision"]+1,
                    "source_revision":row["source_revision"],
                    "secret_source_revision":row["secret_source_revision"]},result=None,created_at=now,updated_at=now))
            c.execute(connectors.update().where(connectors.c.connector_id==connector_id).values(
                configuration_revision=next_revision,active_configuration_revision=next_revision,
                lifecycle="active",connector_revision=row["connector_revision"]+1,
                last_activated_authentication_mode=settings["authentication_mode"],
                validation={"status":"valid","checked_at":validation["result"].get("checked_at"),
                    "intent_id":validation_id,"configuration_revision":next_revision,"reason":None},updated_at=now))
            effect="connector_configuration_committed"
            intent={"intent_id":intent_id,"kind":"connector.reconcile","target_id":connector_id,
                "authority_revision":actual["authority"],"status":"pending"}
            revision=next_revision
        elif action=="connector.secret.version.revoke":
            version_id=_uuid(payload.get("version_id"),"version_id")
            secret=c.execute(sa.select(connector_secrets).where(connector_secrets.c.connector_id==connector_id,connector_secrets.c.secret_id==secret_id,connector_secrets.c.version_id==version_id).with_for_update()).mappings().one_or_none()
            if secret is None:_fail(404,"not_found","Secret version does not exist")
            if secret["state"]=="revoked":_fail(409,"revision_conflict","Secret version is terminally revoked")
            head=c.execute(sa.select(connector_secret_heads).where(connector_secret_heads.c.connector_id==connector_id,connector_secret_heads.c.secret_id==secret_id).with_for_update()).mappings().one()
            intent_id=str(uuid.uuid4())
            c.execute(connector_intents.insert().values(intent_id=intent_id,connector_id=connector_id,
                kind="connector.remote_revoke",actor_id=actor,status="pending",attempts=0,
                payload={"secret_id":secret_id,"version_id":version_id,"purpose":secret["purpose"]},
                result=None,created_at=now,updated_at=now))
            c.execute(connector_secrets.update().where(connector_secrets.c.connector_id==connector_id,connector_secrets.c.secret_id==secret_id,connector_secrets.c.version_id==version_id).values(state="revoked",remote_revocation={"status":"pending","intent_id":intent_id,"observed_at":None,"expires_at":None,"reason":None}))
            c.execute(connector_secret_heads.update().where(connector_secret_heads.c.connector_id==connector_id,connector_secret_heads.c.secret_id==secret_id).values(revision=head["revision"]+1))
            c.execute(connectors.update().where(connectors.c.connector_id==connector_id).values(lifecycle="disabled",active_configuration_revision=None,connector_revision=row["connector_revision"]+1,updated_at=now))
            revision=row["configuration_revision"];effect="connector_secret_revoked";intent={"intent_id":intent_id,"kind":"connector.remote_revoke","target_id":connector_id,"authority_revision":actual["authority"],"status":"pending"}
        elif action=="connector.secret.submission.reconcile":
            submission_id=_uuid(payload.get("submission_id"),"submission_id")
            version_id=_uuid(payload.get("version_id"),"version_id")
            submission=c.execute(sa.select(connector_submissions).where(connector_submissions.c.submission_id==submission_id).with_for_update()).mappings().first()
            if submission is not None and (submission["actor_id"]!=actor or submission["connector_id"]!=connector_id or submission["source_id"]!=source_id or submission["secret_id"]!=secret_id or submission["version_id"]!=version_id):
                _fail(404,"not_found","Submission does not exist")
            if submission is not None and submission["outcome"] == "committed":
                submission_outcome="committed"
            elif submission is not None and submission["outcome"] == "not_committed":
                submission_outcome="not_committed"
            else:
                version_exists=c.execute(sa.select(connector_secrets.c.version_id).where(
                    connector_secrets.c.connector_id==connector_id,
                    connector_secrets.c.secret_id==secret_id,
                    connector_secrets.c.version_id==version_id).with_for_update()).first()
                if version_exists:
                    _fail(503,"outcome_unknown","Secret version exists without a settled admission receipt")
                if submission is None:
                    c.execute(connector_submissions.insert().values(submission_id=submission_id,
                        connector_id=connector_id,source_id=source_id,secret_id=secret_id,
                        version_id=version_id,actor_id=actor,outcome="not_committed",
                        retry_allowed=True,receipt=None,created_at=now))
                else:
                    c.execute(connector_submissions.update().where(
                        connector_submissions.c.submission_id==submission_id,
                        connector_submissions.c.outcome=="unknown").values(
                        outcome="not_committed",retry_allowed=True,receipt=None))
                submission_outcome="not_committed"
            revision=row["configuration_revision"];effect="connector_secret_submission_reconciled";intent=None
        else:_fail(422,"invalid_command","Connector command action is unsupported")
        current=c.execute(sa.select(connectors).where(connectors.c.connector_id==connector_id)).mappings().one()
        event_id=str(uuid.uuid4());sequence=c.execute(sa.select(sa.func.max(assessment_audit_events.c.event_sequence))).scalar_one() or 0
        result={"effect":effect,"connector_id":connector_id,"source_id":source_id,
            "revisions":_revisions(current,policy,context,(head["revision"]+1 if action=="connector.secret.version.revoke" else secret_rev)),"configuration_revision":current["configuration_revision"],
            "active_configuration_revision":current["active_configuration_revision"],"lifecycle":current["lifecycle"],
            "secret_id":secret_id,"version_id":payload.get("version_id"),"version_state":"revoked" if action=="connector.secret.version.revoke" else None,
            "submission_id":payload.get("submission_id"),"submission_outcome":submission_outcome,"flow_id":None,"recovery":current["recovery"]}
        receipt={"schema_version":1,"command_id":command_id,"action":action,"target_id":ZERO,"policy_revision":policy["revision"],"decision_id":str(uuid.uuid4()),"audit_event_id":event_id,"intents":[intent] if intent else [],"result":result}
        c.execute(assessment_audit_events.insert().values(event_id=event_id,event_sequence=sequence+1,actor_id=actor,actor_kind="principal",origin="local_api",action=action,target_id=ZERO,before_value={"connector_id":connector_id,"connector_revision":row["connector_revision"]},after_value=result,membership_ids=[],membership_revision=0,rationale=payload["rationale"],evidence_ref=payload["evidence_ref"],policy_revision=policy["revision"],identity_revision=0,occurred_at=now,received_at=now,correlation_id=str(uuid.uuid4()),command_id=command_id,authorization_context=context.document() if context else None))
        c.execute(connector_receipts.insert().values(connector_id=connector_id,command_id=command_id,actor_id=actor,action=action,request_digest=digest,receipt=receipt,created_at=now))
        return receipt
