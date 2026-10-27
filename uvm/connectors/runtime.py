"""Fail-closed GitHub App credential resolution for reads and writers."""
from __future__ import annotations

import json
import copy
import os
from datetime import datetime, timezone
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

import sqlalchemy as sa

from uvm.connectors.crypto import SecretUnavailable, decrypt
from uvm.github.app_auth import app_jwt
from uvm.github.client import GitHubREST
from uvm.persistence.assessment_schema import assessment_policy
from uvm.persistence.connector_schema import (connectors, connector_secrets,
    connector_secret_heads, connector_setup_flows, connector_intents)

_PERMISSIONS = {"issues": "write", "metadata": "read",
    "administration": "read", "members": "read"}
_READ_PERMISSIONS = {"issues": "read", "metadata": "read",
    "administration": "read", "members": "read"}


def _settings(connection, row):
    from uvm.connectors.api import _settings as read_settings
    return read_settings(row, connection, row["connector_id"])


def _rollback_reconciliation_pending(connection, connector_id):
    intents = connection.execute(sa.select(connector_intents.c.payload).where(
        connector_intents.c.connector_id == connector_id,
        connector_intents.c.kind == "connector.reconcile",
        connector_intents.c.status.in_(["pending", "running", "uncertain"]))).all()
    return any((payload or {}).get("reason") == "configuration_rollback"
        for (payload,) in intents)


def _fixture_request(base: str, path: str, method: str, token: str, payload=None,
        before_request=None):
    lease = before_request(method.upper(), path) if before_request is not None else None
    try:
        body = None if payload is None else json.dumps(payload, sort_keys=True,
            separators=(",", ":")).encode()
        request = Request(base.rstrip("/") + "/" + path.lstrip("/"), data=body,
            method=method, headers={"Accept": "application/vnd.github+json",
                "Authorization": "Bearer " + token,
                "X-GitHub-Api-Version": "2022-11-28",
                **({"Content-Type": "application/json"} if body is not None else {})})
        with urlopen(request, timeout=10) as response:
            data = json.loads(response.read() or b"{}")
            return response.status, data, response.headers
    except HTTPError as exc:
        raise SecretUnavailable("GitHub App credential exchange was rejected") from None
    except (URLError, TimeoutError, OSError, ValueError):
        raise SecretUnavailable("GitHub App credential exchange is unavailable") from None
    finally:
        if callable(lease):
            lease()


def _resolve_record(connection, row, settings, purpose, *, staged: bool, lock: bool = True):
    ref = (settings.get("credentials") or {}).get(purpose)
    if not isinstance(ref, dict):
        raise SecretUnavailable("active GitHub App credential is not configured")
    query = sa.select(connector_secrets).where(
        connector_secrets.c.connector_id == row["connector_id"],
        connector_secrets.c.secret_id == ref.get("secret_id"),
        connector_secrets.c.version_id == ref.get("version_id"))
    if lock:
        query = query.with_for_update()
    secret = connection.execute(query).mappings().first()
    if (secret is None or secret["purpose"] != purpose or secret["state"] == "revoked"
            or secret["quarantine"] != "clear"):
        raise SecretUnavailable("GitHub App credential is revoked or quarantined")
    if not staged and secret["state"] != "active":
        raise SecretUnavailable("GitHub App credential is not active")
    head_query = sa.select(connector_secret_heads.c.revision).where(
        connector_secret_heads.c.connector_id == row["connector_id"],
        connector_secret_heads.c.secret_id == ref.get("secret_id"))
    if lock:
        head_query = head_query.with_for_update()
    head = connection.execute(head_query).scalar_one_or_none()
    if int(head or 0) != ref.get("secret_revision"):
        raise SecretUnavailable("GitHub App credential reference is stale")
    if staged and row["recovery"].get("state") == "awaiting_activation":
        from uvm.connectors.recovery import issuer_version, operator_clearance
        recovery = row["recovery"]
        clearance = operator_clearance(row["connector_id"], recovery.get("recovery_epoch_id"))
        if (not clearance or ref.get("version_id") not in clearance.get("fresh_version_ids", [])
                or not issuer_version(row["connector_id"], ref["secret_id"], ref["version_id"],
                    purpose, recovery.get("recovery_epoch_id"))):
            raise SecretUnavailable("fresh recovery credential is not independently proven")
    record = {"algorithm": secret["algorithm"], "key_id": secret["key_id"],
        "nonce": secret["nonce"], "ciphertext": secret["ciphertext"]}
    try:
        return decrypt(record, row["connector_id"], ref["secret_id"], ref["version_id"])
    except (SecretUnavailable, KeyError, TypeError, ValueError):
        raise SecretUnavailable("GitHub App credential cannot be decrypted") from None


def _app_rest(row, settings, private_key: bytes, before_request=None, read_only=False):
    github = settings.get("github") or {}
    appdata = github.get("app") or {}
    installation = github.get("installation") or {}
    repository_ids = github.get("repository_ids")
    if (not isinstance(repository_ids, list) or not repository_ids
            or any(not isinstance(item, str) or not item.isdigit() for item in repository_ids)
            or len(repository_ids) != len(set(repository_ids))
            or not installation.get("installation_id")):
        raise SecretUnavailable("GitHub App installation scope is incomplete")
    jwt = app_jwt(appdata.get("app_id"), private_key)
    import os
    base = os.environ.get("UVM_GITHUB_API_BASE_URL", "https://api.github.com/")
    installation_id = str(installation.get("installation_id"))
    requested_permissions = (_PERMISSIONS if not read_only and row.get("lifecycle") == "active"
        and row.get("active_configuration_revision") == row.get("configuration_revision")
        else _READ_PERMISSIONS)
    _, observed, _ = _fixture_request(base,
            f"app/installations/{installation_id}", "GET", jwt,
        before_request=before_request)
    app_id = str(appdata.get("app_id"))
    if (str(observed.get("app_id")) != app_id or observed.get("suspended_at")
            or str(observed.get("account", {}).get("id")) != str(installation.get("account_id"))
            or observed.get("permissions") != _PERMISSIONS):
        raise SecretUnavailable("GitHub App installation identity changed")
    _, token_document, _ = _fixture_request(base,
        f"app/installations/{installation_id}/access_tokens",
        "POST", jwt, {"repository_ids": repository_ids, "permissions": requested_permissions},
        before_request=before_request)
    token = token_document.get("token")
    expiry = token_document.get("expires_at")
    permissions = token_document.get("permissions")
    repositories = token_document.get("repositories")
    try:
        expires_at = datetime.fromisoformat(expiry.replace("Z", "+00:00"))
    except (AttributeError, ValueError):
        expires_at = None
    if (not isinstance(token, str) or not token or permissions != requested_permissions
            or expires_at is None
            or expires_at <= datetime.now(timezone.utc)):
            raise SecretUnavailable("GitHub App token scope or expiry is unverified")
    slug = appdata.get("slug")
    if (not isinstance(slug, str) or not slug or len(slug) > 100
            or any(ch not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-" for ch in slug)):
        raise SecretUnavailable("GitHub App bot identity is unavailable")
    api = GitHubREST(token=token, before_request=before_request,
        app_bot_login=slug + "[bot]")
    pages = []
    next_url = api._path("installation/repositories?per_page=100")
    seen = set()
    total = None
    while next_url:
        if next_url in seen:
            raise SecretUnavailable("GitHub installation readback pagination looped")
        seen.add(next_url)
        document, headers = api.get_with_headers(next_url)
        items, count = document.get("repositories"), document.get("total_count")
        if not isinstance(items, list) or type(count) is not int:
            raise SecretUnavailable("GitHub installation readback is incomplete")
        if total is None:
            total = count
        elif count != total:
            raise SecretUnavailable("GitHub installation readback changed between pages")
        pages.extend(items)
        next_url = None
        for part in headers.get("Link", "").split(","):
            if 'rel="next"' in part:
                start, end = part.find("<"), part.find(">")
                if start < 0 or end <= start:
                    raise SecretUnavailable("GitHub installation pagination link is invalid")
                next_url = api._path(part[start + 1:end])
                break
    actual_ids = {str(item.get("id")) for item in pages}
    if total is None or total != len(pages) or actual_ids != set(repository_ids):
        raise SecretUnavailable("GitHub installation repository scope changed")
    return api


def connector_rest(engine, *, connector_id: str | None = None,
                   principal: str | None = None, expected_revisions: dict | None = None,
                   action: str = "connector.configure", authorization_target: str | None = None,
                   allow_candidate: bool = False):
    """Return legacy only before explicit settings; any configured state fences it."""
    from uvm.connectors.api import (_fixture, _revisions, _check_revisions,
        _require, _grants)
    snapshot = None
    with engine.begin() as connection:
        # Connector runtime follows the command lock order: policy authority
        # first, then connector and credential rows. This prevents a resolver
        # racing an authority update from inverting the lifecycle lock order.
        from uvm.assessment.policy_lock import lock_policy
        lock_policy(connection)
        policy = connection.execute(sa.select(assessment_policy).where(
            assessment_policy.c.policy_id == 1).with_for_update()).mappings().first()
        if policy is None:
            raise SecretUnavailable("connector authority is unavailable")
        if connector_id is None:
            rows = connection.execute(sa.select(connectors).where(
                connectors.c.configuration_revision > 0).with_for_update()).mappings().all()
            if not rows:
                return None
            active = [row for row in rows if row["lifecycle"] == "active"
                and row["active_configuration_revision"] == row["configuration_revision"]]
            if len(active) != 1:
                raise SecretUnavailable("explicit connector settings are not active")
            row = active[0]
            connector_id = str(row["connector_id"])
        else:
            binding = _fixture(connector_id)
            row = connection.execute(sa.select(connectors).where(
                connectors.c.connector_id == connector_id).with_for_update()).mappings().first()
            if row is None:
                raise SecretUnavailable("connector settings are unavailable")
            if (row["configuration_revision"] > 0 and row["lifecycle"] == "disabled"
                    # A disabled connector cannot serve runtime work. Permit
                    # only the separately authorised, revision-bound candidate
                    # read used by the public audience approval route so an
                    # operator can resolve a failed rollback safely.
                    and not (allow_candidate and principal is not None
                        and expected_revisions is not None and authorization_target is not None)):
                raise SecretUnavailable("explicit connector settings are disabled")
        if _rollback_reconciliation_pending(connection, connector_id):
            raise SecretUnavailable("connector rollback reconciliation is pending")
        binding = _fixture(connector_id)
        candidate = (row["lifecycle"] != "active"
            or row["active_configuration_revision"] != row["configuration_revision"])
        if candidate and (not allow_candidate or principal is None or connector_id is None):
            raise SecretUnavailable("explicit connector settings are not active")
        if principal is not None:
            if candidate:
                _require(policy["document"], principal, "connector.secret.manage", binding)
            if authorization_target is not None:
                from uvm.assessment.api import _require_authority
                _require_authority(policy["document"], principal, action,
                    authorization_target, origin="local_api", correlation_id="g7-runtime-resolve")
            else:
                _require(policy["document"], principal, action, binding)
        if expected_revisions is not None:
            actual = _revisions(row, policy, None)
            _check_revisions(expected_revisions, actual)
        settings = _settings(connection, row)
        if row["configuration_revision"] == 0:
            return None
        authentication_mode = settings.get("authentication_mode")
        if authentication_mode not in {"github_app_v1", "legacy_token_file"}:
            raise SecretUnavailable("explicit GitHub settings use an unsupported credential mode")
        staged = candidate
        if (row["recovery"].get("state") not in {"clear", "awaiting_activation"}
                or (not staged and row["recovery"].get("state") != "clear")):
            raise SecretUnavailable("connector recovery fence is closed")
        secret_purpose = "private_key" if authentication_mode == "github_app_v1" else "rest_token"
        credential = _resolve_record(connection, row, settings, secret_purpose, staged=staged)
        snapshot = (copy.deepcopy(dict(row)), copy.deepcopy(settings), credential,
            str(row["configuration_revision"]),
            str(row["active_configuration_revision"]), str(row["lifecycle"]),
            str(row["recovery"].get("recovery_epoch_id") or ""),
            copy.deepcopy(dict(policy["document"])))
    if snapshot is None:
        return None
    snap_row, snap_settings, credential, config_rev, active_rev, lifecycle, epoch_id, policy_doc = snapshot
    secret_purpose = "private_key" if snap_settings["authentication_mode"] == "github_app_v1" else "rest_token"
    secret_ref = snap_settings["credentials"][secret_purpose]

    def fence(_method=None, _path=None):
        connection = engine.connect()
        transaction = connection.begin()
        try:
            from uvm.assessment.policy_lock import lock_policy
            lock_policy(connection)
            latest_policy = connection.execute(sa.select(assessment_policy).where(
                assessment_policy.c.policy_id == 1).with_for_update()).mappings().first()
            if latest_policy is None or latest_policy["document"] != policy_doc:
                raise SecretUnavailable("connector policy changed before GitHub dispatch")
            current = connection.execute(sa.select(connectors).where(
                connectors.c.connector_id == snap_row["connector_id"]).with_for_update()).mappings().first()
            if current is None or str(current["configuration_revision"]) != config_rev:
                raise SecretUnavailable("connector revision changed before GitHub dispatch")
            if (str(current["active_configuration_revision"]) != active_rev
                    or str(current["lifecycle"]) != lifecycle
                    or str(current["recovery"].get("recovery_epoch_id") or "") != epoch_id
                    or current["recovery"].get("state") != snap_row["recovery"].get("state")):
                raise SecretUnavailable("connector activation changed before GitHub dispatch")
            current_settings = _settings(connection, current)
            if _rollback_reconciliation_pending(connection, str(current["connector_id"])):
                raise SecretUnavailable("connector rollback reconciliation is pending")
            if current_settings.get("credentials", {}).get(secret_purpose) != secret_ref:
                raise SecretUnavailable("GitHub credential selection changed before dispatch")
            credential = connection.execute(sa.select(connector_secrets).where(
                connector_secrets.c.connector_id == current["connector_id"],
                connector_secrets.c.secret_id == secret_ref["secret_id"],
                connector_secrets.c.version_id == secret_ref["version_id"]).with_for_update()).mappings().first()
            head = connection.execute(sa.select(connector_secret_heads.c.revision).where(
                connector_secret_heads.c.connector_id == current["connector_id"],
                connector_secret_heads.c.secret_id == secret_ref["secret_id"]).with_for_update()).scalar_one_or_none()
            candidate_snapshot = (lifecycle != "active" or active_rev != config_rev)
            eligible_states = {"inactive", "active"} if candidate_snapshot else {"active"}
            if (credential is None or credential["purpose"] != secret_purpose
                    or credential["state"] not in eligible_states or credential["state"] == "revoked"
                    or credential["quarantine"] != "clear"
                    or int(head or 0) != secret_ref["secret_revision"]):
                raise SecretUnavailable("GitHub credential is no longer dispatchable")
            if principal is not None:
                latest_binding = _fixture(str(current["connector_id"]))
                if candidate_snapshot:
                    _require(latest_policy["document"], principal,
                        "connector.secret.manage", latest_binding)
                if authorization_target is not None:
                    from uvm.assessment.api import _require_authority
                    _require_authority(latest_policy["document"], principal, action,
                        authorization_target, origin="local_api", correlation_id="g7-runtime-dispatch")
                else:
                    _require(latest_policy["document"], principal, action, latest_binding)
            # The ordered authority/version locks establish dispatch admission
            # only. Release them before any provider socket I/O; each subsequent
            # REST request re-runs this fence, while durable projection intents
            # retain uncertainty for writes already admitted.
            transaction.commit()
            connection.close()
            return None
        except Exception:
            transaction.rollback()
            connection.close()
            raise

    fence()
    if snap_settings["authentication_mode"] == "github_app_v1":
        return _app_rest(snap_row, snap_settings, credential, before_request=fence,
            read_only=(lifecycle != "active" or active_rev != config_rev))
    return GitHubREST(token=credential.decode("ascii"), before_request=fence)


def prepare_provider_candidate(connection, row, settings):
    """Snapshot/decrypt a candidate for read-only provider validation."""
    from uvm.persistence.g4_schema import github_repositories
    if settings.get("authentication_mode") == "github_app_v1":
        key_pem = _resolve_record(connection, row, settings, "private_key", staged=True, lock=False)
        credential = key_pem
    elif settings.get("authentication_mode") == "legacy_token_file":
        credential = _resolve_record(connection, row, settings, "rest_token", staged=True, lock=False)
    else:
        raise SecretUnavailable("candidate GitHub credential mode is unsupported")
    repositories = []
    for repository_id in settings["github"]["repository_ids"]:
        repository = connection.execute(sa.select(github_repositories).where(
            github_repositories.c.repository_id == repository_id,
            github_repositories.c.enabled.is_(True))).mappings().first()
        if repository is None:
            raise SecretUnavailable("selected GitHub repository is no longer available")
        repositories.append(copy.deepcopy(dict(repository)))
    return {"row":copy.deepcopy(dict(row)),"settings":copy.deepcopy(settings),
        "credential":credential,"repositories":repositories}


def validate_provider_candidate_snapshot(snapshot, before_request=None):
    """Perform bounded provider reads with no UVM database transaction open."""
    from uvm.github.api import _repo_audience
    row, settings = snapshot["row"], snapshot["settings"]
    if settings.get("authentication_mode") == "github_app_v1":
        rest = _app_rest(row, settings, snapshot["credential"],
            read_only=True, before_request=before_request)
    else:
        rest = GitHubREST(token=snapshot["credential"].decode("ascii"),
            before_request=before_request)
    for repository in snapshot["repositories"]:
        repository_id = repository["repository_id"]
        actual, digest = _repo_audience(rest, dict(repository))
        saved = repository["audience_document"] or {}
        expected = {"repository_id": str(repository_id), "private": True,
            "reader_account_ids": sorted(saved.get("reader_account_ids", [])),
            "team_slugs": sorted(saved.get("team_slugs", []))}
        if actual != expected or digest != saved.get("snapshot_sha256"):
            raise SecretUnavailable("selected GitHub repository audience changed")


def validate_provider_candidate(connection, row, settings):
    """Compatibility wrapper; callers should release their transaction first."""
    validate_provider_candidate_snapshot(prepare_provider_candidate(connection, row, settings))


def runtime_secret(engine, purpose: str, *, principal: str | None = None,
        action: str | None = None, authorization_target: str | None = None):
    """Resolve a purpose-bound active secret; legacy fallback is only pre-settings."""
    from uvm.github.webhooks import read_webhook_secret
    with engine.begin() as connection:
        try:
            value, version, policy = runtime_secret_admitted(connection, purpose)
        except SecretUnavailable as exc:
            rows = connection.execute(sa.select(connectors.c.connector_id).where(
                connectors.c.configuration_revision > 0)).all()
            if not rows and purpose == "webhook_secret":
                return read_webhook_secret()
            if not rows and purpose == "preview_secret":
                legacy_preview = os.environ.get("UVM_GITHUB_PREVIEW_SECRET", "").encode()
                if len(legacy_preview) >= 32:
                    return legacy_preview, "legacy-environment"
            raise exc
        if principal is not None and action and authorization_target is not None:
            from uvm.assessment.api import _require_authority
            current_policy = connection.execute(sa.select(assessment_policy).where(
                assessment_policy.c.policy_id == 1).with_for_update()).mappings().first()
            if policy is None or current_policy is None or current_policy["document"] != policy["document"]:
                raise SecretUnavailable("preview authority changed during resolution")
            _require_authority(current_policy["document"], principal, action,
                authorization_target, origin="local_api", correlation_id="g7-preview-secret")
        return value, version


def runtime_secret_admitted(connection, purpose: str):
    """Resolve under caller-held ordered DB locks through durable admission."""
    from uvm.assessment.policy_lock import lock_policy
    lock_policy(connection)
    policy = connection.execute(sa.select(assessment_policy).where(
        assessment_policy.c.policy_id == 1).with_for_update()).mappings().first()
    rows = connection.execute(sa.select(connectors).where(
        connectors.c.configuration_revision > 0).with_for_update()).mappings().all()
    if not rows:
        if purpose == "webhook_secret":
            from uvm.github.webhooks import read_webhook_secret
            legacy_secret, legacy_version = read_webhook_secret()
            return legacy_secret, legacy_version, policy
        if purpose == "preview_secret":
            legacy_preview = os.environ.get("UVM_GITHUB_PREVIEW_SECRET", "").encode()
            if len(legacy_preview) >= 32:
                return legacy_preview, "legacy-environment", policy
        raise SecretUnavailable("explicit connector secret is not configured")
    active = [row for row in rows if row["lifecycle"] == "active"
        and row["active_configuration_revision"] == row["configuration_revision"]]
    if len(active) != 1:
        raise SecretUnavailable("explicit connector settings are not active")
    row = active[0]
    if row["recovery"].get("state") != "clear":
        raise SecretUnavailable("connector recovery fence is closed")
    if _rollback_reconciliation_pending(connection, str(row["connector_id"])):
        raise SecretUnavailable("connector rollback reconciliation is pending")
    settings = _settings(connection, row)
    if (purpose not in {"preview_secret", "webhook_secret"}
            and settings.get("authentication_mode") != "github_app_v1"):
        raise SecretUnavailable("active connector does not use GitHub App credentials")
    value = _resolve_record(connection, row, settings, purpose, staged=False)
    ref = (settings.get("credentials") or {}).get(purpose)
    return value, ref["version_id"], policy
