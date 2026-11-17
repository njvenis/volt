"""Read-only Okta membership publisher for the existing OIDC full-snapshot DTO."""
from __future__ import annotations

import argparse
import asyncio
from contextlib import contextmanager
import datetime as dt
import fcntl
import json
import os
from pathlib import Path
import re
import secrets
import stat
import time
from urllib.parse import urlsplit

from httpx2 import AsyncClient
from joserfc import jwt
from joserfc.jwk import RSAKey
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


SCOPES = ("okta.apps.read", "okta.groups.read", "okta.users.read")
ACCOUNT_STATES = {"ACTIVE", "DEPROVISIONED", "LOCKED_OUT", "PASSWORD_EXPIRED",
    "PROVISIONED", "RECOVERY", "STAGED", "SUSPENDED"}
SYNC_URL = "http://127.0.0.1:8001/api/v1/auth/provider/sync"
CONFIG_KEYS = {"schema_version", "provider_id", "org_url", "api_issuer", "api_base_url",
    "client_id", "app_id", "key_id", "private_key_file", "oidc_config_file",
    "subject_by_user_id", "group_ids", "poll_interval_seconds", "heartbeat_max_age_seconds"}
TOKEN_RE = re.compile(r"[A-Za-z0-9._:-]{1,256}\Z")
MAX_API_RECORDS = 100_000
MAX_API_PAGES = 1_000


def _validated_private_key(path: Path):
    try:
        raw = path.read_bytes()
        key = serialization.load_pem_private_key(raw, password=None)
        if not isinstance(key, rsa.RSAPrivateKey) or key.key_size < 2048:
            raise ValueError
        return key
    except (OSError, ValueError, TypeError):
        raise ValueError("Okta signing key must be an unencrypted RSA private PEM key of at least 2048 bits") from None


@contextmanager
def publisher_state_lock(state_dir: Path):
    state_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    if state_dir.is_symlink() or not state_dir.is_dir():
        raise RuntimeError("durable publisher state directory is not a regular directory")
    lock_path = state_dir / ".publisher.lock"
    lock_fd = os.open(lock_path, os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        lock_stat = os.fstat(lock_fd)
        if (lock_stat.st_uid != os.geteuid() or stat.S_IMODE(lock_stat.st_mode) != 0o600
                or not stat.S_ISREG(lock_stat.st_mode)):
            raise RuntimeError("publisher lock file is not private and owned")
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise RuntimeError("another Okta publisher already owns this durable state directory") from None
        yield
    finally:
        os.close(lock_fd)


def _origin(value: str) -> tuple[str, str, int]:
    parsed = urlsplit(value)
    if (parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password
            or parsed.query or parsed.fragment):
        raise ValueError("Okta URLs must be credential-free HTTPS URLs")
    return parsed.scheme, parsed.hostname.lower(), parsed.port or 443


def _subject(value) -> bool:
    return (isinstance(value, str) and 1 <= len(value) <= 255
            and all(ord(char) >= 0x20 and ord(char) != 0x7f for char in value))


def load_config(path: str | Path) -> dict:
    try:
        value = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        raise ValueError("Okta publisher configuration is unavailable or invalid JSON") from None
    if not isinstance(value, dict) or set(value) != CONFIG_KEYS or value.get("schema_version") != 1:
        raise ValueError("Okta publisher configuration does not match schema version 1")
    org, issuer, api = value["org_url"], value["api_issuer"], value["api_base_url"]
    origin = _origin(org)
    if org.rstrip("/") != f"{origin[0]}://{origin[1]}" or _origin(issuer) != origin or _origin(api) != origin:
        raise ValueError("Okta API URLs must use one exact org origin")
    if issuer.rstrip("/") != org.rstrip("/") + "/oauth2/v1" or api.rstrip("/") != org.rstrip("/") + "/api/v1":
        raise ValueError("Okta Management API issuer/base path is invalid")
    for key in ("provider_id", "client_id", "app_id", "key_id"):
        if not isinstance(value[key], str) or not TOKEN_RE.fullmatch(value[key]):
            raise ValueError(f"Okta publisher {key} is invalid")
    if (type(value["poll_interval_seconds"]) is not int or type(value["heartbeat_max_age_seconds"]) is not int
            or value["poll_interval_seconds"] < 5 or value["heartbeat_max_age_seconds"] < 30
            or value["poll_interval_seconds"] * 3 > value["heartbeat_max_age_seconds"]):
        raise ValueError("poll interval must be at least 5 seconds and leave at least three polls within heartbeat age")
    subjects, groups = value["subject_by_user_id"], value["group_ids"]
    if (not isinstance(subjects, dict) or not subjects or not isinstance(groups, list) or not groups
            or not isinstance(value["private_key_file"], str)
            or not isinstance(value["oidc_config_file"], str)
            or any(not TOKEN_RE.fullmatch(k) or not _subject(v)
                   for k, v in subjects.items())
            or len(set(subjects.values())) != len(subjects)
            or any(not isinstance(group, str) or not TOKEN_RE.fullmatch(group) for group in groups)
            or len(set(groups)) != len(groups)):
        raise ValueError("explicit exact Okta user and group mappings are required")
    try:
        oidc = json.loads(Path(value["oidc_config_file"]).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        raise ValueError("admitted OIDC authority configuration is unavailable or invalid") from None
    if (not isinstance(oidc, dict) or oidc.get("provider_id") != value["provider_id"]
            or oidc.get("heartbeat_max_age_seconds") != value["heartbeat_max_age_seconds"]
            or not isinstance(oidc.get("group_mappings"), dict)
            or set(oidc["group_mappings"]) != set(groups)
            or origin not in {_origin(item) for item in oidc.get("allowed_endpoint_origins", [])}):
        raise ValueError("publisher provider, heartbeat or group IDs differ from admitted OIDC authority config")
    private_key = Path(value["private_key_file"])
    try:
        if private_key.is_symlink() or not private_key.is_file() or stat.S_IMODE(private_key.stat().st_mode) & 0o077:
            raise OSError
        _validated_private_key(private_key)
    except OSError:
        raise ValueError("Okta private key must be a readable regular file with private permissions") from None
    return value


def _read_secret(path: str = "/run/uvm-g7-secrets/oidc_sync_secret") -> str:
    try:
        value = Path(path).read_text(encoding="utf-8").strip()
    except OSError:
        raise RuntimeError("publisher sync credential is unavailable") from None
    if not value:
        raise RuntimeError("publisher sync credential is empty")
    return value


def _client_assertion(config: dict, now: int | None = None) -> str:
    now = int(time.time()) if now is None else now
    _validated_private_key(Path(config["private_key_file"]))
    key = RSAKey.import_key(Path(config["private_key_file"]).read_bytes())
    token_url = config["api_issuer"].rstrip("/") + "/token"
    assertion = jwt.encode({"alg": "RS256", "kid": config["key_id"], "typ": "JWT"}, {
        "iss": config["client_id"], "sub": config["client_id"], "aud": token_url,
        "iat": now, "exp": now + 60, "jti": secrets.token_urlsafe(24)}, key)
    return assertion.decode() if isinstance(assertion, bytes) else assertion


def _next_url(response, original_url: str, base_url: str) -> str | None:
    links = response.headers.get("Link", "")
    match = re.search(r'<([^>]+)>\s*;\s*rel="next"', links)
    if not match:
        return None
    candidate = match.group(1)
    expected_origin, expected_path = _origin(base_url), urlsplit(original_url).path
    parsed, original = urlsplit(candidate), urlsplit(base_url)
    if (parsed.scheme != "https" or (parsed.scheme, (parsed.hostname or "").lower(), parsed.port or 443) != expected_origin
            or parsed.username or parsed.password or parsed.path != expected_path or parsed.fragment):
        raise RuntimeError("Okta pagination link escaped the configured endpoint")
    return candidate


async def _get_all(client: AsyncClient, url: str, *, base_url: str, token: str) -> list[dict]:
    base_origin = _origin(base_url)
    initial = urlsplit(url)
    if ((initial.scheme, (initial.hostname or "").lower(), initial.port or 443) != base_origin
            or not initial.path.startswith(urlsplit(base_url).path.rstrip("/") + "/")
            or initial.username or initial.password or initial.fragment):
        raise RuntimeError("Okta API request escaped the configured base URL")
    rows, next_url, seen = [], url, set()
    while next_url:
        if len(seen) >= MAX_API_PAGES:
            raise RuntimeError("Okta pagination exceeded the bounded page limit")
        if next_url in seen:
            raise RuntimeError("Okta pagination repeated a page")
        seen.add(next_url)
        response = await client.get(next_url, headers={"Authorization": "Bearer " + token,
            "Accept": "application/json"})
        if response.is_redirect:
            raise RuntimeError("Okta API redirected a credential-bearing request")
        if response.status_code != 200:
            raise RuntimeError(f"Okta API page failed with status {response.status_code}")
        try:
            page = response.json()
        except Exception:
            raise RuntimeError("Okta API page was not JSON") from None
        if not isinstance(page, list) or any(not isinstance(item, dict) for item in page):
            raise RuntimeError("Okta API page did not contain object records")
        rows.extend(page)
        if len(rows) > MAX_API_RECORDS:
            raise RuntimeError("Okta API traversal exceeded the bounded record limit")
        next_url = _next_url(response, url, base_url)
    return rows


class OktaPublisher:
    def __init__(self, config: dict, *, revision_dir: Path = Path("/opt/uvm/state/oidc-publisher"),
                 status_file: Path = Path("/opt/uvm/state/oidc-publisher/status.json"),
                 sync_secret_file: str = "/run/uvm-g7-secrets/oidc_sync_secret"):
        self.config = config
        self.revision_dir = revision_dir
        self.status_file = status_file
        self.sync_secret_file = sync_secret_file

    async def token(self, client: AsyncClient) -> str:
        token_url = self.config["api_issuer"].rstrip("/") + "/token"
        response = await client.post(token_url, data={"grant_type": "client_credentials",
            "scope": " ".join(SCOPES), "client_assertion_type":
            "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
            "client_assertion": _client_assertion(self.config)})
        if response.status_code != 200:
            raise RuntimeError(f"Okta token request failed with status {response.status_code}")
        body = response.json()
        if (not isinstance(body, dict) or not isinstance(body.get("access_token"), str)
                or not isinstance(body.get("token_type", "Bearer"), str)
                or body.get("token_type", "Bearer").lower() != "bearer"):
            raise RuntimeError("Okta token response is invalid")
        return body["access_token"]

    async def snapshot(self, client: AsyncClient, token: str) -> list[dict]:
        config, base = self.config, self.config["api_base_url"].rstrip("/")
        app_response = await client.get(f"{base}/apps/{config['app_id']}",
            headers={"Authorization": "Bearer " + token})
        if app_response.status_code != 200 or app_response.is_redirect:
            raise RuntimeError(f"Okta app read failed with status {app_response.status_code}")
        app = app_response.json()
        if not isinstance(app, dict) or app.get("id") != config["app_id"]:
            raise RuntimeError("Okta app identity did not match configured app")
        if app.get("status") != "ACTIVE":
            raise RuntimeError("configured Okta login application is not active")
        client_id = ((app.get("settings") or {}).get("oauthClient") or {}).get("client_id")
        if client_id != config["client_id"]:
            raise RuntimeError("configured Okta application client ID differs from admitted OIDC client")
        assignments = await _get_all(client, f"{base}/apps/{config['app_id']}/users?limit=200",
                                     base_url=config["api_base_url"], token=token)
        identities = []
        seen_users, seen_subjects = set(), set()
        for assignment in assignments:
            user_id = assignment.get("id")
            if not isinstance(user_id, str) or not user_id:
                raise RuntimeError("Okta app assignment omitted user identity")
            if user_id in seen_users:
                raise RuntimeError("Okta app assignments contained a duplicate user")
            seen_users.add(user_id)
            if assignment.get("status") not in ("ACTIVE", "INACTIVE"):
                raise RuntimeError("Okta app assignment state is unknown")
            subject = config["subject_by_user_id"].get(user_id)
            if assignment["status"] == "ACTIVE" and subject is None:
                raise RuntimeError("active Okta app user is missing an explicit OIDC subject mapping")
            user_response = await client.get(f"{base}/users/{user_id}",
                headers={"Authorization": "Bearer " + token})
            if user_response.status_code != 200 or user_response.is_redirect:
                raise RuntimeError(f"Okta account-state read failed with status {user_response.status_code}")
            user = user_response.json()
            if (not isinstance(user, dict) or user.get("id") != user_id
                    or user.get("status") not in ACCOUNT_STATES):
                raise RuntimeError("Okta account-state response is invalid")
            groups = await _get_all(client, f"{base}/users/{user_id}/groups?limit=200",
                                    base_url=config["api_base_url"], token=token)
            group_ids = sorted({group["id"] for group in groups
                if isinstance(group.get("id"), str) and group["id"] in config["group_ids"]})
            if any(not isinstance(group.get("id"), str) for group in groups):
                raise RuntimeError("Okta group response omitted a stable group ID")
            if assignment["status"] != "ACTIVE" or user["status"] != "ACTIVE":
                continue
            if subject in seen_subjects:
                raise RuntimeError("Okta app assignments resolved to duplicate OIDC subjects")
            seen_subjects.add(subject)
            identities.append({"subject": subject, "groups": group_ids})
        return sorted(identities, key=lambda row: row["subject"])

    def _next_revision(self) -> int:
        self.revision_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        if (self.revision_dir.is_symlink() or not self.revision_dir.is_dir()
                or self.revision_dir.stat().st_uid != os.geteuid()
                or stat.S_IMODE(self.revision_dir.stat().st_mode) & 0o077):
            raise RuntimeError("durable publisher state directory is not private and owned")
        path = self.revision_dir / "revision.json"
        try:
            if path.is_symlink():
                raise OSError
            if not path.exists():
                revision = 1
            elif not path.is_file():
                raise OSError
            else:
                if path.stat().st_uid != os.geteuid() or stat.S_IMODE(path.stat().st_mode) != 0o600:
                    raise OSError
                state = json.loads(path.read_text(encoding="ascii"))
                if not isinstance(state, dict) or type(state.get("revision")) is not int or state["revision"] < 0:
                    raise OSError
                revision = state["revision"] + 1
        except (OSError, json.JSONDecodeError):
            raise RuntimeError("durable Okta publisher revision state is invalid") from None
        temporary = self.revision_dir / (".revision-" + secrets.token_hex(8))
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with os.fdopen(fd, "w", encoding="ascii") as stream:
                json.dump({"revision": revision}, stream, sort_keys=True)
                stream.write("\n"); stream.flush(); os.fsync(stream.fileno())
            os.replace(temporary, path)
            dir_fd = os.open(self.revision_dir, os.O_RDONLY)
            try: os.fsync(dir_fd)
            finally: os.close(dir_fd)
        finally:
            temporary.unlink(missing_ok=True)
        return revision

    async def publish(self, client: AsyncClient, token: str, identities: list[dict], *,
                      collection_started_at: float | None = None) -> int:
        collection_started_at = time.time() if collection_started_at is None else collection_started_at
        age = time.time() - collection_started_at
        freshness_budget = (self.config["heartbeat_max_age_seconds"]
            - 2 * self.config["poll_interval_seconds"])
        if age < 0 or age > freshness_budget:
            raise RuntimeError("Okta identity traversal exceeded its conservative freshness budget")
        revision = self._next_revision()
        payload = {"schema_version": 1, "provider_id": self.config["provider_id"],
            "revision": revision, "heartbeat_at": dt.datetime.fromtimestamp(
                collection_started_at, dt.timezone.utc).isoformat(),
            "kind": "full_snapshot", "identities": identities}
        secret = _read_secret(self.sync_secret_file)
        response = await client.post(SYNC_URL, json=payload,
            headers={"Authorization": "Bearer " + secret})
        if response.status_code not in (200, 503):
            raise RuntimeError(f"UVM membership snapshot was rejected with status {response.status_code}")
        if response.status_code == 503:
            raise RuntimeError("UVM membership snapshot service is unavailable")
        result = response.json()
        if (not isinstance(result, dict) or result.get("committed") is not True
                or result.get("revision") != revision or result.get("provider_id") != self.config["provider_id"]):
            raise RuntimeError("UVM membership snapshot acknowledgement is invalid")
        return revision

    def _status(self, *, last_success: float | None, error: str | None) -> None:
        self.status_file.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        temporary = self.status_file.with_suffix(".tmp")
        temporary.write_text(json.dumps({"last_success_epoch": last_success,
            "last_error_class": error}, sort_keys=True) + "\n", encoding="utf-8")
        temporary.chmod(0o600); os.replace(temporary, self.status_file)

    async def run(self) -> None:
        last_success = None
        delay = 1
        with publisher_state_lock(self.revision_dir):
            async with AsyncClient(timeout=15, follow_redirects=False) as client:
                while True:
                    try:
                        access_token = await self.token(client)
                        collection_started_at = time.time()
                        identities = await self.snapshot(client, access_token)
                        await self.publish(client, access_token, identities,
                            collection_started_at=collection_started_at)
                        last_success, delay = time.time(), 1
                        self._status(last_success=last_success, error=None)
                    except asyncio.CancelledError:
                        raise
                    except Exception as exc:
                        self._status(last_success=last_success, error=type(exc).__name__)
                        print(f"OKTA_IDENTITY_SYNC retry error_class={type(exc).__name__}", flush=True)
                        await asyncio.sleep(delay)
                        delay = min(delay * 2, 10)
                        continue
                    await asyncio.sleep(self.config["poll_interval_seconds"])


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True)
    parser.add_argument("--validate-only", action="store_true",
                        help="validate config and private-file admission without contacting Okta")
    parser.add_argument("--status", action="store_true",
                        help="report only the retained local publisher heartbeat status")
    args = parser.parse_args()
    try:
        config = load_config(args.config)
        if args.validate_only:
            print(json.dumps({"status": "valid", "provider_id": config["provider_id"],
                "poll_interval_seconds": config["poll_interval_seconds"],
                "heartbeat_max_age_seconds": config["heartbeat_max_age_seconds"],
                "mapped_subject_count": len(config["subject_by_user_id"]),
                "mapped_group_count": len(config["group_ids"])}))
            return 0
        if args.status:
            status_file = Path("/opt/uvm/state/oidc-publisher/status.json")
            try:
                state = json.loads(status_file.read_text(encoding="utf-8"))
                last = state.get("last_success_epoch")
            except (OSError, json.JSONDecodeError):
                print(json.dumps({"status": "not_ready"}))
                return 1
            age = None if type(last) not in (int, float) else max(0, int(time.time() - last))
            ready = age is not None and age <= config["heartbeat_max_age_seconds"]
            print(json.dumps({"status": "healthy" if ready else "stale",
                "last_success_age_seconds": age, "last_error_class": state.get("last_error_class")}))
            return 0 if ready else 1
        asyncio.run(OktaPublisher(config,
            sync_secret_file=os.environ.get("UVM_OIDC_SYNC_SECRET_FILE",
                "/run/uvm-g7-secrets/oidc_sync_secret")).run())
    except KeyboardInterrupt:
        return 0
    except Exception as exc:
        print(f"OKTA_IDENTITY_SYNC fatal error_class={type(exc).__name__}", flush=True)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
