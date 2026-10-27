"""GitHub webhook envelope and secret-file validation helpers."""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import stat
import uuid
from datetime import datetime
from pathlib import Path
from urllib.parse import urlsplit

MAX_WEBHOOK_BYTES = 25 * 1024 * 1024
_SIGNATURE = re.compile(r"sha256=([0-9a-f]{64})\Z")
_VERSION = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z")


def read_webhook_secret() -> tuple[bytes, str]:
    secret_dir = os.getenv("UVM_GITHUB_WEBHOOK_SECRET_DIR")
    version_file = os.getenv("UVM_GITHUB_WEBHOOK_SECRET_VERSION_FILE")
    if secret_dir or version_file:
        if not secret_dir or not version_file:
            raise RuntimeError("GitHub webhook secret directory and version file must be configured together")
        version = Path(version_file).read_text(encoding="ascii").strip()
        if not _VERSION.fullmatch(version):
            raise RuntimeError("GitHub webhook secret version is invalid")
        path = str(Path(secret_dir) / f"github_webhook_secret_{version}")
    else:
        path = os.getenv("UVM_GITHUB_WEBHOOK_SECRET_FILE")
        version = os.getenv("UVM_GITHUB_WEBHOOK_SECRET_VERSION")
    if not path or not version or not version.strip():
        raise RuntimeError("GitHub webhook secret file and version must be configured")
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except OSError as exc:
        raise RuntimeError("GitHub webhook secret file cannot be opened safely") from exc
    with os.fdopen(descriptor, "rb") as stream:
        info = os.fstat(stream.fileno())
        if stat.S_IMODE(info.st_mode) != 0o600 or not stat.S_ISREG(info.st_mode):
            raise RuntimeError("GitHub webhook secret file must be a regular 0600 file")
        secret = stream.read().strip()
    if len(secret) < 32:
        raise RuntimeError("GitHub webhook secret is missing or too short")
    return secret, version.strip()


def verify_signature(body: bytes, signature: str, secret: bytes) -> bool:
    match = _SIGNATURE.fullmatch(signature or "")
    if match is None:
        return False
    expected = hmac.new(secret, body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, match.group(1))


def _numeric_id(value) -> bool:
    return ((type(value) is int and value > 0)
        or (isinstance(value, str) and re.fullmatch(r"[1-9][0-9]*", value) is not None))


def _positive_integer(value) -> bool:
    return type(value) is int and value > 0


def _timestamp(value) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00" if value.endswith("Z") else value)
    except ValueError:
        return None
    return parsed if parsed.tzinfo is not None else None


def _issue_url(value) -> bool:
    if not isinstance(value, str) or not value:
        return False
    parsed = urlsplit(value)
    return (parsed.scheme in {"http", "https"} and bool(parsed.netloc)
        and re.search(r"/issues/[1-9][0-9]*$", parsed.path) is not None
        and not parsed.query and not parsed.fragment)


def validate_delivery_payload(payload: object, event_type: str) -> str | None:
    """Validate fields consumed by the durable webhook worker."""
    if not isinstance(payload, dict):
        raise ValueError("malformed_envelope")
    repository = payload.get("repository")
    if not isinstance(repository, dict) or not _numeric_id(repository.get("id")):
        raise ValueError("malformed_envelope")
    action = payload.get("action")
    if event_type == "issue_comment":
        comment, issue = payload.get("comment"), payload.get("issue")
        if (action not in {"created", "edited", "deleted"}
                or not isinstance(comment, dict)
                or not _numeric_id(comment.get("id"))
                or not isinstance(comment.get("body"), str)
                or not isinstance(comment.get("user"), dict)
                or not _numeric_id(comment["user"].get("id"))
                or not isinstance(issue, dict)
                or not _issue_url(issue.get("html_url"))):
            raise ValueError("malformed_envelope")
        created, updated = _timestamp(comment.get("created_at")), _timestamp(comment.get("updated_at"))
        if created is None or updated is None or updated < created:
            raise ValueError("malformed_envelope")
    elif event_type == "issues":
        issue = payload.get("issue")
        if (not isinstance(action, str) or not action
                or not isinstance(issue, dict)
                or not _positive_integer(issue.get("number"))
                or not _issue_url(issue.get("html_url"))):
            raise ValueError("malformed_envelope")
    elif event_type != "ping":
        raise ValueError("unsupported_event")
    return action


def parse_delivery(body: bytes, delivery_id: str, event_type: str) -> tuple[dict, str | None]:
    try:
        uuid.UUID(delivery_id)
    except (ValueError, TypeError, AttributeError):
        raise ValueError("invalid_delivery_id") from None
    try:
        payload = json.loads(body)
    except (json.JSONDecodeError, UnicodeDecodeError):
        raise ValueError("malformed_json") from None
    if not isinstance(payload, dict):
        raise ValueError("malformed_envelope")
    if event_type not in {"ping", "issue_comment", "issues"}:
        raise ValueError("unsupported_event")
    action = validate_delivery_payload(payload, event_type)
    return payload, action
