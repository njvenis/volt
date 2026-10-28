"""Canonical signed backup recovery-control report validation."""
from __future__ import annotations

import base64
from datetime import datetime, timezone
import hashlib
import json
import re
import uuid


def canonical_json(value: object) -> bytes:
    def valid(item):
        if isinstance(item, float):
            return False
        if type(item) is int and abs(item) > 9007199254740991:
            return False
        if isinstance(item, dict):
            return all(isinstance(k, str) and valid(v) for k, v in item.items())
        if isinstance(item, list):
            return all(valid(v) for v in item)
        return item is None or type(item) in (str, int, bool)
    if not valid(value):
        raise ValueError("signed JSON cannot contain floats or non-JSON values")
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
        separators=(",", ":"), allow_nan=False).encode("utf-8")


def digest(value: object) -> str:
    return hashlib.sha256(canonical_json(value)).hexdigest()


def verify_signature(document: dict, public_key_path: str, expected_key_id: str | None = None) -> tuple[bytes, bytes]:
    signature = document.get("signature")
    if (not isinstance(signature, dict) or set(signature) != {"algorithm", "key_id", "value"}
            or signature.get("algorithm") != "Ed25519"
            or not isinstance(signature.get("key_id"), str) or not signature["key_id"]):
        raise ValueError("host signature descriptor is invalid")
    if expected_key_id is not None and signature["key_id"] != expected_key_id:
        raise ValueError("host signing key ID is not pinned")
    try:
        value = signature["value"]
        if not isinstance(value, str) or "=" in value:
            raise ValueError
        raw_signature = base64.b64decode(value + "=" * (-len(value) % 4),
            altchars=b"-_", validate=True)
        if len(raw_signature) != 64:
            raise ValueError
        from cryptography.hazmat.primitives import serialization
        with open(public_key_path, "rb") as key_stream:
            key = serialization.load_pem_public_key(key_stream.read())
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        if not isinstance(key, Ed25519PublicKey):
            raise ValueError
        signed = {key: value for key, value in document.items() if key != "signature"}
        raw = canonical_json(signed)
        key.verify(raw_signature, raw)
        return raw, raw_signature
    except Exception as exc:
        raise ValueError("host signature is invalid") from exc


def parse_utc(value: object) -> datetime:
    if not isinstance(value, str):
        raise ValueError("timestamp is invalid")
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None or parsed.utcoffset() != timezone.utc.utcoffset(parsed):
        raise ValueError("timestamp must be UTC")
    return parsed.astimezone(timezone.utc)


def validate_policy(policy: object) -> dict:
    if not isinstance(policy, dict) or set(policy) != {
            "revision", "digest", "bounds", "archive_target_refs", "recovery_profile_refs",
            "maximum_report_age_seconds", "maximum_future_skew_seconds"}:
        raise ValueError("host policy shape is invalid")
    if type(policy["revision"]) is not int or policy["revision"] < 1:
        raise ValueError("host policy revision is invalid")
    if not isinstance(policy["digest"], str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", policy["digest"]):
        raise ValueError("host policy digest is invalid")
    bounds = policy["bounds"]
    expected_fields = {"interval_seconds", "timeout_seconds", "maximum_backup_age_seconds",
        "restore_verification_timeout_seconds"}
    if not isinstance(bounds, dict) or set(bounds) != expected_fields:
        raise ValueError("host policy bounds are invalid")
    for field, limit in bounds.items():
        floor = 60 if field in {"interval_seconds", "maximum_backup_age_seconds"} else 1
        if (not isinstance(limit, dict) or set(limit) != {"min", "max"}
                or type(limit["min"]) is not int or type(limit["max"]) is not int
                or limit["min"] < floor or limit["max"] < limit["min"]):
            raise ValueError("host policy bounds are invalid")
    for name in ("archive_target_refs", "recovery_profile_refs"):
        refs = policy[name]
        if (not isinstance(refs, list) or not refs
                or any(not isinstance(ref, str) or not re.fullmatch(
                    r"[A-Za-z0-9][A-Za-z0-9._:-]{0,255}", ref) for ref in refs)
                or len(set(refs)) != len(refs)):
            raise ValueError("host policy reference registry is invalid")
    for name in ("maximum_report_age_seconds", "maximum_future_skew_seconds"):
        if type(policy[name]) is not int or policy[name] < (1 if name.endswith("age_seconds") else 0):
            raise ValueError("host policy clock bounds are invalid")
    digest_body = {key: value for key, value in policy.items() if key != "digest"}
    if policy["digest"] != "sha256:" + digest(digest_body):
        raise ValueError("host policy digest does not match canonical policy")
    return policy
