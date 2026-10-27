"""Independent fixture authorities for fail-closed local restore recovery.

Production recovery authority is deliberately out of scope.  These helpers
accept only mode-0600, externally mounted, HMAC-bound fixture ledgers.
"""
from __future__ import annotations

import hashlib
import json
import base64
import os
import stat
from pathlib import Path


def _read(path_env: str, key_env: str | None = None) -> tuple[dict, bytes | None]:
    path = os.environ.get(path_env)
    if not path:
        raise ValueError("independent recovery authority is unavailable")
    p = Path(path)
    info = p.lstat()
    if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600 or info.st_size > 1_000_000:
        raise ValueError("independent recovery authority file is unsafe")
    data = json.loads(p.read_text(encoding="utf-8"))
    key = None
    if key_env:
        key_path = Path(os.environ[key_env]); key_info = key_path.lstat()
        if not stat.S_ISREG(key_info.st_mode) or stat.S_IMODE(key_info.st_mode) != 0o600:
            raise ValueError("independent recovery authority key is unsafe")
        key = key_path.read_bytes()
        if len(key) < 32:
            raise ValueError("independent recovery authority key is invalid")
    if not isinstance(data, dict):
        raise ValueError("independent recovery authority document is invalid")
    return data, key


def _verified_document(path_env: str, key_env: str) -> dict:
    doc, key = _read(path_env, key_env)
    signature = doc.get("signature")
    unsigned = {k: v for k, v in doc.items() if k != "signature"}
    canonical = json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode()
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        Ed25519PublicKey.from_public_bytes(key).verify(base64.b64decode(signature, validate=True), canonical)
    except Exception:
        raise ValueError("independent recovery authority signature is invalid")
    return unsigned


def issuer_entry(connector_id: str, secret_id: str, version_id: str, purpose: str,
                 recovery_epoch_id: str, plaintext: bytes) -> dict | None:
    try:
        ledger = _verified_document("UVM_CONNECTOR_ISSUER_LEDGER_FILE", "UVM_CONNECTOR_ISSUER_KEY_FILE")
    except (OSError, ValueError, KeyError, json.JSONDecodeError):
        return None
    if ledger.get("schema_version") != 1:
        return None
    for item in ledger.get("entries", []):
        if (isinstance(item, dict) and item.get("connector_id") == connector_id
                and item.get("secret_id") == secret_id and item.get("version_id") == version_id
                and item.get("purpose") == purpose and item.get("recovery_epoch_id") == recovery_epoch_id
                and item.get("value_sha256") == hashlib.sha256(plaintext).hexdigest()):
            return item
    return None


def issuer_entry_diagnostic(connector_id: str, secret_id: str, version_id: str,
                            purpose: str, recovery_epoch_id: str,
                            plaintext: bytes) -> dict[str, bool]:
    """Return only mismatch flags for labelled fixture troubleshooting."""
    try:
        ledger = _verified_document("UVM_CONNECTOR_ISSUER_LEDGER_FILE", "UVM_CONNECTOR_ISSUER_KEY_FILE")
    except Exception as exc:
        return {"ledger_verified": False, "record_found": False, "connector_matches": False,
            "secret_matches": False, "purpose_matches": False, "epoch_matches": False,
            "issued_after_epoch": False, "value_matches": False,
            "authority_error": type(exc).__name__,
            "ledger_path_configured": bool(os.environ.get("UVM_CONNECTOR_ISSUER_LEDGER_FILE")),
            "key_path_configured": bool(os.environ.get("UVM_CONNECTOR_ISSUER_KEY_FILE"))}
    item = next((entry for entry in ledger.get("entries", [])
        if isinstance(entry, dict) and entry.get("version_id") == version_id), None)
    if item is None:
        return {"ledger_verified": True, "record_found": False, "connector_matches": False,
            "secret_matches": False, "purpose_matches": False, "epoch_matches": False,
            "issued_after_epoch": False, "value_matches": False,
            "authority_error": None}
    return {"ledger_verified": True, "record_found": True,
        "connector_matches": item.get("connector_id") == connector_id,
        "secret_matches": item.get("secret_id") == secret_id,
        "purpose_matches": item.get("purpose") == purpose,
        "epoch_matches": item.get("recovery_epoch_id") == recovery_epoch_id,
        "issued_after_epoch": item.get("issued_after_epoch") is True,
        "value_matches": item.get("value_sha256") == hashlib.sha256(plaintext).hexdigest(),
        "authority_error": None}


def issuer_version(connector_id: str, secret_id: str, version_id: str, purpose: str,
                   recovery_epoch_id: str) -> dict | None:
    try:
        ledger = _verified_document("UVM_CONNECTOR_ISSUER_LEDGER_FILE", "UVM_CONNECTOR_ISSUER_KEY_FILE")
    except (OSError, ValueError, KeyError, json.JSONDecodeError):
        return None
    for item in ledger.get("entries", []):
        if (isinstance(item, dict) and item.get("connector_id") == connector_id
                and item.get("secret_id") == secret_id and item.get("version_id") == version_id
                and item.get("purpose") == purpose and item.get("recovery_epoch_id") == recovery_epoch_id
                and item.get("issued_after_epoch") is True):
            return item
    return None


def operator_clearance(connector_id: str, recovery_epoch_id: str) -> dict | None:
    try:
        doc = _verified_document("UVM_CONNECTOR_OPERATOR_CLEARANCE_FILE", "UVM_CONNECTOR_OPERATOR_KEY_FILE")
    except (OSError, ValueError, KeyError, json.JSONDecodeError):
        return None
    if (doc.get("schema_version") != 1 or doc.get("connector_id") != connector_id
            or doc.get("recovery_epoch_id") != recovery_epoch_id
            or not isinstance(doc.get("operator_id"), str) or not doc["operator_id"].strip()
            or not isinstance(doc.get("rationale"), str) or not doc["rationale"].strip()):
        return None
    if not isinstance(doc.get("fresh_version_ids"), list) or not doc["fresh_version_ids"]:
        return None
    return doc
