"""AES-GCM storage for fixture-scoped connector secret versions."""
from __future__ import annotations

import os
import stat
import uuid
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class SecretUnavailable(RuntimeError):
    """Secret material cannot safely be used."""


def _key(path: str | None = None) -> tuple[bytes, str]:
    filename = path or os.environ.get("UVM_CONNECTOR_LOCAL_KEY_FILE")
    if not filename:
        raise SecretUnavailable("encrypted-local key is not configured")
    try:
        fd = os.open(filename, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except OSError:
        raise SecretUnavailable("encrypted-local key is unavailable") from None
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600:
            raise SecretUnavailable("encrypted-local key must be a regular 0600 file")
        data = stream.read(33)
    if len(data) != 32:
        raise SecretUnavailable("encrypted-local key must contain 256 bits")
    key_id = os.environ.get("UVM_CONNECTOR_LOCAL_KEY_ID", "")
    try:
        key_id = str(uuid.UUID(key_id))
    except (ValueError, TypeError, AttributeError):
        raise SecretUnavailable("encrypted-local key ID is invalid") from None
    return data, key_id


def _aad(connector_id: str, secret_id: str, version_id: str) -> bytes:
    return ("uvm-connector-secret-v1\0" + str(uuid.UUID(connector_id)) + "\0" +
            str(uuid.UUID(secret_id)) + "\0" + str(uuid.UUID(version_id))).encode("ascii")


def encrypt(value: bytes, connector_id: str, secret_id: str, version_id: str,
            *, key_path: str | None = None, nonce: bytes | None = None) -> dict:
    if not isinstance(value, bytes) or not 1 <= len(value) <= 65536:
        raise ValueError("secret must contain 1 to 65536 UTF-8 bytes")
    key, key_id = _key(key_path)
    nonce = nonce if nonce is not None else os.urandom(12)
    if not isinstance(nonce, bytes) or len(nonce) != 12:
        raise ValueError("AES-GCM nonce must contain 96 bits")
    return {"algorithm": "AES-256-GCM-v1", "key_id": key_id,
        "nonce": nonce, "ciphertext": AESGCM(key).encrypt(nonce, value,
            _aad(connector_id, secret_id, version_id))}


def decrypt(record: dict, connector_id: str, secret_id: str, version_id: str,
            *, key_path: str | None = None) -> bytes:
    if record.get("algorithm") != "AES-256-GCM-v1":
        raise SecretUnavailable("secret algorithm is unsupported")
    key, key_id = _key(key_path)
    if record.get("key_id") != key_id:
        raise SecretUnavailable("secret key binding changed")
    try:
        return AESGCM(key).decrypt(record["nonce"], record["ciphertext"],
            _aad(connector_id, secret_id, version_id))
    except (InvalidTag, KeyError, TypeError, ValueError):
        raise SecretUnavailable("secret authentication failed") from None
