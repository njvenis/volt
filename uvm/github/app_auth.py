"""Small GitHub App JWT signer using the configured App private key."""
from __future__ import annotations

import base64
import json
import time

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa


def _b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def app_jwt(app_id: str | int, private_key_pem: bytes, *, now: int | None = None) -> str:
    """Sign a bounded RS256 App JWT (GitHub accepts at most ten minutes)."""
    issued = int(time.time()) if now is None else int(now)
    app = str(app_id)
    if not app.isascii() or not app.isdigit() or len(app) > 20:
        raise ValueError("GitHub App ID is invalid")
    key = serialization.load_pem_private_key(private_key_pem, password=None)
    if not isinstance(key, rsa.RSAPrivateKey) or key.key_size < 2048:
        raise ValueError("GitHub App private key is invalid")
    header = _b64(json.dumps({"alg": "RS256", "typ": "JWT"},
        separators=(",", ":"), sort_keys=True).encode())
    payload = _b64(json.dumps({"iss": app, "iat": issued - 60, "exp": issued + 540},
        separators=(",", ":"), sort_keys=True).encode())
    message = f"{header}.{payload}".encode("ascii")
    signature = key.sign(message, padding.PKCS1v15(), hashes.SHA256())
    return f"{header}.{payload}.{_b64(signature)}"
