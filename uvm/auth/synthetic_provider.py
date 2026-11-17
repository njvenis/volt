"""Synthetic local OIDC provider used only by the disposable G7 container."""
from __future__ import annotations

import asyncio
import base64
import hashlib
import html
import ipaddress
import json
import os
import secrets
import time
from urllib.parse import parse_qs, urlencode

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from httpx2 import AsyncClient
from joserfc import jwt
from joserfc.jwk import RSAKey

app = FastAPI(title="UVM labelled synthetic OIDC provider", docs_url=None, redoc_url=None)
_codes: dict[str, dict] = {}
_failure_mode: str | None = None
_sync_paused = os.environ.get("UVM_OIDC_FIXTURE_HOLD_SYNC") == "1"
_login_states: dict[str, dict] = {}
_login_attempts: dict[str, list[float]] = {}


def _required(name: str) -> str:
    value = os.environ.get(name, "")
    if not value:
        raise RuntimeError(f"synthetic OIDC provider configuration missing {name}")
    return value


def _file_secret(name: str) -> str:
    path = _required(name)
    value = open(path, encoding="utf-8").read().strip()
    if not value:
        raise RuntimeError("synthetic provider secret file is empty")
    return value


def _key() -> RSAKey:
    return RSAKey.import_key(open(_required("UVM_OIDC_PROVIDER_KEY_FILE"), "rb").read())


def _config() -> tuple[str, str, str, str]:
    return (_required("UVM_OIDC_ISSUER"), _required("UVM_OIDC_CLIENT_ID"),
        _required("UVM_OIDC_CALLBACK_URL"), _required("UVM_OIDC_FIXTURE_SUBJECT"))


def _credential() -> dict:
    if not os.environ.get("UVM_OIDC_DEMO_CREDENTIALS_FILE"):
        raise RuntimeError("password login is disabled for this provider")
    try:
        with open(_required("UVM_OIDC_DEMO_CREDENTIALS_FILE"), encoding="utf-8") as stream:
            value = json.load(stream)
    except (OSError, json.JSONDecodeError):
        raise RuntimeError("demo credential file is unavailable or invalid") from None
    if (not isinstance(value, dict) or set(value) != {"schema", "username", "salt", "password_hash"}
            or value["schema"] != "uvm.demo-credential.v1"
            or not isinstance(value["username"], str) or not isinstance(value["salt"], str)
            or not isinstance(value["password_hash"], str)):
        raise RuntimeError("demo credential file schema is invalid")
    return value


def _password_matches(username: str, password: str) -> bool:
    credential = _credential()
    encoded_password = password.encode("utf-8")
    if len(encoded_password) > 1024:
        return False
    try:
        salt = bytes.fromhex(credential["salt"])
        expected = bytes.fromhex(credential["password_hash"])
        actual = hashlib.scrypt(encoded_password, salt=salt, n=2**15, r=8, p=1,
                                dklen=32, maxmem=64 * 1024 * 1024)
    except (ValueError, TypeError):
        return False
    return (secrets.compare_digest(username.encode(), credential["username"].encode())
            and secrets.compare_digest(actual, expected))


def _limited(peer: str) -> bool:
    now = time.monotonic()
    attempts = [stamp for stamp in _login_attempts.get(peer, []) if now - stamp < 300]
    _login_attempts[peer] = attempts
    return len(attempts) >= 10


def _failed(peer: str) -> None:
    _login_attempts.setdefault(peer, []).append(time.monotonic())


def _issue_code(query: dict, subject: str, *, name: str = "Local Demo Administrator",
                email: str = "demo-admin@localhost.invalid", fault: str = "") -> RedirectResponse:
    _issuer, client_id, callback, _default_subject = _config()
    code = secrets.token_urlsafe(32)
    _codes[code] = {"client_id": client_id, "callback": callback,
        "challenge": query["code_challenge"], "nonce": query["nonce"], "subject": subject,
        "name": name, "email": email, "fault": fault, "expires": time.time() + 120}
    return RedirectResponse(callback + "?" + urlencode({"code": code, "state": query["state"]}), status_code=302)


@app.get("/healthz")
def healthz():
    failure = _failure_mode or os.environ.get("UVM_G7_PROVIDER_FAILURE", "")
    return JSONResponse({"provider": "labelled-synthetic-local", "ready": not bool(failure)},
        status_code=503 if failure == "readiness" else 200)


@app.get("/.well-known/openid-configuration")
def discovery():
    issuer, _client_id, _callback, _subject = _config()
    if (_failure_mode or os.environ.get("UVM_G7_PROVIDER_FAILURE")) == "discovery":
        return JSONResponse({"error": "synthetic provider unavailable"}, status_code=503)
    browser_origin = os.environ.get("UVM_OIDC_BROWSER_AUTHORIZATION_ORIGIN", "").rstrip("/")
    internal_origin = os.environ.get("UVM_OIDC_INTERNAL_ENDPOINT_ORIGIN", "").rstrip("/")
    return {"issuer": issuer,
        "authorization_endpoint": (browser_origin or issuer) + "/authorize",
        "token_endpoint": (internal_origin or issuer) + "/token",
        "jwks_uri": (internal_origin or issuer) + "/jwks",
        "response_types_supported": ["code"], "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "token_endpoint_auth_methods_supported": ["client_secret_basic"]}


@app.get("/jwks")
def jwks():
    if (_failure_mode or os.environ.get("UVM_G7_PROVIDER_FAILURE")) == "jwks":
        return JSONResponse({"error": "synthetic provider unavailable"}, status_code=503)
    public = _key().as_dict(private=False)
    public.update(kid="uvm-g7-local-rsa-1", use="sig", alg="RS256")
    return {"keys": [public]}


@app.get("/authorize")
def authorize(request: Request):
    issuer, client_id, callback, default_subject = _config()
    query = request.query_params
    if (query.get("client_id") != client_id or query.get("redirect_uri") != callback
            or query.get("response_type") != "code" or "openid" not in query.get("scope", "").split()
            or query.get("code_challenge_method") != "S256" or not query.get("code_challenge")
            or not query.get("state") or not query.get("nonce")):
        return JSONResponse({"error": "invalid_request"}, status_code=400)
    if (_failure_mode or os.environ.get("UVM_G7_PROVIDER_FAILURE")) == "authorize":
        return JSONResponse({"error": "synthetic provider unavailable"}, status_code=503)
    if os.environ.get("UVM_OIDC_FIXTURE_MODE") == "1":
        # Explicit test-only fixture mode; never enabled by the portable demo.
        return _issue_code(dict(query), query.get("fixture_subject", default_subject),
            name=query.get("fixture_name", "Synthetic Fixture User"),
            email=query.get("fixture_email", "synthetic@example.invalid"),
            fault=query.get("fixture_fault", ""))
    if not os.environ.get("UVM_OIDC_DEMO_CREDENTIALS_FILE"):
        return JSONResponse({"error": "login_unavailable"}, status_code=503)
    csrf = secrets.token_urlsafe(32)
    now = time.time()
    for key in [key for key, item in _login_states.items() if item["expires"] <= now]:
        _login_states.pop(key, None)
    if len(_login_states) >= 1000:
        return JSONResponse({"error": "login_temporarily_unavailable"}, status_code=503)
    _login_states[csrf] = {"query": dict(query), "expires": time.time() + 300}
    response = HTMLResponse("""<!doctype html><html><head><meta charset=utf-8><title>VOLT local demo sign in</title></head>
<body><main><h1>Local demo sign in</h1><form method=post action=/login>
<input type=hidden name=csrf value=""" + html.escape(csrf, quote=True) + """>
<label>Username <input name=username autocomplete=username required></label>
<label>Password <input name=password type=password autocomplete=current-password required></label>
<button type=submit>Sign in</button></form></main></body></html>""")
    response.headers["Cache-Control"] = "no-store"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.set_cookie("uvm_demo_login_csrf", csrf, httponly=True, secure=False,
        samesite="strict", path="/login", max_age=300)
    return response


@app.post("/login")
async def demo_login(request: Request):
    peer = request.client.host if request.client else "unknown"
    try:
        fields = parse_qs((await request.body()).decode("utf-8"), strict_parsing=True)
    except Exception:
        fields = {}
    csrf = fields.get("csrf", [""])[0]
    state = _login_states.get(csrf)
    cookie = request.cookies.get("uvm_demo_login_csrf", "")
    if (not csrf or not secrets.compare_digest(csrf, cookie) or not state
            or state["expires"] <= time.time()):
        return HTMLResponse("Sign-in failed. Check your credentials and try again.", status_code=400,
            headers={"Cache-Control": "no-store"})
    if _limited(peer):
        return HTMLResponse("Sign-in failed. Check your credentials and try again.", status_code=429,
            headers={"Cache-Control": "no-store"})
    username = fields.get("username", [""])[0]
    password = fields.get("password", [""])[0]
    try:
        valid = _password_matches(username, password)
    except RuntimeError:
        valid = False
    if not valid:
        _failed(peer)
        return HTMLResponse("Sign-in failed. Check your credentials and try again.", status_code=401,
            headers={"Cache-Control": "no-store"})
    _login_attempts.pop(peer, None)
    _login_states.pop(csrf, None)
    response = _issue_code(state["query"], _config()[3])
    response.delete_cookie("uvm_demo_login_csrf", path="/login", samesite="strict")
    return response


@app.post("/token")
async def token(request: Request):
    if (_failure_mode or os.environ.get("UVM_G7_PROVIDER_FAILURE")) == "token":
        return JSONResponse({"error": "server_error"}, status_code=503)
    issuer, client_id, callback, _default_subject = _config()
    client_secret = _file_secret("UVM_OIDC_CLIENT_SECRET_FILE")
    auth = request.headers.get("authorization", "")
    try:
        kind, encoded = auth.split(" ", 1)
        supplied_id, supplied_secret = base64.b64decode(encoded).decode().split(":", 1)
    except Exception:
        kind, supplied_id, supplied_secret = "", "", ""
    form = parse_qs((await request.body()).decode("ascii"), strict_parsing=True)
    code = form.get("code", [""])[0]
    verifier = form.get("code_verifier", [""])[0]
    entry = _codes.get(code)
    if (kind != "Basic" or supplied_id != client_id or supplied_secret != client_secret
            or form.get("grant_type") != ["authorization_code"] or not entry
            or entry["expires"] <= time.time() or form.get("redirect_uri") != [callback]
            or entry["client_id"] != client_id or entry["callback"] != callback
            or not verifier or not secrets.compare_digest(
                base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("="),
                entry["challenge"])):
        return JSONResponse({"error": "invalid_grant"}, status_code=400)
    del _codes[code]
    now = int(time.time())
    token_expiry = now - 1 if entry["fault"] == "expired" else now + 300
    signed = jwt.encode({"alg": "RS256", "kid": "uvm-g7-local-rsa-1", "typ": "JWT"}, {
        "iss": issuer, "sub": entry["subject"], "aud": client_id,
        "iat": now, "exp": token_expiry, "nonce": entry["nonce"],
        "name": entry["name"], "email": entry["email"]}, _key())
    if entry["fault"] == "issuer":
        # Re-issue with the wrong configured issuer, still signed by the
        # trusted key, so the issuer assertion is independently exercised.
        claims = {"iss": issuer + "/wrong", "sub": entry["subject"], "aud": client_id,
            "iat": now, "exp": now + 300, "nonce": entry["nonce"]}
        signed = jwt.encode({"alg": "RS256", "kid": "uvm-g7-local-rsa-1", "typ": "JWT"}, claims, _key())
    elif entry["fault"] == "audience":
        claims = {"iss": issuer, "sub": entry["subject"], "aud": "wrong-client",
            "iat": now, "exp": now + 300, "nonce": entry["nonce"]}
        signed = jwt.encode({"alg": "RS256", "kid": "uvm-g7-local-rsa-1", "typ": "JWT"}, claims, _key())
    elif entry["fault"] == "nonce":
        claims = {"iss": issuer, "sub": entry["subject"], "aud": client_id,
            "iat": now, "exp": now + 300, "nonce": "wrong-nonce"}
        signed = jwt.encode({"alg": "RS256", "kid": "uvm-g7-local-rsa-1", "typ": "JWT"}, claims, _key())
    elif entry["fault"] == "subject":
        claims = {"iss": issuer, "sub": 42, "aud": client_id,
            "iat": now, "exp": now + 300, "nonce": entry["nonce"]}
        signed = jwt.encode({"alg": "RS256", "kid": "uvm-g7-local-rsa-1", "typ": "JWT"}, claims, _key())
    id_token = signed.decode() if isinstance(signed, bytes) else signed
    if entry["fault"] == "signature":
        id_token = id_token[:-1] + ("A" if id_token[-1] != "A" else "B")
    return {"access_token": secrets.token_urlsafe(24), "token_type": "Bearer",
        "expires_in": 300, "id_token": id_token}


@app.post("/__fixture/failure")
async def fixture_failure(request: Request):
    global _failure_mode, _sync_paused
    from fastapi import HTTPException
    try:
        peer = ipaddress.ip_address((request.client.host if request.client else "").split("%", 1)[0])
    except ValueError:
        raise HTTPException(403, "fixture control requires a container-loopback peer") from None
    if not peer.is_loopback:
        raise HTTPException(403, "fixture control requires a container-loopback peer")
    authorization = request.headers.get("authorization", "")
    expected = _file_secret("UVM_OIDC_OPERATOR_SECRET_FILE")
    if not authorization.startswith("Bearer ") or not secrets.compare_digest(authorization[7:], expected):
        raise HTTPException(401, "fixture control denied")
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(422, "fixture control request is invalid") from None
    if (not isinstance(body, dict) or set(body) not in ({"mode"}, {"mode", "revision"})
            or body["mode"] not in {None, "discovery", "jwks", "authorize", "token", "sync", "readiness"}):
        raise HTTPException(422, "fixture control request is invalid")
    if "revision" in body:
        if body["mode"] != "sync" or type(body["revision"]) is not int or body["revision"] < 1:
            raise HTTPException(422, "fixture control request is invalid")
        revision_path = _required("UVM_OIDC_PROVIDER_REVISION_FILE")
        temporary_path = revision_path + ".tmp"
        with open(temporary_path, "w", encoding="ascii") as stream:
            stream.write(str(body["revision"]))
        os.replace(temporary_path, revision_path)
    _failure_mode = body["mode"]
    _sync_paused = body["mode"] == "sync"
    print(f"G7_OIDC_FIXTURE_CONTROL mode={body['mode'] or 'none'} sync_paused={_sync_paused}"
        + (f" revision={body['revision']}" if "revision" in body else ""), flush=True)
    return {"provider": "labelled-synthetic-local", "failure_mode": _failure_mode,
        **({"revision": body["revision"]} if "revision" in body else {})}


@app.on_event("startup")
async def start_identity_sync():
    asyncio.create_task(_sync_loop())


async def _sync_loop():
    issuer, _client_id, _callback, _subject = _config()
    provider_id = _required("UVM_OIDC_PROVIDER_ID")
    secret = _file_secret("UVM_OIDC_SYNC_SECRET_FILE")
    try:
        identities = json.loads(_required("UVM_OIDC_FIXTURE_IDENTITIES"))
    except json.JSONDecodeError as exc:
        raise RuntimeError("synthetic identity fixture is invalid") from exc
    revision_path = _required("UVM_OIDC_PROVIDER_REVISION_FILE")
    while True:
        try:
            if _sync_paused or (_failure_mode or os.environ.get("UVM_G7_PROVIDER_FAILURE")) == "sync":
                await asyncio.sleep(5)
                continue
            try:
                revision = int(open(revision_path, encoding="ascii").read().strip()) + 1
            except FileNotFoundError:
                revision = 1
            tmp = revision_path + ".tmp"
            with open(tmp, "w", encoding="ascii") as stream:
                stream.write(str(revision))
            os.replace(tmp, revision_path)
            payload = {"schema_version": 1, "provider_id": provider_id,
                "revision": revision, "heartbeat_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "kind": "full_snapshot", "identities": identities}
            async with AsyncClient(timeout=3) as client:
                response = await client.post("http://127.0.0.1:8001/api/v1/auth/provider/sync",
                    json=payload, headers={"Authorization": "Bearer " + secret})
            if response.status_code not in (200, 503):
                print(f"G7_OIDC_SYNC status={response.status_code}", flush=True)
        except Exception as exc:
            # Before the API is ready, retry and log only the exception class;
            # never log credentials, response bodies or identity subject values.
            print(f"G7_OIDC_SYNC retry error_class={type(exc).__name__}", flush=True)
        await asyncio.sleep(5)
