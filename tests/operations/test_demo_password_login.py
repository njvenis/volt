from __future__ import annotations

import base64
import copy
import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from urllib.parse import parse_qs, urlsplit
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from fastapi.testclient import TestClient

from deploy.compose.setup import demo_password_verifier
from uvm.auth import synthetic_provider as provider


class DemoPasswordLoginTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.credentials = Path(self.temp.name) / "credentials.json"
        # This static salted verifier is a synthetic fixture, not the plaintext
        # password used by the request tests below.
        self.credentials.write_text(json.dumps({"schema": "uvm.demo-credential.v1",
            "username": "named-admin", "salt": "000102030405060708090a0b0c0d0e0f",
            "password_hash": "c000ef9581e24eb51ae1b3d41a793dd37b138acb1e55223d674dee5c3a166e6c"}),
            encoding="utf-8")
        self.credentials.chmod(0o600)
        self.client_secret = Path(self.temp.name) / "client-secret"
        self.client_secret.write_text("synthetic-client-secret")
        self.signing_key = Path(self.temp.name) / "provider-private.pem"
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.signing_key.write_bytes(key.private_bytes(serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        self.client = TestClient(provider.app)
        provider._login_states.clear()
        provider._login_attempts.clear()
        provider._fixture_identities_override = None
        provider._failure_mode = None
        provider._sync_paused = False
        self.env = patch.dict("os.environ", {
            "UVM_OIDC_ISSUER": "http://127.0.0.1:8190",
            "UVM_OIDC_CLIENT_ID": "volt-compose-demo",
            "UVM_OIDC_CALLBACK_URL": "http://127.0.0.1:8180/api/v1/auth/callback",
            "UVM_OIDC_FIXTURE_SUBJECT": "local-testing-admin-subject",
            "UVM_OIDC_DEMO_CREDENTIALS_FILE": str(self.credentials),
            "UVM_OIDC_CLIENT_SECRET_FILE": str(self.client_secret),
            "UVM_OIDC_PROVIDER_KEY_FILE": str(self.signing_key),
        }, clear=True)
        self.env.start()

    def tearDown(self):
        self.env.stop()
        provider._login_states.clear()
        provider._login_attempts.clear()
        provider._fixture_identities_override = None
        provider._failure_mode = None
        provider._sync_paused = False
        self.temp.cleanup()

    def authorize(self):
        verifier = "qualified-test-code-verifier-value"
        challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")
        return self.client.get("/authorize", params={
            "client_id": "volt-compose-demo",
            "redirect_uri": "http://127.0.0.1:8180/api/v1/auth/callback",
            "response_type": "code", "scope": "openid profile",
            "code_challenge_method": "S256", "code_challenge": challenge,
            "state": "state-value", "nonce": "nonce-value",
        }, follow_redirects=False)

    def login(self, response, username, password, *, csrf=None):
        token = csrf if csrf is not None else response.text.split("name=csrf value=", 1)[1].split(">", 1)[0]
        return self.client.post("/login", data={"csrf": token, "username": username,
            "password": password}, follow_redirects=False)

    def test_password_signin_issues_code_for_configured_subject_only(self):
        page = self.authorize()
        self.assertEqual(page.status_code, 200)
        self.assertIn("Local demo sign in", page.text)
        result = self.login(page, "named-admin", "long-test-password-value")
        self.assertEqual(result.status_code, 302)
        self.assertIn("state=state-value", result.headers["location"])
        self.assertEqual(len(provider._codes), 1)
        self.assertEqual(next(iter(provider._codes.values()))["subject"], "local-testing-admin-subject")

    def test_password_login_completes_oidc_code_exchange_with_stable_subject(self):
        page = self.authorize()
        result = self.login(page, "named-admin", "long-test-password-value")
        params = parse_qs(urlsplit(result.headers["location"]).query)
        self.assertEqual(params["state"], ["state-value"])
        token = self.client.post("/token", auth=("volt-compose-demo", "synthetic-client-secret"), data={
            "grant_type": "authorization_code", "code": params["code"][0],
            "redirect_uri": "http://127.0.0.1:8180/api/v1/auth/callback",
            "code_verifier": "qualified-test-code-verifier-value"})
        self.assertEqual(token.status_code, 200, token.text)
        payload = token.json()["id_token"].split(".")[1]
        claims = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
        self.assertEqual(claims["iss"], "http://127.0.0.1:8190")
        self.assertEqual(claims["sub"], "local-testing-admin-subject")

    def test_wrong_password_and_unknown_username_have_same_response(self):
        wrong = self.login(self.authorize(), "named-admin", "incorrect-password-value")
        unknown = self.login(self.authorize(), "not-an-account", "incorrect-password-value")
        self.assertEqual((wrong.status_code, wrong.text), (unknown.status_code, unknown.text))
        self.assertNotIn("named-admin", wrong.text)

    def test_csrf_mismatch_is_rejected_without_attempting_credentials(self):
        response = self.login(self.authorize(), "named-admin", "long-test-password-value", csrf="attacker")
        self.assertEqual(response.status_code, 400)
        self.assertEqual(provider._login_attempts, {})

    def test_attempt_limit_bounds_password_checks(self):
        for _ in range(10):
            failed = self.login(self.authorize(), "named-admin", "incorrect-password-value")
            self.assertEqual(failed.status_code, 401)
        limited = self.login(self.authorize(), "named-admin", "long-test-password-value")
        self.assertEqual(limited.status_code, 429)

    def test_password_login_is_disabled_without_demo_credential_file(self):
        with patch.dict("os.environ", {"UVM_OIDC_DEMO_CREDENTIALS_FILE": ""}):
            response = self.authorize()
        self.assertEqual(response.status_code, 503)

    def test_synthetic_auto_signin_requires_explicit_test_fixture_mode(self):
        with patch.dict("os.environ", {"UVM_OIDC_DEMO_CREDENTIALS_FILE": "",
                                       "UVM_OIDC_FIXTURE_MODE": "1"}):
            response = self.authorize()
        self.assertEqual(response.status_code, 302)
        self.assertEqual(next(iter(provider._codes.values()))["subject"], "local-testing-admin-subject")

    def test_identity_snapshot_override_requires_loopback_operator_control_and_exact_schema(self):
        operator_secret = Path(self.temp.name) / "operator-secret"
        operator_secret.write_text("fixture-control-secret")
        with patch.dict("os.environ", {"UVM_OIDC_OPERATOR_SECRET_FILE": str(operator_secret)}):
            client = TestClient(provider.app, client=("127.0.0.1", 8765))
            accepted = client.post("/__fixture/failure", headers={
                "Authorization": "Bearer fixture-control-secret"}, json={
                    "mode": None, "identities": [{"subject": "local-testing-admin-subject", "groups": []}]})
            self.assertEqual(accepted.status_code, 200, accepted.text)
            self.assertFalse(provider._sync_paused)
            self.assertEqual(provider._fixture_identities_override,
                [{"subject": "local-testing-admin-subject", "groups": []}])
            self.assertIsNone(provider._failure_mode)
            invalid = client.post("/__fixture/failure", headers={
                "Authorization": "Bearer fixture-control-secret"}, json={
                    "mode": None, "identities": [{"subject": "subject", "groups": ["group"], "email": "ignored"}]})
            self.assertEqual(invalid.status_code, 422)
            denied = client.post("/__fixture/failure", headers={"Authorization": "Bearer wrong"}, json={
                "mode": None, "identities": []})
            self.assertEqual(denied.status_code, 401)

    def test_rejected_fixture_control_is_observationally_unchanged(self):
        operator_secret = Path(self.temp.name) / "operator-secret"
        operator_secret.write_text("fixture-control-secret")
        revision_file = Path(self.temp.name) / "provider-revision"
        revision_file.write_text("41")
        identity_state = [{"subject": "existing-subject", "groups": ["existing-group"]}]
        provider._fixture_identities_override = identity_state
        provider._failure_mode = "jwks"
        provider._sync_paused = True
        before = (copy.deepcopy(provider._fixture_identities_override), provider._failure_mode,
            provider._sync_paused, revision_file.read_text())
        with patch.dict("os.environ", {"UVM_OIDC_OPERATOR_SECRET_FILE": str(operator_secret),
                                        "UVM_OIDC_PROVIDER_REVISION_FILE": str(revision_file)}):
            client = TestClient(provider.app, client=("127.0.0.1", 8765))
            cases = (
                {"mode": None, "revision": 42, "identities": [
                    {"subject": "replacement-subject", "groups": ["replacement-group"]}]},
                {"mode": "not-allowed", "revision": 42, "identities": [
                    {"subject": "replacement-subject", "groups": ["replacement-group"]}]},
                {"mode": "discovery", "revision": 42, "identities": [
                    {"subject": "replacement-subject", "groups": ["replacement-group"]}]},
                {"mode": "sync", "revision": 0, "identities": [
                    {"subject": "replacement-subject", "groups": ["replacement-group"]}]},
            )
            for body in cases:
                with self.subTest(body=body):
                    rejected = client.post("/__fixture/failure", headers={
                        "Authorization": "Bearer fixture-control-secret"}, json=body)
                    self.assertEqual(rejected.status_code, 422)
                    after = (copy.deepcopy(provider._fixture_identities_override), provider._failure_mode,
                        provider._sync_paused, revision_file.read_text())
                    self.assertEqual(after, before)
            self.assertEqual(list(Path(self.temp.name).glob("provider-revision.*.tmp")), [])

    def test_verifier_requires_confirmation_and_minimum_length(self):
        for password, confirm in (("short", "short"), ("long-password-value", "other-password-value"),
                                  ("x" * 1025, "x" * 1025)):
            with self.subTest(password=password), self.assertRaises(SystemExit):
                demo_password_verifier("named-admin", password, confirm)


if __name__ == "__main__":
    unittest.main()
