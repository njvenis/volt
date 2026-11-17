from __future__ import annotations

import asyncio
import base64
import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives import serialization

from uvm.auth.okta_publisher import (OktaPublisher, _client_assertion, _get_all, load_config,
    publisher_state_lock)


class Response:
    def __init__(self, payload, *, status=200, headers=None):
        self.payload, self.status_code = payload, status
        self.headers = headers or {}
        self.is_redirect = 300 <= status < 400

    def json(self):
        return self.payload


class PagerClient:
    def __init__(self, responses):
        self.responses = responses
        self.urls = []

    async def get(self, url, **kwargs):
        self.urls.append(url)
        return self.responses[url]


class SnapshotClient:
    def __init__(self, *, account_status="ACTIVE", assignments=None, group_ids=None):
        self.account_status = account_status
        self.assignments = [{"id": "00u-admin", "status": "ACTIVE"}] if assignments is None else assignments
        self.group_ids = ["00g-admin"] if group_ids is None else group_ids

    async def get(self, url, **kwargs):
        if url.endswith("/apps/volt-app-id"):
            return Response({"id": "volt-app-id", "status": "ACTIVE",
                "settings": {"oauthClient": {"client_id": "service-client-id"}}})
        if "/apps/volt-app-id/users" in url:
            return Response(self.assignments)
        if url.endswith("/users/00u-admin"):
            return Response({"id": "00u-admin", "status": self.account_status})
        if "/users/00u-admin/groups" in url:
            return Response([{"id": group} for group in self.group_ids])
        raise AssertionError("unexpected synthetic Okta API URL")


class TokenClient:
    def __init__(self): self.request = None
    async def post(self, url, **kwargs):
        self.request = (url, kwargs)
        return Response({"access_token": "synthetic-access-token"})


class SyncClient:
    def __init__(self, response=None): self.request = None; self.response = response or Response({"committed": True, "provider_id": "okta-demo", "revision": 1})
    async def post(self, url, **kwargs):
        self.request = (url, kwargs)
        return self.response


class OktaPublisherTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.key = self.root / "private.pem"
        private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.key.write_bytes(private.private_bytes(serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        self.key.chmod(0o600)
        self.oidc = self.root / "oidc.json"
        self.oidc.write_text(json.dumps({"provider_id": "okta-demo", "heartbeat_max_age_seconds": 120,
            "allowed_endpoint_origins": ["https://tenant.example.okta.com"],
            "group_mappings": {"00g-admin": {"role_ids": ["volt-admin"], "source_scopes": []}}}))
        self.config = {"schema_version": 1, "provider_id": "okta-demo",
            "org_url": "https://tenant.example.okta.com",
            "api_issuer": "https://tenant.example.okta.com/oauth2/v1",
            "api_base_url": "https://tenant.example.okta.com/api/v1",
            "client_id": "service-client-id", "app_id": "volt-app-id", "key_id": "key-1",
            "private_key_file": str(self.key), "oidc_config_file": str(self.oidc),
            "subject_by_user_id": {"00u-admin": "okta_sub-admin+stable"},
            "group_ids": ["00g-admin"],
            "poll_interval_seconds": 30, "heartbeat_max_age_seconds": 120}
        self.oidc.write_text(json.dumps({"provider_id": "okta-demo", "client_id": "service-client-id",
            "heartbeat_max_age_seconds": 120, "allowed_endpoint_origins": ["https://tenant.example.okta.com"],
            "group_mappings": {"00g-admin": {"role_ids": ["volt-admin"], "source_scopes": []}}}))

    def tearDown(self):
        self.temp.cleanup()

    def test_configuration_requires_origin_bound_urls_explicit_mappings_and_poll_margin(self):
        path = self.root / "publisher.json"
        path.write_text(json.dumps(self.config))
        self.assertEqual(load_config(path)["poll_interval_seconds"], 30)
        for field, value in (("api_issuer", "https://evil.example/oauth2/v1"),
                             ("poll_interval_seconds", 41),
                             ("subject_by_user_id", {}),
                             ("group_ids", [])):
            changed = dict(self.config); changed[field] = value; path.write_text(json.dumps(changed))
            with self.subTest(field=field), self.assertRaises(ValueError):
                load_config(path)

    def test_pagination_follows_only_same_origin_same_endpoint_links(self):
        first = "https://tenant.example.okta.com/api/v1/users?limit=200"
        second = "https://tenant.example.okta.com/api/v1/users?after=next"
        client = PagerClient({first: Response([{"id": "a"}], headers={"Link": f'<{second}>; rel="next"'}),
                              second: Response([{"id": "b"}])})
        self.assertEqual(asyncio.run(_get_all(client, first,
            base_url=self.config["api_base_url"], token="synthetic")), [{"id": "a"}, {"id": "b"}])
        self.assertEqual(client.urls, [first, second])
        evil = "https://attacker.example/steal"
        client = PagerClient({first: Response([], headers={"Link": f'<{evil}>; rel="next"'})})
        with self.assertRaisesRegex(RuntimeError, "escaped"):
            asyncio.run(_get_all(client, first, base_url=self.config["api_base_url"], token="secret"))
        self.assertEqual(client.urls, [first])

    def test_revision_survives_publisher_restart(self):
        state = self.root / "state"
        publisher = OktaPublisher(self.config, revision_dir=state)
        self.assertEqual(publisher._next_revision(), 1)
        self.assertEqual(OktaPublisher(self.config, revision_dir=state)._next_revision(), 2)
        self.assertEqual((state / "revision.json").stat().st_mode & 0o777, 0o600)

    def test_only_one_real_process_owns_collection_and_publish_state(self):
        state = self.root / "state"
        code = ("import sys,time; from pathlib import Path; from uvm.auth.okta_publisher import publisher_state_lock; "
                "exec('with publisher_state_lock(Path(sys.argv[1])):\\n print(\"held\",flush=True)\\n time.sleep(3)')")
        first = subprocess.Popen([sys.executable, "-c", code, str(state)], stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, text=True, env={**os.environ, "PYTHONPATH": str(Path.cwd())})
        try:
            self.assertEqual(first.stdout.readline().strip(), "held")
            second_code = ("import sys; from pathlib import Path; from uvm.auth.okta_publisher import publisher_state_lock; "
                           "publisher_state_lock(Path(sys.argv[1])).__enter__()")
            second = subprocess.run([sys.executable, "-c", second_code, str(state)], capture_output=True,
                text=True, env={**os.environ, "PYTHONPATH": str(Path.cwd())})
            self.assertNotEqual(second.returncode, 0)
            self.assertIn("another Okta publisher", second.stderr)
        finally:
            first.terminate(); first.wait(timeout=5)
            first.stdout.close(); first.stderr.close()

    def test_failed_sync_post_consumes_revision_without_duplicate_on_retry(self):
        state = self.root / "state"
        secret = self.root / "sync-secret"; secret.write_text("local-test-secret"); secret.chmod(0o600)
        publisher = OktaPublisher(self.config, revision_dir=state, sync_secret_file=str(secret))
        failed = SyncClient(Response({"error": "unavailable"}, status=503))
        with self.assertRaisesRegex(RuntimeError, "unavailable"):
            asyncio.run(publisher.publish(failed, "token", []))
        successful = SyncClient(Response({"committed": True, "provider_id": "okta-demo", "revision": 2}))
        self.assertEqual(asyncio.run(publisher.publish(successful, "token", [])), 2)

    def test_stale_collection_watermark_is_rejected_without_publication(self):
        state = self.root / "state"
        secret = self.root / "sync-secret"; secret.write_text("local-test-secret"); secret.chmod(0o600)
        client = SyncClient()
        publisher = OktaPublisher(self.config, revision_dir=state, sync_secret_file=str(secret))
        # A traversal that began before an intervening Okta group revocation is
        # already older than the conservative budget; it cannot refresh heartbeat.
        with self.assertRaisesRegex(RuntimeError, "freshness budget"):
            asyncio.run(publisher.publish(client, "token", [{"subject": "old", "groups": ["00g-admin"]}],
                collection_started_at=time.time() - 61))
        self.assertIsNone(client.request)
        self.assertFalse((state / "revision.json").exists())

    def test_service_app_uses_private_key_jwt_and_org_token_issuer(self):
        assertion = _client_assertion(self.config, now=1_000)
        claims = json.loads(base64.urlsafe_b64decode(assertion.split(".")[1] + "=="))
        self.assertEqual(claims["iss"], "service-client-id")
        self.assertEqual(claims["sub"], "service-client-id")
        self.assertEqual(claims["aud"], "https://tenant.example.okta.com/oauth2/v1/token")
        self.assertEqual(claims["exp"] - claims["iat"], 60)
        client = TokenClient()
        token = asyncio.run(OktaPublisher(self.config).token(client))
        url, request = client.request
        self.assertEqual(url, claims["aud"])
        self.assertEqual(token, "synthetic-access-token")
        self.assertEqual(request["data"]["scope"], "okta.apps.read okta.groups.read okta.users.read")
        self.assertNotIn("client_secret", request["data"])

    def test_publish_sends_full_snapshot_and_uses_private_sync_file(self):
        secret = self.root / "sync-secret"
        secret.write_text("synthetic-sync-secret\n")
        secret.chmod(0o600)
        client = SyncClient()
        publisher = OktaPublisher(self.config, revision_dir=self.root / "state",
            sync_secret_file=str(secret))
        revision = asyncio.run(publisher.publish(client, "synthetic-api-token",
            [{"subject": "okta_sub-admin+stable", "groups": ["00g-admin"]}]))
        self.assertEqual(revision, 1)
        url, request = client.request
        self.assertEqual(url, "http://127.0.0.1:8001/api/v1/auth/provider/sync")
        self.assertEqual(request["headers"]["Authorization"], "Bearer synthetic-sync-secret")
        self.assertEqual(request["json"]["kind"], "full_snapshot")
        self.assertEqual(request["json"]["identities"], [{"subject": "okta_sub-admin+stable", "groups": ["00g-admin"]}])

    def test_complete_snapshot_contains_exact_subject_and_explicit_groups(self):
        publisher = OktaPublisher(self.config)
        rows = asyncio.run(publisher.snapshot(SnapshotClient(), "synthetic-token"))
        self.assertEqual(rows, [{"subject": "okta_sub-admin+stable", "groups": ["00g-admin"]}])
        removed_group = asyncio.run(publisher.snapshot(SnapshotClient(group_ids=[]), "synthetic-token"))
        self.assertEqual(removed_group, [{"subject": "okta_sub-admin+stable", "groups": []}])

    def test_app_client_identity_must_match_admitted_oidc_client(self):
        class MismatchedApp(SnapshotClient):
            async def get(self, url, **kwargs):
                if url.endswith("/apps/volt-app-id"):
                    return Response({"id": "volt-app-id", "status": "ACTIVE",
                        "settings": {"oauthClient": {"client_id": "other-client"}}})
                return await super().get(url, **kwargs)
        with self.assertRaisesRegex(RuntimeError, "client ID differs"):
            asyncio.run(OktaPublisher(self.config).snapshot(MismatchedApp(), "synthetic-token"))

    def test_validate_key_rejects_malformed_encrypted_and_undersized_private_keys(self):
        path = self.root / "publisher.json"; path.write_text(json.dumps(self.config))
        original = self.key.read_bytes()
        encrypted = rsa.generate_private_key(public_exponent=65537, key_size=2048).private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
            serialization.BestAvailableEncryption(b"local-test-passphrase"))
        for invalid in (b"not a pem key", encrypted):
            self.key.write_bytes(invalid); self.key.chmod(0o600)
            with self.assertRaisesRegex(ValueError, "unencrypted RSA"):
                load_config(path)
        ec_key = ec.generate_private_key(ec.SECP256R1())
        self.key.write_bytes(ec_key.private_bytes(serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8, serialization.NoEncryption())); self.key.chmod(0o600)
        with self.assertRaisesRegex(ValueError, "unencrypted RSA"):
            load_config(path)
        small = rsa.generate_private_key(public_exponent=65537, key_size=1024)
        self.key.write_bytes(small.private_bytes(serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8, serialization.NoEncryption())); self.key.chmod(0o600)
        with self.assertRaisesRegex(ValueError, "unencrypted RSA private PEM"):
            load_config(path)
        self.key.write_bytes(original); self.key.chmod(0o600)

    def test_disabled_account_and_removed_app_assignment_are_absent_from_snapshot(self):
        publisher = OktaPublisher(self.config)
        self.assertEqual(asyncio.run(publisher.snapshot(
            SnapshotClient(account_status="SUSPENDED"), "synthetic-token")), [])
        self.assertEqual(asyncio.run(publisher.snapshot(
            SnapshotClient(assignments=[]), "synthetic-token")), [])

    def test_unmapped_assigned_account_or_incomplete_page_aborts_snapshot(self):
        publisher = OktaPublisher(self.config)

        class Unmapped(SnapshotClient):
            async def get(self, url, **kwargs):
                if "/apps/volt-app-id/users" in url:
                    return Response([{"id": "00u-unmapped", "status": "ACTIVE"}])
                return await super().get(url, **kwargs)

        with self.assertRaisesRegex(RuntimeError, "explicit OIDC subject mapping"):
            asyncio.run(publisher.snapshot(Unmapped(), "synthetic-token"))

        first = "https://tenant.example.okta.com/api/v1/apps/volt-app-id/users?limit=200"
        client = PagerClient({first: Response([], status=403)})
        with self.assertRaisesRegex(RuntimeError, "status 403"):
            asyncio.run(_get_all(client, first, base_url=self.config["api_base_url"], token="synthetic-token"))


if __name__ == "__main__":
    unittest.main()
