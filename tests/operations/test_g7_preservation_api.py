import os
import unittest
from datetime import datetime, timezone
from unittest.mock import patch

import sqlalchemy as sa
from fastapi import HTTPException
from starlette.requests import Request


class PreservationApiTest(unittest.TestCase):
    def test_canonical_timestamp_strings_are_normalized_to_utc_z(self):
        from uvm.operations.preservation_source import _wire
        self.assertEqual(_wire("2026-10-28T19:40:29+01:00"),
            "2026-10-28T18:40:29.000000Z")

    def setUp(self):
        from uvm.persistence import ingestion_schema  # register shared metadata
        from uvm.operations import preservation_source  # register canonical source tables
        from uvm.persistence.assessment_schema import assessment_policy
        from uvm.persistence.schema import uvm_metadata
        self.engine = sa.create_engine("sqlite://")
        uvm_metadata.create_all(self.engine)
        self.scope = ("synthetic", "account-a", "scope-a")
        policy = {"revision": 1, "principals": {"alice": {"enabled": True},
                "source-service": {"enabled": True}},
            "native_authority": {"mode": "uvm_native_v1", "revision": 1,
                "access_groups": {"group-a": {"enabled": True, "revision": 1,
                    "source_scopes": [{"source_family": self.scope[0],
                        "source_account_id": self.scope[1], "scope_key": self.scope[2]}],
                    "memberships": [{"principal_id": "alice", "effective_from": "2026-01-01T00:00:00Z",
                        "enabled": True, "revision": 1}],
                    "permissions": [{"permission_id": "read-a", "role_id": "role-a",
                        "action": "preservation.read", "target_scope": {"group_ids": ["*"]}},
                        {"permission_id": "audit-a", "role_id": "role-a",
                        "action": "audit.read.deployment", "deployment_scopes": ["g7-local"],
                        "target_scope": {"group_ids": ["*"]}}]}},
                "revocations": []}, "denies": []}
        with self.engine.begin() as connection:
            connection.execute(assessment_policy.insert().values(policy_id=1, revision=1,
                document=policy, updated_at=datetime.now(timezone.utc), updated_by="test"))
        from uvm.auth.schema import AuthorityContext
        self.context = AuthorityContext(principal_id="alice", credential_mode="oidc_session",
            issuer="https://issuer.invalid", subject="subject", link_id="link-a", link_revision=1,
            session_id="session-a", session_revision=1, access_groups=("group-a",),
            group_revision=1, mapping_revision=1, policy_revision=1,
            source_scopes=(self.scope,), role_ids=(), evaluated_at=datetime.now(timezone.utc),
            group_roles=(("group-a", ("role-a",)),), group_scopes=(("group-a", (self.scope,)),))

    def tearDown(self):
        self.engine.dispose()

    def test_authorized_missing_baseline_is_honest_unknown_and_other_scope_is_404(self):
        from uvm.api.app import create_app
        with patch.dict(os.environ, {"UVM_AUTH_MODE": "bearer"}, clear=False):
            app = create_app(self.engine, principals={}, cursor_secret="g7-cursor-secret")
        route = next(r for r in app.routes if getattr(r, "path", None) == "/api/v1/operations/preservation")
        auth_dependency = route.dependant.dependencies[0].call
        app.dependency_overrides[auth_dependency] = lambda: {
            "name": "alice", "scopes": (self.scope,), "context": self.context}
        request = Request({"type": "http", "method": "GET",
            "path": "/api/v1/operations/preservation",
            "query_string": b"source_family=synthetic&source_account_id=account-a&scope_key=scope-a",
            "headers": [], "scheme": "http", "server": ("test", 80),
            "client": ("127.0.0.1", 12345), "root_path": "", "app": app})
        with patch.dict(os.environ, {"UVM_G7_PRESERVATION_REPORT_DIR": "/nonexistent/g7-reports",
                "UVM_G7_PRESERVATION_PUBLIC_KEY_FILE": "/nonexistent/g7-public.pem"}, clear=False):
            body = route.endpoint(request, source_family="synthetic",
                source_account_id="account-a", scope_key="scope-a",
                principal={"name": "alice", "scopes": (self.scope,), "context": self.context})
            self.assertIsNone(body["snapshot_id"])
            self.assertEqual(body["elapsed_preservation"], "unverified")
            self.assertEqual([c["state"] for c in body["classes"]], ["unknown"] * 3)
            self.assertTrue(all(c["expected_records"] is None for c in body["classes"]))
            with self.assertRaises(HTTPException) as denied:
                route.endpoint(request, source_family="synthetic",
                    source_account_id="account-a", scope_key="other-scope",
                    principal={"name": "alice", "scopes": (self.scope,), "context": self.context})
            self.assertEqual(denied.exception.status_code, 404)

    def test_current_deny_revokes_previously_authorized_session(self):
        from uvm.operations.preservation_api import _authority
        principal = {"name": "alice", "scopes": (self.scope,), "context": self.context}
        allowed, fingerprint = _authority(self.engine, principal, self.scope, "preservation.read")
        self.assertTrue(allowed)
        self.assertEqual(len(fingerprint), 64)
        from uvm.persistence.assessment_schema import assessment_policy
        with self.engine.begin() as connection:
            policy = dict(connection.execute(sa.select(assessment_policy.c.document)
                .where(assessment_policy.c.policy_id == 1)).scalar_one())
            policy["denies"] = [{"deny_id": "revoked-after-session",
                "principal_id": "alice", "actions": ["preservation.read"],
                "target_ids": ["*"]}]
            connection.execute(assessment_policy.update().where(
                assessment_policy.c.policy_id == 1).values(document=policy))
        denied, denied_fingerprint = _authority(self.engine, principal, self.scope,
            "preservation.read")
        self.assertFalse(denied)
        self.assertIsNone(denied_fingerprint)

    def test_cursor_expiry_and_current_authority_change_have_distinct_errors(self):
        import json
        from unittest.mock import patch
        from starlette.requests import Request
        from uvm.api.app import create_app
        from uvm.operations.preservation_api import _authority, _cursor
        from uvm.operations.preservation import tuple_digest
        app = create_app(self.engine, principals={}, cursor_secret="g7-cursor-secret")
        route = next(r for r in app.routes if getattr(r, "path", None) ==
            "/api/v1/operations/preservation/records")
        principal = {"name": "alice", "scopes": (self.scope,), "context": self.context}
        allowed, authority = _authority(self.engine, principal, self.scope, "preservation.read")
        self.assertTrue(allowed)
        snapshot_id = "00000000-0000-4000-8000-000000000041"
        payload = {"valid_until": "2999-01-01T00:00:00Z", "classes": [{
            "class_id": "product.source_evidence", "dto": {"state": "verified"},
            "members": []}]}

        def invoke(cursor):
            request = Request({"type": "http", "method": "GET",
                "path": "/api/v1/operations/preservation/records",
                "query_string": b"snapshot_id=" + snapshot_id.encode() +
                    b"&class_id=product.source_evidence&limit=1",
                "headers": [], "scheme": "http", "server": ("test", 80),
                "client": ("127.0.0.1", 12345), "root_path": "", "app": app})
            return route.endpoint(request, snapshot_id=snapshot_id,
                class_id="product.source_evidence", limit=1, cursor=cursor,
                principal=principal)

        base = {"snapshot_id": snapshot_id, "class_id": "product.source_evidence",
            "limit": 1, "after": "observation\0opaque", "scope": tuple_digest(self.scope),
            "authority": authority,
            "report_digest": __import__("hashlib").sha256(json.dumps(payload, sort_keys=True,
                separators=(",", ":")).encode()).hexdigest()}
        with patch("uvm.operations.preservation_api._find_snapshot",
                return_value=(payload, self.scope)):
            expired = _cursor(app.state.cursor_secret, {**base, "expires_at": 1})
            with self.assertRaises(HTTPException) as expired_error:
                invoke(expired)
            self.assertEqual(expired_error.exception.status_code, 409)
            self.assertEqual(expired_error.exception.detail["code"], "cursor_expired")
            changed_authority = _cursor(app.state.cursor_secret,
                {**base, "authority": "b" * 64, "expires_at": 4102444800})
            with self.assertRaises(HTTPException) as changed_error:
                invoke(changed_authority)
            self.assertEqual(changed_error.exception.status_code, 400)
            self.assertEqual(changed_error.exception.detail["code"], "invalid_cursor")

    def test_record_projection_is_allowlisted_and_keeps_metadata_hashes_null(self):
        from uvm.operations.preservation_api import _record_item
        member = {"record_key": "observation:opaque", "record_kind": "observation",
            "retained_at": "2026-10-28T12:00:00Z", "state": "changed", "reasons": ["record_missing"],
            "expected_sha256": None, "actual_sha256": None, "record_sha256": "a" * 64,
            "byte_bearing": False, "payload": "must never be returned"}
        item = _record_item(member, "product.source_evidence", False)
        self.assertEqual(set(item), {"record_key", "record_kind", "retained_at", "state",
            "reasons", "expected_sha256", "actual_sha256", "record_sha256", "readback_url"})
        self.assertIsNone(item["expected_sha256"])
        self.assertIsNone(item["actual_sha256"])
        self.assertNotIn("payload", item)
        observation_bytes = {**member, "byte_bearing": True,
            "expected_sha256": "b" * 64, "actual_sha256": "b" * 64,
            "evidence_id": "00000000-0000-4000-8000-000000000001"}
        self.assertIsNone(_record_item(observation_bytes,
            "product.source_evidence", True)["readback_url"])
        registration = {**observation_bytes, "record_kind": "evidence_registration",
            "record_key": "evidence_registration:opaque"}
        self.assertEqual(_record_item(registration, "product.source_evidence", True)["readback_url"],
            "/api/v1/operations/preservation/evidence/00000000-0000-4000-8000-000000000001")
        self.assertIsNone(_record_item({**member, "record_kind": "private_payload"},
            "product.source_evidence", True))

    def test_internal_source_adapter_uses_configured_session_and_exact_grant(self):
        import asyncio
        import json
        from uvm.api.app import create_app
        with patch.dict(os.environ, {"UVM_AUTH_MODE": "bearer",
                "UVM_G7_SOURCE_ADAPTER_SUBJECT": "subject",
                "UVM_G7_SOURCE_ADAPTER_ISSUER": "https://issuer.invalid",
                "UVM_G7_DEPLOYMENT_ID": "g7-local",
                "UVM_G7_STORAGE_GENERATION": "generation-a"}, clear=False):
            app = create_app(self.engine, principals={}, cursor_secret="g7-cursor-secret")
        route = next(r for r in app.routes if getattr(r, "path", None) ==
            "/internal/g7/preservation/source-snapshot")

        async def invoke(principal, body):
            raw = json.dumps(body).encode()
            sent = False
            async def receive():
                nonlocal sent
                if sent:
                    return {"type": "http.disconnect"}
                sent = True
                return {"type": "http.request", "body": raw, "more_body": False}
            request = Request({"type": "http", "method": "POST",
                "path": "/internal/g7/preservation/source-snapshot", "query_string": b"",
                "headers": [(b"content-type", b"application/json")], "scheme": "http",
                "server": ("test", 80), "client": ("127.0.0.1", 12345),
                "root_path": "", "app": app}, receive=receive)
            return await route.endpoint(request, principal=principal)

        body = {"schema_version": 1, "scope": dict(zip(
            ("source_family", "source_account_id", "scope_key"), self.scope)),
            "class_ids": ["product.source_evidence", "product.audit_history",
                "operational.scanner_collection"]}
        service_config = {"UVM_G7_SOURCE_ADAPTER_SUBJECT": "subject",
            "UVM_G7_SOURCE_ADAPTER_ISSUER": "https://issuer.invalid",
            "UVM_G7_SOURCE_ADAPTER_PRINCIPAL": "source-service",
            "UVM_G7_DEPLOYMENT_ID": "g7-local",
            "UVM_G7_STORAGE_GENERATION": "00000000-0000-4000-8000-000000000017",
            "UVM_G7_RECOVERY_EPOCH": "1", "UVM_G7_VOLUME_SET_DIGEST": "a" * 64}
        with patch.dict(os.environ, service_config, clear=False):
            result = asyncio.run(invoke({"name": "alice", "scopes": (self.scope,),
                "context": self.context}, body))
        self.assertEqual(result["storage_generation"], "00000000-0000-4000-8000-000000000017")
        self.assertEqual([item["class_id"] for item in result["classes"]],
            ["operational.scanner_collection", "product.audit_history", "product.source_evidence"])
        by_class = {item["class_id"]: item for item in result["classes"]}
        self.assertTrue(by_class["product.source_evidence"]["complete"])
        self.assertEqual(by_class["product.source_evidence"]["members"], [])
        self.assertFalse(by_class["product.audit_history"]["complete"])
        self.assertEqual(by_class["product.audit_history"]["coverage_reason"], "audit_scope_incomplete")
        self.assertFalse(by_class["operational.scanner_collection"]["complete"])
        from uvm.auth.schema import AuthorityContext
        service_context = AuthorityContext(principal_id="source-service", credential_mode="service_bearer",
            issuer=None, subject=None, link_id=None, link_revision=None, session_id=None,
            session_revision=None, access_groups=(), group_revision=0, mapping_revision=1,
            policy_revision=1, source_scopes=(self.scope,), role_ids=(),
            evaluated_at=datetime.now(timezone.utc))
        source_scope = dict(zip(("source_family", "source_account_id", "scope_key"), self.scope))
        service_grants = [
            {"grant_id": "source-read", "action": "preservation.read",
                "source_scopes": [source_scope], "deployment_scopes": []},
            {"grant_id": "audit-read", "action": "audit.read.deployment",
                "source_scopes": [source_scope], "deployment_scopes": ["g7-local"]},
            {"grant_id": "audit-export", "action": "audit.export.deployment",
                "source_scopes": [source_scope], "deployment_scopes": ["g7-local"]}]
        with patch.dict(os.environ, service_config, clear=False):
            service_result = asyncio.run(invoke({"name": "source-service", "scopes": (self.scope,),
                "context": service_context, "service_grants": service_grants}, body))
        self.assertEqual(service_result["scope"], body["scope"])
        with patch.dict(os.environ, service_config, clear=False):
            with self.assertRaises(HTTPException) as missing_grant:
                asyncio.run(invoke({"name": "source-service", "scopes": (self.scope,),
                    "context": service_context, "service_grants": []}, body))
            self.assertEqual(missing_grant.exception.status_code, 404)
        with patch.dict(os.environ, service_config, clear=False):
            with self.assertRaises(HTTPException) as denied:
                asyncio.run(invoke({"name": "alice", "scopes": (self.scope,),
                    "context": self.context}, {**body, "scope": {**body["scope"], "scope_key": "other"}}))
            self.assertEqual(denied.exception.status_code, 404)
            wrong_service = self.context.__class__(**{**self.context.__dict__, "subject": "other-subject"})
            with self.assertRaises(HTTPException) as masked:
                asyncio.run(invoke({"name": "alice", "scopes": (self.scope,),
                    "context": wrong_service}, body))
            self.assertEqual(masked.exception.status_code, 404)
            with self.assertRaises(HTTPException) as wrong_service:
                asyncio.run(invoke({"name": "caller-selected-actor", "scopes": (self.scope,),
                    "context": service_context, "service_grants": service_grants}, body))
            self.assertEqual(wrong_service.exception.status_code, 404)
            from uvm.persistence.assessment_schema import assessment_policy
            with self.engine.begin() as connection:
                changed = dict(connection.execute(sa.select(assessment_policy.c.document)
                    .where(assessment_policy.c.policy_id == 1)).scalar_one())
                changed["denies"] = [{"deny_id": "service-deny", "principal_id": "source-service",
                    "actions": ["preservation.read"], "target_ids": ["*"]}]
                connection.execute(assessment_policy.update().where(
                    assessment_policy.c.policy_id == 1).values(document=changed))
            with self.assertRaises(HTTPException) as denied_service:
                asyncio.run(invoke({"name": "source-service", "scopes": (self.scope,),
                    "context": service_context, "service_grants": service_grants}, body))
            self.assertEqual(denied_service.exception.status_code, 404)
