"""Real PostgreSQL journey for durable local account claim and lifecycle."""
from __future__ import annotations

import json
import io
import logging
import os
import secrets
import stat
import subprocess
import sys
import tempfile
import threading
import unittest
import uuid
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from pathlib import Path
from unittest.mock import patch

import sqlalchemy as sa
from fastapi.testclient import TestClient


class LocalAccountsPostgreSQLTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dsn = os.environ.get("UVM_LOCAL_AUTH_TEST_DSN", "")
        if not cls.dsn:
            raise unittest.SkipTest("UVM_LOCAL_AUTH_TEST_DSN must point to a dedicated local-auth test database")
        cls.engine = sa.create_engine(cls.dsn, pool_pre_ping=True)
        with cls.engine.connect() as c:
            if c.dialect.name != "postgresql":
                raise RuntimeError("local account acceptance requires PostgreSQL")
            name = c.exec_driver_sql("select current_database()").scalar_one()
            major = int(c.exec_driver_sql("show server_version_num").scalar_one()) // 10000
            if name != "volt_easy_auth_test" or major != 18:
                raise RuntimeError("test DSN must name the owned volt_easy_auth_test PostgreSQL 18 database")
        cls._migrate()

    @classmethod
    def _migrate(cls):
        # Released migration 0011 copies declaration metadata. A fresh standard
        # Alembic process avoids accumulating those copies across fixture resets.
        subprocess.run([sys.executable, "-m", "alembic", "-c", "alembic.ini", "upgrade", "head"],
            cwd=Path(__file__).resolve().parents[2],
            env={**os.environ, "UVM_DB_URL": cls.dsn}, check=True, timeout=45)

    @classmethod
    def tearDownClass(cls):
        if hasattr(cls, "engine"):
            cls.engine.dispose()

    def setUp(self):
        # This test database is unique to this outcome. Reset only its public
        # schema so each invocation exercises the committed migration chain.
        with self.engine.begin() as c:
            c.exec_driver_sql("DROP SCHEMA public CASCADE")
            c.exec_driver_sql("CREATE SCHEMA public")
        self._migrate()
        self.temp = tempfile.TemporaryDirectory(prefix="volt-easy-auth-")
        root = Path(self.temp.name)
        self.scanner_pages = root / "scanner-evidence"
        self.scanner_pages.mkdir(mode=0o700)
        self.config_path = root / "local-auth.json"
        self.delivery_path = root / "bootstrap.json"
        self.key_path = root / "connector.key"
        self.key_path.write_bytes(secrets.token_bytes(32)); self.key_path.chmod(0o600)
        self.installation_id = "6c4be03e-8b9e-42a4-9545-7b17dd24a001"
        self.secret_source_id = str(uuid.uuid4())
        config = {"schema_version": 1, "installation_id": self.installation_id,
            "public_origin": "http://127.0.0.1",
            "secret_source": {"kind": "encrypted_local_v1", "secret_source_id": self.secret_source_id,
                "key_path": str(self.key_path)},
            "bootstrap_delivery": {"kind": "private_file", "path": str(self.delivery_path)},
            "session_policy": {"ttl_seconds": 3600},
            "trusted_ingress": {"mode": "loopback", "allowed_hosts": ["127.0.0.1"],
                "allowed_peer_cidrs": ["127.0.0.0/8"]}}
        self.config_path.write_text(json.dumps(config)); self.config_path.chmod(0o600)
        self.env = patch.dict(os.environ, {"UVM_AUTH_MODE": "local",
            "UVM_LOCAL_AUTH_CONFIG_FILE": str(self.config_path), "UVM_DB_URL": self.dsn,
            "UVM_SCANNER_EVIDENCE_DIR": str(self.scanner_pages),
            "UVM_API_CURSOR_SECRET": secrets.token_urlsafe(32),
            "UVM_INGRESS_ALLOWED_PEER_CIDRS": "127.0.0.0/8",
            "UVM_INGRESS_ALLOWED_HOSTS": "127.0.0.1"}, clear=False)
        self.env.start()
        from uvm.auth.maintenance import run as maintain
        maintain("prepare-setup", config_path=str(self.config_path))
        capability_doc = json.loads(self.delivery_path.read_text())
        self.assertEqual(stat.S_IMODE(self.delivery_path.stat().st_mode), 0o600)
        self.capability = capability_doc["capability"]
        from uvm.api.app import create_app
        self.app = create_app(self.engine, principals={}, cursor_secret=secrets.token_bytes(32))
        self.client = TestClient(self.app, base_url="http://127.0.0.1",
            client=("127.0.0.1", 52123))
        self.origin = {"Origin": "http://127.0.0.1", "Content-Type": "application/json"}

    def tearDown(self):
        self.env.stop()
        self.temp.cleanup()

    def _local_admin(self):
        password = secrets.token_urlsafe(20) + "A7!"
        claim = self.client.post("/api/v1/auth/setup/claim",
            json={"capability": self.capability, "username": "first-admin",
                "display_name": "First Admin", "password": password}, headers=self.origin)
        self.assertEqual(claim.status_code, 201, claim.text)
        cookie = self.client.cookies.get("uvm_session")
        return cookie, claim.json()["csrf_token"]

    def _registration_command(self, command_id, deployment, suffix="one"):
        return {"schema_version": 1, "command_id": command_id,
            "action": "connector.binding.register", "target_id": "00000000-0000-0000-0000-000000000000",
            "membership_ids": [],
            "expected_policy_revision": deployment["policy_revision"],
            "expected_authority_revision": deployment["authority_revision"],
            "expected_connector_registry_revision": deployment["connector_registry_revision"],
            "payload": {"display_name": "Test Scanner " + suffix, "source_family": "qualys",
                "account_label": "Test account " + suffix, "product": "qualys_vm",
                "platform_id": "us1", "scope": {"kind":"account_visible"},
                "environment_label": "Production", "rationale": "Register a disabled source binding",
                "evidence_ref": "test:registration:" + suffix, "grant_initial_read": True}}

    def _protected_client(self, cookie):
        client = TestClient(self.app, base_url="http://127.0.0.1", client=("127.0.0.1", 52125))
        client.cookies.set("uvm_session", cookie, domain="127.0.0.1", path="/")
        return client

    def test_claim_atomic_replay_session_restart_password_and_purpose_bound_enrolment(self):
        setup_password = secrets.token_urlsafe(20) + "A7!"
        payload = {"capability": self.capability, "username": "first-admin",
            "display_name": "First Admin", "password": setup_password}

        # The same token may be presented concurrently, but one transaction
        # commits the principal, authority, session and audit receipt only.
        def claim_once():
            with closing(TestClient(self.app, base_url="http://127.0.0.1", client=("127.0.0.1", 52124))) as client:
                return client.post("/api/v1/auth/setup/claim", json=payload, headers=self.origin).status_code
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(lambda _: claim_once(), range(2)))
        self.assertEqual(sorted(results), [201, 401])
        # The winning cookie belonged to its isolated concurrent client. Sign
        # in normally to verify independently persisted session issuance.
        signed_in = self.client.post("/api/v1/auth/local/login",
            json={"username": "first-admin", "password": setup_password}, headers=self.origin)
        self.assertEqual(signed_in.status_code, 200, signed_in.text)
        with self.engine.connect() as c:
            claim_receipt = c.execute(sa.text("select intent_id from assessment_command_receipts where action='local.setup.claimed'")).scalar_one()
            self.assertIsNotNone(claim_receipt)
            self.assertEqual(c.execute(sa.text("select count(*) from administration_reconciliation_intents where intent_id=:id"),
                {"id": claim_receipt}).scalar_one(), 1)
        response = self.client.get("/api/v1/auth/session")
        self.assertEqual(response.status_code, 200)
        session = response.json()
        self.assertEqual(session["credential_mode"], "local_session")
        self.assertTrue(session["protected_admin"])
        self.assertEqual(self.client.get("/api/v1/auth/config").json()["setup_state"], "claimed")
        self.assertEqual(self.client.post("/api/v1/auth/setup/claim", json=payload, headers=self.origin).status_code, 401)
        deployment = self.client.get("/api/v1/deployment")
        self.assertEqual(deployment.status_code, 200, deployment.text)
        self.assertTrue(deployment.json()["can_register_connector"])
        self.assertEqual(deployment.json()["connectors"], [])

        # The PostgreSQL row, not an in-process auth cache, restores authority.
        from uvm.api.app import create_app
        restart_app = create_app(self.engine, principals={}, cursor_secret=secrets.token_bytes(32))
        restarted = TestClient(restart_app, base_url="http://127.0.0.1", client=("127.0.0.1", 52125))
        restarted.cookies.update(self.client.cookies)
        self.assertEqual(restarted.get("/api/v1/auth/session").status_code, 200)
        csrf = restarted.get("/api/v1/auth/session").json()["csrf_token"]
        changed_password = secrets.token_urlsafe(20) + "C8!"
        wrong_csrf = restarted.post("/api/v1/auth/local/password",
            json={"current_password": setup_password, "new_password": changed_password}, headers=self.origin)
        self.assertEqual(wrong_csrf.status_code, 403)
        wrong_csrf = restarted.post("/api/v1/auth/local/password",
            json={"current_password": setup_password, "new_password": changed_password},
            headers={**self.origin, "X-CSRF-Token": secrets.token_urlsafe(32)})
        self.assertEqual(wrong_csrf.status_code, 403)
        other_session = TestClient(restart_app, base_url="http://127.0.0.1", client=("127.0.0.1", 52126))
        other_login = other_session.post("/api/v1/auth/local/login",
            json={"username": "first-admin", "password": setup_password}, headers=self.origin)
        self.assertEqual(other_login.status_code, 200)
        cross_session = restarted.post("/api/v1/auth/local/password",
            json={"current_password": setup_password, "new_password": changed_password},
            headers={**self.origin, "X-CSRF-Token": other_login.json()["csrf_token"]})
        self.assertEqual(cross_session.status_code, 403)
        changed = restarted.post("/api/v1/auth/local/password",
            json={"current_password": setup_password, "new_password": changed_password},
            headers={**self.origin, "X-CSRF-Token": csrf})
        self.assertEqual(changed.status_code, 204, changed.text)
        self.assertEqual(restarted.get("/api/v1/auth/session").status_code, 401)
        login = restarted.post("/api/v1/auth/local/login",
            json={"username": "first-admin", "password": changed_password}, headers=self.origin)
        self.assertEqual(login.status_code, 200, login.text)

        # Host account creation has no verifier or grants. Enrolment capability
        # purpose and account binding are checked before setting its password.
        from uvm.auth.maintenance import run as maintain
        maintain("create-account", "scanner-operator", "Scanner Operator", str(self.config_path))
        enrol_cap = json.loads(self.delivery_path.read_text())["capability"]
        with self.engine.connect() as c:
            row = c.execute(sa.text("select status, verifier, capability_generation from local_accounts where username_normalized='scanner-operator'")).one()
            self.assertEqual((row.status, row.verifier), ("pending", None))
        # Recovery cannot consume an enrolment capability.
        rejected = restarted.post("/api/v1/auth/local/recovery",
            json={"capability": enrol_cap, "new_password": secrets.token_urlsafe(20) + "D9!"}, headers=self.origin)
        self.assertEqual(rejected.status_code, 401)
        enrolled_password = secrets.token_urlsafe(20) + "E2!"
        enrolled = restarted.post("/api/v1/auth/local/enrol",
            json={"capability": enrol_cap, "new_password": enrolled_password}, headers=self.origin)
        self.assertEqual(enrolled.status_code, 204, enrolled.text)
        sign_in = restarted.post("/api/v1/auth/local/login",
            json={"username": "scanner-operator", "password": enrolled_password}, headers=self.origin)
        self.assertEqual(sign_in.status_code, 200, sign_in.text)
        self.assertFalse(sign_in.json()["protected_admin"])

    def test_abandonment_is_durable_and_fences_delayed_registration_retry(self):
        cookie, csrf = self._local_admin()
        deployment = self.client.get("/api/v1/deployment").json()
        command = self._registration_command(str(__import__("uuid").uuid4()), deployment)
        headers = {**self.origin, "X-CSRF-Token": csrf}
        abandoned = self.client.post(f"/api/v1/assessment/commands/{command['command_id']}/abandon",
            json={"schema_version": 1, "command": command, "rationale": "Request outcome was uncertain",
                "evidence_ref": "test:unknown-outcome"}, headers=headers)
        self.assertEqual(abandoned.status_code, 200, abandoned.text)
        self.assertEqual(abandoned.json()["disposition"], "not_committed")
        self.assertEqual(abandoned.json()["actor_id"], self.client.get("/api/v1/auth/session").json()["principal_id"])
        retry = self.client.post("/api/v1/assessment/commands", json=command, headers=headers)
        self.assertEqual(retry.status_code, 409, retry.text)
        self.assertEqual(retry.json()["error"]["code"], "command_terminal")
        again = self.client.post(f"/api/v1/assessment/commands/{command['command_id']}/abandon",
            json={"schema_version": 1, "command": command, "rationale": "Request outcome was uncertain",
                "evidence_ref": "test:unknown-outcome"}, headers=headers)
        self.assertEqual(again.status_code, 200)
        self.assertEqual(again.json()["audit_event_id"], abandoned.json()["audit_event_id"])
        changed = dict(command, payload={**command["payload"], "account_label": "different"})
        conflict = self.client.post(f"/api/v1/assessment/commands/{command['command_id']}/abandon",
            json={"schema_version": 1, "command": changed, "rationale": "Changed bytes",
                "evidence_ref": "test:changed"}, headers=headers)
        self.assertEqual(conflict.status_code, 409)
        self.assertEqual(self.client.get("/api/v1/deployment").json()["connectors"], [])

    def test_registration_submission_races_abandonment_under_policy_serialization(self):
        cookie, csrf = self._local_admin()
        deployment = self.client.get("/api/v1/deployment").json()
        command = self._registration_command(str(__import__("uuid").uuid4()), deployment, "race")
        headers = {**self.origin, "X-CSRF-Token": csrf}
        disposition = {"schema_version": 1, "command": command,
            "rationale": "Resolve an uncertain registration", "evidence_ref": "test:race"}

        def submit():
            with closing(self._protected_client(cookie)) as client:
                return client.post("/api/v1/assessment/commands", json=command, headers=headers)

        def abandon():
            with closing(self._protected_client(cookie)) as client:
                return client.post(f"/api/v1/assessment/commands/{command['command_id']}/abandon",
                    json=disposition, headers=headers)

        with ThreadPoolExecutor(max_workers=2) as pool:
            submitted, abandoned = list(pool.map(lambda fn: fn(), (submit, abandon)))
        print("PG_COMMAND_RACE", {"command_id": command["command_id"],
            "submit_status": submitted.status_code, "abandon_status": abandoned.status_code,
            "disposition": abandoned.json().get("disposition"),
            "registered_count": len(self.client.get("/api/v1/deployment").json()["connectors"])})
        self.assertIn((submitted.status_code, abandoned.status_code), {(200, 200), (409, 200)})
        outcome = abandoned.json()["disposition"]
        self.assertIn(outcome, {"committed", "not_committed"})
        connectors = self.client.get("/api/v1/deployment").json()["connectors"]
        if outcome == "committed":
            self.assertEqual(submitted.status_code, 200)
            self.assertEqual(abandoned.json()["receipt"]["command_id"], command["command_id"])
            self.assertEqual(len(connectors), 1)
            self.assertEqual(connectors[0]["source"]["source_account_id"], submitted.json()["result"]["source_tuple"]["source_account_id"])
        else:
            self.assertEqual(submitted.status_code, 409)
            self.assertEqual(submitted.json()["error"]["code"], "command_terminal")
            self.assertEqual(connectors, [])

    def test_abandonment_returns_exact_committed_receipt(self):
        _, csrf = self._local_admin()
        deployment = self.client.get("/api/v1/deployment").json()
        command = self._registration_command(str(__import__("uuid").uuid4()), deployment, "committed")
        headers = {**self.origin, "X-CSRF-Token": csrf}
        submitted = self.client.post("/api/v1/assessment/commands", json=command, headers=headers)
        self.assertEqual(submitted.status_code, 200, submitted.text)
        self.assertEqual(submitted.json()["target_id"], "00000000-0000-0000-0000-000000000000")
        self.assertIn("connector_id", submitted.json()["result"]["allocated_ids"])
        abandoned = self.client.post(f"/api/v1/assessment/commands/{command['command_id']}/abandon",
            json={"schema_version": 1, "command": command, "rationale": "Reconcile confirmed write",
                "evidence_ref": "test:committed"}, headers=headers)
        self.assertEqual(abandoned.status_code, 200, abandoned.text)
        self.assertEqual(abandoned.json()["disposition"], "committed")
        self.assertEqual(abandoned.json()["receipt"], submitted.json())

    def test_registration_and_abandonment_reject_schema_extras_at_runtime(self):
        _, csrf = self._local_admin()
        deployment = self.client.get("/api/v1/deployment").json()
        command = self._registration_command(str(__import__("uuid").uuid4()), deployment, "strict")
        command["unexpected"] = "rejected"
        headers = {**self.origin, "X-CSRF-Token": csrf}
        rejected = self.client.post("/api/v1/assessment/commands", json=command, headers=headers)
        self.assertEqual(rejected.status_code, 400, rejected.text)
        command.pop("unexpected")
        abandon = {"schema_version": 1, "command": command, "rationale": "uncertain",
            "evidence_ref": "test:strict", "unexpected": True}
        rejected_abandon = self.client.post(
            f"/api/v1/assessment/commands/{command['command_id']}/abandon",
            json=abandon, headers=headers)
        self.assertEqual(rejected_abandon.status_code, 422, rejected_abandon.text)

    def test_native_v2_typed_delegation_uses_independent_exact_ceilings(self):
        from uvm.assessment.api import _envelope_allows
        pair = {"connector_id": "11111111-1111-4111-8111-111111111111",
            "source_family": "qualys", "source_account_id": "tenant", "scope_key": "prod"}
        source = {key: pair[key] for key in ("source_family", "source_account_id", "scope_key")}
        limits = {"allowed_environments": [], "allowed_service_ids": [],
            "allowed_sla_clock_bases": [], "allowed_sla_severities": [],
            "allowed_sla_start_sources": [], "allowed_identity_scalar_fields": {}}
        duties = {"approval_requires_distinct_actor": True, "prohibit_requester_approval": True,
            "required_approver_count": 1, "prohibited_action_pairs": []}
        envelope = {"version": 2, "actions": ["connector.configure", "assessment.read"],
            "target_scope": {"kind": "deployment", "deployment_ids": [self.installation_id]},
            "connector_ids": [pair["connector_id"]], "connector_sources": [pair],
            "source_read_targets": [source], "limits": limits, "separation_of_duties": duties}
        connector_role = {"actions": ["connector.configure"], "target_scope": {
            "kind": "connector", "connector_ids": [pair["connector_id"]], "source_pairs": [pair]},
            "limits": limits, "separation_of_duties": duties}
        read_role = {"actions": ["assessment.read"], "target_scope": {
            "kind": "source_read", "membership_mode": "all_current", "source_scopes": [source]},
            "limits": limits, "separation_of_duties": duties}
        self.assertTrue(_envelope_allows(envelope, connector_role))
        self.assertTrue(_envelope_allows(envelope, read_role))
        invalid_pair = {**pair, "scope_key": "other"}
        self.assertFalse(_envelope_allows(envelope, {"actions": ["connector.configure"],
            "target_scope": {"kind": "connector", "connector_ids": [pair["connector_id"]],
                "source_pairs": [invalid_pair]}, "limits": limits, "separation_of_duties": duties}))
        self.assertFalse(_envelope_allows(envelope, {"actions": ["connector.configure"],
            "target_scope": {"kind": "source_read", "membership_mode": "all_current",
                "source_scopes": [source]}, "limits": limits, "separation_of_duties": duties}))

    def test_local_source_ceiling_stays_paired_to_its_granting_group(self):
        from datetime import datetime, timezone
        from uvm.auth.schema import AuthorityContext
        source_a = ("qualys", "account-a", "prod")
        source_b = ("qualys", "account-b", "prod")
        context = AuthorityContext(principal_id="principal", credential_mode="local_session",
            issuer=None, subject=None, link_id=None, link_revision=None, session_id="session",
            session_revision=1, access_groups=("read-a", "connector-b"), group_revision=1,
            mapping_revision=1, policy_revision=1, source_scopes=(source_a, source_b), role_ids=(),
            evaluated_at=datetime.now(timezone.utc), group_roles=(
                ("read-a", ("assessment.read",)), ("connector-b", ("connector.configure",))),
            group_scopes=(("read-a", (source_a,)), ("connector-b", (source_b,))))
        self.assertEqual(context.scopes_for_granting_groups({"read-a"}), {source_a})
        self.assertEqual(context.scopes_for_granting_groups({"connector-b"}), {source_b})



    def test_audit_failure_rolls_back_claim_and_leaves_capability_reusable(self):
        setup_password = secrets.token_urlsafe(20) + "F3!"
        payload = {"capability": self.capability, "username": "rollback-admin",
            "display_name": "Rollback Admin", "password": setup_password}
        with self.engine.begin() as c:
            c.exec_driver_sql("""CREATE FUNCTION reject_local_claim_audit() RETURNS trigger LANGUAGE plpgsql AS $$
                BEGIN IF NEW.action = 'local.setup.claimed' THEN RAISE EXCEPTION 'injected local audit failure'; END IF; RETURN NEW; END $$""")
            c.exec_driver_sql("CREATE TRIGGER reject_local_claim_audit BEFORE INSERT ON assessment_audit_events FOR EACH ROW EXECUTE FUNCTION reject_local_claim_audit()")
        failed = self.client.post("/api/v1/auth/setup/claim", json=payload, headers=self.origin)
        self.assertEqual(failed.status_code, 503)
        with self.engine.connect() as c:
            self.assertEqual(c.exec_driver_sql("select count(*) from local_accounts").scalar_one(), 0)
            self.assertEqual(c.exec_driver_sql("select count(*) from assessment_command_receipts where action='local.setup.claimed'").scalar_one(), 0)
            self.assertEqual(c.exec_driver_sql("select count(*) from administration_reconciliation_intents").scalar_one(), 0)
            self.assertIsNone(c.exec_driver_sql("select claimed_at from local_auth_installation where singleton_id=1").scalar_one())
            self.assertIsNone(c.exec_driver_sql("select consumed_at from local_auth_capabilities where purpose='setup'").scalar_one())
        with self.engine.begin() as c:
            c.exec_driver_sql("DROP TRIGGER reject_local_claim_audit ON assessment_audit_events")
            c.exec_driver_sql("DROP FUNCTION reject_local_claim_audit()")
        claimed = self.client.post("/api/v1/auth/setup/claim", json=payload, headers=self.origin)
        self.assertEqual(claimed.status_code, 201, claimed.text)

    def test_database_failure_logs_hide_password_verifier_and_capability(self):
        password = "Secret Database Failure Password 8!"
        with self.engine.begin() as c:
            c.exec_driver_sql("""CREATE FUNCTION reject_local_account_write() RETURNS trigger LANGUAGE plpgsql AS $$
                BEGIN RAISE EXCEPTION 'injected account write failure'; END $$""")
            c.exec_driver_sql("CREATE TRIGGER reject_local_account_write BEFORE INSERT ON local_accounts FOR EACH ROW EXECUTE FUNCTION reject_local_account_write()")
        logger = logging.getLogger("uvm.api.app")
        sink = io.StringIO(); handler = logging.StreamHandler(sink); logger.addHandler(handler)
        try:
            response = self.client.post("/api/v1/auth/setup/claim", json={"capability": self.capability,
                "username": "first-admin", "display_name": "First Admin", "password": password}, headers=self.origin)
        finally:
            logger.removeHandler(handler)
            with self.engine.begin() as c:
                c.exec_driver_sql("DROP TRIGGER reject_local_account_write ON local_accounts")
                c.exec_driver_sql("DROP FUNCTION reject_local_account_write()")
        self.assertEqual(response.status_code, 503)
        self.assertNotIn(password, sink.getvalue())
        self.assertNotIn("$argon2id$", sink.getvalue())
        self.assertNotIn(self.capability, sink.getvalue())

    def test_failed_login_attempt_is_durably_throttled(self):
        self._local_admin()
        response = self.client.post("/api/v1/auth/local/login",
            json={"username": "first-admin", "password": "wrong password"}, headers=self.origin)
        self.assertEqual(response.status_code, 401)
        with self.engine.connect() as c:
            attempts = c.execute(sa.text("select coalesce(sum(attempts), 0) from local_login_throttles")).scalar_one()
        self.assertGreaterEqual(attempts, 1, "failed attempt counter must commit before returning 401")

    def test_password_contract_uses_normalized_phc_and_exact_account_names(self):
        from uvm.auth.local import LocalAuth, _password_hash, _password_verify
        composed = "Cafe\u0301PasswordLong!7"
        verifier = _password_hash(composed)
        self.assertTrue(verifier.startswith("$argon2id$v=19$m=19456,t=2,p=1$"))
        self.assertTrue(_password_verify(verifier, "Caf\u00e9PasswordLong!7"))
        self.assertFalse(_password_verify(verifier, composed + "x"))
        with self.assertRaises(Exception):
            LocalAuth._validate_password("short")
        with self.assertRaises(Exception):
            LocalAuth._validate_password("passwordpassword")
        with self.assertRaises(Exception):
            self.app.state.oidc_auth._validate_account(" first-admin", "Name", "A valid password long 1!")

    def test_local_config_rejects_remote_http_unsupported_scheme_and_host_mismatch(self):
        from uvm.auth.local import load_local_config
        original = json.loads(self.config_path.read_text())
        with patch.dict(os.environ, {"UVM_LOCAL_AUTH_CONFIG_FILE": str(self.config_path)}):
            for origin in ("http://10.1.2.3", "ftp://127.0.0.1"):
                invalid = dict(original, public_origin=origin)
                self.config_path.write_text(json.dumps(invalid))
                self.config_path.chmod(0o600)
                with self.subTest(origin=origin), self.assertRaises(RuntimeError):
                    load_local_config()
            invalid = json.loads(json.dumps(original))
            invalid["trusted_ingress"]["allowed_hosts"] = ["example.invalid"]
            self.config_path.write_text(json.dumps(invalid))
            self.config_path.chmod(0o600)
            with self.assertRaises(RuntimeError):
                load_local_config()

    def test_password_recovery_race_never_leaves_old_password_session_valid(self):
        old_password = "Initial Admin Password 6!"
        claim = self.client.post("/api/v1/auth/setup/claim", json={"capability": self.capability,
            "username": "first-admin", "display_name": "First Admin", "password": old_password},
            headers=self.origin)
        self.assertEqual(claim.status_code, 201, claim.text)
        from uvm.auth.maintenance import run as maintain
        maintain("issue-recovery", "first-admin", config_path=str(self.config_path))
        recovery_capability = json.loads(self.delivery_path.read_text())["capability"]
        new_password = "A New Password Long Enough 7!"
        barrier = threading.Barrier(2)
        login_client = TestClient(self.app, base_url="http://127.0.0.1", client=("127.0.0.1", 52131))
        recovery_client = TestClient(self.app, base_url="http://127.0.0.1", client=("127.0.0.1", 52132))
        def login():
            barrier.wait()
            return login_client.post("/api/v1/auth/local/login",
                json={"username": "first-admin", "password": old_password}, headers=self.origin)
        def recover():
            barrier.wait()
            return recovery_client.post("/api/v1/auth/local/recovery",
                json={"capability": recovery_capability, "new_password": new_password}, headers=self.origin)
        with ThreadPoolExecutor(max_workers=2) as pool:
            login_result, recovery_result = list(pool.map(lambda fn: fn(), (login, recover)))
        self.assertEqual(recovery_result.status_code, 204, recovery_result.text)
        self.assertIn(login_result.status_code, {200, 401})
        if login_result.status_code == 200:
            login_client.cookies.set("uvm_session", login_result.cookies.get("uvm_session"),
                domain="127.0.0.1", path="/")
            self.assertEqual(login_client.get("/api/v1/auth/session").status_code, 401,
                "a session issued before recovery must be revoked by the credential revision change")

    def test_password_change_race_never_leaves_old_password_session_valid(self):
        old_password = "Initial Admin Password 6!"
        claim = self.client.post("/api/v1/auth/setup/claim", json={"capability": self.capability,
            "username": "first-admin", "display_name": "First Admin", "password": old_password},
            headers=self.origin)
        self.assertEqual(claim.status_code, 201, claim.text)
        csrf = claim.json()["csrf_token"]
        new_password = "Changed Admin Password Long 8!"
        barrier = threading.Barrier(2)
        login_client = TestClient(self.app, base_url="http://127.0.0.1", client=("127.0.0.1", 52141))
        def login():
            barrier.wait()
            return login_client.post("/api/v1/auth/local/login",
                json={"username": "first-admin", "password": old_password}, headers=self.origin)
        def change():
            barrier.wait()
            return self.client.post("/api/v1/auth/local/password",
                json={"current_password": old_password, "new_password": new_password},
                headers={**self.origin, "X-CSRF-Token": csrf})
        with ThreadPoolExecutor(max_workers=2) as pool:
            login_result, change_result = list(pool.map(lambda fn: fn(), (login, change)))
        self.assertEqual(change_result.status_code, 204, change_result.text)
        self.assertIn(login_result.status_code, {200, 401})
        if login_result.status_code == 200:
            login_client.cookies.update(login_result.cookies)
            self.assertEqual(login_client.get("/api/v1/auth/session").status_code, 401)
        self.assertEqual(self.client.post("/api/v1/auth/local/login",
            json={"username": "first-admin", "password": new_password}, headers=self.origin).status_code, 200)

    def test_local_mode_never_falls_back_when_database_records_local_install(self):
        from types import SimpleNamespace
        from uvm.auth.service import install_auth
        app = SimpleNamespace(state=SimpleNamespace(engine=self.engine))
        for mode in ("bearer", "oidc", "unknown"):
            with patch.dict(os.environ, {"UVM_AUTH_MODE": mode}):
                with self.assertRaises(RuntimeError):
                    install_auth(app)
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("UVM_AUTH_MODE", None)
            with self.assertRaises(RuntimeError):
                install_auth(app)

    def test_non_admin_cannot_read_deployment_inventory(self):
        self._local_admin()
        from uvm.auth.maintenance import run as maintain
        maintain("create-account", "scanner-operator", "Scanner Operator", str(self.config_path))
        capability = json.loads(self.delivery_path.read_text())["capability"]
        operator = TestClient(self.app, base_url="http://127.0.0.1", client=("127.0.0.1", 52135))
        self.assertEqual(operator.post("/api/v1/auth/local/enrol",
            json={"capability": capability, "new_password": "Scanner Operator Password 7!"},
            headers=self.origin).status_code, 204)
        response = operator.post("/api/v1/auth/local/login",
            json={"username": "scanner-operator", "password": "Scanner Operator Password 7!"}, headers=self.origin)
        self.assertEqual(response.status_code, 200)
        inventory = operator.get("/api/v1/deployment")
        self.assertEqual(inventory.status_code, 403, inventory.text)

    def test_native_principal_disable_reenable_does_not_restore_old_local_session(self):
        _, csrf = self._local_admin()
        from uvm.auth.maintenance import run as maintain
        maintain("create-account", "scanner-operator", "Scanner Operator", str(self.config_path))
        capability = json.loads(self.delivery_path.read_text())["capability"]
        operator = TestClient(self.app, base_url="http://127.0.0.1", client=("127.0.0.1", 52136))
        password = "Scanner Operator Password 7!"
        self.assertEqual(operator.post("/api/v1/auth/local/enrol",
            json={"capability": capability, "new_password": password}, headers=self.origin).status_code, 204)
        login = operator.post("/api/v1/auth/local/login",
            json={"username": "scanner-operator", "password": password}, headers=self.origin)
        self.assertEqual(login.status_code, 200)
        operator.cookies.update(login.cookies)
        principal_id = login.json()["principal_id"]

        def update(enabled):
            deployment = self.client.get("/api/v1/deployment").json()
            policy_revision, authority_revision = deployment["policy_revision"], deployment["authority_revision"]
            command = {"command_id": str(__import__("uuid").uuid4()), "action": "principal.update",
                "target_id": "00000000-0000-4000-8000-000000000000", "membership_ids": [],
                "expected_revisions": {"target": policy_revision, "policy": policy_revision,
                    "identity_membership": 0, "owners": 0, "authority": authority_revision},
                "payload": {"principal_id": principal_id, "enabled": enabled}}
            response = self.client.post("/api/v1/assessment/commands", json=command,
                headers={**self.origin, "X-CSRF-Token": csrf})
            self.assertEqual(response.status_code, 200, response.text)
        update(False)
        self.assertEqual(operator.get("/api/v1/auth/session").status_code, 401)
        update(True)
        self.assertEqual(operator.get("/api/v1/auth/session").status_code, 401)

    def test_prepare_setup_reemits_existing_capability_without_rotation(self):
        from uvm.auth.maintenance import run as maintain
        before = json.loads(self.delivery_path.read_text())["capability"]
        with self.engine.connect() as c:
            audit_count = c.exec_driver_sql("select count(*) from assessment_audit_events where action='local.setup.capability_issued'").scalar_one()
            cap_count = c.exec_driver_sql("select count(*) from local_auth_capabilities where purpose='setup' and consumed_at is null").scalar_one()
        maintain("prepare-setup", config_path=str(self.config_path))
        after = json.loads(self.delivery_path.read_text())["capability"]
        self.assertEqual(after, before)
        with self.engine.connect() as c:
            self.assertEqual(c.exec_driver_sql("select count(*) from assessment_audit_events where action='local.setup.capability_issued'").scalar_one(), audit_count)
            self.assertEqual(c.exec_driver_sql("select count(*) from local_auth_capabilities where purpose='setup' and consumed_at is null").scalar_one(), cap_count)

    def test_restore_capability_revocation_also_invalidates_local_sessions(self):
        self._local_admin()
        self.assertEqual(self.client.get("/api/v1/auth/session").status_code, 200)
        from uvm.auth.maintenance import run as maintain
        maintain("revoke-capabilities", config_path=str(self.config_path))
        self.assertEqual(self.client.get("/api/v1/auth/session").status_code, 401)

    def test_user_and_peer_buckets_are_independent_with_separate_limits(self):
        self._local_admin()
        def wrong(username):
            return self.client.post("/api/v1/auth/local/login",
                json={"username": username, "password": "wrong password"}, headers=self.origin).status_code
        self.assertEqual([wrong("first-admin") for _ in range(5)], [401] * 4 + [429])
        self.assertEqual(wrong("first-admin"), 429)
        # The user bucket is blocked, but another username on this peer still
        # reaches the independent peer counter and receives ordinary denial.
        self.assertEqual(wrong("missing-account"), 401)
        with self.engine.connect() as c:
            counts = list(c.execute(sa.text("select attempts, blocked_until from local_login_throttles order by attempts desc")))
        self.assertEqual(sorted(row.attempts for row in counts), [1, 5, 6])
        self.assertEqual(sum(row.blocked_until is not None for row in counts), 1)


    def test_openapi_validates_actual_local_and_oidc_session_handler_responses(self):
        from tests.operations.test_export_openapi import MODULE, schema_accepts
        from uvm.auth.service import OIDCAuth
        from uvm.auth.schema import AuthorityContext
        from datetime import datetime, timezone
        from fastapi import FastAPI
        from starlette.requests import Request
        self._local_admin()
        response = self.client.get("/api/v1/auth/session")
        self.assertEqual(response.status_code, 200)
        document = MODULE.export_schema()
        session = document["paths"]["/api/v1/auth/session"]["get"]["responses"]["200"]["content"]["application/json"]["schema"]
        combined = {**session, "components": document["components"]}
        self.assertTrue(schema_accepts(combined, response.json()))
        local = next(item for item in session["anyOf"] if "local" in item["x-uvm-auth-modes"])
        oidc = next(item for item in session["anyOf"] if "oidc" in item["x-uvm-auth-modes"])
        self.assertTrue(schema_accepts({**local, "components":document["components"]}, response.json()))
        self.assertFalse(schema_accepts({**oidc, "components":document["components"]}, response.json()))
        # Exercise the real OIDC session handler with a synthetic, already
        # resolved service context; no provider contact or auth acceptance claim.
        service = OIDCAuth.__new__(OIDCAuth)
        service.config = {}
        context = AuthorityContext("synthetic-principal", "service_bearer", None, None,
            None, None, None, None, (), 0, 1, 1, (), (), datetime.now(timezone.utc))
        app = FastAPI()
        service.install_routes(app)
        endpoint = next(route.endpoint for route in app.routes if getattr(route,"path",None) == "/api/v1/auth/session")
        with patch.object(service, "resolve_request", return_value=context):
            oidc_response = json.loads(endpoint(Request({"type":"http", "headers":[]})).body)
        self.assertTrue(schema_accepts(combined, oidc_response))
        self.assertTrue(schema_accepts({**oidc, "components":document["components"]}, oidc_response))
        self.assertFalse(schema_accepts({**local, "components":document["components"]}, oidc_response))

    def _admin_command(self, csrf, action, payload, **revisions):
        import uuid
        if action.startswith("access_group."):
            payload = {**payload, "rationale": "Delegate exact authority", "evidence_ref": "test:delegation"}
        deployment = self.client.get("/api/v1/deployment").json()
        revision = deployment["policy_revision"]
        return self.client.post("/api/v1/assessment/commands", json={
            "command_id": str(uuid.uuid4()), "action": action,
            "target_id": "00000000-0000-4000-8000-000000000000", "membership_ids": [],
            "expected_revisions": {"target": revision, "policy": revision,
                "identity_membership": 0, "owners": 0, "authority": deployment["authority_revision"], **revisions},
            "payload": payload}, headers={**self.origin, "X-CSRF-Token": csrf})

    def test_pending_enable_preserves_enrolment_and_cannot_issue_recovery(self):
        _, csrf = self._local_admin()
        from uvm.auth.maintenance import run as maintain
        maintain("create-account", "pending-user", "Pending User", str(self.config_path))
        token = json.loads(self.delivery_path.read_text())["capability"]
        with self.engine.connect() as c:
            principal = c.exec_driver_sql("select principal_id from local_accounts where username='pending-user'").scalar_one()
        enabled = self._admin_command(csrf, "principal.update", {"principal_id": principal, "enabled": True})
        self.assertEqual(enabled.status_code, 200, enabled.text)
        with self.engine.connect() as c:
            row = c.exec_driver_sql("select status,verifier,credential_revision from local_accounts where username='pending-user'").one()
            self.assertEqual(tuple(row), ("pending", None, 1))
        with self.assertRaises(RuntimeError):
            maintain("issue-recovery", "pending-user", config_path=str(self.config_path))
        self.assertEqual(self.client.post("/api/v1/auth/local/recovery", json={
            "capability": token, "new_password": "Pending user password 7!"}, headers=self.origin).status_code, 401)
        self.assertEqual(self.client.post("/api/v1/auth/local/enrol", json={
            "capability": token, "new_password": "Pending user password 7!"}, headers=self.origin).status_code, 204)

    def test_expired_prepare_is_stable_and_only_explicit_rotate_reissues(self):
        from datetime import datetime, timedelta, timezone
        from uvm.auth.maintenance import run as maintain
        from uvm.persistence.auth_schema import local_capabilities
        with self.engine.begin() as c:
            c.execute(local_capabilities.update().where(local_capabilities.c.purpose == "setup").values(
                expires_at=datetime.now(timezone.utc) - timedelta(seconds=1)))
            before = c.execute(sa.select(local_capabilities)).mappings().one()
            audit_count = c.exec_driver_sql("select count(*) from assessment_audit_events").scalar_one()
        maintain("prepare-setup", config_path=str(self.config_path))
        self.assertEqual(json.loads(self.delivery_path.read_text())["capability"], self.capability)
        with self.engine.connect() as c:
            self.assertEqual(dict(c.execute(sa.select(local_capabilities)).mappings().one()), dict(before))
            self.assertEqual(c.exec_driver_sql("select count(*) from assessment_audit_events").scalar_one(), audit_count)
        payload = {"capability": self.capability, "username": "admin", "display_name": "Admin",
            "password": "Setup password long 7!"}
        self.assertEqual(self.client.post("/api/v1/auth/setup/claim", json=payload, headers=self.origin).status_code, 401)
        maintain("rotate-setup", config_path=str(self.config_path))
        replacement = json.loads(self.delivery_path.read_text())["capability"]
        self.assertNotEqual(replacement, self.capability)
        self.assertEqual(self.client.post("/api/v1/auth/setup/claim", json=payload, headers=self.origin).status_code, 401)
        payload["capability"] = replacement
        self.assertEqual(self.client.post("/api/v1/auth/setup/claim", json=payload, headers=self.origin).status_code, 201)

    def test_receipt_and_intent_failures_independently_roll_back_complete_claim(self):
        payload = {"capability": self.capability, "username": "rollback-admin", "display_name": "Admin",
            "password": "Rollback password long 7!"}
        for table in ("assessment_command_receipts", "administration_reconciliation_intents"):
            with self.subTest(failure=table):
                with self.engine.begin() as c:
                    baseline_audit = c.exec_driver_sql("select count(*) from assessment_audit_events").scalar_one()
                    c.exec_driver_sql("CREATE FUNCTION reject_claim_write() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'injected claim write failure'; END $$")
                    c.exec_driver_sql(f"CREATE TRIGGER reject_claim_write BEFORE INSERT ON {table} FOR EACH ROW EXECUTE FUNCTION reject_claim_write()")
                failed = self.client.post("/api/v1/auth/setup/claim", json=payload, headers=self.origin)
                self.assertEqual(failed.status_code, 503, failed.text)
                with self.engine.connect() as c:
                    for empty in ("auth_principals", "local_accounts", "local_sessions", "assessment_policy", "administration_reconciliation_intents"):
                        self.assertEqual(c.exec_driver_sql(f"select count(*) from {empty}").scalar_one(), 0)
                    self.assertEqual(c.exec_driver_sql("select count(*) from assessment_audit_events").scalar_one(), baseline_audit)
                    self.assertEqual(c.exec_driver_sql("select count(*) from assessment_command_receipts where action='local.setup.claimed'").scalar_one(), 0)
                    self.assertIsNone(c.exec_driver_sql("select claimed_at from local_auth_installation").scalar_one())
                    self.assertIsNone(c.exec_driver_sql("select consumed_at from local_auth_capabilities where purpose='setup'").scalar_one())
                with self.engine.begin() as c:
                    c.exec_driver_sql(f"DROP TRIGGER reject_claim_write ON {table}")
                    c.exec_driver_sql("DROP FUNCTION reject_claim_write()")
        self.assertEqual(self.client.post("/api/v1/auth/setup/claim", json=payload, headers=self.origin).status_code, 201)

    def test_rolling_windows_survive_restart_and_block_before_kdf(self):
        from datetime import datetime, timedelta, timezone
        import uvm.auth.local as local
        start = datetime.now(timezone.utc)
        def wrong(username):
            return self.client.post("/api/v1/auth/local/login", json={
                "username": username, "password": "Unknown wrong password 7!"}, headers=self.origin)
        with patch.object(local, "_now", return_value=start):
            self.assertEqual(wrong("missing").status_code, 401)
        with patch.object(local, "_now", return_value=start + timedelta(minutes=14)):
            self.assertEqual([wrong("missing").status_code for _ in range(4)], [401, 401, 401, 429])
        # Expiring the oldest failure at minute 15 leaves four recent failures.
        with patch.object(local, "_now", return_value=start + timedelta(minutes=15)):
            response = wrong("missing")
            self.assertEqual(response.status_code, 429)
            self.assertEqual(response.headers["retry-after"], "840")
        from uvm.api.app import create_app
        app = create_app(self.engine, principals={}, cursor_secret=secrets.token_bytes(32))
        restarted = TestClient(app, base_url="http://127.0.0.1", client=("127.0.0.1", 52123))
        with patch.object(local, "_now", return_value=start + timedelta(minutes=28, seconds=59)):
            with patch.object(local, "_password_verify", side_effect=AssertionError("blocked attempt performed KDF")):
                blocked = restarted.post("/api/v1/auth/local/login", json={
                    "username": "missing", "password": "Unknown wrong password 7!"}, headers=self.origin)
                self.assertEqual(blocked.status_code, 429)
                self.assertEqual(blocked.headers["retry-after"], "1")
        with patch.object(local, "_now", return_value=start + timedelta(minutes=29)):
            self.assertEqual(wrong("missing").status_code, 401)

    def test_success_cannot_reset_peer_budget_and_peer_window_rolls(self):
        from datetime import datetime, timedelta, timezone
        import uvm.auth.local as local
        password = "Known successful password 7!"
        claimed = self.client.post("/api/v1/auth/setup/claim", json={"capability": self.capability,
            "username": "known", "display_name": "Known", "password": password}, headers=self.origin)
        self.assertEqual(claimed.status_code, 201)
        start = datetime.now(timezone.utc)
        def attempt(username, value="Unknown wrong password 7!"):
            return self.client.post("/api/v1/auth/local/login", json={"username": username,
                "password": value}, headers=self.origin)
        with patch.object(local, "_now", return_value=start):
            self.assertEqual(attempt("missing-0").status_code, 401)
        with patch.object(local, "_now", return_value=start + timedelta(minutes=14)):
            for number in range(1, 29):
                self.assertEqual(attempt(f"missing-{number}").status_code, 401)
            self.assertEqual(attempt("known", password).status_code, 200)
            self.assertEqual(attempt("missing-29").status_code, 429)
        with patch.object(local, "_now", return_value=start + timedelta(minutes=15)):
            response = attempt("missing-30")
            self.assertEqual(response.status_code, 429)
            self.assertEqual(response.headers["retry-after"], "840")
        with patch.object(local, "_now", return_value=start + timedelta(minutes=28, seconds=59)):
            with patch.object(local, "_password_verify", side_effect=AssertionError("blocked peer performed KDF")):
                self.assertEqual(attempt("known", password).status_code, 429)
        with patch.object(local, "_now", return_value=start + timedelta(minutes=29)):
            self.assertEqual(attempt("known", password).status_code, 200)

    def test_wrong_password_and_unknown_account_each_perform_one_kdf(self):
        import uvm.auth.local as local
        verifier = local._password_hash("Existing account password 7!")
        original = local.Argon2id
        class CountingArgon:
            calls = 0
            def __init__(self, **kwargs):
                self.kdf = original(**kwargs)
            @staticmethod
            def verify_phc_encoded(*args):
                CountingArgon.calls += 1
                return original.verify_phc_encoded(*args)
            def derive(self, *args):
                CountingArgon.calls += 1
                return self.kdf.derive(*args)
        with patch.object(local, "Argon2id", CountingArgon):
            for value in (verifier, None, "invalid"):
                CountingArgon.calls = 0
                self.assertFalse(local._password_verify(value, "Unknown wrong password 7!"))
                self.assertEqual(CountingArgon.calls, 1)
        self._local_admin()
        with patch.object(local, "Argon2id", CountingArgon):
            for username in ("first-admin", "unknown-user"):
                CountingArgon.calls = 0
                response = self.client.post("/api/v1/auth/local/login", json={
                    "username": username, "password": "Unknown wrong password 7!"}, headers=self.origin)
                self.assertEqual(response.status_code, 401)
                self.assertEqual(CountingArgon.calls, 1)


    def _seed_source_group(self, source, ordinal, *, published=False):
        """Retain a minimal observed target; no scanner or live tenant contact."""
        import uuid
        from datetime import datetime, timezone
        from uvm.persistence.schema import (groups, workloads, incarnations, exposures,
            exposure_workload_memberships, occurrences)
        from uvm.persistence.observation_schema import source_observations
        from uvm.persistence.ingestion_schema import collection_runs
        gid, wid, iid, eid, oid, rid = [str(uuid.uuid4()) for _ in range(6)]
        now = datetime.now(timezone.utc)
        with self.engine.begin() as c:
            c.execute(groups.insert().values(group_id=gid, source_family=source['source_family'],
                native_id_scheme='qid', native_id_authority=source['source_account_id'],
                native_id_value=str(ordinal), revision=1, created_at=now))
            c.execute(workloads.insert().values(workload_id=wid, stable_attrs={}, revision=1, created_at=now))
            c.execute(incarnations.insert().values(incarnation_id=iid, workload_id=wid, revision=1, created_at=now))
            c.execute(exposures.insert().values(exposure_id=eid, group_id=gid, workload_id=wid, revision=1, created_at=now))
            c.execute(exposure_workload_memberships.insert().values(exposure_id=eid, workload_id=wid))
            c.execute(occurrences.insert().values(occurrence_id=oid, exposure_id=eid,
                incarnation_id=iid, workload_id=wid, first_ingested_at=now, revision=1, created_at=now))
            c.execute(collection_runs.insert().values(run_id=rid, revision=1, schema_version=1,
                schedule_id='test-scope', schedule_revision=1, **source, state='completed',
                retrieval_status='complete', retrieval_reasons=[], coverage_status='unknown', coverage_reasons=[],
                freshness_status='unknown', freshness_reasons=[], facts_snapshot={}, provenance_snapshot={}, created_at=now))
            c.execute(source_observations.insert().values(schema_version=1, observation_id=str(uuid.uuid4()),
                revision=1, source_family=source['source_family'], source_account_id=source['source_account_id'],
                run_id=rid, source_record_ordinal=ordinal, collection_status='success', collected_at=now,
                raw_evidence_ref='synthetic:test', raw_evidence_sha256='a'*64, missing_fields=[],
                occurrence_id=oid, retention_order=ordinal, ingest_outcome='created'))
            if published:
                # Promotion metadata for this synthetic permission-isolation
                # fixture. Real pipeline/publication atomicity is exercised by
                # the separate TLS collection and final-audit-failure methods.
                from uvm.scanners import store
                from uvm.persistence.connector_schema import connectors
                from uvm.persistence.auth_schema import local_accounts
                binding = c.execute(sa.select(connectors).where(
                    connectors.c.source_family == source['source_family'],
                    connectors.c.source_account_id == source['source_account_id'],
                    connectors.c.scope_key == source['scope_key'])).mappings().one()
                principal = c.execute(sa.select(local_accounts.c.principal_id).where(
                    local_accounts.c.username_normalized == 'first-admin')).scalar_one()
                operation, _ = store.admit(c, store.OperationAdmission(binding['connector_id'],
                    binding['source_id'], str(uuid.uuid4()), principal, 'collect', 'a'*64, 0,
                    str(uuid.uuid4()), '00000000-0000-0000-0000-000000000000', rid), now=now)
                for stage in ('evidence','observations','resolution','published'):
                    store.advance_finalization(c, operation['operation_id'], stage)
                store.publish(c, operation, published_at=now,
                    retrieval={'status':'complete','reason_codes':[]},
                    coverage={'status':'unknown','reason_codes':[]}, freshness={'status':'unknown','reason_codes':[]})
                store.finish(c, operation['operation_id'], status='succeeded', now=now)
        return gid

    def test_public_native_delegation_and_cross_source_isolation(self):
        import copy
        import uuid
        from datetime import datetime, timedelta, timezone
        from uvm.persistence.assessment_schema import assessment_policy
        from uvm.auth.maintenance import run as maintain
        _, csrf = self._local_admin()
        registered = []
        for suffix in ('a', 'b'):
            deployment = self.client.get('/api/v1/deployment').json()
            command = self._registration_command(str(uuid.uuid4()), deployment, suffix)
            response = self.client.post('/api/v1/assessment/commands', json=command,
                headers={**self.origin, 'X-CSRF-Token': csrf})
            self.assertEqual(response.status_code, 200, response.text)
            registered.append({**response.json()['result']['allocated_ids'], 'source_tuple':response.json()['result']['source_tuple']})
        source_a = registered[0]['source_tuple']
        source_b = registered[1]['source_tuple']
        target_a = self._seed_source_group(source_a, 1, published=True)
        target_b = self._seed_source_group(source_b, 2, published=True)
        maintain('create-account', 'delegated', 'Delegated User', str(self.config_path))
        token = json.loads(self.delivery_path.read_text())['capability']
        operator = TestClient(self.app, base_url='http://127.0.0.1', client=('127.0.0.1', 52141))
        self.assertEqual(operator.post('/api/v1/auth/local/enrol', json={'capability':token,
            'new_password':'Delegated user password 7!'}, headers=self.origin).status_code, 204)
        login = operator.post('/api/v1/auth/local/login', json={'username':'delegated',
            'password':'Delegated user password 7!'}, headers=self.origin)
        self.assertEqual(login.status_code, 200)
        principal = login.json()['principal_id']
        with self.engine.connect() as c:
            document = c.execute(sa.select(assessment_policy.c.document)).scalar_one()
        envelope = document['native_authority']['grantable_envelope']
        groups = []
        # Read A and administer connector B through two independently delegated groups.
        for source, allocated, actions, scope in (
            (source_a, registered[0], ('assessment.read','audit.read'),
                {'kind':'source_read','membership_mode':'all_current','source_scopes':[source_a]}),
            (source_b, registered[1], ('connector.read','connector.configure'),
                {'kind':'connector','connector_ids':[registered[1]['connector_id']],
                    'source_pairs':[{'connector_id':registered[1]['connector_id'], **source_b}]})):
            group = str(uuid.uuid4())
            permissions = [{'permission_id':str(uuid.uuid4()), 'role_id':str(uuid.uuid4()),
                'action':action, 'target_scope':scope, 'limits':envelope['limits'],
                'separation_of_duties':envelope['separation_of_duties']} for action in actions]
            created = self._admin_command(csrf, 'access_group.create', {'access_group_id':group,
                'display_name':'Delegated scope', 'enabled':True, 'source_scopes':[source], 'permissions':permissions})
            self.assertEqual(created.status_code, 200, created.text)
            member = self._admin_command(csrf, 'access_group.membership.set', {'access_group_id':group,
                'principal_id':principal, 'enabled':True,
                'effective_from':(datetime.now(timezone.utc)+timedelta(seconds=1)).isoformat(),
                'effective_until':None}, access_group=1)
            self.assertEqual(member.status_code, 200, member.text)
            groups.append(group)
        # Advance the native membership evaluation clock beyond the admitted
        # future start; retain the public command and authentication paths.
        future = datetime.now(timezone.utc)+timedelta(seconds=3)
        class MembershipClock(datetime):
            @classmethod
            def now(cls, tz=None):
                return future.astimezone(tz)
        with patch('uvm.auth.local._now', return_value=future), patch('uvm.auth.native_authority.datetime', MembershipClock):
            self.assertEqual(operator.get(f"/api/v1/connectors/{registered[1]['connector_id']}",
                params={'source_id':registered[1]['source_id']}).status_code, 200)
            self.assertEqual(operator.get(f"/api/v1/connectors/{registered[0]['connector_id']}",
                params={'source_id':registered[0]['source_id']}).status_code, 403)
            self.assertEqual(operator.get('/api/v1/assessment/audit', params={'group_id':target_a}).status_code, 200)
            self.assertEqual(operator.get('/api/v1/assessment/audit', params={'group_id':target_b}).status_code, 403)
            self.assertEqual(operator.get(f'/api/v1/assessment/groups/{target_a}').status_code, 200)
            self.assertEqual(operator.get(f'/api/v1/assessment/groups/{target_b}').status_code, 403)
            runs = operator.get('/api/v1/ingestion/runs')
            self.assertEqual(runs.status_code, 200, runs.text)
            self.assertEqual({row['source_account_id'] for row in runs.json()['items']}, {source_a['source_account_id']})
            with self.engine.connect() as c:
                b_run = str(c.execute(sa.text('select run_id from collection_runs where source_account_id=:account'),
                    {'account':source_b['source_account_id']}).scalar_one())
            self.assertEqual(operator.get('/api/v1/ingestion/runs/'+b_run).status_code, 403)

        # A v1 wildcard envelope must never admit typed delegation.
        with self.engine.begin() as c:
            original = c.execute(sa.select(assessment_policy.c.document)).scalar_one()
            changed = copy.deepcopy(original)
            state = changed['native_authority']
            state['mode'] = 'uvm_native_v1'
            state['grantable_envelope']['version'] = 1
            state['grantable_envelope']['target_scope'] = {key:['*'] for key in
                ('group_ids','source_families','environments','service_ids')}
            state['grantable_envelope']['target_scope']['membership_mode'] = 'all_current'
            c.execute(assessment_policy.update().values(document=changed))
        permissions = [{**item, "permission_id": str(uuid.uuid4()), "role_id": str(uuid.uuid4())} for item in permissions]
        rejected = self._admin_command(csrf, 'access_group.create', {'access_group_id':str(uuid.uuid4()),
            'display_name':'Forbidden typed v1', 'enabled':True, 'source_scopes':[source_b], 'permissions':permissions})
        self.assertEqual(rejected.status_code, 403, rejected.text)


    def _registered_scanner(self, csrf, suffix='bridge'):
        import uuid
        command = self._registration_command(str(uuid.uuid4()), self.client.get('/api/v1/deployment').json(), suffix)
        response = self.client.post('/api/v1/assessment/commands', json=command,
            headers={**self.origin, 'X-CSRF-Token':csrf})
        self.assertEqual(response.status_code, 200, response.text)
        return command, response.json()

    def _scanner_request(self, csrf):
        from starlette.requests import Request
        cookie = self.client.cookies.get('uvm_session')
        return Request({'type':'http', 'method':'POST', 'path':'/api/v1/scanners',
            'headers':[(b'cookie', ('uvm_session='+cookie).encode()), (b'origin',b'http://127.0.0.1'),
                (b'x-csrf-token',csrf.encode())]})

    def _submit_qualys(self, csrf, receipt, *, secret_id=None, purpose='qualys_vm_basic'):
        import uuid
        result = receipt['result']
        connector_id = result['allocated_ids']['connector_id']
        source_id = result['allocated_ids']['source_id']
        slot = result['credential_slots']['qualys_vm_basic']['secret_id']
        read = self.client.get(f'/api/v1/connectors/{connector_id}/secrets/{slot}', params={'source_id':source_id})
        self.assertEqual(read.status_code, 200, read.text)
        body = {'schema_version':1, 'submission_id':str(uuid.uuid4()), 'version_id':str(uuid.uuid4()),
            'source_id':source_id, 'purpose':purpose, 'expected_revisions':read.json()['revisions'],
            'rationale':'Install test credential', 'evidence_ref':'test:private-credential',
            'input':{'kind':'value','value':json.dumps({'username':'synthetic-reader','password':'Synthetic scanner secret 7!'})}}
        response = self.client.post(f'/api/v1/connectors/{connector_id}/secrets/{secret_id or slot}/versions',
            json=body, headers={**self.origin, 'X-CSRF-Token':csrf})
        return response

    def test_qualys_registration_generates_identity_and_enforces_purpose_slot(self):
        import uuid
        _, csrf = self._local_admin()
        command, receipt = self._registered_scanner(csrf)
        result = receipt['result']
        source = result['source_tuple']
        for value in (source['source_account_id'],source['scope_key'], result['credential_slots']['qualys_vm_basic']['secret_id']):
            self.assertEqual(str(uuid.UUID(value)), value)
        self.assertNotEqual(source['source_account_id'], command['payload']['account_label'])
        replay = self.client.post('/api/v1/assessment/commands', json=command,
            headers={**self.origin, 'X-CSRF-Token':csrf})
        self.assertEqual(replay.status_code, 200)
        self.assertEqual(replay.json(), receipt)
        second_command = {**command, 'command_id':str(uuid.uuid4())}
        deployment = self.client.get('/api/v1/deployment').json()
        second_command.update(expected_policy_revision=deployment['policy_revision'],
            expected_authority_revision=deployment['authority_revision'],
            expected_connector_registry_revision=deployment['connector_registry_revision'])
        second = self.client.post('/api/v1/assessment/commands', json=second_command,
            headers={**self.origin, 'X-CSRF-Token':csrf})
        self.assertEqual(second.status_code, 200, second.text)
        self.assertNotEqual(second.json()['result']['source_tuple'], source)
        self.assertEqual(self._submit_qualys(csrf, receipt, secret_id=str(uuid.uuid4())).status_code, 403)
        self.assertEqual(self._submit_qualys(csrf, receipt, purpose='rest_token').status_code, 403)
        foreign = second.json()['result']['credential_slots']['qualys_vm_basic']['secret_id']
        self.assertEqual(self._submit_qualys(csrf, receipt, secret_id=foreign).status_code, 403)
        submitted = self._submit_qualys(csrf, receipt)
        self.assertEqual(submitted.status_code, 201, submitted.text)
        self.assertEqual(submitted.json()['result']['version_state'], 'active')
        with self.engine.connect() as c:
            encrypted = c.exec_driver_sql("select purpose,state,ciphertext from g7_connector_secrets").all()
            self.assertEqual(len(encrypted), 1)
            self.assertEqual(tuple(encrypted[0][:2]), ('qualys_vm_basic','active'))
            self.assertNotIn(b'Synthetic scanner secret', encrypted[0].ciphertext)

    def test_scanner_bridge_same_connection_rollback_receipt_and_handle_lifetime(self):
        import uuid
        from dataclasses import asdict
        from uvm.connectors.scanner_runtime import SharedScannerRuntime
        from uvm.scanners import contracts as dto
        from uvm.persistence.connector_schema import connector_configurations
        _, csrf = self._local_admin()
        _, receipt = self._registered_scanner(csrf)
        ids = receipt['result']['allocated_ids']
        runtime = SharedScannerRuntime(self.app)
        request = self._scanner_request(csrf)
        snapshot = runtime.authorize(request=request, action='scanner.configuration.save',
            connector_id=ids['connector_id'], source_id=ids['source_id'])
        digest = 'b'*64
        baseline = {}
        with self.engine.connect() as c:
            for table in ('assessment_audit_events','g7_connector_intents','g7_connector_receipts'):
                baseline[table] = c.exec_driver_sql(f'select count(*) from {table}').scalar_one()
        for failure_table in ('assessment_audit_events','g7_connector_intents','g7_connector_receipts'):
            with self.subTest(failure=failure_table):
                with self.engine.begin() as c:
                    c.exec_driver_sql("CREATE FUNCTION reject_scanner_write() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'injected scanner transaction failure'; END $$")
                    c.exec_driver_sql(f'CREATE TRIGGER reject_scanner_write BEFORE INSERT ON {failure_table} FOR EACH ROW EXECUTE FUNCTION reject_scanner_write()')
                with self.assertRaises(sa.exc.DBAPIError):
                    with runtime.transaction(request=request, action='scanner.configuration.save',
                            connector_id=ids['connector_id'], source_id=ids['source_id'],
                            expected_revisions=snapshot.expected_revisions) as tx:
                        tx.connection.execute(connector_configurations.insert().values(connector_id=ids['connector_id'],
                            configuration_revision=1, settings={'test_marker':True}, actor_id=snapshot.principal_id,
                            created_at=__import__('datetime').datetime.now(__import__('datetime').timezone.utc)))
                        intent = tx.record_audited_intent(command_id=str(uuid.uuid4()), request_digest=digest,
                            rationale='Test atomic transaction', evidence_ref='test:rollback', operation_id=None, run_id=None)
                        tx.record_audited_receipt(intent_id=intent.intent_id, result=dto.SaveConfigurationResult('staged',1),
                            shared_state=dto.ScannerSharedStateChange('staged',1,None))
                with self.engine.connect() as c:
                    self.assertEqual(c.exec_driver_sql('select count(*) from g7_connector_configurations').scalar_one(), 0)
                    row = c.exec_driver_sql('select configuration_revision,connector_revision,lifecycle from g7_connectors').one()
                    self.assertEqual(tuple(row),(0,1,'disabled'))
                    for table, count in baseline.items():
                        self.assertEqual(c.exec_driver_sql(f'select count(*) from {table}').scalar_one(), count)
                with self.engine.begin() as c:
                    c.exec_driver_sql(f'DROP TRIGGER reject_scanner_write ON {failure_table}')
                    c.exec_driver_sql('DROP FUNCTION reject_scanner_write()')
        command_id = str(uuid.uuid4())
        with runtime.transaction(request=request, action='scanner.configuration.save', connector_id=ids['connector_id'],
                source_id=ids['source_id'], expected_revisions=snapshot.expected_revisions) as tx:
            self.assertIs(tx.connection, tx.connection)
            metadata = runtime.read_registration_metadata(transaction=tx)
            self.assertEqual(asdict(metadata.source_tuple), receipt['result']['source_tuple'])
            with self.assertRaises(RuntimeError):
                SharedScannerRuntime(self.app).read_registration_metadata(transaction=tx)
            intent = tx.record_audited_intent(command_id=command_id, request_digest=digest,
                rationale='Save exact scanner', evidence_ref='test:save', operation_id=None, run_id=None)
            committed = tx.record_audited_receipt(intent_id=intent.intent_id, result=dto.SaveConfigurationResult('staged',1),
                shared_state=dto.ScannerSharedStateChange('staged',1,None))
        with self.assertRaises(RuntimeError):
            _ = tx.connection
        with self.assertRaises(RuntimeError):
            runtime.read_registration_metadata(transaction=tx)
        with runtime.transaction(request=request, action='scanner.configuration.save', connector_id=ids['connector_id'], source_id=ids['source_id']) as tx:
            replay = tx.read_command(command_id=command_id, request_digest=digest)
            self.assertEqual(replay.receipt, committed.receipt)
            self.assertEqual(tx.snapshot.connector_revision, 2)
            with self.assertRaises(__import__('fastapi').HTTPException):
                tx.read_command(command_id=command_id, request_digest='c'*64)

    def test_scanner_credential_lease_releases_policy_lock_and_fences_rotation_and_revocation(self):
        from fastapi import HTTPException
        from datetime import datetime, timezone
        from uvm.connectors.scanner_runtime import SharedScannerRuntime
        from uvm.assessment.policy_lock import _LOCK_KEY
        _, csrf = self._local_admin()
        _, receipt = self._registered_scanner(csrf)
        ids = receipt['result']['allocated_ids']
        self.assertEqual(self._submit_qualys(csrf, receipt).status_code, 201)
        runtime = SharedScannerRuntime(self.app)
        request = self._scanner_request(csrf)
        def snapshot():
            return runtime.authorize(request=request, action='scanner.connection.test',
                connector_id=ids['connector_id'], source_id=ids['source_id'])
        before = snapshot()
        with runtime.credential_attempt(request=request, action='test', snapshot=before) as lease:
            self.assertTrue(lease.authorization_header().startswith('Basic '))
            self.assertEqual(str(lease),'QualysBasicCredential(<redacted>)')
            with self.engine.begin() as c:
                self.assertTrue(c.execute(sa.text('select pg_try_advisory_xact_lock(:a,:b)'),
                    {'a':_LOCK_KEY[0],'b':_LOCK_KEY[1]}).scalar_one())
        with self.assertRaises(RuntimeError):
            lease.authorization_header()
        self.assertEqual(self._submit_qualys(csrf, receipt).status_code, 201)
        with self.assertRaises(HTTPException) as conflict:
            runtime.assert_current(request=request, action='scanner.connection.test', snapshot=before)
        self.assertEqual(conflict.exception.status_code, 409)
        after = snapshot()
        principal = self.client.get('/api/v1/auth/session').json()['principal_id']
        revoked = self._admin_command(csrf, 'access_group.membership.set', {
            'access_group_id':ids['access_group_id'], 'principal_id':principal, 'enabled':False,
            'effective_from':datetime.now(timezone.utc).isoformat(), 'effective_until':None}, access_group=1)
        self.assertEqual(revoked.status_code, 200, revoked.text)
        with self.assertRaises(HTTPException) as denied:
            with runtime.credential_attempt(request=request, action='test', snapshot=after):
                self.fail('revoked grant yielded a credential')
        self.assertEqual(denied.exception.status_code, 403)
        self.assertEqual(self.client.get(f"/api/v1/connectors/{ids['connector_id']}",
            params={'source_id':ids['source_id']}).status_code, 403)


    def _secret_command_body(self, receipt, action, **extra):
        import uuid
        result = receipt['result']
        ids = result['allocated_ids']
        slot = result['credential_slots']['qualys_vm_basic']['secret_id']
        read = self.client.get(f"/api/v1/connectors/{ids['connector_id']}/secrets/{slot}",
            params={'source_id':ids['source_id']})
        self.assertEqual(read.status_code, 200, read.text)
        return {'schema_version':1, 'command_id':str(uuid.uuid4()), 'action':action,
            'target_id':'00000000-0000-4000-8000-000000000000', 'membership_ids':[],
            'expected_revisions':read.json()['revisions'], 'payload':{
                'connector_id':ids['connector_id'], 'source_id':ids['source_id'], 'secret_id':slot,
                'rationale':'Explicit local credential lifecycle', 'evidence_ref':'test:local-lifecycle', **extra}}

    def test_public_local_secret_revocation_is_scoped_and_never_uses_fixture_binding(self):
        import uuid
        from fastapi import HTTPException
        from datetime import datetime, timezone
        from uvm.connectors.scanner_runtime import SharedScannerRuntime
        _, csrf = self._local_admin()
        _, receipt = self._registered_scanner(csrf, 'revoke-a')
        _, other = self._registered_scanner(csrf, 'revoke-b')
        uploaded = self._submit_qualys(csrf, receipt)
        self.assertEqual(uploaded.status_code, 201, uploaded.text)
        version = uploaded.json()['result']['version_id']
        body = self._secret_command_body(receipt, 'connector.secret.version.revoke', version_id=version)
        ids = receipt['result']['allocated_ids']
        runtime = SharedScannerRuntime(self.app)
        request = self._scanner_request(csrf)
        snapshot = runtime.authorize(request=request, action='scanner.connection.test',
            connector_id=ids['connector_id'], source_id=ids['source_id'])
        headers = {**self.origin, 'X-CSRF-Token':csrf}
        with patch('uvm.connectors.api._fixture', side_effect=AssertionError('local command used fixture')):
            cross = {**body, 'command_id':str(uuid.uuid4()), 'payload':{**body['payload'],
                'source_id':other['result']['allocated_ids']['source_id']}}
            self.assertEqual(self.client.post('/api/v1/assessment/commands', json=cross, headers=headers).status_code, 403)
            cross['payload'] = {**body['payload'],
                'secret_id':other['result']['credential_slots']['qualys_vm_basic']['secret_id']}
            self.assertEqual(self.client.post('/api/v1/assessment/commands', json=cross, headers=headers).status_code, 403)
            revoked = self.client.post('/api/v1/assessment/commands', json=body, headers=headers)
            self.assertEqual(revoked.status_code, 200, revoked.text)
            self.assertEqual(revoked.json()['result']['version_state'], 'revoked')
            replay = self.client.post('/api/v1/assessment/commands', json=body, headers=headers)
            self.assertEqual(replay.status_code, 200)
            self.assertEqual(replay.json(), revoked.json())
        with self.assertRaises(HTTPException) as fenced:
            with runtime.credential_attempt(request=request, action='test', snapshot=snapshot):
                self.fail('revoked credential yielded a lease')
        self.assertEqual(fenced.exception.status_code, 409)
        # Principal remains protected, but removing this exact native group
        # denies subsequent secret lifecycle writes through current grants.
        denied_body = self._secret_command_body(receipt, 'connector.secret.submission.reconcile',
            submission_id=str(uuid.uuid4()), version_id=str(uuid.uuid4()))
        principal = self.client.get('/api/v1/auth/session').json()['principal_id']
        disabled = self._admin_command(csrf, 'access_group.membership.set', {
            'access_group_id':ids['access_group_id'], 'principal_id':principal, 'enabled':False,
            'effective_from':datetime.now(timezone.utc).isoformat(), 'effective_until':None}, access_group=1)
        self.assertEqual(disabled.status_code, 200, disabled.text)
        denied_body['expected_revisions']['policy'] = self.client.get('/api/v1/deployment').json()['policy_revision']
        with patch('uvm.connectors.api._fixture', side_effect=AssertionError('denied local command used fixture')):
            denied = self.client.post('/api/v1/assessment/commands', json=denied_body, headers=headers)
        self.assertEqual(denied.status_code, 403, denied.text)

    def test_public_local_uncertain_submission_reconciliation_fences_delayed_writer(self):
        import uuid
        import time
        from datetime import datetime, timezone
        cookie, csrf = self._local_admin()
        _, receipt = self._registered_scanner(csrf, 'unknown-a')
        _, other = self._registered_scanner(csrf, 'unknown-b')
        ids = receipt['result']['allocated_ids']
        slot = receipt['result']['credential_slots']['qualys_vm_basic']['secret_id']
        submission_id, version_id = str(uuid.uuid4()), str(uuid.uuid4())
        reconcile = self._secret_command_body(receipt, 'connector.secret.submission.reconcile',
            submission_id=submission_id, version_id=version_id)
        body = {'schema_version':1,'submission_id':submission_id,'version_id':version_id,
            'source_id':ids['source_id'], 'purpose':'qualys_vm_basic',
            'expected_revisions':reconcile['expected_revisions'], 'rationale':'Test interrupted local submission',
            'evidence_ref':'test:interrupted-submit', 'input':{'kind':'value', 'value':json.dumps({
                'username':'synthetic-reader','password':'Synthetic delayed secret 7!'})}}
        directory = Path(self.temp.name) / 'submission-pause'
        directory.mkdir(mode=0o700)
        pause = directory / 'pause'
        pause.write_text('paused')
        marker = directory / ('admitted-' + submission_id)
        headers = {**self.origin, 'X-CSRF-Token':csrf}
        def submit():
            with closing(self._protected_client(cookie)) as client:
                return client.post(f"/api/v1/connectors/{ids['connector_id']}/secrets/{slot}/versions",
                    json=body, headers=headers)
        with patch.dict(os.environ, {'UVM_G7_DISPOSABLE_MODE':'1',
                'UVM_CONNECTOR_TEST_SUBMISSION_PAUSE_DIR':str(directory)}), \
                patch('uvm.connectors.api._fixture', side_effect=AssertionError('local reconcile used fixture')):
            with ThreadPoolExecutor(max_workers=1) as pool:
                future = pool.submit(submit)
                try:
                    deadline = time.monotonic() + 10
                    while not marker.exists() and time.monotonic() < deadline:
                        time.sleep(0.01)
                    self.assertTrue(marker.exists(), 'submission did not reach durable admission')
                    lookup = self.client.get(f"/api/v1/connectors/{ids['connector_id']}/secret-submissions/{submission_id}",
                        params={'source_id':ids['source_id'], 'secret_id':slot, 'version_id':version_id})
                    self.assertEqual(lookup.status_code, 200, lookup.text)
                    self.assertEqual(lookup.json()['outcome'], 'unknown')
                    cross = self._secret_command_body(other, 'connector.secret.submission.reconcile',
                        submission_id=submission_id, version_id=version_id)
                    rejected = self.client.post('/api/v1/assessment/commands', json=cross, headers=headers)
                    self.assertEqual(rejected.status_code, 404, rejected.text)
                    settled = self.client.post('/api/v1/assessment/commands', json=reconcile, headers=headers)
                    self.assertEqual(settled.status_code, 200, settled.text)
                    self.assertEqual(settled.json()['result']['submission_outcome'], 'not_committed')
                    replay = self.client.post('/api/v1/assessment/commands', json=reconcile, headers=headers)
                    self.assertEqual(replay.status_code, 200)
                    self.assertEqual(replay.json(), settled.json())
                finally:
                    pause.unlink(missing_ok=True)
                delayed = future.result(timeout=10)
                self.assertEqual(delayed.status_code, 409, delayed.text)
        with self.engine.connect() as c:
            self.assertEqual(c.exec_driver_sql('select count(*) from g7_connector_secrets').scalar_one(), 0)
            row = c.execute(sa.text('select outcome,retry_allowed from g7_connector_submissions where submission_id=:id'),
                {'id':submission_id}).one()
            self.assertEqual(tuple(row), ('not_committed',True))
        # No fixture fallback and no blanket protected-admin permission after
        # native source grant revocation, even for an identical prior receipt.
        principal = self.client.get('/api/v1/auth/session').json()['principal_id']
        disabled = self._admin_command(csrf, 'access_group.membership.set', {
            'access_group_id':ids['access_group_id'], 'principal_id':principal, 'enabled':False,
            'effective_from':datetime.now(timezone.utc).isoformat(), 'effective_until':None}, access_group=1)
        self.assertEqual(disabled.status_code, 200, disabled.text)
        self.assertEqual(self.client.post('/api/v1/assessment/commands', json=reconcile, headers=headers).status_code, 403)

    def test_unpublished_registered_qualys_checkpoint_is_hidden_from_shared_readers(self):
        _, csrf = self._local_admin()
        _, receipt = self._registered_scanner(csrf, 'unpublished')
        group = self._seed_source_group(receipt['result']['source_tuple'], 1)
        with self.engine.connect() as c:
            run = str(c.exec_driver_sql('select run_id from collection_runs').scalar_one())
            self.assertEqual(c.exec_driver_sql('select count(*) from source_observations').scalar_one(), 1)
        # This retained fixture checkpoint has no provider publication. Current
        # real local grants alone must not promote it through generic readers.
        listing = self.client.get('/api/v1/ingestion/runs')
        self.assertEqual(listing.status_code, 200, listing.text)
        self.assertEqual(listing.json()['items'], [])
        detail = self.client.get('/api/v1/ingestion/runs/' + run)
        self.assertEqual(detail.status_code, 404, detail.text)
        self.assertEqual(self.client.get('/api/v1/unresolved').json()['items'], [])
        finding = self.client.get('/api/v1/assessment/groups/' + group)
        self.assertEqual(finding.status_code, 403, finding.text)
        self.assertEqual(self.client.get('/api/v1/assessment/groups').json()['items'], [])

    def test_shared_scanner_mount_is_pure_and_preserves_existing_lifespan(self):
        from uvm.connectors.scanner_install import install_shared_scanners
        from uvm.scanners.service import _WORKER_LOCK
        from fastapi import FastAPI
        app = FastAPI()
        app.state.engine = self.engine
        @app.get('/healthz')
        def health(): return {'ok': True}
        directory = Path(self.temp.name) / 'private-scanner-pages'
        events = []
        app.router.on_startup.append(lambda: events.append('prior-start'))
        app.router.on_shutdown.append(lambda: events.append('prior-stop'))
        def reject_sql(*args, **kwargs):
            raise AssertionError('scanner construction performed SQL')
        sa.event.listen(self.engine, 'before_cursor_execute', reject_sql)
        try:
            service = install_shared_scanners(app,
                private_evidence_directory=directory, public_origin='http://127.0.0.1')
        finally:
            sa.event.remove(self.engine, 'before_cursor_execute', reject_sql)
        self.assertFalse(directory.exists(), 'constructor accessed private state')
        self.assertEqual(events, [])
        self.assertIsNone(service._worker_connection)
        directory.mkdir(mode=0o700)
        with patch.object(service, '_client_factory', side_effect=AssertionError('startup contacted scanner')):
            with TestClient(app, base_url='http://127.0.0.1', client=('127.0.0.1',52164)) as client:
                self.assertEqual(events, ['prior-start'])
                self.assertIsNotNone(service._worker_connection)
                self.assertEqual(client.get('/healthz').status_code, 200)
                with self.engine.begin() as c:
                    self.assertFalse(c.execute(sa.text('select pg_try_advisory_xact_lock(:a,:b)'),
                        {'a':_WORKER_LOCK[0], 'b':_WORKER_LOCK[1]}).scalar_one())
        self.assertEqual(events, ['prior-start','prior-stop'])
        self.assertIsNone(service._worker_connection)
        with self.engine.begin() as c:
            self.assertTrue(c.execute(sa.text('select pg_try_advisory_xact_lock(:a,:b)'),
                {'a':_WORKER_LOCK[0], 'b':_WORKER_LOCK[1]}).scalar_one())


    def _initialize_scanner_rule_cli(self):
        result = subprocess.run([sys.executable, '-m', 'uvm.auth.maintenance',
            'initialize-scanner-rule', '--config',str(self.config_path)],
            cwd=Path(__file__).resolve().parents[2], text=True, capture_output=True, timeout=20)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_trusted_fixed_scanner_rule_initialization_is_idempotent_and_conflict_closed(self):
        from uvm.persistence.identity_repository import DurableIdentityError
        from uvm.auth.maintenance import run as maintain
        self._local_admin()
        with self.engine.connect() as c:
            before = c.exec_driver_sql('select document from assessment_policy').scalar_one()
        self._initialize_scanner_rule_cli()
        self._initialize_scanner_rule_cli()
        with self.engine.connect() as c:
            self.assertEqual(c.exec_driver_sql('select count(*) from identity_rule_definitions').scalar_one(), 1)
            decision = c.exec_driver_sql("select principal_id,policy_revision,decision_details from identity_authorisation_decisions where action='identity.rule_provision'").one()
            self.assertEqual(decision.principal_id, 'host-maintenance:'+self.installation_id)
            self.assertEqual(decision.policy_revision, '1')
            self.assertEqual(decision.decision_details['application_policy_revision'], 1)
            self.assertEqual(c.exec_driver_sql('select document from assessment_policy').scalar_one(), before)
            self.assertEqual(c.exec_driver_sql('select verified_asset_locator from identity_rule_definitions').scalar_one(), False)
        with self.assertRaises(RuntimeError):
            maintain('initialize-scanner-rule', username='arbitrary-rule', config_path=str(self.config_path))
        with patch.dict(os.environ, {'UVM_AUTH_MODE':'oidc'}), self.assertRaises(RuntimeError):
            maintain('initialize-scanner-rule', config_path=str(self.config_path))
        with self.engine.begin() as c:
            c.exec_driver_sql("update identity_rule_definitions set definition_digest='conflicting-retained-definition'")
        with self.assertRaises(DurableIdentityError):
            maintain('initialize-scanner-rule', config_path=str(self.config_path))
        import hashlib
        key = int.from_bytes(hashlib.sha256(('volt-local-scanner-rule-v1\0'+self.installation_id).encode()).digest()[:8], 'big', signed=True)
        with self.engine.connect() as c:
            self.assertTrue(c.execute(sa.text('select pg_try_advisory_lock(:key)'), {'key':key}).scalar_one())
            c.execute(sa.text('select pg_advisory_unlock(:key)'), {'key':key})

    def _actual_scanner_pipeline(self, *, fail_publication=False):
        import base64
        import uuid
        from http.server import BaseHTTPRequestHandler
        from tests.scanners.test_qualys_vm_protocol import PAGE, LAST_PAGE, local_https_server
        from uvm.scanners.qualys_vm import QualysVMClient, _production_transport
        self._initialize_scanner_rule_cli()
        case = self
        calls = []
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                correct = self.headers.get('Authorization') == 'Basic '+base64.b64encode(
                    b'synthetic-reader:Synthetic scanner secret 7!').decode()
                calls.append((self.path, correct))
                body = (LAST_PAGE if 'id_min=' in self.path else PAGE).replace(
                    b'https://qualysapi.qualys.com', case.fixture_origin.encode())
                if not correct: body = b'synthetic denied'
                self.send_response(200 if correct else 401)
                self.send_header('Content-Length',str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            def log_message(self,*args): pass
        with local_https_server(Handler) as (server, ssl_context):
            self.fixture_origin = f'https://127.0.0.1:{server.server_port}'
            def factory(platform):
                client = QualysVMClient(platform, _transport=lambda request, timeout, deadline:
                    _production_transport(request, timeout, deadline, _ssl_context=ssl_context))
                client.origin = self.fixture_origin  # explicit test endpoint only
                return client
            service = self.app.state.scanner_service
            with patch.object(service, '_client_factory', side_effect=factory):
                with TestClient(self.app, base_url='http://127.0.0.1', client=('127.0.0.1',52171)) as client:
                    self.client = client
                    _, csrf = self._local_admin()
                    _, receipt = self._registered_scanner(csrf, 'actual-pipeline')
                    ids = receipt['result']['allocated_ids']
                    connector, source = ids['connector_id'], ids['source_id']
                    headers = {**self.origin, 'X-CSRF-Token':csrf}
                    def view():
                        response = client.get(f'/api/v1/scanners/{connector}', params={'source_id':source})
                        self.assertEqual(response.status_code,200,response.text)
                        return response.json()
                    def command(action, **payload):
                        return {'schema_version':1,'command_id':str(uuid.uuid4()),'action':action,
                            'target_id':connector,'membership_ids':[], 'expected_revisions':view()['expected_revisions'],
                            'payload':{'source_id':source,'rationale':'Actual shared backend test',
                                'evidence_ref':'test:actual-pipeline', **payload}}
                    def post(body):
                        return client.post(f'/api/v1/scanners/{connector}/commands', json=body, headers=headers)
                    initial = view()
                    self.assertEqual(initial['credential']['revision'],0)
                    self.assertIsNone(initial['expected_revisions']['secret'])
                    saved = post(command('scanner.configuration.save', settings={'product':'qualys_vm',
                        'api_version':'2.0','platform_id':'us1','scope':{'kind':'account_visible'},'collection_mode':'manual'}))
                    self.assertEqual(saved.status_code,200,saved.text)
                    metadata = view()
                    # First upload uses ONLY public ScannerView fences/head revision.
                    vector = {**metadata['expected_revisions'], 'secret':metadata['credential']['revision']}
                    slot = metadata['credential']['secret_id']
                    uploaded = client.post(f'/api/v1/connectors/{connector}/secrets/{slot}/versions', json={
                        'schema_version':1,'submission_id':str(uuid.uuid4()),'version_id':str(uuid.uuid4()),
                        'source_id':source,'purpose':'qualys_vm_basic','expected_revisions':vector,
                        'rationale':'Actual encrypted upload','evidence_ref':'test:actual-crypto',
                        'input':{'kind':'value','value':json.dumps({'username':'synthetic-reader',
                            'password':'Synthetic scanner secret 7!'})}}, headers=headers)
                    self.assertEqual(uploaded.status_code,201,uploaded.text)
                    self.assertEqual(view()['credential']['revision'],metadata['credential']['revision']+1)
                    self.assertEqual(calls,[])
                    def version():
                        metadata = view()
                        return {'configuration_revision':metadata['configuration_revision'],
                            'credential_version_id':metadata['credential']['version_id']}
                    probed = post(command('scanner.connection.test',**version()))
                    self.assertEqual(probed.status_code,200,probed.text)
                    self.assertEqual(probed.json()['result']['status'],'succeeded')
                    self.assertEqual(len(calls),1)
                    activated = post(command('scanner.configuration.activate',**version(),
                        validation_operation_id=probed.json()['result']['operation_id']))
                    self.assertEqual(activated.status_code,200,activated.text)
                    self.assertEqual(len(calls),1)
                    if fail_publication:
                        with self.engine.begin() as c:
                            c.exec_driver_sql("""CREATE FUNCTION reject_final_publication_audit() RETURNS trigger LANGUAGE plpgsql AS $$
                                BEGIN IF NEW.origin='scanner_api' AND NEW.action='scanner.collection.start'
                                AND NEW.after_value->>'stage'='committed' THEN RAISE EXCEPTION 'injected final publication failure'; END IF; RETURN NEW; END $$""")
                            c.exec_driver_sql('CREATE TRIGGER reject_final_publication_audit BEFORE INSERT ON assessment_audit_events FOR EACH ROW EXECUTE FUNCTION reject_final_publication_audit()')
                    collected_command = command('scanner.collection.start',**version())
                    collected = post(collected_command)
                    self.assertEqual(len(calls),3)
                    self.assertTrue(all(correct for _,correct in calls))
                    replay = post(collected_command)
                    self.assertEqual(len(calls),3,'replay performed vendor HTTP')
                    if fail_publication:
                        self.assertEqual(collected.status_code,503,collected.text)
                        self.assertEqual(replay.status_code,200,replay.text)
                        operation = replay.json()
                        self.assertEqual(operation['status'],'interrupted')
                        run = operation['run_id']
                        self.assertEqual(client.get('/api/v1/ingestion/runs').json()['items'],[])
                        self.assertEqual(client.get('/api/v1/ingestion/runs/'+run).status_code,404)
                        self.assertEqual(client.get('/api/v1/unresolved').json()['items'],[])
                        self.assertEqual(client.get('/api/v1/assessment/groups').json()['items'],[])
                        with self.engine.connect() as c:
                            self.assertEqual(c.exec_driver_sql('select count(*) from collection_runs').scalar_one(),1)
                            self.assertEqual(c.exec_driver_sql('select count(*) from source_observations').scalar_one(),3)
                            self.assertEqual(c.exec_driver_sql('select count(*) from identity_resolutions').scalar_one(),3)
                            self.assertEqual(c.exec_driver_sql('select count(*) from qualys_vm_publications').scalar_one(),0)
                            gid = str(c.exec_driver_sql('select group_id from groups').scalar_one())
                        self.assertEqual(client.get('/api/v1/assessment/groups/'+gid).status_code,403)
                        denied = client.get(f'/api/v1/scanners/{connector}/runs/{run}/detections',params={'source_id':source})
                        self.assertEqual(denied.status_code,404,denied.text)
                    else:
                        self.assertEqual(collected.status_code,200,collected.text)
                        self.assertEqual(replay.json(),collected.json())
                        self.assertEqual(collected.json()['result']['status'],'succeeded')
                        run = collected.json()['result']['run_id']
                        page = client.get(f'/api/v1/scanners/{connector}/runs/{run}/detections', params={'source_id':source})
                        self.assertEqual(page.status_code,200,page.text)
                        data = page.json()
                        self.assertEqual(len(data['items']),3)
                        self.assertEqual(len({item['group_id'] for item in data['items']}),1)
                        self.assertEqual({item['qid'] for item in data['items']},{'1001'})
                        self.assertEqual(data['coverage']['status'],'unknown')
                        self.assertEqual(data['source_freshness']['status'],'unknown')
                        listing = client.get('/api/v1/ingestion/runs')
                        self.assertEqual(listing.status_code,200,listing.text)
                        self.assertEqual([row['run_id'] for row in listing.json()['items']],[run])
                        detail = client.get('/api/v1/ingestion/runs/'+run)
                        self.assertEqual(detail.status_code,200,detail.text)
                        self.assertEqual(len(detail.json()['observations']),3)
                        self.assertEqual(len(client.get('/api/v1/unresolved').json()['items']),3)
                        with self.engine.connect() as c:
                            for table in ('workloads','exposures','occurrences'):
                                self.assertEqual(c.exec_driver_sql(f'select count(*) from {table}').scalar_one(),0)
                        retained = {path.read_bytes() for path in self.scanner_pages.glob('*.xml')}
                        self.assertEqual(retained,{PAGE.replace(b'https://qualysapi.qualys.com',self.fixture_origin.encode()),LAST_PAGE})

    def test_actual_public_two_page_qualys_collection_and_shared_readback(self):
        self._actual_scanner_pipeline()

    def test_actual_final_audit_failure_hides_independent_qualys_checkpoints(self):
        self._actual_scanner_pipeline(fail_publication=True)


if __name__ == "__main__":
    unittest.main()
