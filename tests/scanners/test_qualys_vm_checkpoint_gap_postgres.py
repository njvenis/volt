"""PostgreSQL proof for observation-commit/checkpoint-gap replay semantics."""
from __future__ import annotations

import os
import unittest
import uuid
from datetime import datetime, timezone
import tempfile

import sqlalchemy as sa

import uvm.api.app  # registers retained observation tables in shared metadata
from uvm.persistence.observation_store import ObservationRepository
from uvm.scanners.evidence import PrivateEvidenceStore
from uvm.scanners.qualys_vm import (QualysPage, observations_for_page, parse_page)
from uvm.scanners.store import (OperationAdmission, admit, advance_finalization,
    finish_attempt, interrupt_running, read_operation, record_page, reserve_attempt,
    reconcile_interrupted_finalization, attempts)

PG_URL = os.environ.get("UVM_TEST_PG_URL")
XML = b'''<HOST_LIST_VM_DETECTION_OUTPUT><RESPONSE><HOST_LIST><HOST><ID>42</ID>
<DETECTION_LIST><DETECTION><QID>1001</QID><TYPE>Confirmed</TYPE><SEVERITY>4</SEVERITY>
<STATUS>Active</STATUS><PORT>443</PORT><PROTOCOL>tcp</PROTOCOL><SSL>1</SSL>
<UNIQUE_VULN_ID>candidate</UNIQUE_VULN_ID><LAST_FOUND_DATETIME>2026-01-02T00:00:00Z</LAST_FOUND_DATETIME>
</DETECTION></DETECTION_LIST></HOST></HOST_LIST></RESPONSE></HOST_LIST_VM_DETECTION_OUTPUT>'''


@unittest.skipUnless(PG_URL, "UVM_TEST_PG_URL must target disposable migrated PostgreSQL")
class QualysCheckpointGapPostgresTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.engine = sa.create_engine(PG_URL)
        cls.observations = ObservationRepository(cls.engine)

    @classmethod
    def tearDownClass(cls):
        cls.engine.dispose()

    def setUp(self):
        self.connector_id, self.source_id = str(uuid.uuid4()), str(uuid.uuid4())
        self.run_id = str(uuid.uuid4())
        self.now = datetime.now(timezone.utc)
        with self.engine.begin() as connection:
            connection.execute(sa.text("""
                INSERT INTO g7_connectors (connector_id, source_id, source_family,
                    source_account_id, scope_key, source_revision, secret_source_id,
                    secret_source_revision, connector_revision, configuration_revision,
                    active_configuration_revision, last_activated_authentication_mode,
                    lifecycle, validation, recovery, environment_label, updated_at)
                VALUES (:connector, :source, 'qualys', 'account', 'account_visible',
                    1, NULL, 0, 1, 1, 1, NULL, 'active', '{}'::jsonb, '{}'::jsonb,
                    'gap-test', now())
            """), {"connector": self.connector_id, "source": self.source_id})

    def tearDown(self):
        with self.engine.begin() as connection:
            connection.execute(sa.text("DELETE FROM g7_connectors WHERE connector_id=:id"),
                {"id": self.connector_id})

    def test_observation_commit_before_checkpoint_replays_locally_without_http(self):
        command = str(uuid.uuid4())
        version = str(uuid.uuid4())
        request_digest = "a" * 64
        request_identity = "b" * 64
        parsed = parse_page(XML)
        page = QualysPage(1, "fixture://test", XML, parsed)
        with tempfile.TemporaryDirectory() as directory:
            evidence_store = PrivateEvidenceStore(directory)
            evidence = evidence_store.write(XML)
            observations = observations_for_page(page, source_account_id="account",
                account_authority_id="generated-account-authority", run_id=self.run_id,
                collected_at=self.now, evidence_ref=evidence.ref,
                evidence_sha256=evidence.sha256)
            operation_request = OperationAdmission(self.connector_id, self.source_id,
                command, "actor", "collect", request_digest, 1, version,
                str(uuid.uuid4()), self.run_id)
            with self.engine.begin() as connection:
                operation, replay = admit(connection, operation_request, now=self.now)
                self.assertFalse(replay)
                attempt = reserve_attempt(connection, operation["operation_id"],
                    page_ordinal=1, request_identity_sha256=request_identity, now=self.now)
                finish_attempt(connection, operation["operation_id"], attempt,
                    response_class="success", success=True, http_status=200, now=self.now)
                record_page(connection, operation["operation_id"], page_ordinal=1,
                    request_identity_sha256=request_identity,
                    continuation_sha256=None, evidence_ref=evidence.ref,
                    response_sha256=evidence.sha256, byte_count=evidence.size,
                    host_count=parsed.host_count,
                    detection_count=len(parsed.detections), attempt_count=1, now=self.now)
                advance_finalization(connection, operation["operation_id"], "evidence")

            # The real retained-observation writer commits independently. Simulate
            # process loss before the operation can record its next checkpoint.
            first_write = self.observations.write_run("account", self.run_id,
                [(observations[0], "created")])
            self.assertEqual(first_write.status, "created")
            with self.engine.begin() as connection:
                self.assertEqual(interrupt_running(connection, now=self.now), 1)

            # Restart recovery is local-only: exact repository resend is duplicate,
            # the in-flight HTTP attempt count is unchanged, and the status remains
            # interrupted. No provider request is reissued.
            replay_write = self.observations.write_run("account", self.run_id,
                [(observations[0], "created")])
            self.assertEqual(replay_write.status, "duplicate")
            with self.engine.begin() as connection:
                reconcile_interrupted_finalization(connection,
                    operation["operation_id"], "observations")
                replay, is_replay = admit(connection, operation_request, now=self.now)
                self.assertTrue(is_replay)
                self.assertEqual(replay["status"], "interrupted")
                count = connection.execute(sa.select(sa.func.count()).select_from(
                    attempts).where(attempts.c.operation_id == operation["operation_id"])).scalar_one()
                self.assertEqual(count, 1)
            retained = self.observations.read_run("account", self.run_id)
            self.assertEqual(len(retained.rows), 1)
            with self.engine.connect() as connection:
                stored = read_operation(connection, operation["operation_id"])
            self.assertEqual(stored["status"], "interrupted")
            self.assertEqual(stored["finalization_stage"], "observations")


if __name__ == "__main__":
    unittest.main()
