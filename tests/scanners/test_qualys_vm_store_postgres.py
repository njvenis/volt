"""Committed PostgreSQL tests for the additive 0066 operation ledger.

Run after `alembic upgrade head` with UVM_TEST_PG_URL set. Tests commit state,
reopen connections to simulate process restart, and contain no SQLite fallback.
"""
from __future__ import annotations

import os
import threading
import unittest
import uuid
from datetime import datetime, timezone

import sqlalchemy as sa

from uvm.scanners.store import (OperationAdmission, OperationError, admit,
    advance_finalization, finish, finish_attempt, interrupt_running,
    read_operation, record_page, reserve_attempt, attempts, pages)

PG_URL = os.environ.get("UVM_TEST_PG_URL")


@unittest.skipUnless(PG_URL, "UVM_TEST_PG_URL must target disposable migrated PostgreSQL")
class QualysOperationPostgresTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.engine = sa.create_engine(PG_URL)

    @classmethod
    def tearDownClass(cls):
        cls.engine.dispose()

    def setUp(self):
        self.connector_id, self.source_id = str(uuid.uuid4()), str(uuid.uuid4())
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
                    'postgres-test', now())
            """), {"connector": self.connector_id, "source": self.source_id})

    def tearDown(self):
        with self.engine.begin() as connection:
            connection.execute(sa.text("DELETE FROM g7_connectors WHERE connector_id=:id"),
                {"id": self.connector_id})

    def request(self, *, command_id=None, action="collect", principal="actor-a", digest=None):
        return OperationAdmission(self.connector_id, self.source_id,
            command_id or str(uuid.uuid4()), principal, action,
            digest or "a" * 64, 1, str(uuid.uuid4()), str(uuid.uuid4()),
            str(uuid.uuid4()) if action == "collect" else None)

    def test_admission_page_and_finalization_survive_commits_and_connections(self):
        request = self.request()
        with self.engine.begin() as connection:
            row, replayed = admit(connection, request, now=self.now)
            self.assertFalse(replayed)
        with self.engine.begin() as connection:
            replay, replayed = admit(connection, request, now=self.now)
            self.assertTrue(replayed)
            self.assertEqual(replay["operation_id"], row["operation_id"])
            with self.assertRaisesRegex(OperationError, "command_id_reused"):
                admit(connection, self.request(command_id=request.command_id,
                    principal="actor-b"), now=self.now)

        request_digest = "b" * 64
        with self.engine.begin() as connection:
            attempt = reserve_attempt(connection, row["operation_id"],
                page_ordinal=1, request_identity_sha256=request_digest, now=self.now)
            finish_attempt(connection, row["operation_id"], attempt,
                response_class="success", success=True, http_status=200, now=self.now)
            record_page(connection, row["operation_id"], page_ordinal=1,
                request_identity_sha256=request_digest, continuation_sha256="c" * 64,
                evidence_ref="qualys-page-v1/" + "d" * 32,
                response_sha256="e" * 64, byte_count=128, host_count=2,
                detection_count=3, attempt_count=1, now=self.now)
        # Exact page and stage replay is safe after reconnect.
        with self.engine.begin() as connection:
            record_page(connection, row["operation_id"], page_ordinal=1,
                request_identity_sha256=request_digest, continuation_sha256="c" * 64,
                evidence_ref="qualys-page-v1/" + "d" * 32,
                response_sha256="e" * 64, byte_count=128, host_count=2,
                detection_count=3, attempt_count=1, now=self.now)
            with self.assertRaisesRegex(OperationError, "page_replay_conflict"):
                record_page(connection, row["operation_id"], page_ordinal=1,
                    request_identity_sha256=request_digest, continuation_sha256="c" * 64,
                    evidence_ref="qualys-page-v1/" + "d" * 32,
                    response_sha256="f" * 64, byte_count=128, host_count=2,
                    detection_count=3, attempt_count=1, now=self.now)
            advance_finalization(connection, row["operation_id"], "evidence")
        with self.engine.begin() as connection:
            advance_finalization(connection, row["operation_id"], "evidence")
            for stage in ("observations", "resolution", "published"):
                advance_finalization(connection, row["operation_id"], stage)
            finish(connection, row["operation_id"], status="succeeded", now=self.now)
        with self.engine.connect() as connection:
            stored = read_operation(connection, row["operation_id"])
            page_rows = connection.execute(sa.select(pages).where(
                pages.c.operation_id == row["operation_id"])).mappings().all()
            attempt_rows = connection.execute(sa.select(attempts).where(
                attempts.c.operation_id == row["operation_id"])).mappings().all()
        self.assertEqual(stored["status"], "succeeded")
        self.assertEqual(stored["finalization_stage"], "published")
        self.assertEqual(len(page_rows), 1)
        self.assertEqual(len(attempt_rows), 1)

    def test_process_restart_marks_reserved_attempt_and_replay_sends_no_new_request(self):
        request = self.request()
        with self.engine.begin() as connection:
            operation, _ = admit(connection, request, now=self.now)
            reserve_attempt(connection, operation["operation_id"], page_ordinal=1,
                request_identity_sha256="f" * 64, now=self.now)
        with self.engine.begin() as connection:
            n = interrupt_running(connection, now=self.now)
            self.assertEqual(n, 1)
        with self.engine.begin() as connection:
            replay, was_replay = admit(connection, request, now=self.now)
            self.assertTrue(was_replay)
            self.assertEqual(replay["status"], "interrupted")
            stored_attempt = connection.execute(sa.select(attempts).where(
                attempts.c.operation_id == operation["operation_id"])).mappings().one()
            self.assertEqual(stored_attempt["error_code"], "process_interrupted")
            self.assertFalse(stored_attempt["success"])
            self.assertEqual(stored_attempt["attempt_no"], 1)
            retry, was_replay = admit(connection, self.request(), now=self.now)
            self.assertFalse(was_replay)
            self.assertNotEqual(retry["operation_id"], operation["operation_id"])

    def test_committed_concurrent_admission_allows_only_one_running_operation(self):
        barrier = threading.Barrier(2)
        outcomes = []
        lock = threading.Lock()
        def contender():
            request = self.request()
            barrier.wait(timeout=5)
            try:
                with self.engine.begin() as connection:
                    operation, _ = admit(connection, request, now=self.now)
                result = ("admitted", operation["operation_id"])
            except OperationError as exc:
                result = (exc.code, None)
            with lock:
                outcomes.append(result)
        threads = [threading.Thread(target=contender) for _ in range(2)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=10)
        self.assertTrue(all(not thread.is_alive() for thread in threads))
        self.assertEqual(sum(status == "admitted" for status, _ in outcomes), 1)
        self.assertEqual(sum(status == "operation_in_progress" for status, _ in outcomes), 1)

    def test_test_operation_may_succeed_without_collection_publication(self):
        with self.engine.begin() as connection:
            row, _ = admit(connection, self.request(action="test"), now=self.now)
            finish(connection, row["operation_id"], status="succeeded", now=self.now)
        with self.engine.connect() as connection:
            self.assertEqual(read_operation(connection, row["operation_id"])["status"], "succeeded")


if __name__ == "__main__":
    unittest.main()
