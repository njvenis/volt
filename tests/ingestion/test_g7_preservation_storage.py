import hashlib
import os
import stat
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path


class FixtureEvidenceStorageTest(unittest.TestCase):
    def test_atomic_no_replace_publication_and_verified_read(self):
        from uvm.ingestion.scheduled_collector import FileFixtureEvidenceSink
        with tempfile.TemporaryDirectory() as directory:
            sink = FileFixtureEvidenceSink(directory)
            raw = b"synthetic received response"
            digest = hashlib.sha256(raw).hexdigest()
            sink.put("fixture/page/1", raw, digest)
            sink.put("fixture/page/1", raw, digest)
            path = sink._path("fixture/page/1")
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            self.assertEqual(path.read_bytes(), raw)
            self.assertEqual(sink.read("fixture/page/1", digest), raw)
            with self.assertRaises(ValueError):
                sink.put("fixture/page/1", b"different", hashlib.sha256(b"different").hexdigest())

    def test_symlinked_object_is_never_reused_or_read(self):
        from uvm.ingestion.scheduled_collector import FileFixtureEvidenceSink
        with tempfile.TemporaryDirectory() as directory:
            sink = FileFixtureEvidenceSink(directory)
            sink._path("fixture/page/1").symlink_to("/etc/passwd")
            raw = b"response"
            with self.assertRaises((OSError, ValueError)):
                sink.put("fixture/page/1", raw, hashlib.sha256(raw).hexdigest())
            with self.assertRaises(OSError):
                sink.read("fixture/page/1", hashlib.sha256(raw).hexdigest())

    def test_symlinked_root_is_rejected_without_changing_target_permissions(self):
        from uvm.ingestion.scheduled_collector import FileFixtureEvidenceSink
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "target"
            target.mkdir(mode=0o755)
            os.chmod(target, 0o755)
            link = Path(directory) / "evidence"
            link.symlink_to(target, target_is_directory=True)
            raw = b"response"
            with self.assertRaises(OSError):
                FileFixtureEvidenceSink(link).put("fixture/page/1", raw,
                    hashlib.sha256(raw).hexdigest())
            self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o755)


class ReservedTransportFailureTest(unittest.TestCase):
    def test_received_http_failure_is_checkpointed_with_real_bytes(self):
        import sqlalchemy as sa
        from uvm.ingestion import CollectionScheduleV1
        from uvm.ingestion.scheduled_collector import (FixtureResponse,
            MemoryFixtureEvidenceSink, ScheduledCollector)
        from uvm.persistence.ingestion_store import IngestionStore
        from uvm.persistence.schema import uvm_metadata

        class FailedHttpClient:
            source_family = "synthetic"
            def fetch(self, cursor):
                return FixtureResponse(b"synthetic 503 response", response_class="503",
                    error_code="upstream_unavailable", success=False)

        engine = sa.create_engine("sqlite://")
        uvm_metadata.create_all(engine)
        now = datetime(2026, 10, 28, 12, tzinfo=timezone.utc)
        schedule = CollectionScheduleV1("preservation-http-failure", 1, "synthetic",
            "account", "scope", max_attempts=1, max_page_attempts=1,
            total_deadline=timedelta(seconds=30))
        sink = MemoryFixtureEvidenceSink()
        store = IngestionStore(engine)
        run = ScheduledCollector(store, schedule, FailedHttpClient(),
            clock=lambda: now, evidence_sink=sink).collect(now)
        self.assertEqual(run.state, "partial")
        stored = store.read_run(run.run_id)
        self.assertEqual(stored["attempts"][0]["response_class"], "503")
        self.assertEqual(stored["attempts"][0]["error_code"], "upstream_unavailable")
        self.assertEqual(len(stored["pages"]), 1)
        page = stored["pages"][0]
        self.assertTrue(page["failed"])
        self.assertEqual(page["response_class"], "503")
        self.assertEqual(sink.read(page["page_ref"], page["evidence_digest"]),
            b"synthetic 503 response")
        self.assertEqual(len(store.read_request_reservations(run.run_id)), 1)
        self.assertEqual(stored["evidence"][0]["byte_size"], len(b"synthetic 503 response"))
        engine.dispose()

    def test_transport_exception_has_reservation_but_no_fabricated_response(self):
        import sqlalchemy as sa
        from uvm.ingestion import CollectionScheduleV1
        from uvm.ingestion.scheduled_collector import ScheduledCollector, MemoryFixtureEvidenceSink
        from uvm.persistence.ingestion_store import IngestionStore
        from uvm.persistence.schema import uvm_metadata

        class FailedClient:
            source_family = "synthetic"
            def fetch(self, cursor):
                raise OSError("secret scanner URL and response material must not be retained")

        engine = sa.create_engine("sqlite://")
        uvm_metadata.create_all(engine)
        now = datetime(2026, 10, 28, 12, tzinfo=timezone.utc)
        schedule = CollectionScheduleV1("preservation-test", 1, "synthetic", "account",
            "scope", max_attempts=1, max_page_attempts=1,
            total_deadline=timedelta(seconds=30))
        store = IngestionStore(engine)
        collector = ScheduledCollector(store, schedule, FailedClient(),
            clock=lambda: now, evidence_sink=MemoryFixtureEvidenceSink())
        run = collector.collect(now)
        self.assertEqual(run.state, "partial")
        stored = store.read_run(run.run_id)
        self.assertEqual(stored["attempts"][0]["response_class"], "transport_error")
        self.assertEqual(stored["attempts"][0]["error_code"], "other")
        self.assertEqual(stored["pages"], [])
        self.assertEqual(stored["evidence"], [])
        reservations = store.read_request_reservations(run.run_id)
        self.assertEqual(len(reservations), 1)
        self.assertEqual(reservations[0]["attempt_no"], 1)
        self.assertEqual(reservations[0]["page_ordinal"], 1)
        self.assertEqual(len(reservations[0]["request_identity_sha256"]), 64)
        self.assertNotIn("secret scanner URL", str(stored))
        engine.dispose()

    def test_interrupted_reserved_request_remains_running_without_invented_end_time(self):
        import sqlalchemy as sa
        from uvm.ingestion import CollectionScheduleV1
        from uvm.ingestion.scheduled_collector import ScheduledCollector, MemoryFixtureEvidenceSink
        from uvm.persistence.ingestion_store import IngestionStore
        from uvm.persistence.schema import uvm_metadata

        class InterruptedClient:
            source_family = "synthetic"
            def fetch(self, cursor):
                raise KeyboardInterrupt("simulated process interruption")

        engine = sa.create_engine("sqlite://")
        uvm_metadata.create_all(engine)
        now = datetime(2026, 10, 28, 12, tzinfo=timezone.utc)
        schedule = CollectionScheduleV1("interrupted-reservation", 1, "synthetic", "account",
            "scope", max_attempts=1, max_page_attempts=1,
            total_deadline=timedelta(seconds=30))
        store = IngestionStore(engine)
        collector = ScheduledCollector(store, schedule, InterruptedClient(),
            clock=lambda: now, evidence_sink=MemoryFixtureEvidenceSink())
        with self.assertRaises(KeyboardInterrupt):
            collector.collect(now)
        resumed = collector.collect(now)
        self.assertEqual(resumed.state, "running")
        self.assertIsNone(resumed.ended_at)
        self.assertEqual(resumed.attempts, [])
        self.assertEqual(len(store.read_request_reservations(resumed.run_id)), 1)
        engine.dispose()
