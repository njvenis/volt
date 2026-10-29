"""CR-09: a real scanner checkpoint rolls back when its audit insert fails."""
import unittest
from datetime import datetime, timedelta, timezone
import sqlalchemy as sa
from uvm.ingestion import CollectionScheduleV1
from uvm.ingestion.scheduled_collector import ScheduledCollector, MemoryFixtureEvidenceSink
from uvm.persistence.ingestion_store import IngestionStore
from uvm.persistence.schema import uvm_metadata
from uvm.persistence.assessment_schema import assessment_audit_events
from uvm.persistence.ingestion_schema import collection_runs, collection_request_reservations

class CheckpointAtomicityTests(unittest.TestCase):
    def test_audit_failure_rolls_back_checkpoint_and_reservation_before_request(self):
        engine = sa.create_engine('sqlite://')
        uvm_metadata.create_all(engine)
        calls = []
        class Client:
            source_family = 'synthetic'
            def fetch(self, cursor):
                calls.append(cursor)
                raise AssertionError('request must follow audited reservation')
        def fail_audit(conn, cursor, statement, parameters, context, many):
            if statement.startswith('INSERT INTO assessment_audit_events'):
                raise RuntimeError('injected audit failure')
        sa.event.listen(engine, 'before_cursor_execute', fail_audit)
        now = datetime.now(timezone.utc)
        schedule = CollectionScheduleV1('atomic-checkpoint', 1, 'synthetic', 'account',
            'scope', max_attempts=1, max_page_attempts=1, total_deadline=timedelta(seconds=30))
        with self.assertRaisesRegex(RuntimeError, 'injected audit failure'):
            ScheduledCollector(IngestionStore(engine), schedule, Client(), clock=lambda: now,
                evidence_sink=MemoryFixtureEvidenceSink()).collect(now)
        self.assertEqual(calls, [])
        with engine.connect() as conn:
            for table in (collection_runs, collection_request_reservations, assessment_audit_events):
                self.assertEqual(conn.execute(sa.select(sa.func.count()).select_from(table)).scalar_one(), 0)
        engine.dispose()
