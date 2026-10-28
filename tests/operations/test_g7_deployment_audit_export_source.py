from datetime import datetime, timezone
import unittest
import uuid

import sqlalchemy as sa

from uvm.assessment.audit_export import DeploymentAuditExportSource
from uvm.persistence.assessment_schema import assessment_audit_events, assessment_sink_export_receipts


class DeploymentAuditExportSourceTest(unittest.TestCase):
    def setUp(self):
        self.engine = sa.create_engine("sqlite:///:memory:")
        assessment_audit_events.create(self.engine)
        assessment_sink_export_receipts.create(self.engine)
        self.authorized = []
        self.source = DeploymentAuditExportSource(self.engine,
            lambda: self.authorized.append(True))
        self.events = [str(uuid.uuid4()), str(uuid.uuid4())]
        with self.engine.begin() as connection:
            for sequence, event_id in enumerate(self.events, 1):
                connection.execute(assessment_audit_events.insert().values(
                    event_id=event_id, event_sequence=sequence,
                    actor_id="fixture-actor", actor_kind="human", origin="test",
                    action="test.audit", target_id=str(uuid.uuid4()), before_value={}, after_value={},
                    membership_ids=[], membership_revision=1, rationale="fixture",
                    evidence_ref="fixture", policy_revision=1, identity_revision=1,
                    occurred_at=datetime.now(timezone.utc), received_at=datetime.now(timezone.utc),
                    correlation_id=str(uuid.uuid4()), command_id=str(uuid.uuid4()),
                    authorization_context=None))

    def tearDown(self):
        self.engine.dispose()

    def test_deployment_export_reads_all_targets_and_pages_monotonically(self):
        self.assertEqual(self.source.count_authorised_audit_events(), 2)
        first = self.source.list_authorised_audit_page(1)
        second = self.source.list_authorised_audit_page(1, int(first[0]["event_sequence"]))
        self.assertEqual([str(row["event_id"]) for row in first + second], self.events)
        self.assertEqual(len(self.authorized), 3)

    def test_deployment_receipt_is_idempotent_and_revalidated(self):
        event_id = self.events[0]
        receipt = "fixture:sink:" + event_id
        now = datetime.now(timezone.utc)
        self.assertTrue(self.source.acknowledge_sink_export(event_id, "g7-siem", receipt, now))
        self.assertFalse(self.source.acknowledge_sink_export(event_id, "g7-siem", receipt, now))
        self.assertEqual(self.source.get_sink_receipt(event_id, "g7-siem"), receipt)
        self.assertEqual(self.source.sink_backlog_count("g7-siem"), 1)
        self.assertEqual(len(self.authorized), 4)
        with self.assertRaises(ValueError):
            self.source.acknowledge_sink_export(event_id, "g7-siem", "changed", now)
        self.assertEqual(len(self.authorized), 5)


if __name__ == "__main__":
    unittest.main()
