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

        # SQLite fixtures discard datetime timezone metadata; isolate the
        # PostgreSQL timestamp adaptation here, outside production verification.
        from unittest.mock import patch
        from uvm.audit_export.integrity import event_digest
        def fixture_digest(event, version="g7-audit-anchor/v1"):
            event = dict(event)
            for field in ("occurred_at", "received_at"):
                if isinstance(event[field], datetime) and event[field].tzinfo is None:
                    event[field] = event[field].replace(tzinfo=timezone.utc)
            return event_digest(event, version)
        self.digest_patch = patch("uvm.audit_export.integrity.event_digest", side_effect=fixture_digest)
        self.digest_patch.start()
        self.addCleanup(self.digest_patch.stop)
        self.source = DeploymentAuditExportSource(self.engine, lambda: self.authorized.append(True))

    def tearDown(self):
        self.engine.dispose()

    def test_deployment_export_reads_all_targets_and_pages_monotonically(self):
        self.assertEqual(self.source.count_authorised_audit_events(), 2)
        first = self.source.list_authorised_audit_page(1)
        second = self.source.list_authorised_audit_page(1, int(first[0]["event_sequence"]))
        self.assertEqual([str(row["event_id"]) for row in first + second], self.events)
        self.assertEqual(len(self.authorized), 4)

    def test_v2_normalizes_source_and_export_timestamp_representations_without_rewriting_v1(self):
        from uvm.audit_export.integrity import event_digest
        from uvm.audit_export.exporter import _event_payload
        source = self.source.list_authorised_audit_page(1)[0]
        for field in ("occurred_at", "received_at"):
            source[field] = source[field].replace(tzinfo=timezone.utc)
        exported = _event_payload(source)
        self.assertNotEqual(event_digest(source, "g7-audit-anchor/v1"),
            event_digest(exported, "g7-audit-anchor/v1"))
        self.assertEqual(event_digest(source, "g7-audit-anchor/v2"),
            event_digest(exported, "g7-audit-anchor/v2"))

    def test_later_append_is_excluded_and_acknowledgement_context_cannot_be_forged(self):
        event_id = self.events[0]
        payload = self.source.list_authorised_audit_page(1)[0]
        binding = self.source.acknowledgement_binding(payload)
        with self.engine.begin() as connection:
            new = {**payload, "event_id": str(uuid.uuid4()), "event_sequence": 3}
            connection.execute(assessment_audit_events.insert().values(**new))
        self.assertEqual(self.source.count_authorised_audit_events(), 2)
        self.assertEqual([row["event_sequence"] for row in self.source.list_authorised_audit_page(10)], [1, 2])
        receipt = "postgres:uvm_audit_export.events:" + event_id
        for key, wrong in (("event_sequence", 2), ("payload_digest", "f" * 64),
                ("watermark", 3), ("context_id", "foreign")):
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.source.acknowledge_sink_export(event_id, "g7-siem", receipt,
                    datetime.now(timezone.utc), **{**binding, key: wrong})
        with self.engine.connect() as connection:
            self.assertEqual(connection.execute(sa.select(sa.func.count()).select_from(
                assessment_sink_export_receipts)).scalar_one(), 0)

    def test_deployment_receipt_is_idempotent_and_revalidated(self):
        event_id = self.events[0]
        receipt = "postgres:uvm_audit_export.events:" + event_id
        binding = self.source.acknowledgement_binding(self.source.list_authorised_audit_page(1)[0])
        now = datetime.now(timezone.utc)
        self.assertTrue(self.source.acknowledge_sink_export(event_id, "g7-siem", receipt, now, **binding))
        self.assertFalse(self.source.acknowledge_sink_export(event_id, "g7-siem", receipt, now, **binding))
        self.assertEqual(self.source.get_sink_receipt(event_id, "g7-siem"), receipt)
        self.assertEqual(self.source.sink_backlog_count("g7-siem"), 1)
        self.assertGreaterEqual(len(self.authorized), 5)
        with self.assertRaises(ValueError):
            self.source.acknowledge_sink_export(event_id, "g7-siem", "changed", now, **binding)


if __name__ == "__main__":
    unittest.main()
