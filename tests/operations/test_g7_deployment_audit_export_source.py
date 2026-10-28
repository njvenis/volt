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

    def test_final_reconciliation_excludes_later_receipts_and_rejects_context_changes(self):
        payload=self.source.list_authorised_audit_page(1)[0]
        later=str(uuid.uuid4())
        with self.engine.begin() as c:
            c.execute(assessment_audit_events.insert().values(**{**payload,'event_id':later,'event_sequence':3}))
            for event_id in (self.events[0],later):
                c.execute(assessment_sink_export_receipts.insert().values(event_id=event_id,sink_id='g7-siem',
                    sink_receipt='receipt:'+event_id,acknowledged_at=datetime.now(timezone.utc)))
        with self.source.reconciliation_operation('g7-siem') as (connection,receipts):
            self.assertTrue(connection.in_transaction())
            self.assertEqual(receipts,{self.events[0]:'receipt:'+self.events[0]})
        self.source.authority_fingerprint='original-policy'
        self.source._authorize=lambda:'changed-policy'
        with self.assertRaises(PermissionError):
            with self.source.reconciliation_operation('g7-siem'):pass

    def test_actual_audit_state_consumer_keeps_captured_watermark_after_append(self):
        from tools import g7_container_audit_export as tool
        from unittest.mock import patch,MagicMock
        import contextlib,io,json,os,sys
        from uvm.audit_export.exporter import _event_payload
        original=self.source.list_authorised_audit_page
        def page(*args):
            rows=original(*args)
            for row in rows:
                for field in ('occurred_at','received_at'):row[field]=row[field].replace(tzinfo=timezone.utc)
            return rows
        self.source.list_authorised_audit_page=page
        rows=page(100)
        with self.engine.begin() as c:
            c.execute(assessment_audit_events.insert().values(**{**rows[0],'event_id':str(uuid.uuid4()),'event_sequence':3}))
        sink=MagicMock();sink.__enter__.return_value.execute.return_value.fetchall.return_value=[(row['event_id'],_event_payload(row)) for row in rows]
        authority=MagicMock();authority.inventory.return_value=[]
        output=io.StringIO()
        with patch.object(tool,'configure_source',return_value=self.source),patch('psycopg.connect',return_value=sink),patch(
                'uvm.audit_export.integrity.AuditAnchorAuthority',return_value=authority),patch.object(tool,'event_attribution',return_value={'kind':'deployment'}),patch.dict(
                os.environ,{'G7_SIEM_DSN':'offline','G7_AUDIT_ANCHOR_SIGNER_DSN':'offline','UVM_G7_RECOVERY_EPOCH':'1'}),patch.object(
                sys,'argv',['test','audit-state']),contextlib.redirect_stdout(output):
            self.assertEqual(tool.main(),0)
        result=json.loads(output.getvalue())
        self.assertEqual(result['context']['source_watermark'],2)
        self.assertEqual(result['dto']['audit_copy']['expected_events'],2)
        self.assertEqual(result['dto']['audit_copy']['pending_receipts'],2)
        self.assertEqual(sink.__enter__.return_value.execute.call_args.args[1],(2,[]))
        authority.inventory.assert_called_once_with('g7-siem',watermark=2,expected_event_ids=set())

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
