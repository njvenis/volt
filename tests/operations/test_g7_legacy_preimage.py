"""Legacy input representation is retained independently; old anchors stay immutable."""
from contextlib import contextmanager
from datetime import datetime,timezone
from types import SimpleNamespace
import unittest
import uuid
from unittest.mock import patch
from uvm.audit_export.integrity import event_digest,legacy_event_digest,LegacyPreimageUnavailable
from uvm.audit_export.exporter import AuditExporter,_event_payload

class LegacyPreimageTests(unittest.TestCase):
    def setUp(self):
        self.event={'event_id':str(uuid.uuid4()),'event_sequence':1,'actor_id':'fixture','actor_kind':'human',
            'origin':'unit','action':'assessment.set','target_id':str(uuid.uuid4()),'before_value':{},'after_value':{},
            'membership_ids':[],'membership_revision':1,'rationale':'fixture','evidence_ref':'fixture',
            'policy_revision':1,'identity_revision':1,'occurred_at':datetime(2026,10,28,tzinfo=timezone.utc),
            'received_at':datetime(2026,10,28,tzinfo=timezone.utc),'correlation_id':str(uuid.uuid4()),
            'command_id':str(uuid.uuid4()),'authorization_context':None}
        self.metadata={'legacy_time_preimage':{field:{'kind':'datetime'} for field in ('occurred_at','received_at')}}

    def test_datetime_preimage_reconstructs_from_offset_strings_and_detects_actual_content_change(self):
        wire=_event_payload(self.event)
        original=event_digest(self.event,'g7-audit-anchor/v1')
        self.assertNotEqual(original,event_digest(wire,'g7-audit-anchor/v1'))
        wire['occurred_at']='2026-10-28T01:00:00+01:00'
        self.assertEqual(original,legacy_event_digest(wire,self.metadata))
        self.assertNotEqual(original,legacy_event_digest({**wire,'rationale':'changed'},self.metadata))
        self.assertEqual(event_digest(self.event,'g7-audit-anchor/v2'),event_digest(wire,'g7-audit-anchor/v2'))

    def test_string_preimage_requires_exact_safe_format_and_never_truncates_tampered_precision(self):
        wire=_event_payload(self.event)
        metadata={'legacy_time_preimage':{field:{'kind':'string','timespec':'seconds','offset_minutes':0,'zone':'offset'} for field in ('occurred_at','received_at')}}
        self.assertEqual(event_digest(wire,'g7-audit-anchor/v1'),legacy_event_digest(self.event,metadata))
        for missing in (None,{}, {'source_time_values':{'occurred_at':'string'}}):
            with self.subTest(metadata=missing),self.assertRaises(LegacyPreimageUnavailable):legacy_event_digest(wire,missing)
        with self.assertRaises(LegacyPreimageUnavailable):legacy_event_digest({**wire,'received_at':'2026-10-28T00:00:00.000001Z'},metadata)

    def test_exporter_uses_same_legacy_reconstruction_and_missing_metadata_does_not_mint_anomaly(self):
        incident=[]
        anchor={'contract_version':'g7-audit-anchor/v1','payload_sha256':event_digest(self.event,'g7-audit-anchor/v1'),
            'sink_receipt':'receipt','affected_scope':self.event['target_id']}
        class Lease:
            def get(self):return anchor
            def anomaly(self,*args):incident.append(args);return 'fixture-incident'
        class Anchors:
            @contextmanager
            def locked(self,*args):yield Lease()
        source=SimpleNamespace(get_sink_receipt=lambda *args:'receipt',preservation_legacy_metadata=lambda *args:self.metadata)
        exporter=AuditExporter('unused',source,anchor_authority=Anchors());wire=_event_payload(self.event)
        with patch.object(exporter,'_read_sink_record',return_value=wire):
            self.assertEqual(exporter._export_one(wire,'fixture'),'deduplicated')
        self.assertEqual(incident,[])
        source.preservation_legacy_metadata=lambda *args:None
        with patch.object(exporter,'_read_sink_record',return_value=wire),self.assertRaises(LegacyPreimageUnavailable):
            exporter._export_one(wire,'fixture')
        self.assertEqual(incident,[])
