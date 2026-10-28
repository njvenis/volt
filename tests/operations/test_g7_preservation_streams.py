"""Independent membership and current-head regression coverage (synthetic)."""
import argparse
import copy
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from tools import g7_preservation_inventory as producer
from uvm.operations.preservation import CLASSES, canonical_json, load_report, unknown_class

class PreservationStreamTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        now = datetime.now(timezone.utc)
        wire = lambda dt: dt.isoformat().replace('+00:00', 'Z')
        self.scope = ('synthetic', 'account', 'scope')
        token = self.root/'token'; token.write_text('synthetic'); token.chmod(0o600)
        key_path = self.root/'key'; key = Ed25519PrivateKey.generate()
        key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption())); key_path.chmod(0o600)
        self.args = argparse.Namespace(token_file=str(token), signing_key_file=str(key_path),
            source_family=self.scope[0], source_account_id=self.scope[1], scope_key=self.scope[2],
            origin='http://unused.invalid', deployment_id='synthetic', storage_generation='00000000-0000-4000-8000-000000000001',
            audit_state_file=str(self.root/'audit'), audit_state_failure_reason='audit_scope_incomplete',
            recovery_epoch=1, environment='synthetic', freshness_seconds=300, previous_report=None,
            key_id='synthetic', metadata_output=None, report_dir=str(self.root/'reports-1'),
            trust_dir=str(self.root/'trust'), volume_set_digest='a'*64, schema_head_digest='c'*64,
            key_valid_from=wire(now-timedelta(hours=1)), key_valid_until=wire(now+timedelta(hours=1)),
            admit_new_members=True, provision_controller=True)
        self.snapshot = {'schema_version': 1, 'deployment_id': 'synthetic', 'scope': dict(zip(
            ('source_family','source_account_id','scope_key'), self.scope)),
            'storage_generation': self.args.storage_generation, 'recovery_epoch':1,'volume_set_digest':'a'*64, 'checked_at': wire(now-timedelta(seconds=1)),
            'source_watermark': {c:1 for c,_ in CLASSES}, 'schema_head_digest':'c'*64, 'classes': [
                {'class_id': c, 'complete': True, 'members': [
                    {'record_kind':'observation_linkage','stable_key':'one','record_sha256':'b'*64,
                     'raw_sha256':None,'byte_size':None,'evidence_id':None,'observed_at':wire(now-timedelta(days=1))}
                ] if c=='product.source_evidence' else []} for c,_ in CLASSES]}
        dto = unknown_class('product.audit_history','P1Y','baseline_missing')
        dto.update(baseline_digest='sha256:'+'e'*64,state='verified',reasons=[],expected_records=0,verified_records=0,missing_records=0,
            changed_records=0,unreadable_records=0,unexpected_records=0)
        dto['audit_copy'] = {k: ([] if k=='reasons' else 'verified' if k=='state' else
            self.snapshot['checked_at'] if k=='checked_at' else 0) for k in dto['audit_copy']}
        self.audit = {'schema_version':1,'class_id':'product.audit_history','audit_targets':[],
            'dto':dto,'members':[], 'context':{'deployment_id':'synthetic',
                'storage_generation':self.args.storage_generation,'recovery_epoch':1,
                'volume_set_digest':'a'*64,'scope':list(self.scope), 'source_watermark':0,
                'export_context_id':'d'*64,'sink_watermark':0,'anchor_watermark':0}}
        self.write_audit()
        self.env = {'UVM_G7_DEPLOYMENT_ID':'synthetic','UVM_G7_RECOVERY_EPOCH':'1',
            'UVM_G7_STORAGE_GENERATION': self.args.storage_generation,'UVM_G7_VOLUME_SET_DIGEST':'a'*64,
            'UVM_G7_PRESERVATION_PUBLIC_KEY_FILE':str(self.root/'trust/public.pem'),
            'UVM_G7_PRESERVATION_KEY_ID':'synthetic','UVM_G7_PRESERVATION_TRUST_DIR':self.args.trust_dir}

    def write_audit(self):
        path=Path(self.args.audit_state_file); path.write_text(json.dumps(self.audit)); path.chmod(0o600)

    def capture(self, number):
        self.args.report_dir=str(self.root/f'reports-{number}')
        with patch.object(producer,'_request', return_value=(200, canonical_json(self.snapshot), {})):
            return producer.capture(self.args)

    def read(self, number):
        with patch.dict(os.environ,{**self.env,'UVM_G7_PRESERVATION_REPORT_DIR':str(self.root/f'reports-{number}')},clear=False):
            return load_report(self.scope)

    def test_loss_does_not_shrink_expectation_and_old_report_is_rejected(self):
        first=self.capture(1)
        self.assertIsNotNone(self.read(1)[0])
        before={p: p.read_bytes() for p in (self.root/'trust').rglob('*') if p.is_file()}
        self.assertEqual(self.read(1)[0]['snapshot_id'],first['snapshot_id'])
        self.assertEqual(before,{p:p.read_bytes() for p in before})
        self.args.admit_new_members=False; self.args.provision_controller=False
        self.snapshot['classes'][0]['members']=[]
        self.capture(2)
        payload,reason=self.read(2); self.assertEqual(reason,'')
        source=payload['classes'][0]['dto']
        self.assertEqual((source['state'],source['expected_records'],source['missing_records']),('gap',1,1))
        self.assertEqual(self.read(1),(None,'baseline_untrusted'))

    def test_explicit_addition_preserves_prior_members_and_advances_capture_facts(self):
        from uvm.operations.preservation_streams import read_stream,namespace,INVENTORY
        self.capture(1)
        ns=namespace('synthetic',INVENTORY,self.scope,'product.source_evidence')
        before,_=read_stream(self.args.trust_dir,self.root/'trust/public.pem',ns)
        added=copy.deepcopy(self.snapshot['classes'][0]['members'][0]); added['stable_key']='two'
        self.snapshot['classes'][0]['members'].append(added)
        self.snapshot['checked_at']=(datetime.fromisoformat(self.snapshot['checked_at'].replace('Z','+00:00'))+timedelta(milliseconds=100)).isoformat().replace('+00:00','Z')
        self.snapshot['source_watermark']['product.source_evidence']=2
        self.capture(2)
        after,_=read_stream(self.args.trust_dir,self.root/'trust/public.pem',ns)
        self.assertEqual(after['content']['members'][:1],before['content']['members'])
        self.assertEqual(len(after['content']['members']),2)
        self.assertNotEqual(after['content']['capture_id'],before['content']['capture_id'])
        self.assertEqual(after['content']['captured_at'],self.snapshot['checked_at'])
        self.assertEqual(after['content']['source_watermark']['product.source_evidence'],2)
        self.args.admit_new_members=False;self.args.provision_controller=False
        self.snapshot['classes'][0]['members']=self.snapshot['classes'][0]['members'][1:]
        self.capture(3)
        dto=self.read(3)[0]['classes'][0]['dto']
        self.assertEqual((dto['expected_records'],dto['missing_records']),(2,1))

    def test_even_validly_signed_inventory_successor_cannot_shrink_history(self):
        from uvm.operations.preservation_streams import read_stream,namespace,INVENTORY,sign,digest,immutable,replace_head,publish
        self.capture(1)
        ns=namespace('synthetic',INVENTORY,self.scope,'product.source_evidence')
        before,old_digest=read_stream(self.args.trust_dir,self.root/'trust/public.pem',ns)
        content=copy.deepcopy(before['content']);content['members']=[]
        key=serialization.load_pem_private_key(Path(self.args.signing_key_file).read_bytes(),None)
        with self.assertRaisesRegex(ValueError,'inventory_history_removed_or_changed'):
            publish(self.root/'trust',key,self.args.key_id,ns,content)
        # Bypass the publisher to exercise the independent consumer itself.
        invalid=sign({**before,'sequence':before['sequence']+1,'predecessor':old_digest,'content':content},key,self.args.key_id)
        invalid_digest=digest(invalid)
        immutable(self.root/'trust/objects'/f'{invalid_digest}.json',invalid)
        replace_head(self.root/'trust/heads'/f'{digest(ns)}.json',{'sequence':before['sequence']+1,'digest':invalid_digest})
        with self.assertRaisesRegex(ValueError,'inventory_history_removed_or_changed'):
            read_stream(self.args.trust_dir,self.root/'trust/public.pem',ns)

    def test_explicit_controller_only_operation_does_not_capture_or_advance_class_heads(self):
        self.args.provision_controller_only=True
        with patch.object(producer,'_request',side_effect=AssertionError('controller-only must not read source')):
            result=producer.capture(self.args)
        self.assertEqual(result['source_reads'],0)
        self.assertFalse(result['inventory_or_report_heads_changed'])
        self.assertTrue((self.root/'trust/controller.json').is_file())
        self.assertFalse((self.root/'trust/heads').exists())

    def test_replacement_controller_is_provisioned_before_generation_bound_reads(self):
        self.capture(1)
        self.args.storage_generation='00000000-0000-4000-8000-000000000002'
        self.snapshot['storage_generation']=self.args.storage_generation
        self.audit['context']['storage_generation']=self.args.storage_generation; self.write_audit()
        self.args.admit_new_members=False
        self.args.report_dir=str(self.root/'reports-2')
        def source_read(*args, **kwargs):
            controller=json.loads((self.root/'trust/controller.json').read_text())['payload']
            self.assertEqual(controller['storage_generation'],self.args.storage_generation)
            return 200,canonical_json(self.snapshot),{}
        with patch.object(producer,'_request',side_effect=source_read):
            producer.capture(self.args)

    def test_future_report_is_rejected_by_both_consumers(self):
        from uvm.operations.preservation import tuple_digest
        from uvm.operations.preservation_streams import sign
        from uvm.operations.preservation_api import _find_snapshot
        result = self.capture(1)
        path = Path(self.args.report_dir) / (tuple_digest(self.scope) + ".json")
        document = json.loads(path.read_text())
        payload = document["payload"]
        payload["checked_at"] = "2999-01-01T00:00:00Z"
        key = serialization.load_pem_private_key(Path(self.args.signing_key_file).read_bytes(), None)
        invalid = canonical_json(sign(payload, key, self.args.key_id))
        path.write_bytes(invalid)
        for retained in (Path(self.args.report_dir)/"snapshots").glob("*.json"):
            retained.write_bytes(invalid)
        env = {**self.env, "UVM_G7_PRESERVATION_REPORT_DIR": self.args.report_dir}
        with patch.dict(os.environ, env, clear=False):
            self.assertEqual(load_report(self.scope), (None, "baseline_untrusted"))
            self.assertEqual(_find_snapshot(result["snapshot_id"]), (None, None))

    def test_metadata_remains_readable_to_separate_verifier_under_private_umask(self):
        import stat
        original_umask = os.umask(0o077)
        try:
            self.capture(1)
        finally:
            os.umask(original_umask)
        for directory in (Path(self.args.trust_dir), *(Path(self.args.trust_dir)/name for name in ("heads","pins","objects")),
                Path(self.args.report_dir)/"snapshots"):
            self.assertEqual(stat.S_IMODE(directory.stat().st_mode), 0o755, str(directory))
        for path in (Path(self.args.trust_dir)/"objects").glob("*.json"):
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o644)

    def test_unknown_legacy_result_keeps_actual_internal_check_time_without_public_partial_counts(self):
        self.capture(1)
        self.args.admit_new_members=False;self.args.provision_controller=False
        self.audit['dto']=unknown_class('product.audit_history','P1Y','legacy_preimage_unavailable')
        self.audit['context']['checked_at']=self.snapshot['checked_at'];self.write_audit()
        self.capture(2)
        payload,reason=self.read(2);self.assertEqual(reason,'')
        audit=payload['classes'][1]['dto']
        self.assertEqual(audit['state'],'unknown')
        self.assertEqual(audit['reasons'],['legacy_preimage_unavailable'])
        self.assertIsNone(audit['expected_records']);self.assertIsNone(audit['audit_copy']['checked_at'])

    def test_fresh_outer_context_cannot_retime_stale_audit_counts(self):
        self.capture(1)
        self.args.admit_new_members=False;self.args.provision_controller=False
        self.audit['context']['checked_at']=self.snapshot['checked_at']
        self.audit['dto']['audit_copy']['checked_at']='2000-01-01T00:00:00Z';self.write_audit()
        self.capture(2)
        dto=self.read(2)[0]['classes'][1]['dto']
        self.assertEqual(dto['state'],'unknown');self.assertIsNone(dto['expected_records'])

    def test_stale_foreign_audit_input_cannot_be_retimed(self):
        self.capture(1)
        self.args.admit_new_members=False; self.args.provision_controller=False
        self.audit['context']['deployment_id']='foreign'
        self.audit['dto']['audit_copy']['checked_at']='2000-01-01T00:00:00Z'; self.write_audit()
        self.capture(2)
        payload,_=self.read(2)
        audit=next(c['dto'] for c in payload['classes'] if c['class_id']=='product.audit_history')
        self.assertEqual(audit['state'],'unknown'); self.assertIsNone(audit['expected_records'])
