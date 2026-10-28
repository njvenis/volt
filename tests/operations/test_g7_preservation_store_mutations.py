"""Regression probes mutate real local stores, never signed report outcomes."""
import hashlib
import importlib.util
import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import sqlalchemy as sa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi import HTTPException
from uvm.ingestion import CollectionScheduleV1
from uvm.ingestion.scheduled_collector import ScheduledCollector, ConfiguredFixtureClient, FixtureResponse, FileFixtureEvidenceSink
from uvm.persistence.ingestion_store import IngestionStore
from uvm.persistence.ingestion_schema import ingestion_evidence, collection_request_reservations
from uvm.persistence.assessment_schema import assessment_policy
from uvm.operations.preservation_streams import publish, namespace, INVENTORY, CONTROLLER, sign, replace_head

ROOT=Path(__file__).resolve().parents[2]

class PreservationStoreMutationTests(unittest.TestCase):
    def setUp(self):
        spec=importlib.util.spec_from_file_location('g7_mutation_fixture',ROOT/'tests/operations/test_g7_preservation_api.py')
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        self.fixture=module.PreservationApiTest();self.fixture.setUp();self.addCleanup(self.fixture.tearDown)
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name)
        self.now=datetime.now(timezone.utc)
        self.raw=json.dumps({'fixture_schema':'uvm.synthetic.fixture.v1','records':[],'next_cursor':None,'terminal':True}).encode()
        class Client(ConfiguredFixtureClient): source_family='synthetic'
        self.bytes=self.root/'bytes'
        self.sink=FileFixtureEvidenceSink(self.bytes)
        self.run=ScheduledCollector(IngestionStore(self.fixture.engine),
            CollectionScheduleV1('g7-store-mutation',1,*self.fixture.scope,max_attempts=1,max_page_attempts=1,
                total_deadline=timedelta(seconds=30)),Client({None:[FixtureResponse(self.raw,response_class='200',terminal=True)]}),
            clock=lambda:self.now,evidence_sink=self.sink).collect(self.now)

    def test_reservation_tamper_changes_the_canonical_scanner_inventory(self):
        from uvm.operations import preservation_source
        original=preservation_source._wire
        def sqlite_wire(value):
            return original(value.replace(tzinfo=timezone.utc) if isinstance(value,datetime) and value.tzinfo is None else value)
        def inventory():
            with self.fixture.engine.connect() as conn:
                return {item['stable_key']:item['record_sha256'] for item in preservation_source._scanner_members(conn,self.fixture.scope)[0]}
        with patch.object(preservation_source,'_wire',side_effect=sqlite_wire):
            before=inventory()
            with self.fixture.engine.begin() as conn:
                conn.execute(collection_request_reservations.update().values(request_identity_sha256='f'*64))
            after=inventory()
        self.assertEqual(set(before),set(after))
        self.assertTrue(any(before[key]!=after[key] for key in before))

    def test_joint_byte_and_registration_tamper_cannot_pass_independent_expectation(self):
        from uvm.api.app import create_app
        fixture=self.fixture
        with fixture.engine.begin() as conn:
            policy=conn.execute(sa.select(assessment_policy.c.document)).scalar_one()
            policy['native_authority']['access_groups']['group-a']['permissions'].append({
                'permission_id':'evidence','role_id':'role-a','action':'preservation.evidence.read',
                'target_scope':{'group_ids':['*']}})
            conn.execute(assessment_policy.update().values(document=policy))
            row=conn.execute(sa.select(ingestion_evidence).order_by(ingestion_evidence.c.run_revision)).mappings().first()
        trust=self.root/'trust';trust.mkdir(mode=0o755)
        key=Ed25519PrivateKey.generate();public=trust/'public.pem'
        public.write_bytes(key.public_key().public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo));public.chmod(0o644)
        member={'record_key':'evidence_registration:'+row['evidence_id'],'record_kind':'evidence_registration',
            'retained_at':self.now.isoformat().replace('+00:00','Z'),'state':'verified','reasons':[],
            'expected_sha256':row['sha256'],'actual_sha256':row['sha256'],'record_sha256':'a'*64,
            'byte_bearing':True,'evidence_id':row['evidence_id']}
        publish(trust,key,'synthetic',namespace('synthetic',INVENTORY,fixture.scope,'product.source_evidence'),
            {'complete':True,'members':[{'member':member,'byte_size':len(self.raw)}]})
        controller={'contract_id':'g7-data-preservation/v1','purpose':CONTROLLER,'deployment_id':'synthetic',
            'recovery_epoch':1,'storage_generation':'00000000-0000-4000-8000-000000000001','volume_set_digest':'b'*64,
            'key_valid_from':(self.now-timedelta(hours=1)).isoformat().replace('+00:00','Z'),
            'key_valid_until':(self.now+timedelta(hours=1)).isoformat().replace('+00:00','Z')}
        replace_head(trust/'controller.json',sign(controller,key,'synthetic'))
        env={'UVM_G7_PRESERVATION_TRUST_DIR':str(trust),'UVM_G7_PRESERVATION_PUBLIC_KEY_FILE':str(public),
            'UVM_G7_PRESERVATION_KEY_ID':'synthetic','UVM_G7_DEPLOYMENT_ID':'synthetic','UVM_G7_RECOVERY_EPOCH':'1',
            'UVM_G7_STORAGE_GENERATION':controller['storage_generation'],'UVM_G7_VOLUME_SET_DIGEST':'b'*64,
            'UVM_G7_SOURCE_EVIDENCE_ROOT':str(self.bytes)}
        app=create_app(fixture.engine,principals={},cursor_secret='synthetic-cursor-secret')
        endpoint=next(route.endpoint for route in app.routes if getattr(route,'path',None)=='/api/v1/operations/preservation/evidence/{evidence_id}')
        principal={'name':'alice','context':fixture.context,'scopes':(fixture.scope,)}
        with patch.dict(os.environ,env):
            self.assertEqual(endpoint(row['evidence_id'],principal=principal).body,self.raw)
            changed=b'jointly changed bytes';self.sink._path(row['evidence_ref']).write_bytes(changed)
            with fixture.engine.begin() as conn:
                conn.execute(ingestion_evidence.update().values(sha256=hashlib.sha256(changed).hexdigest(),byte_size=len(changed)))
            with self.assertRaises(HTTPException) as denied:endpoint(row['evidence_id'],principal=principal)
            self.assertEqual(denied.exception.status_code,409)
            self.assertEqual(denied.exception.detail['code'],'evidence_changed')
