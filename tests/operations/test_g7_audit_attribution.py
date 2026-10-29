"""Focused read-query coverage using isolated SQLite lineage projections."""
import copy
import unittest
import uuid
import sqlalchemy as sa
from tools.g7_container_audit_export import event_attribution,captured_attribution
from uvm.audit_export.integrity import event_digest

class AuditAttributionTests(unittest.TestCase):
    def setUp(self):
        self.engine=sa.create_engine('sqlite://');self.addCleanup(self.engine.dispose)
        meta=sa.MetaData();uid=sa.Uuid(as_uuid=False)
        self.groups=sa.Table('groups',meta,sa.Column('group_id',uid,primary_key=True))
        self.obs=sa.Table('source_observations',meta,sa.Column('observation_id',uid,primary_key=True),
            sa.Column('source_family',sa.String),sa.Column('source_account_id',sa.String),sa.Column('run_id',sa.String))
        self.links=sa.Table('identity_resolutions',meta,sa.Column('group_id',uid),
            sa.Column('observation_id',uid),sa.Column('occurrence_id',uid))
        self.runs=sa.Table('collection_runs',meta,sa.Column('run_id',sa.String),
            sa.Column('source_family',sa.String),sa.Column('source_account_id',sa.String),sa.Column('scope_key',sa.String))
        meta.create_all(self.engine)
        self.target=str(uuid.uuid4());self.occurrences=[];self.scope=('local','account','selected')
        with self.engine.begin() as c:
            c.execute(self.groups.insert().values(group_id=self.target))
            for scope in ('selected','other'):
                run_id=uuid.uuid4().hex;obs_id=str(uuid.uuid4());occ=str(uuid.uuid4());self.occurrences.append(occ)
                # SQLite UUID storage is hex; the production PostgreSQL UUID
                # cast renders dashed text. Keep this fixture adaptation local.
                c.execute(self.runs.insert().values(run_id=run_id,source_family='local',source_account_id='account',scope_key=scope))
                c.execute(self.obs.insert().values(observation_id=obs_id,source_family='local',source_account_id='account',run_id=run_id))
                c.execute(self.links.insert().values(group_id=self.target,observation_id=obs_id,occurrence_id=occ))
        self.event={'event_id':str(uuid.uuid4()),'event_sequence':1,'actor_id':'fixture','actor_kind':'human',
            'origin':'unit','action':'assessment.set','target_id':self.target,'before_value':{},'after_value':{},
            'membership_ids':[self.occurrences[0]],'membership_revision':1,'rationale':'fixture',
            'evidence_ref':'fixture','policy_revision':1,'identity_revision':1,'occurred_at':'2026-10-28T00:00:00Z',
            'received_at':'2026-10-28T00:00:00Z','correlation_id':str(uuid.uuid4()),'command_id':str(uuid.uuid4()),
            'authorization_context':None}

    def test_exact_event_membership_selects_scope_and_proven_foreign_scope_is_distinct(self):
        with self.engine.connect() as c:
            self.assertEqual(event_attribution(c,self.event,self.scope),{'kind':'source','target_id':self.target,'scope':list(self.scope)})
            foreign={**self.event,'membership_ids':[self.occurrences[1]]}
            self.assertEqual(event_attribution(c,foreign,self.scope)['kind'],'foreign_source')
            incomplete={**self.event,'membership_ids':[self.occurrences[0],str(uuid.uuid4())]}
            self.assertIsNone(event_attribution(c,incomplete,self.scope))
        with self.engine.begin() as c:c.execute(self.runs.delete())
        with self.engine.connect() as c:self.assertIsNone(event_attribution(c,self.event,self.scope))

    def test_lineage_loss_uses_only_unchanged_independently_admitted_event(self):
        target={'kind':'source','target_id':self.target,'scope':list(self.scope)}
        inventory={'audit_targets':[target],'members':[{'member':{'record_kind':'audit_event',
            'record_key':f"audit_event:{self.event['event_id']}:1",'canonicalization_version':'g7-audit-anchor/v2',
            'legacy_payload_sha256':event_digest(self.event,'g7-audit-anchor/v2')}}]}
        with self.engine.begin() as c:c.execute(self.links.delete());c.execute(self.groups.delete())
        with self.engine.connect() as c:self.assertIsNone(event_attribution(c,self.event,self.scope))
        self.assertEqual(captured_attribution(self.event,inventory,self.scope),target)
        changed=copy.deepcopy(self.event);changed['rationale']='tampered'
        self.assertIsNone(captured_attribution(changed,inventory,self.scope))
        self.assertIsNone(captured_attribution(self.event,None,self.scope))
