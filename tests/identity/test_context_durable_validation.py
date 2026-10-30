"""Invalid pinned context rejects before every actual retained-writer branch."""
from dataclasses import replace
from datetime import datetime, timedelta, timezone
import unittest
import uuid

import sqlalchemy as sa

import uvm.api.app  # register all metadata used by the actual writer
from uvm.identity import IdentityState, MissingField, RuleV1, resolve
from uvm.persistence.schema import uvm_metadata
from uvm.persistence.ingestion_schema import collection_runs
from uvm.persistence.observation_store import ObservationRepository
from uvm.persistence.identity_repository import IdentityRepository, AuthorisationDecision
from fixtures import make_observation


class DurableContextValidationTest(unittest.TestCase):
    def setUp(self):
        self.at = datetime(2026, 10, 30, 12, tzinfo=timezone.utc)
        self.engine = sa.create_engine('sqlite://')
        uvm_metadata.create_all(self.engine)
        def auth(action, target_id, context):
            return AuthorisationDecision(str(uuid.uuid4()), True, 'fixture', action,
                target_id, 'fixture', '1', 'context regression', 'synthetic',
                str(uuid.uuid4()), self.at, {})
        self.repository = IdentityRepository(self.engine, auth)
        self.rule = RuleV1('context-validation', 1, ('provisioning_key','service_key'),
            verified_asset_locator=True, workload_context_fields=('environment',))
        self.repository.provision_rule(self.rule, self.at)
        self.seed({'provisioning_key':'one','environment':'local'})
        self.seed({'service_key':'two','environment':'local'})

    def tearDown(self):
        self.engine.dispose()

    def retain(self, **changes):
        run = str(uuid.uuid4())
        source = make_observation(run_id=run, asset_locator='host-'+run,
            observed_at=self.at-timedelta(hours=2), collected_at=self.at-timedelta(hours=1), **changes)
        source = replace(source, missing_fields=tuple(m for m in source.missing_fields if m.field!='vulnerability_refs'))
        with self.engine.begin() as c:
            c.execute(collection_runs.insert().values(run_id=run, revision=1, schema_version=1,
                manual_origin='context-test', schedule_id='synthetic', schedule_revision=1,
                source_family=source.source_family, source_account_id=source.source_account_id,
                scope_key='all', state='completed', started_at=source.collected_at, ended_at=source.collected_at,
                retrieval_status='complete', retrieval_reasons=[], coverage_status='complete', coverage_reasons=[],
                freshness_status='fresh', freshness_reasons=[], facts_snapshot={}, provenance_snapshot={}, created_at=self.at))
        ObservationRepository(self.engine, clock=lambda:self.at).write_run(source.source_account_id, run, [(source,'created')])
        return source

    def seed(self, inputs):
        source = self.retain()
        return self.repository.resolve_retained(str(uuid.uuid4()), source.observation_id, 1, self.rule, inputs, self.at)

    def snapshot(self):
        with self.engine.connect() as c:
            return {table.name:[tuple(row) for row in c.execute(sa.select(table))]
                for table in uvm_metadata.sorted_tables}

    def test_rejects_invalid_present_context_without_graph_resolution_request_or_sla_effects(self):
        for branch, inputs, changes in [
            ('no-match-evidence', {}, {}),
            ('new-match', {'provisioning_key':'new'}, {}),
            ('matched', {'provisioning_key':'one'}, {}),
            ('ambiguous', {'provisioning_key':'one','service_key':'two'}, {}),
            ('missing-native', {'provisioning_key':'one'}, {'native_id_value':None}),
            ('missing-component', {'provisioning_key':'one'}, {'component_locator':None})]:
            for invalid in ('', '   ', '\t', None, 7, True):
                with self.subTest(branch=branch, invalid=invalid):
                    source = self.retain(**changes)
                    supplied={**inputs,'environment':invalid}
                    before=self.snapshot()
                    with self.assertRaises(ValueError):
                        self.repository.resolve_retained(str(uuid.uuid4()), source.observation_id, 1, self.rule, supplied, self.at)
                    self.assertEqual(before,self.snapshot())
                    state=IdentityState()
                    with self.assertRaises(ValueError):
                        resolve(state,source,self.rule,supplied,self.at)
                    self.assertEqual(state.__dict__,IdentityState().__dict__)

    def test_missing_valid_and_empty_context_legacy_semantics_remain(self):
        source=self.retain()
        result=self.repository.resolve_retained(str(uuid.uuid4()),source.observation_id,1,self.rule,{},self.at)
        self.assertEqual(result.outcome,'unresolved')
        legacy=RuleV1('legacy',1,('provisioning_key',),verified_asset_locator=True)
        self.repository.provision_rule(legacy,self.at)
        source=self.retain()
        result=self.repository.resolve_retained(str(uuid.uuid4()),source.observation_id,1,legacy,{'environment':'   '},self.at)
        self.assertEqual(result.outcome,'unresolved')
