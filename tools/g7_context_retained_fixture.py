"""Bounded retained-input context matrix for the disposable public journey."""
from datetime import timedelta
import hashlib
import json
import uuid

import sqlalchemy as sa

from uvm.identity import MissingField, RuleV1, SourceObservationV1
from uvm.persistence.identity_repository import AuthorisationDecision, IdentityRepository
from uvm.persistence.observation_store import ObservationRepository
from uvm.persistence.ingestion_schema import collection_runs
from uvm.persistence.schema import groups, workloads, incarnations, exposures, occurrences
from uvm.persistence.lineage_schema import identity_resolutions, identity_resolution_requests
from uvm.persistence.exception_sla_schema import sla_ingest_receipts, sla_episode_contracts, sla_clock_events
from uvm.persistence.metrics_schema import g7_sla_evaluations


def context_matrix(engine, now):
    def auth(action, target_id, context):
        return AuthorisationDecision(str(uuid.uuid4()), True, 'g7-fixture', action,
            target_id, 'fixture', '1', 'Synthetic context matrix', 'synthetic:context',
            str(uuid.uuid4()), now, {})
    repository = IdentityRepository(engine, auth)
    rule = RuleV1('g7-context-matrix', 1, ('provisioning_key',),
        verified_asset_locator=True, workload_context_fields=('environment', 'service_id', 'unused'))
    repository.provision_rule(rule, now)

    def retain(label, key, context, host=None, native='exception-sla-ingestion-v1', **changes):
        run_id, observation_id, request_id = (str(uuid.uuid4()) for _ in range(3))
        observed, collected = now-timedelta(seconds=2), now-timedelta(seconds=1)
        with engine.begin() as c:
            c.execute(collection_runs.insert().values(run_id=run_id, revision=1, schema_version=1,
                manual_origin='synthetic-context-matrix', schedule_id='synthetic', schedule_revision=1,
                source_family='local', source_account_id='g7-local', scope_key='all', state='completed',
                started_at=collected, ended_at=collected, retrieval_status='complete', retrieval_reasons=[],
                coverage_status='complete', coverage_reasons=[], freshness_status='fresh', freshness_reasons=[],
                facts_snapshot={}, provenance_snapshot={}, created_at=now))
        source = SourceObservationV1(schema_version=1, observation_id=observation_id, revision=1,
            source_family='local', source_account_id='g7-local', run_id=run_id, source_record_ordinal=0,
            collection_status='success', observed_at=observed, collected_at=collected,
            raw_evidence_ref='synthetic:'+label, raw_evidence_sha256=hashlib.sha256(label.encode()).hexdigest(),
            missing_fields=tuple(MissingField(f, 'not_applicable') for f in (
                'source_record_locator', 'source_first_seen_at', 'report_id', 'coverage_scope')),
            native_id_scheme='fixture', native_id_authority='g7-local', native_id_value=native,
            asset_locator=host or 'context-host-'+label, component_locator='context-component',
            source_rating='low', vulnerability_refs=('CVE-2099-0010',), **changes)
        ObservationRepository(engine, clock=lambda: now).write_run('g7-local', run_id, [(source, 'created')])
        inputs={**({'provisioning_key':key} if key else {}), **context}
        return source, request_id, inputs

    def resolve(label, key, context, **kwargs):
        source, request, inputs = retain(label, key, context, **kwargs)
        result = repository.resolve_retained(request, source.observation_id, 1, rule, inputs, now)
        with engine.connect() as c:
            attrs = c.execute(sa.select(workloads.c.stable_attrs).where(workloads.c.workload_id==result.workload_id)).scalar_one_or_none()
            receipt = c.execute(sa.select(sla_ingest_receipts).where(sla_ingest_receipts.c.occurrence_id==result.occurrence_id)).mappings().first() if result.occurrence_id else None
            contract = c.execute(sa.select(sla_episode_contracts).where(sla_episode_contracts.c.episode_id==receipt['episode_id'])).mappings().one() if receipt else None
            head = c.execute(sa.select(g7_sla_evaluations).where(g7_sla_evaluations.c.occurrence_id==result.occurrence_id,
                g7_sla_evaluations.c.is_authoritative.is_(True)).order_by(g7_sla_evaluations.c.revision.desc())).mappings().first() if result.occurrence_id else None
        return {'label':label, 'request_id':request, 'observation_id':source.observation_id,
            'inputs':inputs, 'rule':{'id':rule.rule_id, 'version':1, 'context':list(rule.workload_context_fields)},
            'outcome':result.outcome, 'reason':result.reason, 'group_id':result.group_id,
            'occurrence_id':result.occurrence_id, 'workload_id':result.workload_id, 'attrs':attrs,
            'receipt':dict(receipt) if receipt else None, 'contract':dict(contract) if contract else None,
            'head':dict(head) if head else None}

    out={}
    out['missing_environment']=resolve('missing-environment', 'context-missing-env', {'service_id':'g7-sla-service-covered'})
    out['later_environment_not_admitted']=resolve('later-environment', 'context-missing-env', {'environment':'local','service_id':'g7-sla-service-covered'})
    out['missing_service']=resolve('missing-service', 'context-missing-service', {'environment':'local'})
    out['later_service_not_admitted']=resolve('later-service', 'context-missing-service', {'environment':'local','service_id':'g7-sla-service-covered'})
    out['optional_unused_absent']=resolve('known', 'context-known', {'environment':'local','service_id':'g7-sla-service-covered'}, host='context-known')
    out['omitted_followup']=resolve('omitted', 'context-known', {}, host='context-known')
    out['conflicting_followup']=resolve('conflict', 'context-known', {'environment':'other'}, host='context-conflict', native='context-conflict-new-native')
    # Read the same known atom after both followups, without adding a source row.
    with engine.connect() as c:
        known=out['optional_unused_absent']
        head=c.execute(sa.select(g7_sla_evaluations).where(g7_sla_evaluations.c.occurrence_id==known['occurrence_id'],
            g7_sla_evaluations.c.is_authoritative.is_(True)).order_by(g7_sla_evaluations.c.revision.desc())).mappings().one()
        out['known_head_after_followups']=dict(head)
    if out['conflicting_followup']['outcome']!='unresolved' or out['conflicting_followup']['occurrence_id'] is not None:
        raise RuntimeError('context conflict was admitted')
    if out['known_head_after_followups'] != out['optional_unused_absent']['head']:
        raise RuntimeError('followup changed an admitted known clock/head')
    for name in ('later_environment_not_admitted','later_service_not_admitted'):
        missing='environment' if 'environment' in name else 'service_id'
        if missing in out[name]['attrs']:
            raise RuntimeError('later context enriched a retained missing selector')
    return json.loads(json.dumps(out, default=lambda value: value.isoformat()))
