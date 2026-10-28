"""Synthetic retained UVM sentinel, written only in the disposable UVM database."""
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import uuid
import sqlalchemy as sa
from uvm.persistence.schema import groups, workloads, incarnations, exposures, occurrences
from uvm.persistence.observation_schema import source_observations
from uvm.persistence.ingestion_schema import collection_runs
from uvm.persistence.assessment_schema import (assessment_group_state,
    assessment_audit_events, assessment_projection_intents, assessment_command_receipts)
from uvm.persistence.g4_schema import github_repositories, github_group_issues


def seed(engine):
    ids = {name: str(uuid.uuid5(uuid.NAMESPACE_URL, 'volt:g7:recovery-fixture:' + name))
        for name in ('group', 'workload', 'incarnation', 'exposure', 'occurrence',
            'run', 'observation', 'event', 'command', 'decision', 'intent')}
    now = datetime.now(timezone.utc)
    assessed = {'value': 'high', 'actor_id': 'g7-actor', 'rationale': 'Synthetic retained recovery decision',
        'updated_at': now.isoformat().replace('+00:00', 'Z'), 'evidence_ref': 'g7-recovery-fixture'}
    with engine.begin() as c:
        c.execute(groups.insert().values(group_id=ids['group'], source_family='local',
            native_id_scheme='fixture', native_id_authority='g7-local',
            native_id_value='recovery-sentinel-v1', revision=1, created_at=now))
        c.execute(workloads.insert().values(workload_id=ids['workload'], stable_attrs={'environment': 'local'}, revision=1, created_at=now))
        c.execute(incarnations.insert().values(incarnation_id=ids['incarnation'], workload_id=ids['workload'], host_locator='synthetic-recovery-host', first_observed_at=now, revision=1, created_at=now))
        c.execute(exposures.insert().values(exposure_id=ids['exposure'], group_id=ids['group'], workload_id=ids['workload'], first_observed_at=now, revision=1, created_at=now))
        c.execute(occurrences.insert().values(occurrence_id=ids['occurrence'], exposure_id=ids['exposure'], incarnation_id=ids['incarnation'], workload_id=ids['workload'], component_locator='synthetic-component', first_observed_at=now, first_ingested_at=now, revision=1, created_at=now))
        c.execute(collection_runs.insert().values(run_id=ids['run'], revision=1, schema_version=1,
            manual_origin='g7-recovery-fixture', schedule_id='synthetic', schedule_revision=1,
            source_family='local', source_account_id='g7-local', scope_key='all', state='completed',
            started_at=now, ended_at=now, retrieval_status='complete', retrieval_reasons=[],
            coverage_status='complete', coverage_reasons=[], freshness_status='fresh', freshness_reasons=[],
            facts_snapshot={}, provenance_snapshot={'environment': 'synthetic-local'}, created_at=now))
        c.execute(source_observations.insert().values(schema_version=1, observation_id=ids['observation'], revision=1,
            source_family='local', source_account_id='g7-local', run_id=ids['run'], source_record_ordinal=0,
            collection_status='success', observed_at=now, collected_at=now,
            raw_evidence_ref='synthetic:g7-recovery-sentinel', raw_evidence_sha256='a'*64,
            missing_fields=[], retention_order=1, ingest_outcome='created', occurrence_id=ids['occurrence'], source_rating='low'))
        c.execute(assessment_group_state.insert().values(group_id=ids['group'], revision=2,
            document={'assessed_severity': assessed}, updated_at=now))
        sequence = c.execute(sa.select(sa.func.coalesce(sa.func.max(assessment_audit_events.c.event_sequence), 0) + 1)).scalar_one()
        c.execute(assessment_audit_events.insert().values(event_id=ids['event'], event_sequence=sequence,
            actor_id='g7-actor', actor_kind='principal', origin='synthetic_recovery_fixture', action='severity.override',
            target_id=ids['group'], before_value={}, after_value={'assessed_severity': assessed},
            membership_ids=[ids['occurrence']], membership_revision=1, rationale=assessed['rationale'],
            evidence_ref='g7-recovery-fixture', policy_revision=1, identity_revision=1,
            occurred_at=now, received_at=now, correlation_id=ids['command'], command_id=ids['command']))
        c.execute(assessment_projection_intents.insert().values(intent_id=ids['intent'], event_id=ids['event'],
            target_id=ids['group'], membership_ids=[ids['occurrence']], status='uncertain', created_at=now))
        c.execute(assessment_command_receipts.insert().values(command_id=ids['command'], principal_id='g7-actor',
            action='severity.override', target_id=ids['group'], request_digest='b'*64, decision_id=ids['decision'],
            audit_event_id=ids['event'], intent_id=ids['intent'],
            result={'command_id': ids['command'], 'decision_id': ids['decision'], 'audit_event_id': ids['event'], 'outcome': 'committed'}, created_at=now))
        c.execute(github_repositories.insert().values(repository_id='synthetic-recovery-repo', github_host='github.example.invalid',
            owner='synthetic', name='recovery', enabled=False, audience_revision=1, audience_document={}, updated_at=now))
        c.execute(github_group_issues.insert().values(group_id=ids['group'], repository_id='synthetic-recovery-repo',
            issue_node_id='synthetic-node', issue_number=7, issue_url='https://github.example.invalid/synthetic/recovery/issues/7',
            state='uncertain', desired_revision=2, applied_revision=1, audience_revision=1,
            discrepancy_codes=['restore_uncertain_effect'], document={}, updated_at=now))
    return ids


def main():
    if os.environ.get('UVM_G7_DISPOSABLE_MODE') != '1':
        raise RuntimeError('retained fixture requires the authorised disposable environment')
    engine = sa.create_engine(sa.URL.create('postgresql+psycopg', username='uvm_app',
        password=Path('/run/secrets/uvm_db_password').read_text().strip(),
        host='127.0.0.1', port=5432, database='uvm'))
    print(json.dumps(seed(engine), sort_keys=True))


if __name__ == '__main__':
    main()
