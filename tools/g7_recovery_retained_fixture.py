"""Synthetic retained UVM sentinel, written only in the disposable UVM database."""
from datetime import datetime, timedelta, timezone
import json
import hashlib
import os
from pathlib import Path
import uuid
import sqlalchemy as sa
from uvm.persistence.schema import groups, workloads, incarnations, exposures, occurrences
from uvm.persistence.observation_schema import source_observations
from uvm.persistence.ingestion_schema import collection_runs
from uvm.persistence.assessment_schema import (assessment_group_state,
    assessment_audit_events, assessment_projection_intents, assessment_command_receipts)
from uvm.persistence.g4_schema import (exposure_episodes, github_repositories,
    github_group_issues)
from uvm.persistence.exception_sla_schema import (source_observation_receipts,
    sla_clock_events, sla_episode_contracts, sla_ingest_receipts)
from uvm.persistence.metrics_schema import (g7_sla_evaluations, sla_policy_heads,
    sla_policy_versions)
from uvm.identity import MissingField, RuleV1, SourceObservationV1
from uvm.persistence.identity_repository import (AuthorisationDecision,
    IdentityRepository)
from uvm.persistence.observation_store import ObservationRepository
from uvm.persistence.observation_schema import source_observations


def seed_exception_sla(engine):
    """Create the SLA candidate through the retained-observation writer.

    Source and collection facts are synthetic fixture input. The immutable
    retention receipt, episode binding, SLA receipt and evaluation are all
    produced by ObservationRepository and IdentityRepository.
    """
    clock_file = os.environ.get('UVM_G7_TEST_CLOCK_FILE')
    if not clock_file:
        raise RuntimeError('G7 SLA fixture requires the disposable server clock file')
    now = datetime.fromisoformat(Path(clock_file).read_text().strip().replace('Z', '+00:00'))
    if now.tzinfo is None or now.utcoffset() is None:
        raise RuntimeError('G7 SLA fixture clock must be timezone-aware')
    now = now.astimezone(timezone.utc)
    ids = {name: str(uuid.uuid5(uuid.NAMESPACE_URL,
        'volt:g7:exception-sla-ingestion-fixture:' + name))
        for name in ('run', 'high_observation', 'breach_observation',
            'gap_observation', 'deadline_observation', 'replacement_observation',
            'high_resolution', 'breach_resolution', 'gap_resolution',
            'deadline_resolution', 'replacement_resolution')}
    expected_group_id = os.environ.get('UVM_G7_SLA_EXPECTED_GROUP_ID') or str(uuid.uuid5(uuid.NAMESPACE_URL,
        'volt:g7:exception-sla-ingestion-fixture:identity-id:1'))
    observed = now.replace(microsecond=0) - timedelta(hours=30)
    collected = observed + timedelta(hours=1)
    policy_id = 'g7-exception-sla-ingestion-fixture-v1'
    policy = {'policy_id': policy_id, 'version': 1,
        'effective_from': (now - timedelta(days=2)).isoformat().replace('+00:00', 'Z'),
        'effective_until': None, 'scope': {'group_ids': [expected_group_id],
            'environments': ['local'], 'service_ids': [
                'g7-sla-service-covered', 'g7-sla-service-breached',
                'g7-sla-service-unknown', 'g7-sla-service-deadline-boundary',
                'g7-sla-service-replacement', 'g7-sla-service-legacy']},
        'eligibility': {'included_severities': ['critical', 'high'], 'excluded_classifications': []},
        'classification': {'source_rating_map': {'critical': 'critical', 'low': 'high'}},
        'duration_seconds_by_severity': {'critical': 3600, 'high': 86400},
        'clock_basis': 'elapsed_utc_seconds', 'deadline_reference_rules': {'bindings': []},
        'backfill': {'mode': 'prospective'}, 'start_source': 'uvm_ingest_commit_v1'}
    source_specs = [
        ('covered_six_hours', ids['high_observation'], 0, 'low'),
        ('already_breached', ids['breach_observation'], 1, 'critical'),
        ('unknown_coverage', ids['gap_observation'], 2, 'unclassified'),
        ('deadline_boundary', ids['deadline_observation'], 3, 'low'),
        ('replacement_member', ids['replacement_observation'], 4, 'low'),
    ]
    with engine.begin() as c:
        published_policy = c.execute(sa.select(sla_policy_versions).where(
            sla_policy_versions.c.policy_id == policy_id,
            sla_policy_versions.c.version == 1)).mappings().one_or_none()
        if published_policy is None:
            raise RuntimeError('prospective G7 policy was not published through the public policy writer')
        published_document = published_policy['document']
        for field in ('policy_id', 'version', 'eligibility', 'classification',
                'duration_seconds_by_severity', 'clock_basis', 'start_source', 'backfill'):
            if published_document.get(field) != policy.get(field):
                raise RuntimeError(f'publicly published G7 policy does not match fixture contract field {field}')
        published_scope = published_document.get('scope', {})
        if (expected_group_id not in published_scope.get('group_ids', [])
                or published_scope.get('environments') != policy['scope']['environments']
                or published_scope.get('service_ids') != policy['scope']['service_ids']):
            raise RuntimeError('publicly published G7 policy does not cover the writer target and fixture dimensions')
        c.execute(collection_runs.insert().values(run_id=ids['run'], revision=1, schema_version=1,
            manual_origin='g7-exception-sla-ingestion-fixture', schedule_id='synthetic',
            schedule_revision=1, source_family='local', source_account_id='g7-local',
            scope_key='all', state='completed', started_at=collected, ended_at=collected,
            retrieval_status='complete', retrieval_reasons=[], coverage_status='complete',
            coverage_reasons=[], freshness_status='fresh', freshness_reasons=[],
            facts_snapshot={'environment': 'synthetic-local'},
            provenance_snapshot={'environment': 'synthetic-local'}, created_at=now))

    missing = tuple(MissingField(name, 'not_applicable') for name in (
        'source_record_locator', 'source_first_seen_at',
        'report_id', 'coverage_scope'))
    observations = []
    for index, (name, observation_id, ordinal, rating) in enumerate(source_specs):
        raw = f'g7-exception-sla-source-v1:{name}'.encode()
        observations.append(SourceObservationV1(schema_version=1,
            observation_id=observation_id, revision=1, source_family='local',
            source_account_id='g7-local', run_id=ids['run'], source_record_ordinal=ordinal,
            collection_status='success', observed_at=observed, collected_at=collected,
            raw_evidence_ref=f'synthetic:g7-exception-sla-source-v1:{name}',
            raw_evidence_sha256=hashlib.sha256(raw).hexdigest(), missing_fields=missing,
            native_id_scheme='fixture', native_id_authority='g7-local',
            native_id_value='exception-sla-ingestion-v1', asset_locator=f'host-sla-{name}',
            component_locator=f'component-sla-{name}', source_rating=rating,
            vulnerability_refs=('CVE-2099-0001',)))
    retained = ObservationRepository(engine, clock=lambda: now).write_run(
        'g7-local', ids['run'], [(row, 'created') for row in observations])
    if retained.status != 'created' or retained.new_rows != len(observations):
        raise RuntimeError(f'authoritative positive retention did not create all fixture rows: {retained}')

    decision_time = now
    def authorise(action, target_id, context):
        return AuthorisationDecision(decision_id=str(uuid.uuid4()), allowed=True,
            principal_id='g7-fixture', action=action, target_id=target_id,
            scope='fixture:identity-rule-provision', policy_revision='fixture-v1',
            reason='Provision the synthetic G7 fixture identity rule',
            evidence_ref='g7-exception-sla-ingestion-fixture',
            correlation_id=ids['high_resolution'], decided_at=decision_time, details={})
    identity = IdentityRepository(engine, authorisation_evaluator=authorise)
    rule = RuleV1('g7-exception-sla-fixture-rule', 1,
        ('provisioning_key', 'service_key'), verified_asset_locator=True,
        workload_context_fields=('environment', 'service_id'))
    identity.provision_rule(rule, now)
    import uvm.identity.model as identity_model
    import uvm.identity.resolver as identity_resolver
    original_model_new_id = identity_model.new_id
    original_new_id = identity_resolver.new_id
    id_sequence = 0
    def deterministic_fixture_id():
        nonlocal id_sequence
        id_sequence += 1
        return str(uuid.uuid5(uuid.NAMESPACE_URL,
            f'volt:g7:exception-sla-ingestion-fixture:identity-id:{id_sequence}'))
    def resolve_fixture(row, request_id, workload_name, base=0):
        nonlocal id_sequence
        id_sequence = base
        identity_model.new_id = deterministic_fixture_id
        identity_resolver.new_id = deterministic_fixture_id
        return identity.resolve_retained(request_id, row.observation_id, 1, rule,
            {'provisioning_key': f'g7-sla-{workload_name}',
             'service_key': f'g7-sla-key-{workload_name}',
             'environment': 'local', 'service_id': f'g7-sla-service-{workload_name}'}, now)

    def rollback_state_counts():
        with engine.connect() as c:
            return tuple(c.execute(sa.select(sa.func.count()).select_from(table)).scalar_one()
                for table in (sla_ingest_receipts, sla_clock_events, exposure_episodes,
                    source_observation_receipts, g7_sla_evaluations))

    rollback_baseline = rollback_state_counts()

    def fail_first_sla_receipt(connection, cursor, statement, parameters, context, executemany):
        if statement.lstrip().lower().startswith('insert') and 'sla_ingest_receipts' in statement.lower():
            raise RuntimeError('fixture_fail_after_authoritative_sla_receipt_insert')

    import sqlalchemy as sqlalchemy
    try:
        sqlalchemy.event.listen(engine, 'after_cursor_execute', fail_first_sla_receipt)
        try:
            result = resolve_fixture(observations[0], ids['high_resolution'], 'covered', 0)
        except RuntimeError as error:
            if str(error) != 'fixture_fail_after_authoritative_sla_receipt_insert':
                raise
        else:
            with engine.connect() as c:
                episode = c.execute(sa.select(exposure_episodes).where(
                    exposure_episodes.c.exposure_id == result.exposure_id,
                    exposure_episodes.c.is_current.is_(True))).mappings().first()
                contract = (c.execute(sa.select(sla_episode_contracts).where(
                    sla_episode_contracts.c.episode_id == episode['episode_id'])).mappings().first()
                    if episode else None)
                receipt = c.execute(sa.select(sla_ingest_receipts).where(
                    sla_ingest_receipts.c.occurrence_id == result.occurrence_id)).mappings().first()
            raise RuntimeError('SLA receipt rollback failpoint did not fire: ' + json.dumps({
                'group_id': result.group_id, 'exposure_id': result.exposure_id,
                'occurrence_id': result.occurrence_id,
                'outcome': result.outcome, 'reason': result.reason,
                'candidate_workload_ids': list(result.candidate_workload_ids),
                'candidate_explanations': repr(result.candidate_explanations),
                'episode_id': episode['episode_id'] if episode else None,
                'contract_version': contract['contract_version'] if contract else None,
                'receipt_id': receipt['receipt_id'] if receipt else None,
                'receipt_writer_attempted': receipt is not None}))
        finally:
            sqlalchemy.event.remove(engine, 'after_cursor_execute', fail_first_sla_receipt)
        rollback_after = rollback_state_counts()
        if rollback_after != rollback_baseline:
            raise RuntimeError('atomic ingest rollback leaked episode/SLA state or lost retained input: '
                f'baseline={rollback_baseline}; after={rollback_after}')
        results = []
        for row, request_id, workload_name, base in (
                (observations[0], ids['high_resolution'], 'covered', 0),
                (observations[1], ids['breach_resolution'], 'breached', 100),
                (observations[2], ids['gap_resolution'], 'unknown', 200),
                (observations[3], ids['deadline_resolution'], 'deadline-boundary', 300),
                (observations[4], ids['replacement_resolution'], 'replacement', 400)):
            results.append(resolve_fixture(row, request_id, workload_name, base))
    finally:
        identity_model.new_id = original_model_new_id
        identity_resolver.new_id = original_new_id
    members = []
    with engine.connect() as c:
        for (name, _, _, _), result in zip(source_specs, results):
            if not result.occurrence_id or not result.group_id or not result.exposure_id:
                raise RuntimeError(f'authoritative positive did not resolve to an exact membership: {result}')
            episode = c.execute(sa.select(exposure_episodes.c.episode_id).where(
                exposure_episodes.c.exposure_id == result.exposure_id,
                exposure_episodes.c.is_current.is_(True))).scalar_one()
            receipt = c.execute(sa.select(sla_ingest_receipts).where(
                sla_ingest_receipts.c.episode_id == episode,
                sla_ingest_receipts.c.occurrence_id == result.occurrence_id)).mappings().one()
            evaluation = c.execute(sa.select(g7_sla_evaluations).where(
                g7_sla_evaluations.c.episode_id == episode,
                g7_sla_evaluations.c.occurrence_id == result.occurrence_id,
                g7_sla_evaluations.c.is_authoritative.is_(True)).order_by(
                    g7_sla_evaluations.c.revision.desc()).limit(1)).mappings().one()
            if receipt['ingested_at'] != now:
                raise RuntimeError('authoritative writer did not persist the logical ingest anchor')
            members.append({'key': name, 'group': result.group_id,
                'exposure': result.exposure_id, 'occurrence': result.occurrence_id,
                'episode': episode, 'evaluation': evaluation['evaluation_id'],
                'revision': int(evaluation['revision']),
                'deadline_at': (evaluation['current_deadline_at'].isoformat().replace('+00:00', 'Z')
                    if evaluation['current_deadline_at'] else None),
                'deadline_basis': evaluation['deadline_basis'],
                'gap_reasons': list(evaluation['gap_reasons']),
                'receipt_id': receipt['receipt_id']})
    # Reimport/refresh and a verified rebuild pass through the same retained
    # observation and identity writers as the initial positive. The refresh
    # maps to its existing occurrence; the rebuilt host gets a new occurrence
    # in the existing exposure and therefore its own first-positive receipt.
    def retain_followup(name, asset_locator, component_locator, observed_at, collected_at,
                        ordinal):
        run_id = str(uuid.uuid5(uuid.NAMESPACE_URL,
            f'volt:g7:exception-sla-ingestion-fixture:{name}:run'))
        observation_id = str(uuid.uuid5(uuid.NAMESPACE_URL,
            f'volt:g7:exception-sla-ingestion-fixture:{name}:observation'))
        resolution_id = str(uuid.uuid5(uuid.NAMESPACE_URL,
            f'volt:g7:exception-sla-ingestion-fixture:{name}:resolution'))
        with engine.begin() as c:
            c.execute(collection_runs.insert().values(run_id=run_id, revision=1,
                schema_version=1, manual_origin=f'g7-exception-sla-{name}',
                schedule_id='synthetic', schedule_revision=1, source_family='local',
                source_account_id='g7-local', scope_key='all', state='completed',
                started_at=collected_at, ended_at=collected_at, retrieval_status='complete',
                retrieval_reasons=[], coverage_status='complete', coverage_reasons=[],
                freshness_status='fresh', freshness_reasons=[],
                facts_snapshot={'environment': 'synthetic-local'},
                provenance_snapshot={'environment': 'synthetic-local'}, created_at=now))
        raw = f'g7-exception-sla-source-v1:{name}'.encode()
        row = SourceObservationV1(schema_version=1, observation_id=observation_id,
            revision=1, source_family='local', source_account_id='g7-local', run_id=run_id,
            source_record_ordinal=ordinal, collection_status='success', observed_at=observed_at,
            collected_at=collected_at, raw_evidence_ref=f'synthetic:g7-exception-sla-source-v1:{name}',
            raw_evidence_sha256=hashlib.sha256(raw).hexdigest(), missing_fields=missing,
            native_id_scheme='fixture', native_id_authority='g7-local',
            native_id_value='exception-sla-ingestion-v1', asset_locator=asset_locator,
            component_locator=component_locator, source_rating='low',
            vulnerability_refs=('CVE-2099-0001',))
        stored = ObservationRepository(engine, clock=lambda: now).write_run(
            'g7-local', run_id, [(row, 'created')])
        if stored.status != 'created' or stored.new_rows != 1:
            raise RuntimeError(f'{name} source refresh was not retained by the actual writer: {stored}')
        result = identity.resolve_retained(resolution_id, row.observation_id, 1, rule,
            {'provisioning_key': 'g7-sla-covered', 'service_key': 'g7-sla-key-covered',
             'environment': 'local', 'service_id': 'g7-sla-service-covered'}, now)
        if result.outcome != 'matched' or not result.exposure_id:
            raise RuntimeError(f'{name} identity continuity did not resolve: {result}')
        with engine.connect() as c:
            episode_id = c.execute(sa.select(exposure_episodes.c.episode_id).where(
                exposure_episodes.c.exposure_id == result.exposure_id,
                exposure_episodes.c.is_current.is_(True))).scalar_one()
            occurrence = c.execute(sa.select(occurrences).where(
                occurrences.c.occurrence_id == result.occurrence_id)).mappings().one()
            receipt = c.execute(sa.select(sla_ingest_receipts).where(
                sla_ingest_receipts.c.episode_id == episode_id,
                sla_ingest_receipts.c.occurrence_id == result.occurrence_id)).mappings().one()
            evaluation = c.execute(sa.select(g7_sla_evaluations).where(
                g7_sla_evaluations.c.episode_id == episode_id,
                g7_sla_evaluations.c.occurrence_id == result.occurrence_id,
                g7_sla_evaluations.c.is_authoritative.is_(True)).order_by(
                    g7_sla_evaluations.c.revision.desc()).limit(1)).mappings().one()
        return {'name': name, 'observation_id': observation_id, 'run_id': run_id,
            'group_id': result.group_id, 'exposure_id': result.exposure_id,
            'episode_id': episode_id, 'occurrence_id': result.occurrence_id,
            'incarnation_id': occurrence['incarnation_id'],
            'first_ingested_at': receipt['ingested_at'].isoformat().replace('+00:00', 'Z'),
            'receipt_id': receipt['receipt_id'], 'evaluation_id': evaluation['evaluation_id'],
            'deadline_at': (evaluation['current_deadline_at'].isoformat().replace('+00:00', 'Z')
                if evaluation['current_deadline_at'] else None)}

    original_covered = members[0]
    refresh = retain_followup('reimport_refresh', 'host-sla-covered_six_hours',
        'component-sla-covered_six_hours', observed, collected + timedelta(minutes=1), 10)
    if (refresh['occurrence_id'] != original_covered['occurrence']
            or refresh['receipt_id'] != original_covered['receipt_id']
            or refresh['first_ingested_at'] != now.isoformat().replace('+00:00', 'Z')
            or refresh['deadline_at'] != original_covered['deadline_at']):
        raise RuntimeError(f'reimport/refresh reset the applicable membership SLA anchor: {refresh}')
    rebuild = retain_followup('verified_rebuild', 'host-sla-covered_six_hours-rebuilt',
        'component-sla-covered_six_hours', observed + timedelta(hours=1), collected + timedelta(minutes=2), 11)
    if (rebuild['exposure_id'] != original_covered['exposure']
            or rebuild['group_id'] != original_covered['group']
            or rebuild['occurrence_id'] == original_covered['occurrence']
            or rebuild['receipt_id'] == original_covered['receipt_id']
            or rebuild['first_ingested_at'] != now.isoformat().replace('+00:00', 'Z')
            or rebuild['deadline_at'] != original_covered['deadline_at']):
        raise RuntimeError(f'verified rebuild failed stable exposure/new membership SLA assertions: {rebuild}')
    members.append({'key': 'verified_rebuild_membership', 'group': rebuild['group_id'],
        'exposure': rebuild['exposure_id'], 'occurrence': rebuild['occurrence_id'],
        'episode': rebuild['episode_id'], 'evaluation': rebuild['evaluation_id'],
        'revision': 1, 'deadline_at': rebuild['deadline_at'], 'deadline_basis': 'policy_calculation',
        'gap_reasons': [], 'receipt_id': rebuild['receipt_id']})
    # A separate group outside the exact prospective G7 policy scope exercises
    # the existing G5 episode contract through the same retained-observation
    # writer. Its source timestamps stay older than its actual UVM receipt.
    g5_run = str(uuid.uuid5(uuid.NAMESPACE_URL,
        'volt:g7:exception-sla-g5-compatibility:run'))
    g5_observation_id = str(uuid.uuid5(uuid.NAMESPACE_URL,
        'volt:g7:exception-sla-g5-compatibility:observation'))
    g5_resolution_id = str(uuid.uuid5(uuid.NAMESPACE_URL,
        'volt:g7:exception-sla-g5-compatibility:resolution'))
    g5_native_id = 'exception-sla-g5-compatibility-v1'
    g5_collected = collected + timedelta(minutes=3)
    g5_raw = b'g7-exception-sla-source-v1:g5-compatibility'
    with engine.begin() as c:
        c.execute(collection_runs.insert().values(run_id=g5_run, revision=1,
            schema_version=1, manual_origin='g7-exception-sla-g5-compatibility',
            schedule_id='synthetic', schedule_revision=1, source_family='local',
            source_account_id='g7-local', scope_key='all', state='completed',
            started_at=g5_collected, ended_at=g5_collected, retrieval_status='complete',
            retrieval_reasons=[], coverage_status='complete', coverage_reasons=[],
            freshness_status='fresh', freshness_reasons=[],
            facts_snapshot={'environment': 'synthetic-local'},
            provenance_snapshot={'environment': 'synthetic-local'}, created_at=now))
    g5_source = SourceObservationV1(schema_version=1,
        observation_id=g5_observation_id, revision=1, source_family='local',
        source_account_id='g7-local', run_id=g5_run, source_record_ordinal=0,
        collection_status='success', observed_at=observed, collected_at=g5_collected,
        raw_evidence_ref='synthetic:g7-exception-sla-source-v1:g5-compatibility',
        raw_evidence_sha256=hashlib.sha256(g5_raw).hexdigest(), missing_fields=missing,
        native_id_scheme='fixture', native_id_authority='g7-local',
        native_id_value=g5_native_id, asset_locator='host-sla-g5-compatibility',
        component_locator='component-sla-g5-compatibility', source_rating='low',
        vulnerability_refs=('CVE-2099-0002',))
    g5_retained = ObservationRepository(engine, clock=lambda: now).write_run(
        'g7-local', g5_run, [(g5_source, 'created')])
    if g5_retained.status != 'created' or g5_retained.new_rows != 1:
        raise RuntimeError(f'G5 compatibility source row was not retained by the actual writer: {g5_retained}')
    g5_result = identity.resolve_retained(g5_resolution_id, g5_observation_id, 1, rule,
        {'provisioning_key': 'g7-sla-legacy', 'service_key': 'g7-sla-key-legacy',
         'environment': 'local', 'service_id': 'g7-sla-service-legacy'}, now)
    if g5_result.outcome not in {'new', 'matched'} or not g5_result.occurrence_id:
        raise RuntimeError(f'out-of-scope positive did not retain its G5 identity: {g5_result}')
    with engine.connect() as c:
        g5_episode_id = c.execute(sa.select(exposure_episodes.c.episode_id).where(
            exposure_episodes.c.exposure_id == g5_result.exposure_id,
            exposure_episodes.c.is_current.is_(True))).scalar_one()
        g5_contract = c.execute(sa.select(sla_episode_contracts).where(
            sla_episode_contracts.c.episode_id == g5_episode_id)).mappings().one()
        g5_receipt = c.execute(sa.select(sla_ingest_receipts).where(
            sla_ingest_receipts.c.episode_id == g5_episode_id,
            sla_ingest_receipts.c.occurrence_id == g5_result.occurrence_id)).mappings().one()
    if g5_contract['contract_version'] != 5 or g5_receipt['ingested_at'] != now:
        raise RuntimeError('prospective G7 policy changed the out-of-scope G5 contract or receipt time')
    g5_compatibility = {'group': g5_result.group_id, 'exposure': g5_result.exposure_id,
        'occurrence': g5_result.occurrence_id, 'episode': g5_episode_id,
        'contract_version': int(g5_contract['contract_version']),
        'receipt_id': g5_receipt['receipt_id'], 'observation_id': g5_observation_id,
        'observed_at': observed.isoformat().replace('+00:00', 'Z'),
        'collected_at': g5_collected.isoformat().replace('+00:00', 'Z'),
        'ingested_at': g5_receipt['ingested_at'].isoformat().replace('+00:00', 'Z'),
        'g7_policy_scope_group_ids': [expected_group_id]}
    if any(result.outcome not in {'new', 'matched'} for result in results):
        raise RuntimeError(f'authoritative positives did not resolve: {[item.outcome for item in results]}')
    covered = members[0]
    return {'group': results[0].group_id, 'exposure': covered['exposure'],
        'occurrence': covered['occurrence'], 'episode': covered['episode'],
        'evaluation': covered['evaluation'], 'revision': covered['revision'],
        'members': members,
        'atomic_rollback': {'attempted': True, 'retained_input_count': len(observations),
            'sla_receipts_after_rollback': 0, 'clock_events_after_rollback': 0,
            'episodes_after_rollback': 0},
        'ingested_at': now.isoformat().replace('+00:00', 'Z'),
        'observed_at': observed.isoformat().replace('+00:00', 'Z'),
        'collected_at': collected.isoformat().replace('+00:00', 'Z'),
        'deadline_at': covered['deadline_at'],
        'receipt_id': covered['receipt_id'], 'receipt_writer': 'ObservationRepository.write_run',
        'resolution_writer': 'IdentityRepository.resolve_retained',
        'continuity': {'reimport_refresh': refresh, 'verified_rebuild': rebuild,
            'applicable_membership_original_receipt_id': original_covered['receipt_id'],
            'applicable_membership_original_deadline_at': original_covered['deadline_at']},
        'g5_compatibility': g5_compatibility}


def seed_g5_activation_stage(engine, stage):
    """Create G5 episode membership only through retained source/identity writers.

    ``prepolicy`` establishes a genuine G5 episode before either SLA policy is
    published. ``postlegacy`` and ``postg7`` add independent memberships to
    that same pinned G5 episode after the corresponding public publication.
    """
    clock_file = os.environ.get('UVM_G7_TEST_CLOCK_FILE')
    if not clock_file:
        raise RuntimeError('G5 activation fixture requires the disposable server clock file')
    now = datetime.fromisoformat(Path(clock_file).read_text().strip().replace('Z', '+00:00'))
    if now.tzinfo is None or now.utcoffset() is None:
        raise RuntimeError('G5 activation fixture clock must be timezone-aware')
    now = now.astimezone(timezone.utc)
    if stage == 'prepolicy':
        observed, collected = now - timedelta(hours=2), now - timedelta(hours=1)
        name, component, ordinal = 'g5-prepolicy', 'g5-component-prepolicy', 0
    elif stage == 'pre_g7_target':
        observed, collected = now - timedelta(hours=2), now - timedelta(hours=1)
        name, component, ordinal = 'g7-target-prepolicy', 'g7-target-component-prepolicy', 0
    elif stage == 'postlegacy':
        observed, collected = now - timedelta(milliseconds=500), now - timedelta(milliseconds=250)
        name, component, ordinal = 'g5-postlegacy', 'g5-component-postlegacy', 1
    elif stage == 'postg7':
        observed, collected = now - timedelta(milliseconds=500), now - timedelta(milliseconds=250)
        name, component, ordinal = 'g5-postg7', 'g5-component-postg7', 2
    elif stage == 'recur':
        observed, collected = now - timedelta(milliseconds=500), now - timedelta(milliseconds=250)
        name, component, ordinal = 'g5-recur', 'g5-component-postg7', 3
    else:
        raise RuntimeError(f'unknown G5 activation fixture stage: {stage}')
    suffix = 'volt:g7:exception-sla-g5-staged:' + name
    run_id = str(uuid.uuid5(uuid.NAMESPACE_URL, suffix + ':run'))
    observation_id = str(uuid.uuid5(uuid.NAMESPACE_URL, suffix + ':observation'))
    request_id = str(uuid.uuid5(uuid.NAMESPACE_URL, suffix + ':resolution'))
    raw = ('g7-exception-sla-g5-staged:' + name).encode()
    with engine.begin() as c:
        c.execute(collection_runs.insert().values(run_id=run_id, revision=1,
            schema_version=1, manual_origin=suffix, schedule_id='synthetic',
            schedule_revision=1, source_family='local', source_account_id='g7-local',
            scope_key='all', state='completed', started_at=collected, ended_at=collected,
            retrieval_status='complete', retrieval_reasons=[], coverage_status='complete',
            coverage_reasons=[], freshness_status='fresh', freshness_reasons=[],
            facts_snapshot={'environment': 'synthetic-local'},
            provenance_snapshot={'environment': 'synthetic-local'}, created_at=now))
    missing = tuple(MissingField(field, 'not_applicable') for field in (
        'source_record_locator', 'source_first_seen_at', 'report_id', 'coverage_scope'))
    native_id_value = ('exception-sla-ingestion-v1' if stage == 'pre_g7_target'
        else 'exception-sla-ingestion-v1')
    source = SourceObservationV1(schema_version=1, observation_id=observation_id,
        revision=1, source_family='local', source_account_id='g7-local', run_id=run_id,
        source_record_ordinal=ordinal, collection_status='success', observed_at=observed,
        collected_at=collected, raw_evidence_ref='synthetic:' + suffix,
        raw_evidence_sha256=hashlib.sha256(raw).hexdigest(), missing_fields=missing,
        native_id_scheme='fixture', native_id_authority='g7-local',
        native_id_value=native_id_value,
        asset_locator='host-g7-policy-scope-seed' if stage == 'pre_g7_target' else 'host-g5-staged',
        component_locator='g7-policy-scope-seed' if stage == 'pre_g7_target' else component, source_rating='low',
        vulnerability_refs=('CVE-2099-0010',))
    retained = ObservationRepository(engine, clock=lambda: now).write_run(
        'g7-local', run_id, [(source, 'created')])
    if retained.status != 'created' or retained.new_rows != 1:
        raise RuntimeError(f'{stage} source was not retained by the actual writer: {retained}')
    decision_time = now
    def authorise(action, target_id, context):
        return AuthorisationDecision(decision_id=str(uuid.uuid4()), allowed=True,
            principal_id='g7-fixture', action=action, target_id=target_id,
            scope='fixture:identity-rule-provision', policy_revision='fixture-v1',
            reason='Provision staged G5 fixture identity', evidence_ref=suffix,
            correlation_id=request_id, decided_at=decision_time, details={})
    identity = IdentityRepository(engine, authorisation_evaluator=authorise)
    rule = RuleV1('g7-exception-sla-g5-staged-rule', 1,
        ('provisioning_key', 'service_key'), verified_asset_locator=True,
        workload_context_fields=('environment', 'service_id'))
    if stage == 'prepolicy':
        identity.provision_rule(rule, now)
    result = identity.resolve_retained(request_id, observation_id, 1, rule,
        {'provisioning_key': ('g7-sla-policy-scope-seed' if stage == 'pre_g7_target' else 'g7-sla-g5-staged'),
         'service_key': ('g7-sla-key-policy-scope-seed' if stage == 'pre_g7_target' else 'g7-sla-g5-staged'),
         'environment': ('activation-seed' if stage == 'pre_g7_target' else 'local'),
         'service_id': ('g7-sla-service-policy-scope-seed' if stage == 'pre_g7_target' else 'g7-sla-service-legacy')}, now)
    if stage == 'pre_g7_target' and (result.outcome not in {'new', 'matched'}
            or not result.group_id or not result.exposure_id):
        raise RuntimeError(f'{stage} did not establish a source-covered exposure through the actual identity writer: {result}')
    if result.outcome not in {'new', 'matched'} or not result.occurrence_id:
        raise RuntimeError(f'{stage} did not resolve through the actual identity writer: {result}')
    with engine.connect() as c:
        episode_id = c.execute(sa.select(exposure_episodes.c.episode_id).where(
            exposure_episodes.c.exposure_id == result.exposure_id,
            exposure_episodes.c.is_current.is_(True))).scalar_one()
        contract = c.execute(sa.select(sla_episode_contracts).where(
            sla_episode_contracts.c.episode_id == episode_id)).mappings().one()
        receipt = c.execute(sa.select(sla_ingest_receipts).where(
            sla_ingest_receipts.c.episode_id == episode_id,
            sla_ingest_receipts.c.occurrence_id == result.occurrence_id)).mappings().one()
    expected_contract = 7 if stage == 'recur' else 5
    if contract['contract_version'] != expected_contract:
        raise RuntimeError(f'{stage} expected episode contract {expected_contract}, got {contract}')
    if receipt['ingested_at'] != now or not observed < collected < receipt['ingested_at']:
        raise RuntimeError(f'{stage} retained time does not follow source timestamps')
    return {'stage': stage, 'group_id': result.group_id, 'exposure_id': result.exposure_id,
        'episode_id': episode_id, 'occurrence_id': result.occurrence_id,
        'receipt_id': receipt['receipt_id'], 'observation_id': observation_id,
        'observed_at': observed.isoformat().replace('+00:00', 'Z'),
        'collected_at': collected.isoformat().replace('+00:00', 'Z'),
        'ingested_at': receipt['ingested_at'].isoformat().replace('+00:00', 'Z'),
        'contract_version': int(contract['contract_version'])}


def seed(engine):
    if os.environ.get('UVM_G7_SLA_STAGE') == 'context_matrix':
        from g7_context_retained_fixture import context_matrix
        now = datetime.fromisoformat(Path(os.environ['UVM_G7_TEST_CLOCK_FILE']).read_text().strip().replace('Z', '+00:00'))
        return context_matrix(engine, now)
    if os.environ.get('UVM_G7_SLA_STAGE'):
        return seed_g5_activation_stage(engine, os.environ['UVM_G7_SLA_STAGE'])
    if os.environ.get('UVM_G7_SLA_FIXTURE') == '1':
        return seed_exception_sla(engine)
    warning_fixture = os.environ.get('UVM_G7_WARNING_FIXTURE') == '1'
    identity_fixture = os.environ.get('UVM_G7_IDENTITY_FIXTURE') == '1'
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
            result=({'schema_version': 1, 'command_id': ids['command'],
                'decision_id': ids['decision'], 'audit_event_id': ids['event'],
                'intent_id': ids['intent'], 'committed_revision': 2,
                'projection': 'pending', 'outcome': 'committed'} if warning_fixture else
                {'command_id': ids['command'], 'decision_id': ids['decision'],
                    'audit_event_id': ids['event'], 'outcome': 'committed'}), created_at=now))
        repository_id = '777777' if warning_fixture else ('777776' if identity_fixture else 'synthetic-recovery-repo')
        c.execute(github_repositories.insert().values(repository_id=repository_id, github_host='github.example.invalid',
            owner='synthetic', name='recovery', enabled=False, audience_revision=1, audience_document={}, updated_at=now))
        c.execute(github_group_issues.insert().values(group_id=ids['group'], repository_id=repository_id,
            issue_node_id='synthetic-node', issue_number=7, issue_url='https://github.example.invalid/synthetic/recovery/issues/7',
            state='uncertain', desired_revision=2, applied_revision=1, audience_revision=1,
            discrepancy_codes=['restore_uncertain_effect'], document={}, updated_at=now))
        if warning_fixture:
            # Retain a real G7 starting point for the warning journey. The exception
            # itself is always created later through the public submit/approve API.
            policy_id = 'g7-warning-fixture-v1'
            policy = {'policy_id': policy_id, 'version': 1,
                'effective_from': (now.replace(year=now.year - 1)).isoformat().replace('+00:00', 'Z'),
                'effective_until': None, 'scope': {'group_ids': [ids['group']],
                    'environments': ['local'], 'service_ids': ['*']},
                'eligibility': {'included_severities': ['high'], 'excluded_classifications': []},
                'classification': {'source_rating_map': {'low': 'high'}},
                'duration_seconds_by_severity': {'high': 7200},
                'clock_basis': 'elapsed_utc_seconds', 'deadline_reference_rules': {'bindings': []},
                'backfill': {'mode': 'prospective'}, 'start_source': 'uvm_ingest_commit_v1'}
            head = c.execute(sa.select(sla_policy_heads).where(
                sla_policy_heads.c.head_id == 1).with_for_update()).mappings().one_or_none()
            head_revision = (int(head['revision']) + 1) if head else 1
            if head:
                c.execute(sla_policy_heads.update().where(sla_policy_heads.c.head_id == 1).values(
                    revision=head_revision, updated_at=now))
            else:
                c.execute(sla_policy_heads.insert().values(head_id=1,
                    revision=head_revision, updated_at=now))
            policy_revision = int(c.execute(sa.select(sa.func.coalesce(
                sa.func.max(sla_policy_versions.c.revision), 0) + 1)).scalar_one())
            c.execute(sla_policy_versions.insert().values(policy_id=policy_id, version=1,
                revision=policy_revision, document=policy, created_at=now, created_by='g7-fixture'))
            receipt_id, operation_id = str(uuid.uuid4()), str(uuid.uuid4())
            c.execute(source_observation_receipts.insert().values(receipt_id=receipt_id,
                source_observation_id=ids['observation'], source_account_id='g7-local',
                run_id=ids['run'], source_record_ordinal=0, retention_operation_id=operation_id,
                retained_at=now, source_observed_at=now, source_collected_at=now, created_at=now))
            episode_id = str(uuid.uuid5(uuid.NAMESPACE_URL,
                f"uvm-exposure-episode:{ids['exposure']}:1"))
            c.execute(sla_episode_contracts.insert().values(episode_id=episode_id,
                contract_version=7, start_source='uvm_ingest_commit_v1',
                retention_receipt_id=receipt_id, policy_id=policy_id, policy_version=1,
                pinned_at=now, created_at=now))
            c.execute(sla_ingest_receipts.insert().values(receipt_id=str(uuid.uuid4()),
                retention_receipt_id=receipt_id, episode_id=episode_id,
                occurrence_id=ids['occurrence'], ingested_at=now,
                source_observation_id=ids['observation'], source_observed_at=now,
                source_collected_at=now, ingest_operation_id=operation_id,
                policy_id=policy_id, policy_version=1, created_at=now))
            from uvm.assessment.g7_clock import ensure_current_evaluation
            evaluation = ensure_current_evaluation(c, episode_id=episode_id,
                occurrence_id=ids['occurrence'], known_at=now, assessed_severity='high')
            if not evaluation or evaluation.get('gap_reasons'):
                raise RuntimeError(f'warning fixture G7 evaluation is not authoritative: {evaluation}')
            ids['episode'] = episode_id
            ids['evaluation'] = evaluation['evaluation_id']
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
