"""Atomic, authority-bound H4 scalar supplier transaction and recovery."""
from dataclasses import replace
from datetime import datetime, timezone
import copy
import json
import hashlib
import uuid
import sqlalchemy as sa
from uvm.assessment.policy_lock import lock_policy
from uvm.persistence.assessment_schema import assessment_policy
from uvm.persistence.alias_schema import mapping_alias_events
from uvm.persistence.identity_graph_lock import lock_identity_graph
from uvm.persistence.identity_repository import AuthorisationDecision
from uvm.persistence.lineage_schema import correction_records, identity_rule_definitions
from uvm.persistence.observation_schema import source_observations
from uvm.persistence.schema import workloads, incarnations, exposures, occurrences, groups, exposure_workload_memberships
from uvm.persistence.scalar_schema import identity_scalar_correction_receipts as receipts
from uvm.persistence.scalar_contract import validate_request, canonical, ScalarCorrectionError, ScalarCorrectionOutcomeV1
from uvm.persistence.scalar_history import validate_scalar_history, instant, timestamp, ScalarHistoryUnavailable

UTC = timezone.utc


def _now():
    return datetime.now(UTC)


def _target(connection, record_type, identifier):
    table = workloads if record_type == 'workload' else incarnations
    query = sa.select(table).where(table.c[record_type + '_id'] == identifier)
    if connection.dialect.name == 'postgresql':
        query = query.with_for_update()
    row = connection.execute(query).mappings().first()
    if row is None:
        raise ScalarCorrectionError('Scalar target unavailable')
    return table, dict(row)


def _graph_contexts(connection, body, target):
    workload_id = target['workload_id']
    workload = target if body['record_type'] == 'workload' else connection.execute(
        sa.select(workloads).where(workloads.c.workload_id == workload_id)).mappings().one()
    incs = [dict(r) for r in connection.execute(sa.select(incarnations).where(
        incarnations.c.workload_id == workload_id)).mappings()]
    if body['record_type'] == 'incarnation':
        incs = [r for r in incs if r['incarnation_id'] == body['record_id']]
    inc_ids = [r['incarnation_id'] for r in incs]
    if body['record_type'] == 'workload':
        exp_ids = list(connection.execute(sa.select(exposure_workload_memberships.c.exposure_id).where(
            exposure_workload_memberships.c.workload_id == workload_id)).scalars())
    else:
        exp_ids = list(connection.execute(sa.select(occurrences.c.exposure_id).where(
            occurrences.c.incarnation_id == body['record_id'])).scalars())
    exps = [dict(r) for r in connection.execute(sa.select(exposures).where(exposures.c.exposure_id.in_(exp_ids))).mappings()]
    members = [dict(r) for r in connection.execute(sa.select(occurrences).where(sa.or_(
        occurrences.c.incarnation_id.in_(inc_ids), occurrences.c.exposure_id.in_(exp_ids)))).mappings()]
    exp_ids = sorted(set(exp_ids) | {m['exposure_id'] for m in members})
    exps = [dict(r) for r in connection.execute(sa.select(exposures).where(exposures.c.exposure_id.in_(exp_ids))).mappings()]
    group_ids = sorted({e['group_id'] for e in exps})
    group_rows = {r['group_id']: dict(r) for r in connection.execute(sa.select(groups).where(groups.c.group_id.in_(group_ids))).mappings()}
    observations = [dict(r) for r in connection.execute(sa.select(source_observations).where(
        source_observations.c.occurrence_id.in_([m['occurrence_id'] for m in members]))).mappings()]
    typed = [('workload', workload_id)] + [('incarnation', r['incarnation_id']) for r in incs]
    typed += [('exposure', r['exposure_id']) for r in exps] + [('occurrence', r['occurrence_id']) for r in members]
    typed += [('source_observation', r['observation_id']) for r in observations] + [('group', g) for g in group_ids]
    # A retained exposure membership can lead to descendants now parented
    # to another workload. Their actual current selectors remain authority
    # inputs; the corrected workload's selectors cannot stand in for them.
    related_workload_ids = {workload_id} | {r['workload_id'] for r in members} | {r['workload_id'] for r in exps}
    related_workloads = [dict(r) for r in connection.execute(sa.select(workloads).where(
        workloads.c.workload_id.in_(related_workload_ids))).mappings()]
    related_incarnation_ids = set(inc_ids) | {r['incarnation_id'] for r in members}
    typed += [('workload', r['workload_id']) for r in related_workloads]
    typed += [('incarnation', identifier) for identifier in related_incarnation_ids]
    old_attrs = dict(workload['stable_attrs']); proposed = dict(old_attrs)
    if body['record_type'] == 'workload':
        old_attrs[body['field_name']] = body['old_value']
        proposed[body['field_name']] = body['new_value']
    # Retain complete typed scopes; supplier input cannot omit descendants.
    contexts = []
    for kind, identifier in sorted(set(typed)):
        phases = [('current', dict(r['stable_attrs'])) for r in related_workloads]
        phases += [('old', old_attrs), ('proposed', proposed)]
        for phase, attrs in phases:
            for group_id in group_ids or [None]:
                families = {group_rows[group_id]['source_family']} if group_id else set()
                families.update(o['source_family'] for o in observations)
                for family in sorted(families) or [None]:
                    contexts.append({'record_type': kind, 'record_id': identifier, 'group_id': group_id,
                        'source_family': family, 'environment': attrs.get('environment'),
                        'service_id': attrs.get('service_id'), 'phase': phase})
    contexts = sorted({canonical(c): c for c in contexts}.values(), key=canonical)
    return contexts, sorted({identifier for _, identifier in typed})


def _evaluate(repo, connection, body, digest, contexts, policy, purpose, at, original_target=None, locator_frozen=None):
    evaluate = getattr(repo.authorisation_evaluator, 'evaluate_scalar_on_connection', None)
    if not callable(evaluate):
        raise ScalarCorrectionError('Transaction-compatible scalar authority unavailable')
    decision = evaluate(connection, principal_id=body['principal_id'], action=body['action'],
        target_id=body['record_id'], canonical_request=copy.deepcopy(body), scope_contexts=copy.deepcopy(contexts),
        purpose=purpose, policy_row=policy, evaluated_at=at,
        original_target=copy.deepcopy(original_target), locator_frozen=locator_frozen)
    if (not isinstance(decision, AuthorisationDecision) or decision.allowed is not True
            or decision.principal_id != body['principal_id'] or decision.action != body['action']
            or decision.target_id != body['record_id'] or decision.policy_revision != str(policy['revision'])
            or instant(decision.decided_at) != at or decision.correlation_id != body['correlation_id']
            or decision.evidence_ref != body['evidence_ref'] or decision.reason != body['rationale']
            or decision.details.get('request_digest') != digest or decision.details.get('scope_contexts') != contexts):
        raise ScalarCorrectionError('Transaction-compatible scalar authority unavailable')
    if (purpose == 'execute' and body['record_type'] == 'incarnation' and body['new_value'] is not None
            and (decision.details.get('locator_verification_required') is not True
                or type(decision.details.get('locator_verification_v1')) is not dict)):
        raise ScalarCorrectionError('Locator verification unavailable')
    return decision


def _collisions(connection, body, target):
    kind, field, identifier = body['record_type'], body['field_name'], body['record_id']
    table = workloads if kind == 'workload' else incarnations
    for row in connection.execute(sa.select(table)).mappings():
        if row[kind + '_id'] == identifier:
            continue
        if kind == 'incarnation' and row['workload_id'] != target['workload_id']:
            continue
        value = row['stable_attrs'].get(field) if kind == 'workload' else row[field]
        if value is not None and value in (body['old_value'], body['new_value']):
            raise ScalarCorrectionError('Scalar alias ownership conflict')
    scope = target['workload_id'] if kind == 'incarnation' else None
    rows = connection.execute(sa.select(mapping_alias_events).where(
        mapping_alias_events.c.record_type == kind, mapping_alias_events.c.field_name == field,
        mapping_alias_events.c.scope_a == scope, mapping_alias_events.c.scope_b.is_(None),
        mapping_alias_events.c.old_value.in_([v for v in (body['old_value'], body['new_value']) if v is not None])))
    if any(r._mapping['target_record_id'] != identifier for r in rows):
        raise ScalarCorrectionError('Scalar alias ownership conflict')


def _execute(repo, connection, body, text, digest):
    lock_identity_graph(connection)
    lock_policy(connection, shared=True)
    query = sa.select(assessment_policy).where(assessment_policy.c.policy_id == 1)
    if connection.dialect.name == 'postgresql':
        query = query.with_for_update(read=True)
    policy = connection.execute(query).mappings().first()
    if policy is None or type(policy['revision']) is not int or policy['revision'] < 1:
        raise ScalarCorrectionError('Current scalar authority unavailable')
    previous = connection.execute(sa.select(receipts).where(receipts.c.request_id == body['request_id'])).mappings().first()
    if previous:
        retained = json.loads(previous['canonical_request'])
        table, target = _target(connection, previous['record_type'], previous['record_id'])
        contexts, _ = _graph_contexts(connection, retained, target)
        contexts = sorted({canonical(c): c for c in [*previous['scope_contexts'], *contexts]}.values(), key=canonical)
        disclosure = {**retained, 'principal_id': body['principal_id']}
        # Fresh evaluator binding reflects the trusted current principal; the
        # retained request comparison happens only after disclosure authority.
        disclosure_digest = hashlib.sha256(canonical(disclosure).encode()).hexdigest()
        _evaluate(repo, connection, disclosure, disclosure_digest, contexts, policy, 'replay_disclosure', _now())
        if previous['canonical_request'] != text or previous['request_digest'] != digest:
            raise ScalarCorrectionError('Scalar request ID is bound to different content')
        validate_scalar_history(connection, previous['record_type'], target)
        return copy.deepcopy(previous['result'])
    table, target = _target(connection, body['record_type'], body['record_id'])
    contexts, affected = _graph_contexts(connection, body, target)
    effective = _now()
    decision = _evaluate(repo, connection, body, digest, contexts, policy, 'execute', effective, target)
    locator_frozen = canonical(decision.details['locator_verification_v1']) if 'locator_verification_v1' in decision.details else None
    if target['revision'] != body['expected_target_revision'] or policy['revision'] != body['expected_policy_revision']:
        raise ScalarCorrectionError('Scalar target or policy revision is stale')
    field = body['field_name']
    old = target['stable_attrs'].get(field) if body['record_type'] == 'workload' else target[field]
    if old != body['old_value'] or body['record_type'] == 'workload' and (type(old) is not str or not old):
        raise ScalarCorrectionError('Scalar old value is stale or ineligible')
    if body['record_type'] == 'workload':
        pinned = body['eligibility_rule']
        rule = connection.execute(sa.select(identity_rule_definitions).where(
            identity_rule_definitions.c.rule_id == pinned['rule_id'],
            identity_rule_definitions.c.rule_version == pinned['rule_version'])).mappings().first()
        from uvm.identity.resolver import RuleV1
        if (rule is None or rule['authorisation_decision_id'] is None
                or rule['definition_digest'] != pinned['definition_digest']
                or repo._rule_digest(RuleV1(rule['rule_id'], rule['rule_version'],
                    tuple(rule['workload_match_fields']), verified_asset_locator=rule['verified_asset_locator'])) != pinned['definition_digest']
                or field not in rule['workload_match_fields']):
            raise ScalarCorrectionError('Pinned scalar eligibility unavailable')
    history = validate_scalar_history(connection, body['record_type'], target)
    last_effective = instant(history[-1]['created_at']) if history else instant(target['created_at'])
    last_knowledge = max([instant(target['created_at'])] + [instant(r['_sidecar']['recorded_at'])
        if r['_sidecar'] else instant(r['created_at']) for r in history])
    if effective < last_effective:
        raise ScalarCorrectionError('Scalar server clock regressed')
    _collisions(connection, body, target)
    correction_id = str(uuid.uuid4()); committed_revision = target['revision'] + 1
    values = {'revision': committed_revision}
    if body['record_type'] == 'workload':
        values['stable_attrs'] = {**target['stable_attrs'], field: body['new_value']}
    else:
        values[field] = body['new_value']
    updated = connection.execute(table.update().where(table.c[body['record_type'] + '_id'] == body['record_id'],
        table.c.revision == body['expected_target_revision']).values(**values))
    if updated.rowcount != 1:
        raise ScalarCorrectionError('Scalar target revision changed')
    connection.execute(correction_records.insert().values(correction_id=correction_id,
        record_type=body['record_type'], record_id=body['record_id'], field_name=field,
        old_value=body['old_value'], new_value=body['new_value'], actor=body['principal_id'],
        reason=body['rationale'], correlation_id=body['correlation_id'], affected_record_ids=affected,
        created_at=effective, previous_revision=body['expected_target_revision'], new_revision=committed_revision,
        assessment_impact='unverified', issue_impact='unverified'))
    scope = target['workload_id'] if body['record_type'] == 'incarnation' else None
    alias_rows = connection.execute(sa.select(mapping_alias_events).where(
        mapping_alias_events.c.record_type == body['record_type'], mapping_alias_events.c.field_name == field,
        mapping_alias_events.c.scope_a == scope, mapping_alias_events.c.scope_b.is_(None),
        mapping_alias_events.c.old_value == body['new_value']).order_by(mapping_alias_events.c.event_sequence.desc())).mappings().first()
    events = []
    if alias_rows and alias_rows['action'] == 'activate':
        events.append(('retire', body['new_value']))
    if body['old_value'] is not None:
        events.append(('activate', body['old_value']))
    sequence = int(connection.execute(sa.select(sa.func.coalesce(sa.func.max(mapping_alias_events.c.event_sequence), 0))).scalar_one())
    alias_ids = []
    for action, value in events:
        sequence += 1; alias_id = str(uuid.uuid4()); alias_ids.append(alias_id)
        connection.execute(mapping_alias_events.insert().values(alias_event_id=alias_id,
            correction_id=correction_id, action=action, record_type=body['record_type'], field_name=field,
            scope_a=scope, scope_b=None, old_value=value, target_record_id=body['record_id'],
            evidence_ref=body['evidence_ref'], occurred_at=effective, event_sequence=sequence))
    recorded = _now()
    if recorded < effective or recorded < last_knowledge:
        raise ScalarCorrectionError('Scalar server clock regressed')
    final = _evaluate(repo, connection, body, digest, contexts, policy, 'execute', recorded, target, locator_frozen)
    decision = replace(decision, details={**decision.details,
        **({'locator_verification_v1': final.details['locator_verification_v1']} if locator_frozen is not None else {}), 'final_validation':
        {'evaluated_at': timestamp(recorded), 'policy_revision': str(policy['revision']),
         'grant_ids': final.details.get('grant_ids', [])}})
    repo._authorise(connection, body['action'], body['record_id'], {}, decision=decision)
    knowledge_sequence = int(connection.execute(sa.select(sa.func.coalesce(sa.func.max(receipts.c.knowledge_sequence), 0) + 1)).scalar_one())
    result = {name: body[name] for name in ('schema_version', 'request_id', 'principal_id', 'action',
        'record_type', 'record_id', 'field_name', 'expected_target_revision', 'expected_policy_revision', 'old_value', 'new_value')}
    result.update(status='committed', request_digest=digest, committed_target_revision=committed_revision,
        correction_id=correction_id, decision_id=decision.decision_id, affected_record_ids=affected,
        effective_at=timestamp(effective), recorded_at=timestamp(recorded), knowledge_sequence=knowledge_sequence,
        alias_event_ids=alias_ids, assessment_impact='unverified', issue_impact='unverified')
    connection.execute(receipts.insert().values(request_id=body['request_id'], schema_version=1,
        request_digest=digest, canonical_request=text, principal_id=body['principal_id'], action=body['action'],
        record_type=body['record_type'], record_id=body['record_id'], field_name=field,
        previous_revision=body['expected_target_revision'], new_revision=committed_revision,
        correction_id=correction_id, decision_id=decision.decision_id, recorded_at=recorded,
        knowledge_sequence=knowledge_sequence, scope_contexts=contexts, result=result))
    stored = connection.execute(sa.select(receipts).where(receipts.c.request_id == body['request_id'])).mappings().one()
    _, readback = _target(connection, body['record_type'], body['record_id'])
    validate_scalar_history(connection, body['record_type'], readback)
    if stored['result'] != result or readback['revision'] != committed_revision:
        raise ScalarCorrectionError('Scalar transaction readback failed')
    return result


def correct_scalar_field(repo, request, *, principal_id):
    body, text, digest = validate_request(request, principal_id)
    connection = repo.engine.connect()
    commit_started = False
    try:
        if connection.dialect.name == 'sqlite':
            connection = connection.execution_options(isolation_level='AUTOCOMMIT')
            connection.exec_driver_sql('BEGIN IMMEDIATE')
        result = _execute(repo, connection, body, text, digest)
        commit_started = True
        connection.commit()
        return result
    except sa.exc.DBAPIError as exc:
        if commit_started and not isinstance(exc, sa.exc.IntegrityError) and exc.connection_invalidated:
            return ScalarCorrectionOutcomeV1('unknown_commit', body['request_id'], digest)
        raise
    except ScalarHistoryUnavailable as exc:
        raise ScalarCorrectionError('Identity history unavailable') from exc
    finally:
        try:
            connection.rollback()
        except sa.exc.DBAPIError:
            pass
        connection.close()
