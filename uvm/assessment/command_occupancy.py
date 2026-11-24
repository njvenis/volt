"""One policy-locked occupancy check for the existing shared command ledgers.

Occupancy excludes conflicting writers. It never grants authority or by itself
proves commit/noncommit; callers retain their current authorization and recovery.
"""
from dataclasses import dataclass

import sqlalchemy as sa
from fastapi import HTTPException

from uvm.assessment.policy_lock import lock_policy
from uvm.persistence.assessment_schema import assessment_command_receipts, assessment_command_abandonments
from uvm.persistence.connector_schema import connector_receipts, connector_intents, connector_submissions
from uvm.persistence.local_recovery_schema import local_recovery_approvals


def family_for(action, storage='assessment'):
    if action.startswith('scanner.'):
        return 'scanner'
    if action == 'connector.recovery.clearance.apply':
        return 'connector'
    if action == 'connector.secret.submit':
        return 'secret_submission'
    if storage == 'connector':
        return 'connector'
    return 'local_auth' if action.startswith('local.') else 'assessment'


def _fail(status, code):
    raise HTTPException(status, {'code':code, 'message':'Command identity is already bound or inconsistent'})


@dataclass(frozen=True)
class CommandOccupancy:
    family: str
    principal_id: str
    action: str
    request_digest: str | None
    connector_id: str | None
    source_id: str | None
    secret_id: str | None
    version_id: str | None
    terminal: object = None


def read_occupancy(connection, command_id):
    lock_policy(connection)
    def rows(table, predicate):
        # Old portable unit fixtures create only their historical table slice.
        # PostgreSQL always requires the complete migrated shared ledger schema.
        if connection.dialect.name == 'sqlite' and not sa.inspect(connection).has_table(table.name):
            return []
        return connection.execute(sa.select(table).where(predicate).with_for_update()).mappings().all()
    assessment = rows(assessment_command_receipts, assessment_command_receipts.c.command_id == command_id)
    terminal = rows(assessment_command_abandonments, assessment_command_abandonments.c.command_id == command_id)
    receipts = rows(connector_receipts, connector_receipts.c.command_id == command_id)
    intents = rows(connector_intents, sa.and_(connector_intents.c.kind.in_(('scanner.command','connector.recovery.clearance.apply')),
        connector_intents.c.payload['command_id'].as_string() == command_id))
    submissions = rows(connector_submissions, connector_submissions.c.submission_id == command_id)
    consumed = rows(local_recovery_approvals, local_recovery_approvals.c.consumed_command_id == command_id)
    clearance = bool(receipts and receipts[0]['action']=='connector.recovery.clearance.apply')
    if clearance:
        value=receipts[0]['receipt']
        references=value.get('intents') if isinstance(value,dict) else None
        if not isinstance(references,list) or len(references)!=1 or not isinstance(references[0],dict):
            _fail(503,'inconsistent_operation')
        linked=rows(connector_intents,connector_intents.c.intent_id==references[0].get('intent_id'))
        if (len(linked)!=1 or linked[0]['kind']!='connector.recovery.clearance.apply'
                or linked[0]['status']!='complete' or len(consumed)!=1
                or consumed[0]['connector_id']!=receipts[0]['connector_id']
                or not isinstance(linked[0]['payload'],dict)
                or linked[0]['payload'].get('approval_id')!=consumed[0]['approval_id']):
            _fail(503,'inconsistent_operation')
        if intents and (len(intents)!=1 or intents[0]['intent_id']!=linked[0]['intent_id']):
            _fail(503,'inconsistent_operation')
        intents=linked
    elif consumed or any(row['kind']=='connector.recovery.clearance.apply' for row in intents):
        _fail(503,'inconsistent_operation')
    if any(len(values) > 1 for values in (assessment,terminal,receipts,intents,submissions,consumed)):
        _fail(503, 'inconsistent_operation')
    if terminal and (assessment or receipts or intents or submissions or consumed):
        _fail(503, 'inconsistent_operation')
    if assessment and (receipts or intents or submissions):
        _fail(503, 'inconsistent_operation')
    identities = []
    def add(family, actor, action, digest=None, connector=None, source=None, secret=None, version=None):
        identities.append((family,actor,action,digest,connector,source,secret,version))
    for row in assessment + terminal:
        add(family_for(row['action']),row['principal_id'],row['action'],row['request_digest'])
    for row in receipts:
        value = row['receipt'] if isinstance(row['receipt'],dict) else {}
        result = value.get('result') if isinstance(value.get('result'),dict) else {}
        projection = value.get('projection') if isinstance(value.get('projection'),dict) else {}
        add(family_for(row['action'],'connector'),row['actor_id'],row['action'],row['request_digest'],
            row['connector_id'],result.get('source_id') or projection.get('source_id'),
            result.get('secret_id'),result.get('version_id'))
    for row in intents:
        value = row['payload']
        if not isinstance(value,dict):_fail(503,'inconsistent_operation')
        if row['kind']=='connector.recovery.clearance.apply':
            if (value.get('command_id',command_id)!=command_id
                    or value.get('action','connector.recovery.clearance.apply')!='connector.recovery.clearance.apply'):
                _fail(503,'inconsistent_operation')
            add('connector',row['actor_id'],'connector.recovery.clearance.apply',value.get('request_digest'),
                row['connector_id'],value.get('source_id'))
        else:
            if not isinstance(value.get('action'),str):_fail(503,'inconsistent_operation')
            add('scanner',row['actor_id'],value['action'],value.get('request_digest'),
                row['connector_id'],value.get('source_id'))
    for row in submissions:
        add('secret_submission',row['actor_id'],'connector.secret.submit',None,
            row['connector_id'],row['source_id'],row['secret_id'],row['version_id'])
        if receipts:
            if row['outcome'] != 'committed' or row['receipt'] != receipts[0]['receipt']:
                _fail(503,'inconsistent_operation')
        elif row['outcome'] == 'committed':
            _fail(503,'inconsistent_operation')
    if not identities:
        return None
    merged = []
    for values in zip(*identities):
        defined = {value for value in values if value is not None}
        if len(defined) > 1:
            _fail(503,'inconsistent_operation')
        merged.append(next(iter(defined)) if defined else None)
    return CommandOccupancy(*merged, terminal=terminal[0] if terminal else None)


def guard_command(connection, command_id, *, family, principal_id, action,
                  request_digest=None, connector_id=None, source_id=None,
                  secret_id=None, version_id=None, allow_terminal=False):
    occupied = read_occupancy(connection, command_id)
    if occupied is None:
        return None
    if (occupied.family != family or occupied.principal_id != principal_id or occupied.action != action
            or request_digest is not None and occupied.request_digest is not None and occupied.request_digest != request_digest
            or connector_id is not None and occupied.connector_id is not None and occupied.connector_id != connector_id
            or source_id is not None and occupied.source_id is not None and occupied.source_id != source_id
            or secret_id is not None and occupied.secret_id is not None and occupied.secret_id != secret_id
            or version_id is not None and occupied.version_id is not None and occupied.version_id != version_id):
        _fail(409,'command_conflict')
    if occupied.terminal is not None and not allow_terminal:
        _fail(409,'command_terminal')
    return occupied


def guard_assessment(connection, command_id, principal_id, action, request_digest):
    return guard_command(connection,command_id,family=family_for(action),principal_id=principal_id,
        action=action,request_digest=request_digest)


def guard_connector(connection, command_id, principal_id, action, request_digest, connector_id):
    return guard_command(connection,command_id,family=family_for(action,'connector'),principal_id=principal_id,
        action=action,request_digest=request_digest,connector_id=connector_id)


def guard_submission(connection, submission_id, principal_id, connector_id, source_id, secret_id, version_id):
    return guard_command(connection,submission_id,family='secret_submission',principal_id=principal_id,
        action='connector.secret.submit',connector_id=connector_id,source_id=source_id,
        secret_id=secret_id,version_id=version_id)
