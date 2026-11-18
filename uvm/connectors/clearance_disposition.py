"""Narrow audited recovery for the original synchronous clearance command.

This never admits clearance, substitutes current revisions or grants authority.
Only a committed original receipt or an atomic audit/tombstone is definitive.
"""
from __future__ import annotations

import hashlib
import json
import uuid

import sqlalchemy as sa
from fastapi import HTTPException

from uvm.assessment.command_occupancy import guard_command
from uvm.assessment.policy_lock import lock_policy
from uvm.persistence.assessment_schema import assessment_audit_events,assessment_command_abandonments
from uvm.persistence.connector_schema import connectors,connector_receipts,connector_intents,connector_secret_heads
from uvm.persistence.local_recovery_schema import local_recovery_approvals

ACTION='connector.recovery.clearance.apply'
ABANDON_ACTION='connector.recovery.clearance.abandoned'
ZERO='00000000-0000-4000-8000-000000000000'
REVISIONS={'target','policy','identity_membership','owners','authority','connector','source','secret_source','secret'}
PAYLOAD={'connector_id','source_id','secret_id','version_id','recovery_epoch_id','rationale','evidence_ref'}


def command_schema():
    identifier={'type':'string','format':'uuid'}
    payload={'type':'object','properties':{key:identifier for key in PAYLOAD if key not in {'rationale','evidence_ref'}},
        'required':sorted(PAYLOAD),'additionalProperties':False}
    payload['properties'].update({key:{'type':'string','minLength':1} for key in ('rationale','evidence_ref')})
    fields={'schema_version':{'type':'integer','const':1},'command_id':identifier,'action':{'const':ACTION},
        'target_id':{'const':ZERO},'membership_ids':{'type':'array','maxItems':0},
        'expected_revisions':{'type':'object','properties':{key:{'type':'integer','minimum':0} for key in REVISIONS},
            'required':sorted(REVISIONS),'additionalProperties':False},'payload':payload}
    return {'type':'object','properties':fields,'required':list(fields),'additionalProperties':False}


def response_schemas():
    common={'schema_version':{'type':'integer','const':1},'command_id':{'type':'string','format':'uuid'},
        'action':{'const':ACTION},'actor_id':{'type':'string'},'request_digest':{'type':'string','pattern':'^[0-9a-f]{64}$'}}
    result=[]
    for disposition,extra in (('committed',{'receipt':{'type':'object'}}),('not_committed',{
            'audit_event_id':{'type':'string','format':'uuid'},'committed_at':{'type':'string','format':'date-time'}})):
        fields={**common,'disposition':{'const':disposition},**extra}
        result.append({'type':'object','properties':fields,'required':list(fields),'additionalProperties':False})
    return result


def fail(code='inconsistent_operation',status=503):
    raise HTTPException(status,{'code':code,'message':'Clearance command disposition is unavailable'})


def parse_original(command_id,body):
    from uvm.connectors.api import _uuid
    fields={'schema_version','command_id','action','target_id','membership_ids','expected_revisions','payload'}
    if (not isinstance(body,dict) or set(body)!={'schema_version','command','rationale','evidence_ref'}
            or type(body['schema_version']) is not int or body['schema_version']!=1
            or any(not isinstance(body[k],str) or not body[k].strip() or len(body[k])>2048
                for k in ('rationale','evidence_ref'))):fail('invalid_request',400)
    command=body['command']
    if (not isinstance(command,dict) or set(command)!=fields or type(command['schema_version']) is not int
            or command['schema_version']!=1 or command['command_id']!=command_id
            or command['action']!=ACTION or command['target_id']!=ZERO or command['membership_ids']!=[]
            or not isinstance(command['expected_revisions'],dict) or set(command['expected_revisions'])!=REVISIONS
            or any(type(v) is not int or v<0 for v in command['expected_revisions'].values())
            or not isinstance(command['payload'],dict) or set(command['payload'])!=PAYLOAD
            or any(not isinstance(command['payload'][k],str) or not command['payload'][k].strip()
                for k in ('rationale','evidence_ref'))):fail('invalid_request',400)
    _uuid(command_id,'command_id')
    for key in PAYLOAD-{'rationale','evidence_ref'}:_uuid(command['payload'][key],key)
    return command


def _proof(principal,command,digest):
    return {'schema_version':1,'command_id':command['command_id'],'action':ACTION,
        'actor_id':principal,'request_digest':digest}


def _safe_binding(command,digest):
    return {'command_id':command['command_id'],'action':ACTION,'request_digest':digest,
        **{k:command['payload'][k] for k in ('connector_id','source_id','secret_id','version_id','recovery_epoch_id')},
        'disposition':'not_committed'}


def _intent_complete(connection,row,command,digest,receipt):
    """Validate both original516 and indexed new complete synchronous footprints."""
    references=receipt.get('intents')
    result=receipt.get('result',{})
    if not isinstance(references,list) or len(references)!=1 or not isinstance(result,dict):fail()
    reference=references[0]
    if (not isinstance(reference,dict) or reference.get('kind')!=ACTION or reference.get('status')!='complete'
            or reference.get('target_id')!=row['connector_id']):fail()
    intent=connection.execute(sa.select(connector_intents).where(
        connector_intents.c.intent_id==reference.get('intent_id')).with_for_update()).mappings().one_or_none()
    if (intent is None or intent['kind']!=ACTION or intent['status']!='complete'
            or intent['actor_id']!=row['actor_id'] or intent['connector_id']!=row['connector_id']
            or intent['result']!={'state':'awaiting_activation'}):fail()
    value=intent['payload'];recovery=result.get('recovery',{})
    if not isinstance(value,dict) or not isinstance(recovery,dict):fail()
    indexed={'command_id','action','request_digest'} & set(value)
    if indexed and (indexed!={'command_id','action','request_digest'} or value['command_id']!=command['command_id']
            or value['action']!=ACTION or value['request_digest']!=digest):fail()
    if (value.get('source_id')!=command['payload']['source_id']
            or value.get('recovery_epoch_id')!=command['payload']['recovery_epoch_id']
            or value.get('configuration_revision')!=result.get('configuration_revision')
            or value.get('approval_id')!=recovery.get('approval_id')
            or recovery.get('recovery_epoch_id')!=command['payload']['recovery_epoch_id']
            or recovery.get('state')!='awaiting_activation'):fail()
    approval=connection.execute(sa.select(local_recovery_approvals).where(
        local_recovery_approvals.c.approval_id==value.get('approval_id')).with_for_update()).mappings().one_or_none()
    if approval is None or approval['consumed_command_id']!=command['command_id']:fail()
    document=approval['document']
    if not isinstance(document,dict) or any(document.get(k)!=command['payload'][k]
            for k in ('connector_id','source_id','secret_id','version_id','recovery_epoch_id')):fail()
    return intent


def _committed(connection,row,command,principal,digest):
    receipt=row['receipt'];payload=command['payload']
    if not isinstance(receipt,dict):fail()
    result=receipt.get('result')
    if (row['actor_id']!=principal or row['action']!=ACTION or row['request_digest']!=digest
            or row['connector_id']!=payload['connector_id']):fail('command_conflict',409)
    if (receipt.get('command_id')!=command['command_id'] or receipt.get('action')!=ACTION or receipt.get('target_id')!=ZERO
            or not isinstance(result,dict) or any(result.get(k)!=payload[k]
                for k in ('connector_id','source_id','secret_id','version_id'))):fail()
    _intent_complete(connection,row,command,digest,receipt)
    audit=connection.execute(sa.select(assessment_audit_events).where(
        assessment_audit_events.c.event_id==receipt.get('audit_event_id'))).mappings().one_or_none()
    if (audit is None or audit['command_id']!=command['command_id'] or audit['actor_id']!=principal
            or audit['action']!=ACTION or audit['origin']!='local_api' or audit['target_id']!=ZERO
            or audit['after_value']!=result):fail()
    return {**_proof(principal,command,digest),'disposition':'committed','receipt':receipt}


def _exclude_partial(connection,connector_id,command_id):
    # An audit-only stable state is not definitive rollback. A terminal audit
    # has a different fixed action and is validated separately.
    if connection.execute(sa.select(assessment_audit_events.c.event_id).where(
            assessment_audit_events.c.command_id==command_id,
            assessment_audit_events.c.action==ACTION)).first():fail()
    # Old516 payloads did not carry command_id. A complete linked receipt is
    # readable; an orphan on this connector cannot justify noncommit for any ID.
    legacy=connection.execute(sa.select(connector_intents).where(connector_intents.c.connector_id==connector_id,
        connector_intents.c.kind==ACTION,connector_intents.c.payload['command_id'].as_string().is_(None)).with_for_update()).mappings().all()
    if legacy:
        receipts=connection.execute(sa.select(connector_receipts).where(
            connector_receipts.c.connector_id==connector_id,connector_receipts.c.action==ACTION)).mappings().all()
        for intent in legacy:
            linked=[row for row in receipts if isinstance(row['receipt'],dict)
                and any(isinstance(entry,dict) and entry.get('intent_id')==intent['intent_id']
                    for entry in row['receipt'].get('intents',[]))]
            if len(linked)!=1 or intent['status']!='complete' or intent['result']!={'state':'awaiting_activation'}:fail()
            stored=linked[0];receipt=stored['receipt'];result=receipt.get('result');value=intent['payload']
            if (not isinstance(result,dict) or not isinstance(value,dict) or stored['actor_id']!=intent['actor_id']
                    or receipt.get('command_id')!=stored['command_id'] or receipt.get('action')!=ACTION
                    or result.get('connector_id')!=connector_id or result.get('source_id')!=value.get('source_id')
                    or result.get('configuration_revision')!=value.get('configuration_revision')
                    or not isinstance(result.get('recovery'),dict)
                    or result['recovery'].get('approval_id')!=value.get('approval_id')
                    or result['recovery'].get('recovery_epoch_id')!=value.get('recovery_epoch_id')):fail()
            approval=connection.execute(sa.select(local_recovery_approvals).where(
                local_recovery_approvals.c.approval_id==value.get('approval_id'))).mappings().one_or_none()
            audit=connection.execute(sa.select(assessment_audit_events).where(
                assessment_audit_events.c.event_id==receipt.get('audit_event_id'))).mappings().one_or_none()
            if (approval is None or approval['consumed_command_id']!=stored['command_id']
                    or audit is None or audit['command_id']!=stored['command_id']
                    or audit['actor_id']!=stored['actor_id'] or audit['action']!=ACTION
                    or audit['after_value']!=result):fail()


def abandon_clearance(app,command_id,body,request,principal):
    from uvm.auth.local import LocalAuth
    from uvm.connectors.api import _auth_context,_policy,_require,_qualys_slot,_now,_z
    from uvm.connectors.local_recovery import assert_profile_state
    command=parse_original(command_id,body);payload=command['payload']
    if not isinstance(getattr(app.state,'oidc_auth',None),LocalAuth):fail('forbidden',403)
    digest=hashlib.sha256(json.dumps({'principal_id':principal,**command},sort_keys=True,
        separators=(',',':')).encode('utf-8')).hexdigest()
    with app.state.engine.begin() as connection:
        lock_policy(connection);context=_auth_context(app,request,connection);policy=_policy(connection)
        if context is None or context.credential_mode!='local_session' or context.principal_id!=principal:fail('forbidden',403)
        row=connection.execute(sa.select(connectors).where(connectors.c.connector_id==payload['connector_id']).with_for_update()).mappings().one_or_none()
        if row is None:fail('not_found',404)
        if row['source_id']!=payload['source_id']:fail('source_scope_forbidden',403)
        _require(policy['document'],principal,'connector.configure',row)
        purpose=connection.execute(sa.select(connector_secret_heads.c.purpose).where(
            connector_secret_heads.c.connector_id==row['connector_id'],
            connector_secret_heads.c.secret_id==payload['secret_id'])).scalar_one_or_none()
        if _qualys_slot(connection,row['connector_id'],payload['secret_id'],purpose) is None:fail('forbidden',403)
        assert_profile_state(connection,row)
        occupied=guard_command(connection,command_id,family='connector',principal_id=principal,action=ACTION,
            request_digest=digest,connector_id=row['connector_id'],source_id=row['source_id'],
            secret_id=payload['secret_id'],version_id=payload['version_id'],allow_terminal=True)
        prior=connection.execute(sa.select(connector_receipts).where(connector_receipts.c.command_id==command_id).with_for_update()).mappings().one_or_none()
        if prior is not None:return _committed(connection,prior,command,principal,digest)
        _exclude_partial(connection,row['connector_id'],command_id)
        if occupied is not None and occupied.terminal is None:fail()
        safe=_safe_binding(command,digest)
        if occupied is not None:
            terminal=occupied.terminal
            event=connection.execute(sa.select(assessment_audit_events).where(
                assessment_audit_events.c.event_id==terminal['audit_event_id'])).mappings().one_or_none()
            if (event is None or event['command_id']!=command_id or event['actor_id']!=principal
                    or event['action']!=ABANDON_ACTION or event['target_id']!=row['connector_id']
                    or event['origin']!='local_api' or event['after_value']!=safe
                    or event['occurred_at']!=terminal['created_at']):fail()
            return {**_proof(principal,command,digest),'disposition':'not_committed',
                'audit_event_id':terminal['audit_event_id'],'committed_at':_z(terminal['created_at'])}
        now=_now(app);audit_id=str(uuid.uuid4())
        sequence=connection.execute(sa.select(sa.func.coalesce(sa.func.max(assessment_audit_events.c.event_sequence),0)+1)).scalar_one()
        connection.execute(assessment_audit_events.insert().values(event_id=audit_id,event_sequence=sequence,
            actor_id=principal,actor_kind='local_account',origin='local_api',action=ABANDON_ACTION,
            target_id=row['connector_id'],before_value={'command_id':command_id,'request_digest':digest},after_value=safe,
            membership_ids=[],membership_revision=0,rationale=body['rationale'].strip(),evidence_ref=body['evidence_ref'].strip(),
            policy_revision=policy['revision'],identity_revision=0,occurred_at=now,received_at=now,
            correlation_id=command_id,command_id=command_id,authorization_context=context.document()))
        connection.execute(assessment_command_abandonments.insert().values(command_id=command_id,principal_id=principal,
            action=ACTION,request_digest=digest,audit_event_id=audit_id,created_at=now))
        return {**_proof(principal,command,digest),'disposition':'not_committed',
            'audit_event_id':audit_id,'committed_at':_z(now)}
