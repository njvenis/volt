"""Explicit local recovery authority; no fallback to fixture schema1 proofs.

Private keys/proofs are never returned by a browser operation. Host mount and
journal admission remains the independent delivery authority, not a UUID check.
"""
from __future__ import annotations

import base64
from datetime import datetime, timezone
import hashlib
import hmac
import json
import os
import stat
import uuid
from dataclasses import dataclass

import sqlalchemy as sa
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from fastapi import HTTPException

from uvm.assessment.policy_lock import lock_policy
from uvm.persistence.auth_schema import local_auth_installation, local_capabilities, local_sessions
from uvm.persistence.local_recovery_schema import (
    local_recovery_installation as installations,
    local_recovery_attestations as attestations,
    local_recovery_approvals as approvals)

PROFILE = 'volt_local_recovery_v1'
UTC = timezone.utc


def fail(code='restore_quarantined', status=409):
    message=('Use a password that differs from every retained credential' if code=='credential_material_reused'
        else 'Local recovery authority or binding is unavailable')
    raise HTTPException(status, {'code':code,'message':message})


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode('utf-8')


def _unique(pairs):
    result = {}
    for key,value in pairs:
        if key in result:raise ValueError('duplicate recovery JSON member')
        result[key]=value
    return result


def _reject(_):
    raise ValueError('unsupported recovery JSON number')


def parse_document(raw):
    return json.loads(raw, object_pairs_hook=_unique, parse_float=_reject, parse_constant=_reject)


def private_read(path, *, limit=1_000_000, size=None):
    if not isinstance(path,str) or not os.path.isabs(path) or os.path.normpath(path)!=path:raise ValueError('private recovery path invalid')
    from pathlib import Path
    for component in (Path(path),*Path(path).parents):
        if component.is_symlink():raise ValueError('private recovery path is a symlink')
    fd=os.open(path,os.O_RDONLY|getattr(os,'O_NOFOLLOW',0))
    with os.fdopen(fd,'rb') as stream:
        info=os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode)!=0o600
                or info.st_uid not in {0,os.geteuid()} or info.st_size>limit):
            raise ValueError('private recovery file unsafe')
        data=stream.read(limit+1)
    if len(data)>limit or size is not None and len(data)!=size:raise ValueError('private recovery size invalid')
    return data


def _uuid(value):
    if not isinstance(value,str) or str(uuid.UUID(value))!=value:raise ValueError('recovery UUID invalid')
    return value


def enabled():
    return bool(os.environ.get('UVM_LOCAL_RECOVERY_CONFIG_FILE'))


@dataclass(frozen=True)
class Authority:
    config: dict
    issuer_private: bytes
    issuer_public: bytes
    operator_public: bytes
    material_key: bytes
    fingerprints: dict
    fence: dict

    @property
    def installation_id(self):return self.config['installation_id']

    def sign(self, document):
        return {**document,'signature':base64.b64encode(
            Ed25519PrivateKey.from_private_bytes(self.issuer_private).sign(canonical(document))).decode('ascii')}


def load_authority(local_config=None):
    try:
        from uvm.auth.local import load_local_config
        if os.environ.get('UVM_AUTH_MODE')!='local':raise ValueError('local mode required')
        local_config=local_config or load_local_config()
        path=os.environ['UVM_LOCAL_RECOVERY_CONFIG_FILE']
        config=parse_document(private_read(path))
        fields={'schema_version','profile','installation_id','issuer_key_id','operator_key_id','operator_id',
            'issuer_public_key_file','issuer_private_key_file','operator_public_key_file','material_key_file',
            'restore_fence_file','proof_store'}
        if (not isinstance(config,dict) or set(config)!=fields or type(config['schema_version']) is not int
                or config['schema_version']!=1 or config['profile']!=PROFILE
                or config['proof_store']!={'kind':'postgresql','schema_revision':'0067'}):raise ValueError('config schema invalid')
        for field in ('installation_id','issuer_key_id','operator_key_id'):_uuid(config[field])
        if (config['installation_id']!=local_config['installation_id']
                or config['issuer_key_id']==config['operator_key_id']
                or config['operator_id']!='local-host:'+config['installation_id']):raise ValueError('config identity invalid')
        names=('issuer_private_key_file','issuer_public_key_file','operator_public_key_file','material_key_file')
        if len({os.path.realpath(config[k]) for k in names})!=4:raise ValueError('key paths alias')
        seed,pub,operator,material=(private_read(config[k],size=32) for k in names)
        derived=Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)
        if derived!=pub or pub==operator or material in (seed,pub,operator):raise ValueError('keys are not independent')
        # Never permit AES storage material to become a recovery signing/binding key.
        from uvm.connectors.crypto import _key
        aes,storage_id=_key(local_config['secret_source']['key_path'])
        if storage_id!=local_config['secret_source']['secret_source_id']:
            raise ValueError('encrypted-local source identity changed')
        if (aes in (seed,material) or any(Ed25519PrivateKey.from_private_bytes(key).public_key().public_bytes(
                Encoding.Raw,PublicFormat.Raw)==operator for key in (aes,material))):raise ValueError('recovery key reused')
        fence=parse_document(private_read(config['restore_fence_file']))
        if (not isinstance(fence,dict) or set(fence)!={'schema_version','profile','installation_id',
                'journal_id','restore_generation','recovery_epoch_id'}
                or type(fence['schema_version']) is not int or fence['schema_version']!=1
                or fence['profile']!=PROFILE or fence['installation_id']!=config['installation_id']
                or type(fence['restore_generation']) is not int or fence['restore_generation']<0):raise ValueError('fence invalid')
        _uuid(fence['journal_id'])
        if fence['restore_generation']==0:
            if fence['recovery_epoch_id'] is not None:raise ValueError('initial fence has epoch')
        else:_uuid(fence['recovery_epoch_id'])
        fingerprints={k:hashlib.sha256(v).hexdigest() for k,v in zip(names,(seed,pub,operator,material))}
        fingerprints['encrypted_local_storage_key']=hashlib.sha256(aes).hexdigest()
        fingerprints['encrypted_local_source_id']=hashlib.sha256(storage_id.encode('ascii')).hexdigest()
        return Authority(config,seed,pub,operator,material,fingerprints,fence)
    except (OSError,ValueError,KeyError,TypeError,AttributeError,RuntimeError):
        fail('recovery_authority_unavailable',503)


def validate_binding(connection, authority, *, initialize=False, require_applied=False):
    lock_policy(connection)
    installed=connection.execute(sa.select(local_auth_installation).where(
        local_auth_installation.c.singleton_id==1).with_for_update()).mappings().one_or_none()
    if installed is None or installed['installation_id']!=authority.installation_id:fail('recovery_authority_unavailable',503)
    identities=connection.execute(sa.select(installations.c.installation_id).with_for_update()).scalars().all()
    if any(value!=authority.installation_id for value in identities):fail('recovery_authority_unavailable',503)
    digest=hashlib.sha256(canonical(authority.config)).hexdigest()
    row=connection.execute(sa.select(installations).where(
        installations.c.installation_id==authority.installation_id).with_for_update()).mappings().one_or_none()
    fence=authority.fence
    if row is None:
        if not initialize or fence['restore_generation']!=0 or installed['claimed_at'] is not None:
            fail('recovery_authority_unavailable',503)
        # Profile preparation precedes accounts/bootstrap authority. Missing
        # committed state is never inferred to mean an established install is new.
        from uvm.persistence.auth_schema import auth_principals,local_accounts
        from uvm.persistence.connector_schema import connectors
        from uvm.persistence.assessment_schema import assessment_policy
        if any(connection.execute(sa.select(sa.func.count()).select_from(table)).scalar_one()
                for table in (auth_principals,local_accounts,local_sessions,connectors)):
            fail('recovery_authority_unavailable',503)
        policies=connection.execute(sa.select(assessment_policy.c.document)).scalars().all()
        if any(value.get('native_authority',{}).get('bootstrap_admins') for value in policies):
            fail('recovery_authority_unavailable',503)
        connection.execute(installations.insert().values(installation_id=authority.installation_id,
            configuration_digest=digest,key_fingerprints=authority.fingerprints,journal_id=fence['journal_id'],
            applied_restore_generation=0,applied_recovery_epoch_id=None,applied_at=datetime.now(UTC)))
        row=connection.execute(sa.select(installations).where(
            installations.c.installation_id==authority.installation_id)).mappings().one()
    if (row['configuration_digest']!=digest or row['key_fingerprints']!=authority.fingerprints
            or row['journal_id']!=fence['journal_id']
            or fence['restore_generation']<row['applied_restore_generation']
            or fence['restore_generation']==row['applied_restore_generation']
                and fence['recovery_epoch_id']!=row['applied_recovery_epoch_id']
            or fence['restore_generation']>row['applied_restore_generation']
                and fence['recovery_epoch_id']==row['applied_recovery_epoch_id']):fail('recovery_authority_unavailable',503)
    if require_applied and (row['applied_restore_generation']!=fence['restore_generation']
            or row['applied_recovery_epoch_id']!=fence['recovery_epoch_id']):fail('recovery_authority_unavailable',503)
    return row


def startup_check(engine):
    authority=load_authority()
    with engine.begin() as connection:validate_binding(connection,authority,require_applied=True)


def maintenance_fence(engine, operation, local_config):
    from uvm.auth.local import LocalAuth
    authority=load_authority(local_config)
    now=datetime.now(UTC)
    with engine.begin() as connection:
        row=validate_binding(connection,authority,initialize=operation=='validate-local-recovery')
        fence=authority.fence
        counts={'revoked_sessions':0,'revoked_capabilities':0,'quarantined_connectors':0}
        status='validated'
        if operation=='apply-local-restore-fence':
            status='already_applied'
            if row['applied_restore_generation']!=fence['restore_generation']:
                from uvm.connectors.api import apply_restore_quarantine_connection
                counts['revoked_sessions']=connection.execute(local_sessions.update().where(
                    local_sessions.c.revoked_at.is_(None)).values(revoked_at=now,revision=local_sessions.c.revision+1)).rowcount
                counts['revoked_capabilities']=connection.execute(local_capabilities.delete().where(
                    local_capabilities.c.installation_id==authority.installation_id)).rowcount
                connection.execute(local_auth_installation.update().where(
                    local_auth_installation.c.singleton_id==1).values(setup_generation=local_auth_installation.c.setup_generation+1))
                counts['quarantined_connectors']=apply_restore_quarantine_connection(connection,fence['recovery_epoch_id'])
                connection.execute(approvals.update().where(approvals.c.installation_id==authority.installation_id,
                    approvals.c.superseded_at.is_(None)).values(superseded_at=now))
                connection.execute(installations.update().where(installations.c.installation_id==authority.installation_id).values(
                    applied_restore_generation=fence['restore_generation'],applied_recovery_epoch_id=fence['recovery_epoch_id'],applied_at=now))
                LocalAuth._audit(connection,'host-maintenance','local.recovery.restore_fence_applied',authority.installation_id,now,
                    after_value={**fence,**counts})
                status='applied'
    return {'schema_version':1,'profile':PROFILE,'operation':operation,
        'installation_id':authority.installation_id,'journal_id':fence['journal_id'],
        'restore_generation':fence['restore_generation'],'recovery_epoch_id':fence['recovery_epoch_id'],
        'status':status,**counts}


def recovery_view(connection, row, secret):
    from uvm.scanners.contracts import RecoveryView
    authority=load_authority()
    validate_binding(connection,authority,require_applied=True)
    recovery=row['recovery']
    if (recovery.get('state') not in {'clear','quarantined','awaiting_activation'}
            or recovery.get('recovery_epoch_id')!=authority.fence['recovery_epoch_id']):fail('recovery_authority_unavailable',503)
    fresh=False
    try:
        actual=current_secret(connection,row)
        current_attestation(connection,authority,row,actual)
        fresh=True
    except HTTPException:
        actual=None
    records=connection.execute(sa.select(approvals).where(approvals.c.connector_id==row['connector_id'],
        approvals.c.superseded_at.is_(None))).mappings().all()
    state='missing';approval_id=expires=None
    if len(records)>1:fail('inconsistent_operation',503)
    if records:
        record=records[0];approval_id=record['approval_id']
        proof=record['document']
        if not isinstance(proof,dict) or not isinstance(proof.get('expires_at'),str):fail('inconsistent_operation',503)
        expires=proof['expires_at']
        state='invalidated'
        if fresh and actual is not None:
            try:
                _approval_valid(connection,authority,row,actual,record['document'],check_time=False)
                state=('expired' if datetime.now(UTC)>=record['expires_at'] else
                    'applied' if record['consumed_command_id'] else 'available')
            except HTTPException:pass
    return RecoveryView(recovery['state'],recovery.get('recovery_epoch_id'),
        recovery.get('requires_fresh_credentials') is True,fresh,state,approval_id,expires)


def instant(value):
    if not isinstance(value,str) or not value.endswith('Z'):raise ValueError('UTC recovery timestamp required')
    result=datetime.fromisoformat(value[:-1]+'+00:00')
    if result.tzinfo is None or result.utcoffset().total_seconds()!=0:raise ValueError('UTC recovery timestamp required')
    return result


def stamp(value):return value.astimezone(UTC).isoformat().replace('+00:00','Z')


def source_tuple(row):return {k:row[k] for k in ('source_family','source_account_id','scope_key')}


def credential(raw):
    from uvm.scanners.contracts import QualysBasicCredential
    try:
        value=parse_document(raw)
        if (not isinstance(value,dict) or set(value)!={'username','password'}
                or any(not isinstance(value[k],str) for k in value)):raise ValueError('credential invalid')
        QualysBasicCredential(value['username'],value['password'].encode('utf-8')).close()
        return value
    except (ValueError,TypeError,UnicodeError):fail('credentials_unavailable')


def _context(authority,row,secret_id,version_id):
    return {'profile':PROFILE,'installation_id':authority.installation_id,
        'connector_id':row['connector_id'],'source_id':row['source_id'],'source_tuple':source_tuple(row),
        'secret_id':secret_id,'version_id':version_id,'purpose':'qualys_vm_basic',
        'recovery_epoch_id':row['recovery']['recovery_epoch_id']}


def _commitment(authority,context,value):
    return hmac.new(authority.material_key,b'VOLT.local-recovery.credential.v1\0'+
        canonical({**context,'credential':value}),hashlib.sha256).hexdigest()


def _verify(document,fields,public_key):
    try:
        if (not isinstance(document,dict) or set(document)!=fields or type(document['schema_version']) is not int
                or document['schema_version']!=2 or document['profile']!=PROFILE):raise ValueError('proof schema invalid')
        signature=base64.b64decode(document['signature'],validate=True)
        if len(signature)!=64:raise ValueError('signature invalid')
        Ed25519PublicKey.from_public_bytes(public_key).verify(signature,canonical(
            {k:v for k,v in document.items() if k!='signature'}))
    except Exception:fail()


_ATTESTATION_FIELDS={'schema_version','profile','document_type','attestation_id','installation_id',
    'issuer_key_id','connector_id','source_id','source_tuple','secret_id','version_id','purpose',
    'recovery_epoch_id','issued_at','issued_after_epoch','freshness_policy','credential_commitment','signature'}
_APPROVAL_FIELDS={'schema_version','profile','document_type','approval_id','installation_id','operator_key_id',
    'operator_id','connector_id','source_id','source_tuple','secret_id','version_id','purpose',
    'configuration_revision','recovery_epoch_id','attestation_sha256','rationale','evidence_ref',
    'issued_at','expires_at','signature'}


def attest_fresh(connection,row,secret_id,version_id,raw):
    """Caller holds policy/connector/allocated-slot locks; commit with encryption/audit."""
    from uvm.persistence.connector_schema import connector_secrets
    from uvm.connectors.crypto import decrypt,SecretUnavailable
    authority=load_authority();binding=validate_binding(connection,authority,require_applied=True)
    if (row['recovery'].get('state') not in {'quarantined','awaiting_activation'} or authority.fence['recovery_epoch_id'] is None
            or row['recovery'].get('recovery_epoch_id')!=authority.fence['recovery_epoch_id']):fail()
    value=credential(raw)
    def equality(password):
        return hmac.new(authority.material_key,b'VOLT.local-recovery.password-equality.v1\0'+canonical({
            'installation_id':authority.installation_id,'connector_id':row['connector_id'],
            'secret_id':secret_id,'purpose':'qualys_vm_basic','password':password}),hashlib.sha256).digest()
    candidate=equality(value['password']);reused=False
    versions=connection.execute(sa.select(connector_secrets).where(
        connector_secrets.c.connector_id==row['connector_id'],connector_secrets.c.secret_id==secret_id).with_for_update()).mappings().all()
    for version in versions:
        if version['purpose']!='qualys_vm_basic':fail('credentials_unavailable')
        try:prior=credential(decrypt(version,row['connector_id'],secret_id,version['version_id']))
        except SecretUnavailable:fail('credentials_unavailable')
        reused=hmac.compare_digest(candidate,equality(prior['password'])) or reused
        del prior
    if reused:fail('credential_material_reused')
    now=datetime.now(UTC)
    if now<binding['applied_at']:fail()
    context=_context(authority,row,secret_id,version_id)
    document=authority.sign({'schema_version':2,**context,'document_type':'credential_attestation',
        'attestation_id':str(uuid.uuid4()),'issuer_key_id':authority.config['issuer_key_id'],
        'issued_at':stamp(now),'issued_after_epoch':True,'freshness_policy':'no_retained_password_reuse_v1',
        'credential_commitment':_commitment(authority,context,value)})
    connection.execute(attestations.insert().values(attestation_id=document['attestation_id'],
        installation_id=authority.installation_id,connector_id=row['connector_id'],secret_id=secret_id,
        version_id=version_id,recovery_epoch_id=context['recovery_epoch_id'],document=document,issued_at=now))
    del value
    return document


def current_secret(connection,row,*,secret_id=None,version_id=None):
    from uvm.persistence.connector_binding_schema import connector_bindings
    from uvm.persistence.connector_schema import connector_secrets
    registration=connection.execute(sa.select(connector_bindings.c.registration).where(
        connector_bindings.c.connector_id==row['connector_id']).with_for_update()).scalar_one_or_none()
    if not registration or registration.get('product')!='qualys_vm':fail()
    slot=registration['credential_slots']['qualys_vm_basic']['secret_id']
    if secret_id is not None and secret_id!=slot:fail()
    secret=connection.execute(sa.select(connector_secrets).where(connector_secrets.c.connector_id==row['connector_id'],
        connector_secrets.c.secret_id==slot,connector_secrets.c.state=='active').with_for_update()).mappings().one_or_none()
    if (secret is None or secret['purpose']!='qualys_vm_basic' or secret['quarantine']!='clear'
            or version_id is not None and secret['version_id']!=version_id):fail()
    return secret


def current_attestation(connection,authority,row,secret):
    from uvm.connectors.crypto import decrypt,SecretUnavailable
    binding=validate_binding(connection,authority,require_applied=True)
    context=_context(authority,row,secret['secret_id'],secret['version_id'])
    if context['recovery_epoch_id'] is None or context['recovery_epoch_id']!=authority.fence['recovery_epoch_id']:fail()
    item=connection.execute(sa.select(attestations).where(attestations.c.connector_id==row['connector_id'],
        attestations.c.secret_id==secret['secret_id'],attestations.c.version_id==secret['version_id'],
        attestations.c.recovery_epoch_id==context['recovery_epoch_id'])).mappings().one_or_none()
    if item is None:fail()
    document=item['document'];_verify(document,_ATTESTATION_FIELDS,authority.issuer_public)
    if item['attestation_id']!=document['attestation_id']:fail('inconsistent_operation',503)
    try:
        _uuid(document['attestation_id'])
        if (any(document[k]!=v for k,v in context.items()) or document['document_type']!='credential_attestation'
                or document['issuer_key_id']!=authority.config['issuer_key_id'] or document['issued_after_epoch'] is not True
                or document['freshness_policy']!='no_retained_password_reuse_v1'
                or not binding['applied_at']<=instant(document['issued_at'])<=datetime.now(UTC)):fail()
        value=credential(decrypt(secret,row['connector_id'],secret['secret_id'],secret['version_id']))
        if not hmac.compare_digest(document['credential_commitment'],_commitment(authority,context,value)):fail()
        del value
    except (ValueError,TypeError,KeyError,SecretUnavailable):fail()
    return document


def _approval_valid(connection,authority,row,secret,document,*,check_time=True):
    from datetime import timedelta
    attestation=current_attestation(connection,authority,row,secret)
    _verify(document,_APPROVAL_FIELDS,authority.operator_public)
    try:
        _uuid(document['approval_id'])
        context=_context(authority,row,secret['secret_id'],secret['version_id'])
        issued,expires=instant(document['issued_at']),instant(document['expires_at']);now=datetime.now(UTC)
        if (any(document[k]!=v for k,v in context.items()) or document['document_type']!='operator_clearance'
                or document['operator_key_id']!=authority.config['operator_key_id']
                or document['operator_id']!=authority.config['operator_id']
                or type(document['configuration_revision']) is not int
                or document['configuration_revision']!=row['configuration_revision']
                or document['attestation_sha256']!=hashlib.sha256(canonical(attestation)).hexdigest()
                or not instant(attestation['issued_at'])<=issued<=now
                or not timedelta(0)<expires-issued<=timedelta(minutes=15)
                or check_time and now>=expires
                or any(not isinstance(document[k],str) or not document[k].strip() or len(document[k])>2048
                    for k in ('rationale','evidence_ref'))):fail()
    except (ValueError,TypeError,KeyError):fail()
    return document


def current_approval(connection,authority,row,secret,*,applied=False):
    rows=connection.execute(sa.select(approvals).where(approvals.c.connector_id==row['connector_id'],
        approvals.c.superseded_at.is_(None)).with_for_update()).mappings().all()
    if len(rows)!=1:fail()
    record=rows[0]
    _approval_valid(connection,authority,row,secret,record['document'])
    if (record['approval_id']!=record['document']['approval_id']
            or record['installation_id']!=authority.installation_id
            or record['issued_at']!=instant(record['document']['issued_at'])
            or record['expires_at']!=instant(record['document']['expires_at'])):fail('inconsistent_operation',503)
    if applied and (not record['consumed_command_id'] or row['recovery'].get('approval_id')!=record['approval_id']):fail()
    return record


def require_recovery_lease(connection,row,secret,*,activation=False):
    authority=load_authority();validate_binding(connection,authority,require_applied=True)
    if row['recovery'].get('state')!='awaiting_activation' or not row['recovery'].get('requires_fresh_credentials'):fail()
    actual=current_secret(connection,row,secret_id=secret['secret_id'],version_id=secret['version_id'])
    record=current_approval(connection,authority,row,actual,applied=True)
    if activation:
        from datetime import timedelta
        from uvm.scanners.store import read_configuration
        config=read_configuration(connection,row['connector_id'],row['source_id']);proof=config['validation'] if config else None
        if (not proof or proof['status']!='succeeded' or proof['configuration_revision']!=row['configuration_revision']
                or proof['credential_version_id']!=secret['version_id']
                or proof['restore_epoch_id']!=row['recovery']['recovery_epoch_id']):fail('validation_required')
        try:
            if not timedelta(0)<=datetime.now(UTC)-datetime.fromisoformat(proof['checked_at'])<=timedelta(minutes=15):fail('validation_required')
        except (TypeError,ValueError):fail('validation_required')
    return record


def invalidate_workflow(connection,row,*,now=None):
    """Credential/configuration/approval changes cannot retain a previous test."""
    from uvm.scanners.store import read_configuration,update_configuration
    now=now or datetime.now(UTC)
    connection.execute(approvals.update().where(approvals.c.connector_id==row['connector_id'],
        approvals.c.superseded_at.is_(None)).values(superseded_at=now))
    if read_configuration(connection,row['connector_id'],row['source_id']):
        update_configuration(connection,row['connector_id'],row['source_id'],validation=None,active_snapshot=None)
    recovery=row['recovery']
    if recovery.get('state')!='clear':
        recovery={**recovery,'state':'quarantined','operator_clearance_present':False,'requires_fresh_credentials':True}
        recovery.pop('approval_id',None);recovery.pop('approval_expires_at',None)
    return recovery


def _target(connection,connector_id,source_id):
    from uvm.persistence.connector_schema import connectors
    _uuid(connector_id);_uuid(source_id)
    row=connection.execute(sa.select(connectors).where(connectors.c.connector_id==connector_id).with_for_update()).mappings().one_or_none()
    if row is None or row['source_id']!=source_id or row['source_family']!='qualys':fail()
    return row


def maintenance_request(engine,operation,document,local_config):
    authority=load_authority(local_config)
    try:
        fields={'schema_version','profile','installation_id'}
        if operation=='scanner-recovery-request':fields|={'connector_id','source_id','configuration_revision','rationale','evidence_ref'}
        if (not isinstance(document,dict) or set(document)!=fields or type(document['schema_version']) is not int
                or document['schema_version']!=1 or document['profile']!=PROFILE
                or document['installation_id']!=authority.installation_id):fail('invalid_request',400)
        with engine.begin() as connection:
            validate_binding(connection,authority,require_applied=True)
            if operation=='scanner-recovery-targets':
                from uvm.persistence.connector_schema import connectors
                from uvm.persistence.connector_binding_schema import connector_bindings
                rows=connection.execute(sa.select(connectors,connector_bindings.c.display_name,
                    connector_bindings.c.registration).join(connector_bindings,
                    connector_bindings.c.connector_id==connectors.c.connector_id)).mappings().all()
                return {'schema_version':1,'profile':PROFILE,'installation_id':authority.installation_id,'targets':[
                    {'connector_id':r['connector_id'],'source_id':r['source_id'],'display_name':r['display_name'],
                        'account_label':r['registration']['account_label'],'platform_id':r['registration']['platform_id'],
                        'state':r['recovery']['state'],'configuration_revision':r['configuration_revision']}
                    for r in rows if r['registration'].get('product')=='qualys_vm']}
            if (type(document['configuration_revision']) is not int
                    or any(not isinstance(document[k],str) or not document[k].strip() or len(document[k])>2048
                        for k in ('rationale','evidence_ref'))):fail('invalid_request',400)
            row=_target(connection,document['connector_id'],document['source_id'])
            if (row['configuration_revision']!=document['configuration_revision']
                    or row['configuration_revision']<1 or row['recovery']['state'] not in {'quarantined','awaiting_activation'}):fail()
            secret=current_secret(connection,row)
            attestation=current_attestation(connection,authority,row,secret)
            from uvm.persistence.connector_binding_schema import connector_bindings
            registration=connection.execute(sa.select(connector_bindings).where(
                connector_bindings.c.connector_id==row['connector_id'])).mappings().one()
            return {'schema_version':1,'profile':PROFILE,'operation':'scanner_recovery_approval_request',
                'installation_id':authority.installation_id,'operator_key_id':authority.config['operator_key_id'],
                'operator_id':authority.config['operator_id'],'journal_id':authority.fence['journal_id'],
                'restore_generation':authority.fence['restore_generation'],
                'recovery_epoch_id':authority.fence['recovery_epoch_id'],
                'target':{k:v for k,v in {**_context(authority,row,secret['secret_id'],secret['version_id']),
                    'configuration_revision':row['configuration_revision'],'display_name':registration['display_name'],
                    'account_label':registration['registration']['account_label']}.items()
                    if k not in {'profile','installation_id','recovery_epoch_id'}},
                'attestation':attestation,'attestation_sha256':hashlib.sha256(canonical(attestation)).hexdigest(),
                'rationale':document['rationale'],'evidence_ref':document['evidence_ref']}
    except (ValueError,KeyError,TypeError):fail('invalid_request',400)


def _record_host_import(connection,authority,row,document,now):
    from uvm.assessment.command_occupancy import guard_connector
    from uvm.persistence.assessment_schema import assessment_policy,assessment_audit_events
    from uvm.persistence.connector_schema import connector_receipts,connector_intents
    command_id,audit_id,intent_id,decision_id=(str(uuid.uuid4()) for _ in range(4))
    action='connector.recovery.approval.import';actor=authority.config['operator_id']
    digest=hashlib.sha256(canonical({'approval_id':document['approval_id'],
        'installation_id':authority.installation_id,'connector_id':row['connector_id']})).hexdigest()
    guard_connector(connection,command_id,actor,action,digest,row['connector_id'])
    policy_revision=connection.execute(sa.select(assessment_policy.c.revision).where(assessment_policy.c.policy_id==1)).scalar_one()
    sequence=connection.execute(sa.select(sa.func.coalesce(sa.func.max(assessment_audit_events.c.event_sequence),0)+1)).scalar_one()
    safe={'connector_id':row['connector_id'],'source_id':row['source_id'],
        'approval_id':document['approval_id'],'approval_expires_at':document['expires_at'],'state':'quarantined'}
    connection.execute(assessment_audit_events.insert().values(event_id=audit_id,event_sequence=sequence,
        actor_id=actor,actor_kind='host_maintenance',origin='local_recovery_maintenance',action=action,
        target_id=row['connector_id'],before_value={'recovery_state':row['recovery']['state']},after_value=safe,
        membership_ids=[],membership_revision=0,rationale=document['rationale'],evidence_ref=document['evidence_ref'],
        policy_revision=policy_revision,identity_revision=0,occurred_at=now,received_at=now,correlation_id=command_id,
        command_id=command_id,authorization_context={'credential_mode':'host_maintenance',
            'installation_id':authority.installation_id,'profile':PROFILE,'operator_id':actor}))
    connection.execute(connector_intents.insert().values(intent_id=intent_id,connector_id=row['connector_id'],
        kind=action,actor_id=actor,status='complete',attempts=1,payload=safe,result=safe,created_at=now,updated_at=now))
    receipt={'schema_version':1,'command_id':command_id,'action':action,'target_id':row['connector_id'],
        'policy_revision':policy_revision,'decision_id':decision_id,'audit_event_id':audit_id,
        'intents':[{'intent_id':intent_id,'kind':action,'target_id':row['connector_id'],'status':'complete'}],
        'result':safe}
    connection.execute(connector_receipts.insert().values(connector_id=row['connector_id'],command_id=command_id,
        actor_id=actor,action=action,request_digest=digest,receipt=receipt,created_at=now))
    return {'schema_version':1,'profile':PROFILE,'operation':'scanner_recovery_import',
        'installation_id':authority.installation_id,'connector_id':row['connector_id'],'source_id':row['source_id'],
        'approval_id':document['approval_id'],'approval_expires_at':document['expires_at'],
        'state':'imported','audit_event_id':audit_id,'command_id':command_id}


def maintenance_import(engine,document,local_config):
    from uvm.persistence.connector_schema import connectors
    authority=load_authority(local_config)
    _verify(document,_APPROVAL_FIELDS,authority.operator_public)
    try:
        with engine.begin() as connection:
            validate_binding(connection,authority,require_applied=True)
            row=_target(connection,document['connector_id'],document['source_id'])
            secret=current_secret(connection,row,secret_id=document['secret_id'],version_id=document['version_id'])
            prior=connection.execute(sa.select(approvals).where(approvals.c.approval_id==document['approval_id']).with_for_update()).mappings().one_or_none()
            # An exact import replay returns its original immutable acknowledgement;
            # it neither extends expiry nor changes current workflow state.
            if prior is not None:
                if prior['document']!=document:fail('command_conflict')
                _approval_valid(connection,authority,row,secret,document,check_time=False)
                return prior['acknowledgement']
            _approval_valid(connection,authority,row,secret,document)
            if row['recovery']['state'] not in {'quarantined','awaiting_activation'}:fail()
            now=datetime.now(UTC)
            recovery=invalidate_workflow(connection,row,now=now)
            connection.execute(connectors.update().where(connectors.c.connector_id==row['connector_id']).values(
                recovery=recovery,lifecycle='disabled',active_configuration_revision=None,
                connector_revision=row['connector_revision']+1,updated_at=now))
            ack=_record_host_import(connection,authority,row,document,now)
            connection.execute(approvals.insert().values(approval_id=document['approval_id'],installation_id=authority.installation_id,
                connector_id=row['connector_id'],document=document,acknowledgement=ack,consumed_command_id=None,
                superseded_at=None,issued_at=instant(document['issued_at']),expires_at=instant(document['expires_at'])))
            return ack
    except (ValueError,KeyError,TypeError):fail()


def apply_clearance(connection,row,secret_id,version_id,epoch,command_id):
    authority=load_authority();validate_binding(connection,authority,require_applied=True)
    if (row['recovery']['state']!='quarantined' or row['recovery']['recovery_epoch_id']!=epoch
            or row['lifecycle']!='disabled' or row['active_configuration_revision'] is not None):fail()
    secret=current_secret(connection,row,secret_id=secret_id,version_id=version_id)
    record=current_approval(connection,authority,row,secret)
    if record['consumed_command_id'] is not None:fail('command_conflict')
    connection.execute(approvals.update().where(approvals.c.approval_id==record['approval_id']).values(consumed_command_id=command_id))
    from uvm.scanners.store import read_configuration,update_configuration
    if read_configuration(connection,row['connector_id'],row['source_id']):
        update_configuration(connection,row['connector_id'],row['source_id'],validation=None,active_snapshot=None)
    return {**row['recovery'],'state':'awaiting_activation','requires_fresh_credentials':True,
        'operator_clearance_present':True,'approval_id':record['approval_id'],
        'approval_expires_at':record['document']['expires_at']}


def assert_profile_state(connection,row):
    authority=load_authority()
    validate_binding(connection,authority,require_applied=True)
    if row['recovery'].get('recovery_epoch_id')!=authority.fence['recovery_epoch_id']:fail('recovery_authority_unavailable',503)
    return authority
