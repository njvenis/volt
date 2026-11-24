"""Fixed host-authorised initialization of the adopted local source-only rule."""
from __future__ import annotations

import hashlib
import json
import os
import uuid
from datetime import datetime, timezone

import sqlalchemy as sa

from uvm.auth.local import load_local_config
from uvm.connectors.crypto import _key
from uvm.persistence.auth_schema import local_auth_installation
from uvm.persistence.assessment_schema import assessment_policy
from uvm.persistence.identity_repository import AuthorisationDecision, IdentityRepository
from uvm.scanners.service import qualys_source_only_rule


def initialize_scanner_rule(engine, config):
    """No caller-selected rule, action, actor or public authority is admitted."""
    if os.environ.get('UVM_AUTH_MODE') != 'local' or engine.dialect.name != 'postgresql':
        raise RuntimeError('local PostgreSQL maintenance authority is required')
    initial_key, key_id = _key(config['secret_source']['key_path'])
    if key_id != config['secret_source']['secret_source_id']:
        raise RuntimeError('local secret-source identity changed')
    key_digest = hashlib.sha256(initial_key).digest()
    del initial_key
    installation = config['installation_id']
    configuration_digest = hashlib.sha256(json.dumps(config, sort_keys=True,
        separators=(',', ':')).encode()).hexdigest()
    rule = qualys_source_only_rule()
    if (rule.rule_id != 'qualys_vm_source_only_v1' or rule.rule_version != 1
            or rule.workload_match_fields != ('provisioning_key',)
            or rule.verified_asset_locator is not False or rule.workload_context_fields != ()):
        raise RuntimeError('adopted scanner rule definition changed')
    definition_digest = IdentityRepository._rule_digest(rule)
    target = str(uuid.uuid5(uuid.NAMESPACE_URL,
        f'identity-rule:{rule.rule_id}:{rule.rule_version}:{definition_digest}'))
    expected_context = {'request_id':target, 'rule_id':rule.rule_id,
        'rule_version':rule.rule_version, 'definition_digest':definition_digest}
    lock_key = int.from_bytes(hashlib.sha256(
        ('volt-local-scanner-rule-v1\0'+installation).encode()).digest()[:8], 'big', signed=True)
    with engine.connect() as guard:
        acquired = False
        try:
            guard.execute(sa.text('select pg_advisory_lock(:key)'), {'key':lock_key})
            guard.commit()
            acquired = True

            def validate_host_invocation():
                if os.environ.get('UVM_AUTH_MODE') != 'local' or load_local_config() != config:
                    raise RuntimeError('validated local maintenance configuration changed')
                current_key, current_id = _key(config['secret_source']['key_path'])
                if current_id != key_id or hashlib.sha256(current_key).digest() != key_digest:
                    raise RuntimeError('validated local maintenance key changed')
                del current_key
                persisted = guard.execute(sa.select(local_auth_installation.c.installation_id).where(
                    local_auth_installation.c.singleton_id == 1)).scalar_one_or_none()
                revision = guard.execute(sa.select(assessment_policy.c.revision).where(
                    assessment_policy.c.policy_id == 1)).scalar_one_or_none()
                guard.commit()
                if persisted != installation:
                    raise RuntimeError('persisted local installation does not match host authority')
                return int(revision or 0)

            validate_host_invocation()

            def authorise(action, target_id, context):
                if action != 'identity.rule_provision' or target_id != target or context != expected_context:
                    raise RuntimeError('host scanner rule maintenance denied')
                policy_revision = validate_host_invocation()
                return AuthorisationDecision(str(uuid.uuid4()), True,
                    'host-maintenance:'+installation, action, target,
                    'installation:'+installation+'/rule:'+rule.rule_id+'/1', str(policy_revision),
                    'Initialize the adopted immutable source-only Qualys rule',
                    'local-maintenance:initialize-scanner-rule:'+configuration_digest,
                    target, datetime.now(timezone.utc), {
                        'installation_id':installation, 'host_effective_uid':os.geteuid(),
                        'configuration_sha256':configuration_digest,
                        'configuration_contract':'easy-compose-install/qualys-source-only-v1',
                        'secret_source_id':key_id, 'definition_digest':definition_digest,
                        'application_policy_revision':policy_revision})

            # Session ownership spans the repository's independent transaction.
            # No outer policy transaction holds locks needed by this service.
            IdentityRepository(engine, authorise).provision_rule(rule, datetime.now(timezone.utc))
        finally:
            if acquired:
                try:
                    guard.execute(sa.text('select pg_advisory_unlock(:key)'), {'key':lock_key})
                    guard.commit()
                finally:
                    guard.close()
