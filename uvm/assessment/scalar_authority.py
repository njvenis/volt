"""Current transaction-local authority for the two approved scalar actions."""
from datetime import datetime, timezone
import hashlib
import json
import uuid
import sqlalchemy as sa
from uvm.persistence.identity_repository import AuthorisationDecision
from uvm.persistence.scalar_contract import canonical, ScalarCorrectionError


def _effective(record, at):
    try:
        def instant(value):
            return datetime.fromisoformat(value.replace('Z', '+00:00'))
        return ((not record.get('effective_from') or instant(record['effective_from']) <= at)
                and (not record.get('effective_until') or instant(record['effective_until']) > at))
    except (TypeError, ValueError, AttributeError):
        return False


def _covers(rule, action, field, context, *, deny=False):
    actions = rule.get('actions') or []
    if action not in actions and '*' not in actions:
        return False
    targets = rule.get('target_ids') or []
    scope = rule.get('target_scope') or {}
    group = context.get('group_id')
    if deny:
        if targets and '*' not in targets and context['record_id'] not in targets and group not in targets:
            return False
    else:
        selected = scope.get('group_ids') or targets
        if '*' not in selected and (group or context['record_id']) not in selected:
            return False
    for selector, attr in [('group_ids', 'group_id'), ('source_families', 'source_family'),
                           ('environments', 'environment'), ('service_ids', 'service_id')]:
        allowed = scope.get(selector) or []
        value = context.get(attr)
        if allowed and (value is None or '*' not in allowed and value not in allowed):
            return False
    limits = rule.get('limits') or {}
    for selector, attr in [('allowed_environments', 'environment'), ('allowed_service_ids', 'service_id')]:
        allowed = limits.get(selector) or []
        value = context.get(attr)
        if allowed and (value is None or '*' not in allowed and value not in allowed):
            return False
    fields = limits.get('allowed_identity_scalar_fields') or {}
    if deny:
        return not fields or field in fields.get(action, [])
    return isinstance(fields, dict) and field in fields.get(action, [])


class ScalarPolicyEvaluator:
    """Uses only the locked policy/connection supplied by the repository."""

    def __init__(self, locator_supplier=None):
        # Internal operator composition; never a member of a scalar request.
        self.locator_supplier = locator_supplier

    @staticmethod
    def complete_grants(policy, principal_id, action, field, scope_contexts, evaluated_at):
        principal = policy.get('principals', {}).get(principal_id)
        if not isinstance(principal, dict) or principal.get('enabled') is False or not _effective(principal, evaluated_at):
            raise ScalarCorrectionError('Current scalar authority unavailable')
        identities = {principal_id}
        directory = {x.get('owner_id'): x for x in policy.get('owner_directory', [])}
        for team_id in principal.get('team_ids', []):
            team = directory.get(team_id)
            if team and team.get('owner_type') == 'team' and team.get('enabled', True) and _effective(team, evaluated_at):
                identities.add(team_id)
        grants = []
        for grant in policy.get('grants', []):
            if grant.get('role_id') in policy.get('roles', {}):
                role = policy['roles'][grant['role_id']]
                grant = {**role, **grant, 'actions': role.get('actions', []),
                         'target_scope': role.get('target_scope', {}), 'limits': role.get('limits', {})}
            if grant.get('principal_id') in identities | {'*'} and _effective(grant, evaluated_at):
                grants.append(grant)
        chosen = []
        # Contexts for one typed affected target must all be covered by a
        # single complete grant. Old/proposed/current fragments cannot combine.
        targets = {}
        for context in scope_contexts:
            targets.setdefault((context['record_type'], context['record_id']), []).append(context)
            if any(deny.get('principal_id') in identities | {'*'} and _effective(deny, evaluated_at)
                   and _covers(deny, action, field, context, deny=True) for deny in policy.get('denies', [])):
                raise ScalarCorrectionError('Current scalar authority unavailable')
        for contexts in targets.values():
            complete = [grant for grant in grants if all(_covers(grant, action, field, context) for context in contexts)]
            if not complete:
                raise ScalarCorrectionError('Current scalar authority unavailable')
            chosen.append(sorted(grant.get('grant_id', '') for grant in complete)[0])
        if not targets:
            raise ScalarCorrectionError('Current scalar authority unavailable')
        return sorted(set(chosen))

    def evaluate_scalar_on_connection(self, connection, *, principal_id, action,
            target_id, canonical_request, scope_contexts, purpose, policy_row, evaluated_at,
            original_target=None, locator_frozen=None):
        if purpose not in {'execute', 'replay_disclosure'} or policy_row is None:
            raise ScalarCorrectionError('Current scalar authority unavailable')
        policy = policy_row['document']
        chosen = self.complete_grants(policy, principal_id, action,
            canonical_request['field_name'], scope_contexts, evaluated_at)
        details = {}
        if purpose == 'execute' and canonical_request['record_type'] == 'incarnation' and canonical_request['new_value'] is not None:
            from uvm.assessment.locator_verification import RegisteredLocatorSupplier, sha, stamp
            supplier = self.locator_supplier
            if type(supplier) is not RegisteredLocatorSupplier or original_target is None:
                raise ScalarCorrectionError('Locator verification unavailable')
            proof = (supplier.obtain(canonical_request) if locator_frozen is None else
                json.loads(locator_frozen)['assertion'])
            proof = supplier.validate(connection, proof, canonical_request, original_target, evaluated_at)
            supplier_grants = self.complete_grants(policy, proof['registration']['supplier_principal'],
                action, canonical_request['field_name'], scope_contexts, evaluated_at)
            record = {'evaluated_at': stamp(evaluated_at), 'policy_revision': str(policy_row['revision']),
                'requester_grant_ids': chosen, 'supplier_grant_ids': supplier_grants,
                'registration_digest': sha(canonical(proof['registration']).encode()),
                'original_revision': original_target['revision'], 'intended_value': canonical_request['new_value']}
            if locator_frozen is None:
                provenance = {'assertion': proof, 'assertion_canonical': canonical(proof),
                    'assertion_digest': sha(canonical(proof).encode()), 'registration': proof['registration'],
                    'initial_validation': record, 'final_validation': None}
            else:
                provenance = json.loads(locator_frozen)
                provenance['final_validation'] = record
            details['locator_verification_v1'] = provenance
            details['locator_verification_required'] = True
        digest = hashlib.sha256(canonical(canonical_request).encode()).hexdigest()
        return AuthorisationDecision(str(uuid.uuid4()), True, principal_id, action, target_id,
            'derived-identity-graph', str(policy_row['revision']), canonical_request['rationale'],
            canonical_request['evidence_ref'], canonical_request['correlation_id'], evaluated_at,
            {'request_digest': digest, 'scope_contexts': scope_contexts, 'grant_ids': chosen,
             'purpose': purpose, **details})
