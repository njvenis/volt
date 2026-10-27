"""Strict V1 canonical supplier binding and typed uncertain acknowledgement."""
from dataclasses import dataclass
import hashlib
import json
from uvm.persistence.identity_repository import DurableIdentityError, _uuid

ACTIONS = {'workload': 'identity.workload_field_correct',
           'incarnation': 'identity.incarnation_locator_correct'}


class ScalarCorrectionError(DurableIdentityError):
    pass


@dataclass(frozen=True)
class ScalarCorrectionOutcomeV1:
    status: str
    request_id: str
    request_digest: str


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=True, allow_nan=False)


def validate_request(request, principal_id):
    required = {'schema_version', 'request_id', 'action', 'record_type', 'record_id',
                'field_name', 'expected_target_revision', 'expected_policy_revision',
                'old_value', 'new_value', 'rationale', 'evidence_ref', 'correlation_id'}
    if type(request) is not dict or type(principal_id) is not str or not principal_id:
        raise ScalarCorrectionError('Invalid scalar request')
    record_type = request.get('record_type')
    if record_type == 'workload':
        required.add('eligibility_rule')
    if set(request) != required or record_type not in ACTIONS:
        raise ScalarCorrectionError('Invalid scalar request shape')
    if type(request['schema_version']) is not int or request['schema_version'] != 1:
        raise ScalarCorrectionError('Invalid scalar schema version')
    for name in ('request_id', 'record_id', 'correlation_id'):
        _uuid(request[name], name)
    for name in ('expected_target_revision', 'expected_policy_revision'):
        if type(request[name]) is not int or request[name] < 1:
            raise ScalarCorrectionError('Scalar revisions must be positive integers')
    for name in ('field_name', 'rationale', 'evidence_ref'):
        if type(request[name]) is not str or not request[name]:
            raise ScalarCorrectionError('Scalar strings must be non-empty')
    if request['action'] != ACTIONS[record_type]:
        raise ScalarCorrectionError('Scalar action does not match target type')
    if record_type == 'incarnation' and request['field_name'] != 'host_locator':
        raise ScalarCorrectionError('Ineligible scalar field')
    for name in ('old_value', 'new_value'):
        value = request[name]
        if not (record_type == 'incarnation' and value is None) and (type(value) is not str or not value):
            raise ScalarCorrectionError('Invalid scalar value')
    if request['old_value'] == request['new_value']:
        raise ScalarCorrectionError('Scalar correction must change the value')
    if record_type == 'workload':
        rule = request['eligibility_rule']
        if type(rule) is not dict or set(rule) != {'rule_id', 'rule_version', 'definition_digest'}:
            raise ScalarCorrectionError('Invalid pinned eligibility rule')
        if (type(rule['rule_id']) is not str or not rule['rule_id']
                or type(rule['rule_version']) is not int or rule['rule_version'] < 1
                or type(rule['definition_digest']) is not str
                or len(rule['definition_digest']) != 64
                or any(c not in '0123456789abcdef' for c in rule['definition_digest'])):
            raise ScalarCorrectionError('Invalid pinned eligibility rule')
    body = {**request, 'principal_id': principal_id}
    text = canonical(body)
    return json.loads(text), text, hashlib.sha256(text.encode('utf-8')).hexdigest()
