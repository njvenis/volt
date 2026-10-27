"""Registered local locator supplier; no caller proof, storage or remote service."""
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
import hashlib
import json
import re
import uuid
import sqlalchemy as sa
from uvm.persistence.scalar_contract import canonical, ScalarCorrectionError
from uvm.persistence.schema import incarnations, occurrences
from uvm.persistence.observation_schema import source_observations

UTC = timezone.utc
DIGEST = re.compile(r'^[0-9a-f]{64}$')
INDEPENDENT = {'proof_id', 'incarnation_id', 'workload_id', 'original_revision',
    'field_name', 'proposed_value', 'observation_id', 'occurrence_id', 'evidence_ref',
    'evidence_sha256', 'verified_at', 'expires_at'}
REGISTRATION = {'origin_id', 'supplier_principal', 'registration_version',
    'verifier_version', 'verifier_code_digest', 'configuration_digest',
    'source_scopes', 'maximum_lifetime_seconds'}
ASSERTION = INDEPENDENT | {'kind', 'registration', 'request_digest', 'requesting_principal'}
PROVENANCE = {'assertion', 'assertion_canonical', 'assertion_digest', 'registration',
    'initial_validation', 'final_validation'}


def unavailable():
    raise ScalarCorrectionError('Locator verification unavailable')


def sha(value):
    return hashlib.sha256(value).hexdigest()


def utc(value):
    if type(value) is not str or not value.endswith('Z'):
        unavailable()
    try:
        parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
        if parsed.utcoffset().total_seconds() != 0:
            unavailable()
        return parsed
    except (ValueError, AttributeError):
        unavailable()


def stamp(value):
    return value.astimezone(UTC).isoformat().replace('+00:00', 'Z')


def strict_assertion(proof):
    if type(proof) is not dict or set(proof) != ASSERTION or proof.get('kind') != 'locator_verification_v1':
        unavailable()
    for key in ('proof_id', 'incarnation_id', 'workload_id', 'observation_id', 'occurrence_id'):
        try:
            if str(uuid.UUID(proof[key])) != proof[key]:
                unavailable()
        except (ValueError, TypeError, AttributeError):
            unavailable()
    if (type(proof['original_revision']) is not int or proof['original_revision'] < 1
            or proof['field_name'] != 'host_locator'
            or any(type(proof[k]) is not str or not proof[k] for k in
                ('proposed_value', 'evidence_ref', 'requesting_principal'))
            or any(type(proof[k]) is not str or not DIGEST.fullmatch(proof[k]) for k in
                ('evidence_sha256', 'request_digest'))):
        unavailable()
    registration = proof['registration']
    if (type(registration) is not dict or set(registration) != REGISTRATION
            or any(type(registration[k]) is not str or not registration[k] for k in
                ('origin_id', 'supplier_principal', 'registration_version', 'verifier_version'))
            or any(type(registration[k]) is not str or not DIGEST.fullmatch(registration[k]) for k in
                ('verifier_code_digest', 'configuration_digest'))
            or type(registration['maximum_lifetime_seconds']) is not int
            or not 0 < registration['maximum_lifetime_seconds'] <= 300
            or type(registration['source_scopes']) is not list or not registration['source_scopes']):
        unavailable()
    for scope in registration['source_scopes']:
        if (type(scope) is not dict or set(scope) != {'source_family', 'source_account_id'}
                or any(type(v) is not str or not v for v in scope.values())):
            unavailable()
    start, end = utc(proof['verified_at']), utc(proof['expires_at'])
    if not 0 < (end-start).total_seconds() <= registration['maximum_lifetime_seconds']:
        unavailable()
    return proof


def retained_provenance(provenance, body, request_digest, initial_at, final_at):
    """Historical integrity only: never call a current supplier or policy."""
    if type(provenance) is not dict or set(provenance) != PROVENANCE:
        unavailable()
    proof = strict_assertion(provenance['assertion'])
    text = canonical(proof)
    if (provenance['assertion_canonical'] != text or provenance['assertion_digest'] != sha(text.encode())
            or provenance['registration'] != proof['registration']
            or proof['request_digest'] != request_digest
            or proof['requesting_principal'] != body['principal_id']
            or proof['incarnation_id'] != body['record_id']
            or proof['original_revision'] != body['expected_target_revision']
            or proof['proposed_value'] != body['new_value'] or proof['evidence_ref'] != body['evidence_ref']):
        unavailable()
    for name, at in [('initial_validation', initial_at), ('final_validation', final_at)]:
        record = provenance[name]
        if (type(record) is not dict or set(record) != {'evaluated_at', 'policy_revision',
                'supplier_grant_ids', 'requester_grant_ids', 'registration_digest', 'original_revision', 'intended_value'}
                or record['evaluated_at'] != stamp(at)
                or record['policy_revision'] != str(body['expected_policy_revision'])
                or record['registration_digest'] != sha(canonical(proof['registration']).encode())
                or type(record['original_revision']) is not int
                or record['original_revision'] != proof['original_revision']
                or record['intended_value'] != proof['proposed_value']
                or not utc(proof['verified_at']) <= at < utc(proof['expires_at'])):
            unavailable()
        for key in ('supplier_grant_ids', 'requester_grant_ids'):
            if type(record[key]) is not list or not record[key] or any(type(v) is not str or not v for v in record[key]):
                unavailable()
    return proof


@dataclass(frozen=True)
class LocalAttestationVerifier:
    """Operator-prepared immutable synthetic facts, created BEFORE requests.

    Entries are canonical JSON strings plus local byte paths and exact source
    scopes. The verifier cannot create facts from correction arguments. This
    local fixture is not an approval of real scanner verification semantics.
    """
    entries: tuple  # (canonical independent assertion, evidence path, family, account)
    version: str = 'synthetic-local-v1'

    def configuration(self):
        if type(self.entries) is not tuple or not self.entries:
            unavailable()
        return {'version': self.version, 'entries': [list(entry) for entry in self.entries]}

    def independent(self, proof):
        expected = {k: proof[k] for k in INDEPENDENT}
        matches = [entry for entry in self.entries if json.loads(entry[0]) == expected]
        if len(matches) != 1:
            unavailable()
        _, path, family, account = matches[0]
        try:
            if sha(Path(path).read_bytes()) != proof['evidence_sha256']:
                unavailable()
        except (OSError, ValueError, TypeError):
            unavailable()
        return {'source_family': family, 'source_account_id': account}

    def obtain(self, body, registration):
        matches = []
        for entry in self.entries:
            fact = json.loads(entry[0])
            if (fact.get('incarnation_id') == body['record_id']
                    and fact.get('original_revision') == body['expected_target_revision']
                    and fact.get('proposed_value') == body['new_value']
                    and fact.get('evidence_ref') == body['evidence_ref']):
                matches.append(fact)
        if len(matches) != 1:
            unavailable()
        return {**matches[0], 'kind': 'locator_verification_v1', 'registration': registration,
            'request_digest': sha(canonical(body).encode()), 'requesting_principal': body['principal_id']}


@dataclass(frozen=True)
class RegisteredLocatorSupplier:
    origin_id: str
    supplier_principal: str
    verifier: LocalAttestationVerifier
    source_scopes: tuple  # (source_family, source_account_id)
    registration_version: str = '1'
    maximum_lifetime_seconds: int = 300
    verifier_code_digest: str = ''
    configuration_digest: str = ''

    @classmethod
    def register(cls, origin_id, supplier_principal, verifier, source_scopes):
        # Trusted server composition only; no correction request input reaches
        # this registration path. Digests pin code and immutable configuration.
        return cls(origin_id, supplier_principal, verifier, tuple(source_scopes),
            verifier_code_digest=sha(Path(__file__).read_bytes()),
            configuration_digest=sha(canonical(verifier.configuration()).encode()))

    def metadata(self):
        if (type(self.verifier) is not LocalAttestationVerifier
                or sha(Path(__file__).read_bytes()) != self.verifier_code_digest
                or sha(canonical(self.verifier.configuration()).encode()) != self.configuration_digest):
            unavailable()
        return {'origin_id': self.origin_id, 'supplier_principal': self.supplier_principal,
            'registration_version': self.registration_version, 'verifier_version': self.verifier.version,
            'verifier_code_digest': self.verifier_code_digest, 'configuration_digest': self.configuration_digest,
            'source_scopes': [{'source_family': family, 'source_account_id': account} for family, account in self.source_scopes],
            'maximum_lifetime_seconds': self.maximum_lifetime_seconds}

    def obtain(self, body):
        try:
            return self.verifier.obtain(body, self.metadata())
        except (OSError, KeyError, TypeError, ValueError) as exc:
            raise ScalarCorrectionError('Locator verification unavailable') from exc

    def validate(self, connection, proof, body, original_target, at):
        try:
            proof = strict_assertion(proof)
            if (proof['registration'] != self.metadata()
                    or proof['request_digest'] != sha(canonical(body).encode())
                    or proof['requesting_principal'] != body['principal_id']
                    or proof['incarnation_id'] != body['record_id']
                    or proof['original_revision'] != original_target['revision']
                    or original_target['revision'] != body['expected_target_revision']
                    or proof['workload_id'] != original_target['workload_id']
                    or proof['proposed_value'] != body['new_value']
                    or proof['evidence_ref'] != body['evidence_ref']
                    or not utc(proof['verified_at']) <= at < utc(proof['expires_at'])):
                unavailable()
            source_scope = self.verifier.independent(proof)
            if source_scope not in proof['registration']['source_scopes']:
                unavailable()
            target = connection.execute(sa.select(incarnations).where(incarnations.c.incarnation_id == proof['incarnation_id'])).mappings().one()
            occurrence = connection.execute(sa.select(occurrences).where(occurrences.c.occurrence_id == proof['occurrence_id'])).mappings().one()
            observation = connection.execute(sa.select(source_observations).where(source_observations.c.observation_id == proof['observation_id'])).mappings().one()
            if (target['workload_id'] != proof['workload_id']
                    or occurrence['incarnation_id'] != proof['incarnation_id']
                    or occurrence['workload_id'] != proof['workload_id']
                    or observation['occurrence_id'] != proof['occurrence_id']
                    or observation['raw_evidence_ref'] != proof['evidence_ref']
                    or observation['raw_evidence_sha256'] != proof['evidence_sha256']
                    or any(observation[k] != v for k, v in source_scope.items())
                    or not ((target['revision'] == original_target['revision'] and target['host_locator'] == original_target['host_locator'])
                        or (target['revision'] == original_target['revision']+1 and target['host_locator'] == body['new_value']))):
                unavailable()
            return proof
        except ScalarCorrectionError:
            raise
        except (OSError, KeyError, TypeError, ValueError, sa.exc.NoResultFound) as exc:
            raise ScalarCorrectionError('Locator verification unavailable') from exc
