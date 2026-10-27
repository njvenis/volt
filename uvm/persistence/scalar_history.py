"""Revision-ordered scalar history with separate knowledge and snapshot cuts."""
from datetime import timezone
import hashlib
import json
import sqlalchemy as sa
from uvm.persistence.lineage_schema import correction_records, identity_authorisation_decisions
from uvm.persistence.alias_schema import mapping_alias_events
from uvm.persistence.scalar_schema import identity_scalar_correction_receipts as receipts
from uvm.persistence.scalar_contract import canonical, validate_request


class ScalarHistoryUnavailable(ValueError):
    def __init__(self, classification):
        super().__init__('Identity history unavailable')
        self.classification = classification


def instant(value):
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)


def timestamp(value):
    return instant(value).isoformat().replace('+00:00', 'Z')


def _unavailable(classification='corrupt_positioned_proof'):
    raise ScalarHistoryUnavailable(classification)


class ScalarHistoryProofRead:
    """Private batched proof, confined to one connection and transaction.

    Report materialisation holds the graph guard and a repeatable-read snapshot.
    This object is local to that calculation; no authority or proof is reused
    across transactions, and targets outside the batch retain individual reads.
    """
    def __init__(self, connection, targets):
        self.connection = connection
        self.transaction = connection.get_transaction()
        if self.transaction is None:
            raise ValueError('Scalar proof reads require an active transaction')
        self.targets = set(targets)
        self.records = {}; self.aliases = {}; self.sidecars = {}
        self.linked_receipts = {}; self.linked_aliases = {}; self.decisions = {}
        if not self.targets:
            return
        predicate = lambda table, id_column: sa.or_(*[
            sa.and_(table.c.record_type == kind, id_column.in_(sorted(
                identifier for record_type, identifier in self.targets if record_type == kind)))
            for kind in sorted({kind for kind, _ in self.targets})])
        rows = connection.execute(sa.select(correction_records).where(
            predicate(correction_records, correction_records.c.record_id))
            .order_by(correction_records.c.new_revision)).mappings()
        for row in rows:
            self.records.setdefault((row['record_type'], row['record_id']), []).append(dict(row))
        correction_ids = [row['correction_id'] for rows in self.records.values() for row in rows]
        alias_rows = connection.execute(sa.select(mapping_alias_events).where(sa.or_(
            predicate(mapping_alias_events, mapping_alias_events.c.target_record_id),
            mapping_alias_events.c.correction_id.in_(correction_ids)))
            .order_by(mapping_alias_events.c.event_sequence)).mappings()
        for row in alias_rows:
            row = dict(row)
            self.aliases.setdefault((row['record_type'], row['target_record_id']), []).append(row)
            self.linked_aliases.setdefault(row['correction_id'], []).append(row)
        receipt_rows = connection.execute(sa.select(receipts).where(sa.or_(
            predicate(receipts, receipts.c.record_id), receipts.c.correction_id.in_(correction_ids)))).mappings()
        for row in receipt_rows:
            row = dict(row)
            self.sidecars.setdefault((row['record_type'], row['record_id']), {})[row['correction_id']] = row
            self.linked_receipts[row['correction_id']] = row
        if self.linked_receipts:
            self.decisions = {row['decision_id']: dict(row) for row in connection.execute(
                sa.select(identity_authorisation_decisions).where(
                    identity_authorisation_decisions.c.decision_id.in_(
                        [row['decision_id'] for row in self.linked_receipts.values()]))).mappings()}

    def contains(self, connection, record_type, identifier):
        if connection is not self.connection or connection.get_transaction() is not self.transaction:
            raise ValueError('Scalar proof read cannot cross a transaction boundary')
        return (record_type, identifier) in self.targets


def _receipt_link(connection, correction, receipt, aliases, proof=None):
    try:
        body = json.loads(receipt['canonical_request'])
        principal = body.pop('principal_id')
        bound, text, digest = validate_request(body, principal)
        result = receipt['result']
        result_keys = {'schema_version', 'request_id', 'principal_id', 'action', 'record_type',
            'record_id', 'field_name', 'expected_target_revision', 'expected_policy_revision',
            'old_value', 'new_value', 'status', 'request_digest', 'committed_target_revision',
            'correction_id', 'decision_id', 'affected_record_ids', 'effective_at', 'recorded_at',
            'knowledge_sequence', 'alias_event_ids', 'assessment_impact', 'issue_impact'}
        if (type(result) is not dict or set(result) != result_keys
                or any(type(result[name]) is not int for name in ('schema_version',
                    'expected_target_revision', 'expected_policy_revision',
                    'committed_target_revision', 'knowledge_sequence'))):
            _unavailable()
        decision = (proof.decisions.get(receipt['decision_id']) if proof is not None else
            connection.execute(sa.select(identity_authorisation_decisions).where(
                identity_authorisation_decisions.c.decision_id == receipt['decision_id'])).mappings().one())
        if decision is None:
            _unavailable()
        valid = (text == receipt['canonical_request'] and digest == receipt['request_digest']
            and bound['request_id'] == receipt['request_id']
            and principal == receipt['principal_id'] == correction['actor'] == decision['principal_id']
            and bound['record_type'] == receipt['record_type'] == correction['record_type']
            and bound['record_id'] == receipt['record_id'] == correction['record_id'] == decision['target_id']
            and bound['action'] == receipt['action'] == decision['action']
            and bound['field_name'] == receipt['field_name'] == correction['field_name']
            and bound['expected_target_revision'] == receipt['previous_revision'] == correction['previous_revision']
            and receipt['new_revision'] == correction['new_revision']
            and bound['old_value'] == correction['old_value'] and bound['new_value'] == correction['new_value']
            and bound['rationale'] == correction['reason'] == decision['reason']
            and bound['correlation_id'] == correction['correlation_id'] == decision['correlation_id']
            and bound['evidence_ref'] == decision['evidence_ref']
            and str(bound['expected_policy_revision']) == decision['policy_revision']
            and instant(decision['decided_at']) == instant(correction['created_at'])
            and decision['decision_details']['request_digest'] == digest
            and decision['decision_details']['scope_contexts'] == receipt['scope_contexts']
            and result['schema_version'] == 1 and result['status'] == 'committed'
            and result['request_id'] == receipt['request_id'] and result['request_digest'] == digest
            and result['principal_id'] == principal and result['action'] == bound['action']
            and result['record_type'] == bound['record_type'] and result['record_id'] == bound['record_id']
            and result['field_name'] == bound['field_name']
            and result['expected_target_revision'] == bound['expected_target_revision']
            and result['expected_policy_revision'] == bound['expected_policy_revision']
            and result['old_value'] == bound['old_value'] and result['new_value'] == bound['new_value']
            and result['committed_target_revision'] == correction['new_revision']
            and result['correction_id'] == correction['correction_id']
            and result['decision_id'] == decision['decision_id']
            and result['effective_at'] == timestamp(correction['created_at'])
            and result['recorded_at'] == timestamp(receipt['recorded_at'])
            and result['knowledge_sequence'] == receipt['knowledge_sequence'] > 0
            and result['affected_record_ids'] == correction['affected_record_ids']
            and set(result['affected_record_ids']) == {c['record_id'] for c in receipt['scope_contexts']}
            and result['assessment_impact'] == result['issue_impact'] == 'unverified'
            and result['alias_event_ids'] == [a['alias_event_id'] for a in aliases])
        details = decision['decision_details']
        if 'locator_verification_v1' in details or 'locator_verification_required' in details:
            from uvm.assessment.locator_verification import retained_provenance
            if (bound['record_type'] != 'incarnation' or bound['new_value'] is None
                    or details.get('locator_verification_required') is not True):
                _unavailable()
            try:
                retained = retained_provenance(details['locator_verification_v1'],
                    {**bound, 'principal_id': principal}, digest,
                    instant(correction['created_at']), instant(receipt['recorded_at']))
            except ValueError:
                _unavailable()
            selected = {(c['record_type'], c['record_id']) for c in receipt['scope_contexts']}
            if not {('workload', retained['workload_id']), ('incarnation', retained['incarnation_id']),
                    ('occurrence', retained['occurrence_id']), ('source_observation', retained['observation_id'])} <= selected:
                _unavailable()
        semantics = {name: decision[name] for name in ('principal_id', 'action', 'target_id', 'scope', 'policy_revision', 'reason')}
        semantics.update(allowed=True, details=decision['decision_details'])
        valid = valid and decision['decision_semantics_canonical'] == canonical(semantics)
    except (KeyError, TypeError, ValueError, sa.exc.NoResultFound):
        _unavailable()
    if not valid:
        _unavailable()


def validate_scalar_history(connection, record_type, row, proof=None):
    """Validate all retained proof privately, never expose beyond-known failures."""
    identifier = row[record_type + '_id']
    if proof is not None and not proof.contains(connection, record_type, identifier):
        proof = None
    key = (record_type, identifier)
    records = ([dict(r) for r in proof.records.get(key, [])] if proof is not None else
        [dict(r) for r in connection.execute(sa.select(correction_records).where(
            correction_records.c.record_type == record_type, correction_records.c.record_id == identifier)
            .order_by(correction_records.c.new_revision)).mappings()])
    unpositioned = [r for r in records if r['previous_revision'] == r['new_revision'] == 0]
    if unpositioned:
        # A new scalar receipt promises positive positioning. Contradicting
        # that promise is corruption, not valid legacy default provenance.
        linked = (any(r['correction_id'] in proof.linked_receipts for r in unpositioned)
            if proof is not None else connection.execute(sa.select(receipts.c.request_id).where(
                receipts.c.correction_id.in_([r['correction_id'] for r in unpositioned]))).first())
        fields = row['stable_attrs'] if record_type == 'workload' else row
        malformed = any(r['field_name'] not in fields or r['old_value'] == r['new_value']
            or not r['actor'] or not r['reason'] or not r['correlation_id']
            or r['created_at'] is None for r in unpositioned)
        if linked or malformed:
            _unavailable()
        positioned = [r for r in records if r not in unpositioned]
        if (len({r['new_revision'] for r in positioned}) != len(positioned)
                or any(r['previous_revision'] < 1 or r['new_revision'] != r['previous_revision'] + 1
                    or r['new_revision'] > row['revision'] or r['field_name'] not in fields for r in positioned)):
            _unavailable()
        # Exclude0/0 rows rather than assigning them positions. Still reject
        # independent contradictions in any positioned proof before returning
        # the distinct insufficient-proof interpretation.
        working = dict(fields); expected = row['revision']
        for r in reversed(positioned):
            if r['new_revision'] != expected:
                break  # an unpositioned transition cannot fill this gap
            if working[r['field_name']] != r['new_value']:
                _unavailable()
            working[r['field_name']] = r['old_value']; expected = r['previous_revision']
        for r in positioned:
            sidecar = (proof.linked_receipts.get(r['correction_id']) if proof is not None else
                connection.execute(sa.select(receipts).where(receipts.c.correction_id == r['correction_id'])).mappings().first())
            if sidecar:
                aliases = (proof.linked_aliases.get(r['correction_id'], []) if proof is not None else
                    [dict(a) for a in connection.execute(sa.select(mapping_alias_events).where(
                        mapping_alias_events.c.correction_id == r['correction_id']).order_by(mapping_alias_events.c.event_sequence)).mappings()])
                _receipt_link(connection, r, sidecar, aliases, proof)
                if instant(sidecar['recorded_at']) < instant(r['created_at']):
                    _unavailable()
        _unavailable('insufficient_positioned_proof')
    revision = int(row['revision'])
    if len(records) != revision - 1:
        _unavailable('corrupt_positioned_proof' if records else 'insufficient_positioned_proof')
    values = dict(row['stable_attrs']) if record_type == 'workload' else dict(row)
    for expected, r in zip(range(revision - 1, 0, -1), reversed(records)):
        field = r['field_name']
        if (r['previous_revision'] != expected or r['new_revision'] != expected + 1
                or field not in values or values[field] != r['new_value']):
            _unavailable()
        values[field] = r['old_value']
    aliases = (proof.aliases.get(key, []) if proof is not None else
        [dict(a) for a in connection.execute(sa.select(mapping_alias_events).where(
            mapping_alias_events.c.record_type == record_type,
            mapping_alias_events.c.target_record_id == identifier).order_by(mapping_alias_events.c.event_sequence)).mappings()])
    sidecars = (proof.sidecars.get(key, {}) if proof is not None else
        {r['correction_id']: dict(r) for r in connection.execute(sa.select(receipts).where(
            receipts.c.record_type == record_type, receipts.c.record_id == identifier)).mappings()})
    if set(sidecars) - {r['correction_id'] for r in records}:
        _unavailable()
    active = set(); alias_sequence = 0; knowledge_sequence = 0
    effective = knowledge = instant(row['created_at'])
    for r in records:
        field = r['field_name']; scope = row['workload_id'] if record_type == 'incarnation' else None
        key = lambda value: (field, scope, None, value)
        expected = []
        if r['new_value'] is not None and key(r['new_value']) in active:
            expected.append(('retire', key(r['new_value']))); active.remove(key(r['new_value']))
        if r['old_value'] is not None:
            expected.append(('activate', key(r['old_value']))); active.add(key(r['old_value']))
        actual = [a for a in aliases if a['correction_id'] == r['correction_id']]
        if (expected != [(a['action'], (a['field_name'], a['scope_a'], a['scope_b'], a['old_value'])) for a in actual]
                or any(a['event_sequence'] <= alias_sequence or instant(a['occurred_at']) != instant(r['created_at'])
                       or not a['evidence_ref'] for a in actual)
                or len(actual) == 2 and actual[1]['event_sequence'] != actual[0]['event_sequence'] + 1):
            _unavailable()
        alias_sequence = max([alias_sequence] + [a['event_sequence'] for a in actual])
        receipt = sidecars.get(r['correction_id'])
        at = instant(r['created_at']); recorded = instant(receipt['recorded_at']) if receipt else at
        if at < effective or recorded < at or recorded < knowledge:
            _unavailable()
        if receipt:
            if receipt['knowledge_sequence'] <= knowledge_sequence:
                _unavailable()
            _receipt_link(connection, r, receipt, actual, proof)
            knowledge_sequence = receipt['knowledge_sequence']
        effective, knowledge = at, recorded
        r['_sidecar'] = receipt
    if any(a['correction_id'] not in {r['correction_id'] for r in records} for a in aliases):
        _unavailable()
    return records


def scalar_record_at_context(connection, record_type, row, as_of, known_at, sequence, proof=None):
    records = validate_scalar_history(connection, record_type, row, proof)
    value = dict(row)
    if record_type == 'workload':
        value['stable_attrs'] = dict(value['stable_attrs'])
    visible = []
    excluded = False
    for r in records:
        receipt = r['_sidecar']
        knowledge = instant(receipt['recorded_at']) if receipt else instant(r['created_at'])
        known = knowledge <= known_at and (receipt is None or receipt['knowledge_sequence'] <= sequence)
        selected = known and instant(r['created_at']) <= as_of
        if selected and excluded:
            _unavailable()
        excluded = excluded or not selected
        if known:
            public = {k: v for k, v in r.items() if not k.startswith('_')}
            if receipt:
                public.update(recorded_at=receipt['recorded_at'], knowledge_sequence=receipt['knowledge_sequence'])
            visible.append(public)
    for r in reversed(records):
        receipt = r['_sidecar']
        knowledge = instant(receipt['recorded_at']) if receipt else instant(r['created_at'])
        if instant(r['created_at']) <= as_of and knowledge <= known_at and (receipt is None or receipt['knowledge_sequence'] <= sequence):
            continue
        fields = value['stable_attrs'] if record_type == 'workload' else value
        fields[r['field_name']] = r['old_value']
        value['revision'] = r['previous_revision']
    return value, visible
