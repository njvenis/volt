"""Supported append-only supplied history with current trusted authorisation."""
from datetime import datetime, timezone
import json
import sqlalchemy as sa
from uvm.identity.deadline_reference import (
    DeadlineReferenceV1, DeadlineReferenceError, DeadlineReferenceConflict, utc_text,
)
from uvm.persistence.deadline_reference_schema import (
    identity_deadline_references as references,
    identity_deadline_reference_evidence as evidence,
)
from uvm.persistence.lineage_schema import identity_authorisation_decisions as decisions
from uvm.persistence.schema import occurrences, exposures, groups

UTC = timezone.utc


def _canonical(reference, expected_occurrence_revision, expected_reference_revision):
    return json.dumps({'reference': reference.public(),
        'expected_occurrence_revision': expected_occurrence_revision,
        'expected_reference_revision': expected_reference_revision},
        sort_keys=True, separators=(',', ':'), allow_nan=False)


def _reference(row):
    deadline = row['deadline_at']
    if deadline is not None:
        deadline = deadline.replace(tzinfo=UTC) if deadline.tzinfo is None else deadline.astimezone(UTC)
    return DeadlineReferenceV1(**{key: (deadline if key == 'deadline_at' else row[key])
        for key in DeadlineReferenceV1.__dataclass_fields__})


class DeadlineReferenceStore:
    def __init__(self, engine, authorise):
        self.engine = engine
        self.authorise = authorise

    def write(self, reference, *, expected_occurrence_revision,
              expected_reference_revision, provenance_bytes):
        if not isinstance(reference, DeadlineReferenceV1):
            raise DeadlineReferenceError('DeadlineReferenceV1 is required')
        for name, value, minimum in (('occurrence revision', expected_occurrence_revision, 1),
                                    ('reference revision', expected_reference_revision, 0)):
            if type(value) is not int or value < minimum:
                raise DeadlineReferenceError(f'expected {name} is invalid')
        reference.verify_provenance(provenance_bytes)
        canonical = _canonical(reference, expected_occurrence_revision, expected_reference_revision)
        action = ('identity.deadline_reference.correct' if reference.supersedes_reference_id
                  else 'identity.deadline_reference.record')
        with self.engine.begin() as connection:
            initial = connection.execute(sa.select(occurrences.c.exposure_id, exposures.c.group_id)
                .select_from(occurrences.join(exposures, occurrences.c.exposure_id == exposures.c.exposure_id))
                .where(occurrences.c.occurrence_id == reference.occurrence_id)).mappings().first()
            if initial is None:
                raise DeadlineReferenceConflict('current occurrence is unavailable')
            group = connection.execute(sa.select(groups).where(groups.c.group_id == initial['group_id'])
                .with_for_update()).mappings().one()
            exposure = connection.execute(sa.select(exposures).where(exposures.c.exposure_id == initial['exposure_id'])
                .with_for_update()).mappings().one()
            occurrence = connection.execute(sa.select(occurrences).where(
                occurrences.c.occurrence_id == reference.occurrence_id).with_for_update()).mappings().one()
            if exposure['group_id'] != group['group_id'] or occurrence['exposure_id'] != exposure['exposure_id']:
                raise DeadlineReferenceConflict('current occurrence parent changed')
            rows = self.read_history_on_connection(connection, reference.occurrence_id)
            head = rows[-1] if rows else None
            context = {'request_id': reference.reference_id, 'group_id': group['group_id'],
                'source_family': group['source_family'], 'group_revision': int(group['revision']),
                'exposure_id': exposure['exposure_id'], 'exposure_revision': int(exposure['revision']),
                'occurrence_id': reference.occurrence_id, 'occurrence_revision': int(occurrence['revision']),
                'reference_revision': head['revision'] if head else 0,
                'reference_id': head['reference']['reference_id'] if head else None,
                'supplied_reference': reference.public(), 'provenance_sha256': reference.evidence_sha256}
            prior = connection.execute(sa.select(references).where(
                references.c.reference_id == reference.reference_id)).mappings().first()
            if prior is not None:
                self.authorise(connection, action, reference.occurrence_id, context, persist=False)
                if prior['request_canonical'] != canonical:
                    raise DeadlineReferenceConflict('reference ID is bound to different content')
                return {'reference': _reference(prior).public(), 'revision': int(prior['revision']),
                    'authorisation_decision_id': prior['authorisation_decision_id'], 'replayed': True}
            if occurrence['revision'] != expected_occurrence_revision:
                raise DeadlineReferenceConflict('occurrence revision changed')
            if expected_reference_revision != (head['revision'] if head else 0):
                raise DeadlineReferenceConflict('reference head changed')
            if reference.supersedes_reference_id != (head['reference']['reference_id'] if head else None):
                raise DeadlineReferenceConflict('correction must supersede the current reference')
            retained = connection.execute(sa.select(evidence.c.content).where(
                evidence.c.sha256 == reference.evidence_sha256)).scalar_one_or_none()
            if retained is not None and bytes(retained) != provenance_bytes:
                raise DeadlineReferenceError('retained evidence content mismatch')
            # Re-evaluate current trusted authority immediately before persistence.
            decision = self.authorise(connection, action, reference.occurrence_id, context)
            if retained is None:
                connection.execute(evidence.insert().values(sha256=reference.evidence_sha256,
                    content=provenance_bytes))
            recorded_at = datetime.now(UTC)
            connection.execute(references.insert().values({**reference.public(),
                'deadline_at': reference.deadline_at, 'revision': expected_reference_revision + 1,
                'expected_occurrence_revision': expected_occurrence_revision,
                'expected_reference_revision': expected_reference_revision,
                'request_canonical': canonical, 'identity_snapshot': {**context,
                    'first_observed_at': utc_text(occurrence['first_observed_at'])},
                'authorisation_decision_id': decision.decision_id, 'recorded_at': recorded_at}))
            return {'reference': reference.public(), 'revision': expected_reference_revision + 1,
                'authorisation_decision_id': decision.decision_id, 'replayed': False}

    @staticmethod
    def read_history_on_connection(connection, occurrence_id):
        rows = connection.execute(sa.select(references).where(references.c.occurrence_id == occurrence_id)
            .order_by(references.c.revision)).mappings().all()
        result = []
        previous = None
        for revision, row in enumerate(rows, 1):
            reference = _reference(row)
            if (row['revision'] != revision or row['expected_reference_revision'] != revision - 1
                    or reference.supersedes_reference_id != previous):
                raise DeadlineReferenceError('supplied reference history is contradictory')
            artifact = connection.execute(sa.select(evidence.c.content).where(
                evidence.c.sha256 == reference.evidence_sha256)).scalar_one_or_none()
            reference.verify_provenance(bytes(artifact) if artifact is not None else None)
            if row['request_canonical'] != _canonical(reference, row['expected_occurrence_revision'], row['expected_reference_revision']):
                raise DeadlineReferenceError('retained canonical reference binding changed')
            decision = connection.execute(sa.select(decisions).where(
                decisions.c.decision_id == row['authorisation_decision_id'])).mappings().first()
            expected_action = 'identity.deadline_reference.correct' if previous else 'identity.deadline_reference.record'
            if (decision is None or decision['action'] != expected_action
                    or decision['target_id'] != occurrence_id or not decision['decision_semantics_canonical']):
                raise DeadlineReferenceError('supplied reference lacks matching trusted authorisation')
            result.append({'reference': reference.public(), 'revision': revision,
                'authorisation_decision_id': row['authorisation_decision_id']})
            previous = reference.reference_id
        return result

    @classmethod
    def current_on_connection(cls, connection, membership_ids):
        return {member: (rows[-1] if rows else None) for member in membership_ids
            for rows in [cls.read_history_on_connection(connection, member)]}
