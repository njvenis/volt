"""G3 supplied history companion; no identity or SLA calculation semantics."""
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
import hashlib
import json
import uuid


class DeadlineReferenceError(ValueError):
    pass


class DeadlineReferenceConflict(DeadlineReferenceError):
    pass


def canonical_uuid(value, name):
    try:
        parsed = uuid.UUID(value)
    except (ValueError, TypeError, AttributeError):
        raise DeadlineReferenceError(f"{name} must be a canonical UUID") from None
    if str(parsed) != value:
        raise DeadlineReferenceError(f"{name} must be a canonical UUID")
    return value


def utc_text(value):
    return value.astimezone(timezone.utc).isoformat().replace('+00:00', 'Z') if value else None


@dataclass(frozen=True)
class DeadlineReferenceV1:
    schema_version: int
    reference_id: str
    occurrence_id: str
    deadline_at: datetime | None
    policy_ref: str | None
    evidence_ref: str
    evidence_sha256: str
    supersedes_reference_id: str | None
    rationale: str

    def __post_init__(self):
        if type(self.schema_version) is not int or self.schema_version != 1:
            raise DeadlineReferenceError("unsupported deadline reference version")
        for name in ('reference_id', 'occurrence_id'):
            canonical_uuid(getattr(self, name), name)
        if self.supersedes_reference_id is not None:
            canonical_uuid(self.supersedes_reference_id, 'supersedes_reference_id')
            if self.supersedes_reference_id == self.reference_id:
                raise DeadlineReferenceError("reference cannot supersede itself")
        if self.deadline_at is not None and (not isinstance(self.deadline_at, datetime)
                or self.deadline_at.tzinfo is None or self.deadline_at.utcoffset().total_seconds() != 0):
            raise DeadlineReferenceError("supplied deadline must be UTC or unknown")
        if self.policy_ref is not None and (type(self.policy_ref) is not str or not self.policy_ref.strip()):
            raise DeadlineReferenceError("policy_ref must be supplied or explicitly unknown")
        for name in ('evidence_ref', 'rationale'):
            if type(getattr(self, name)) is not str or not getattr(self, name).strip():
                raise DeadlineReferenceError(f"{name} is required")
        if (type(self.evidence_sha256) is not str or len(self.evidence_sha256) != 64
                or any(c not in '0123456789abcdef' for c in self.evidence_sha256)):
            raise DeadlineReferenceError("evidence_sha256 must be lowercase SHA256")

    def public(self):
        result = asdict(self)
        result['deadline_at'] = utc_text(self.deadline_at)
        return result

    def verify_provenance(self, provenance_bytes):
        if type(provenance_bytes) is not bytes or not 0 < len(provenance_bytes) <= 65536:
            raise DeadlineReferenceError("explicit bounded provenance bytes are required")
        if hashlib.sha256(provenance_bytes).hexdigest() != self.evidence_sha256:
            raise DeadlineReferenceError("provenance digest mismatch")
        def pairs(values):
            result = {}
            for key, value in values:
                if key in result:
                    raise DeadlineReferenceError("duplicate provenance field")
                result[key] = value
            return result
        try:
            source = json.loads(provenance_bytes.decode('utf-8'), object_pairs_hook=pairs,
                parse_constant=lambda _: (_ for _ in ()).throw(DeadlineReferenceError('invalid provenance number')))
        except (UnicodeError, json.JSONDecodeError) as error:
            raise DeadlineReferenceError("provenance must be typed UTF8 JSON") from error
        expected = {'schema_version': 1, 'occurrence_id': self.occurrence_id,
            'deadline_at': utc_text(self.deadline_at), 'policy_ref': self.policy_ref}
        # Compare canonical text, preserving boolean/numeric distinctions.
        if json.dumps(source, sort_keys=True, separators=(',', ':')) != json.dumps(expected, sort_keys=True, separators=(',', ':')):
            raise DeadlineReferenceError("provenance does not bind the exact subject and supplied values")
