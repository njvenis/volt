"""Retained source observations (SourceObservationV1) and their store.

One source row creates one retained observation (CR-02/CR-06 input).
Scanner observation time and collection time are distinct fields; the
collection time is never substituted for the observation time. Missing
optional values are explicit nulls with a reason, never invented.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field, fields, replace
from datetime import datetime
from typing import Optional

SCHEMA_VERSION = 1

MISSING_NOT_SUPPLIED = "not_supplied"
MISSING_NOT_APPLICABLE = "not_applicable"
MISSING_UNVERIFIED = "unverified"
_MISSING_REASONS = (MISSING_NOT_SUPPLIED, MISSING_NOT_APPLICABLE, MISSING_UNVERIFIED)

COLLECTION_SUCCESS = "success"
COLLECTION_PARTIAL = "partial"
COLLECTION_FAILED = "failed"
_COLLECTION_STATUSES = (COLLECTION_SUCCESS, COLLECTION_PARTIAL, COLLECTION_FAILED)


def _require_uuid(value, name: str) -> None:
    """The approved G1 Version 1 contracts make every UVM ID an immutable
    UUID; identity records reject anything that is not a canonical UUID
    string (lowercase, hyphenated)."""
    try:
        parsed = uuid.UUID(value)
    except (AttributeError, TypeError, ValueError):
        raise ValueError(f"{name} must be a UVM UUID, got {value!r}") from None
    if str(parsed) != value:
        raise ValueError(f"{name} must be a canonical UVM UUID, got {value!r}")

# Optional SourceObservationV1 fields: a null here must be declared in
# missing_fields with a reason.
_OPTIONAL_FIELDS = (
    "observed_at",
    "native_id_scheme",
    "native_id_authority",
    "native_id_value",
    "asset_locator",
    "component_locator",
    "source_record_locator",
    "source_rating",
    "vulnerability_refs",
    "source_first_seen_at",
    "report_id",
    "coverage_scope",
)


@dataclass(frozen=True)
class MissingField:
    """Explicit declaration that an optional observation field is absent."""

    field: str
    reason: str

    def __post_init__(self) -> None:
        if self.reason not in _MISSING_REASONS:
            raise ValueError(
                f"missing-field reason must be one of {_MISSING_REASONS}, got {self.reason!r}"
            )


@dataclass(frozen=True)
class SourceObservationV1:
    """One retained source row. Immutable after creation.

    ``occurrence_id`` is the stable UVM occurrence this row refers to *after*
    safe resolution; a freshly retained row has none (it stays in the
    unresolved queue until the resolver names exactly one occurrence).
    """

    # required
    schema_version: int
    observation_id: str
    revision: int
    source_family: str
    source_account_id: str
    run_id: str
    source_record_ordinal: int
    collection_status: str
    collected_at: datetime
    raw_evidence_ref: str
    raw_evidence_sha256: str
    missing_fields: tuple[MissingField, ...] = ()
    # optional (explicit null with reason in missing_fields)
    observed_at: Optional[datetime] = None
    native_id_scheme: Optional[str] = None
    native_id_authority: Optional[str] = None
    native_id_value: Optional[str] = None
    asset_locator: Optional[str] = None
    component_locator: Optional[str] = None
    source_record_locator: Optional[str] = None
    source_rating: Optional[str] = None
    vulnerability_refs: Optional[tuple[str, ...]] = None
    source_first_seen_at: Optional[datetime] = None
    report_id: Optional[str] = None
    coverage_scope: Optional[str] = None
    # set by the resolver after safe resolution; never by ingestion
    occurrence_id: Optional[str] = None

    def __post_init__(self) -> None:
        if self.schema_version != SCHEMA_VERSION:
            raise ValueError(f"unsupported schema_version {self.schema_version!r}")
        if self.revision < 1:
            raise ValueError("revision must be a positive integer")
        _require_uuid(self.observation_id, "observation_id")
        if self.occurrence_id is not None:
            _require_uuid(self.occurrence_id, "occurrence_id")
        if self.collection_status not in _COLLECTION_STATUSES:
            raise ValueError(
                f"collection_status must be one of {_COLLECTION_STATUSES}, "
                f"got {self.collection_status!r}"
            )
        if self.collected_at is None:
            raise ValueError("collected_at is required (collection time)")
        if self.collected_at.tzinfo is None:
            raise ValueError("collected_at must be a timezone-aware UTC instant")
        declared = {m.field for m in self.missing_fields}
        for name in _OPTIONAL_FIELDS:
            if getattr(self, name) is None and name not in declared:
                raise ValueError(
                    f"optional field {name!r} is null but absent from missing_fields"
                )


@dataclass(frozen=True)
class QuarantinedIdReuse:
    """Explicit quarantine record for a reused ``observation_id``.

    The attempted (reused) ID and every source position holding it stay
    durably linked here. ``retained_ids`` maps each position, in the same
    order as ``positions``, to the identity under which that holder is
    retained: the first holder keeps the original ID, every later holder is
    retained under its own distinct surrogate ID, never the reused one. One
    observation_id therefore never identifies two retained rows, the record
    is stable across idempotent retries, and the conflict holder stays
    non-actionable (blocked out of successful cohorts) until corrected.
    """

    attempted_id: str
    retained_ids: tuple[str, ...]  # one per holder, aligned with ``positions``
    positions: tuple  # (source_account_id, run_id, source_record_ordinal) per holder
    reason: str


@dataclass(frozen=True)
class IngestResult:
    status: str  # "created" | "duplicate" | "conflict"
    observation_id: str
    conflict_with: Optional[str] = None
    reason: Optional[str] = None


class ObservationStore:
    """In-memory retained observations with idempotency/conflict semantics.

    Duplicate ``(source_account_id, run_id, source_record_ordinal,
    raw_evidence_sha256)`` is idempotent. A changed row or conflicting bytes
    at the same position are retained as ``conflict`` and never silently
    deduplicated. Every conflict path retains a unique observation ID: a
    reused observation_id — at a different or the same source position — is
    retained under a distinct deterministic surrogate identity (the first
    holder keeps the original), and the reuse is recorded durably in
    ``quarantine``; the conflict holder stays non-actionable (blocked out of
    successful cohorts) until corrected.
    Retrying a retained conflict row under a fresh incoming ID is an
    idempotent conflict returning the stored identity, never a created third
    row. A failed or partial row means the run is not
    a successful cohort; an empty run never is.
    """

    def __init__(self) -> None:
        self._by_key: dict[tuple, SourceObservationV1] = {}
        self._by_position: dict[tuple, list[tuple]] = {}
        self._by_id: dict[str, SourceObservationV1] = {}
        self._conflict_positions: set[tuple] = set()
        self._quarantine_entries: dict[str, list[tuple]] = {}
        # (position, digest) keys whose _by_key holder was retained as
        # "created": only those are idempotent-duplicate eligible. Rows
        # retained as conflict retry as conflict, never duplicate.
        self._created_keys: set[tuple] = set()
        # Keys of conflict holders retained in the same-position different-
        # raw-bytes reused-ID path: legacy idempotent-retry semantics report
        # an exact resend of that retained holder as "duplicate" with its
        # stored (surrogate) identity.
        self._conflict_duplicate_keys: set[tuple] = set()
        self.quarantine: list[QuarantinedIdReuse] = []
        self.observations: list[SourceObservationV1] = []

    @staticmethod
    def _parsed_row(obs: SourceObservationV1) -> tuple:
        """Parsed source fields only: transport/resolver fields
        ``observation_id`` and ``occurrence_id`` are excluded, so resenting a
        stored row under a new UUID (or before/after resolution) is never a
        parsed-row change."""
        return tuple(
            getattr(obs, f.name)
            for f in fields(obs)
            if f.name not in ("observation_id", "occurrence_id")
        )

    def ingest(self, obs: SourceObservationV1) -> IngestResult:
        position = (obs.source_account_id, obs.run_id, obs.source_record_ordinal)
        key = position + (obs.raw_evidence_sha256,)
        stored = self._by_key.get(key)
        if (
            stored is not None
            and key in self._created_keys | self._conflict_duplicate_keys
            and self._parsed_row(stored) == self._parsed_row(obs)
        ):
            # Idempotent duplicate: report the stored identity. A row
            # retained as conflict at this key retries as conflict below,
            # never as duplicate, unless its legacy retry path is marked.
            return IngestResult("duplicate", stored.observation_id)
        id_owner = self._by_id.get(obs.observation_id)
        if id_owner is not None and (
            id_owner.source_account_id, id_owner.run_id,
            id_owner.source_record_ordinal
        ) == position and self._parsed_row(id_owner) == self._parsed_row(obs):
            # An exact resend under a returned surrogate is a retry of the
            # retained conflict, not a new reuse of that surrogate. Preserve
            # the original quarantine and name a different conflict holder.
            for attempted_id, entries in self._quarantine_entries.items():
                if attempted_id == obs.observation_id or not any(
                    rid == obs.observation_id for _, rid in entries
                ):
                    continue
                peer = next(
                    (
                        self._by_key[prior_key].observation_id
                        for prior_key in self._by_position.get(position, ())
                        if self._by_key[prior_key].observation_id
                        != obs.observation_id
                    ),
                    attempted_id,
                )
                return IngestResult(
                    "conflict", obs.observation_id, conflict_with=peer,
                    reason="retry of a retained conflict row; no new row retained",
                )
        if id_owner is not None and (
            id_owner.source_account_id, id_owner.run_id, id_owner.source_record_ordinal
        ) != position:
            # The same observation_id is already retained at a different
            # source position: explicit conflict, both retained, never
            # silently merged. The reused ID is never retained a second
            # time: this holder is retained under a distinct surrogate
            # identity and the reuse is recorded durably in quarantine.
            owner_position = (id_owner.source_account_id, id_owner.run_id,
                              id_owner.source_record_ordinal)
            retained = self._retain_id_reuse_conflict(obs, position)
            self._record_id_reuse(
                obs.observation_id,
                owner_position,
                id_owner.observation_id,
                position,
                retained.observation_id,
            )
            return IngestResult(
                "conflict",
                retained.observation_id,
                conflict_with=id_owner.observation_id,
                reason=(
                    "observation_id already retained at a different source "
                    "position; retained under a distinct surrogate identity, "
                    "reuse quarantined, not merged"
                ),
            )
        if stored is not None:
            # Same raw bytes, but a changed parsed row at the same position:
            # retained as conflict, never silently deduplicated. Retrying a
            # retained conflict under a new incoming ID reports the actually
            # stored conflict ID, not the unstored incoming one. A reused
            # retained observation_id is substituted with a distinct
            # surrogate identity so every retained ID stays unique. When the
            # stored holder IS a quarantined surrogate, the conflict peer is
            # the original ID holder from the retained quarantine record,
            # not the surrogate itself.
            retained = self._retain_conflict(obs, position)
            peer = self._quarantine_peer(retained)
            return IngestResult(
                "conflict",
                retained.observation_id,
                conflict_with=peer if peer is not None else stored.observation_id,
                reason=(
                    "same source position and raw digest but a changed parsed row; "
                    "both retained, not deduplicated"
                ),
            )
        retained_conflict = self._retained_at(position, obs)
        if retained_conflict is not None:
            # Idempotent retry of a retained conflict row at this
            # position+digest (e.g. a reused-ID conflict resent under a fresh
            # incoming ID): report the stored conflict identity, never
            # classify as created or retain a third row.
            self._conflict_positions.add(position)
            return IngestResult(
                "conflict",
                retained_conflict.observation_id,
                conflict_with=retained_conflict.observation_id,
                reason=(
                    "retry of a retained conflict row at this source position "
                    "and digest; stored conflict identity returned, no new "
                    "row retained"
                ),
            )
        prior_keys = self._by_position.get(position)
        if prior_keys:
            # Source position already retained with different raw bytes:
            # both retained, never deduplicated. If the incoming row reuses
            # a retained observation_id, the conflicting row is retained
            # under a distinct surrogate identity and the reuse is
            # quarantined, so every retained ID stays unique.
            prior = self._by_key[prior_keys[0]]
            self._conflict_positions.add(position)
            owner = self._by_id.get(obs.observation_id)
            if owner is not None:
                retained = self._retain_id_reuse_conflict(obs, position)
                self._record_id_reuse(
                    obs.observation_id,
                    (owner.source_account_id, owner.run_id,
                     owner.source_record_ordinal),
                    owner.observation_id,
                    position,
                    retained.observation_id,
                )
                self._conflict_duplicate_keys.add(key)
                return IngestResult(
                    "conflict",
                    retained.observation_id,
                    conflict_with=prior.observation_id,
                    reason=(
                        "source position already retained with different raw bytes; "
                        "both retained, not deduplicated"
                    ),
                )
            self.observations.append(obs)
            self._by_key[key] = obs
            self._by_position[position].append(key)
            self._register_id(obs)
            return IngestResult(
                "conflict",
                obs.observation_id,
                conflict_with=prior.observation_id,
                reason=(
                    "source position already retained with different raw bytes; "
                    "both retained, not deduplicated"
                ),
            )
        self.observations.append(obs)
        self._by_key[key] = obs
        self._by_position.setdefault(position, []).append(key)
        self._created_keys.add(key)
        self._register_id(obs)
        return IngestResult("created", obs.observation_id)

    def _retained_at(
        self, position: tuple, obs: SourceObservationV1
    ) -> Optional[SourceObservationV1]:
        """The retained row at ``position`` with the same raw digest and
        parsed row, if any."""
        for existing in self.observations:
            if (
                (existing.source_account_id, existing.run_id,
                 existing.source_record_ordinal)
                == position
                and existing.raw_evidence_sha256 == obs.raw_evidence_sha256
                and self._parsed_row(existing) == self._parsed_row(obs)
            ):
                return existing
        return None

    def _retain_conflict(
        self, obs: SourceObservationV1, position: tuple
    ) -> SourceObservationV1:
        # Retain a changed-row conflict exactly once per distinct parsed
        # row; returns the actually retained observation so retries report
        # its stored identity. If the incoming row reuses an already
        # retained observation_id, it is retained under a distinct surrogate
        # identity and the reuse is quarantined, never a duplicate ID.
        owner = self._by_id.get(obs.observation_id)
        if owner is not None:
            retained = self._retain_id_reuse_conflict(obs, position)
            self._record_id_reuse(
                obs.observation_id,
                (owner.source_account_id, owner.run_id,
                 owner.source_record_ordinal),
                owner.observation_id,
                position,
                retained.observation_id,
            )
            return retained
        existing = self._retained_at(position, obs)
        if existing is not None:
            self._conflict_positions.add(position)
            return existing
        self.observations.append(obs)
        self._conflict_positions.add(position)
        self._register_id(obs)
        return obs

    _QUARANTINED_NAMESPACE = uuid.NAMESPACE_URL

    @classmethod
    def _quarantined_id(
        cls, attempted_id: str, position: tuple, digest: str, salt: int = 0
    ) -> str:
        # Deterministic UUIDv5 surrogate identity for a reused-ID conflict
        # holder (approved G1 contracts: every UVM ID is a UUID), keyed over
        # the full source-position/digest/attempted-ID so a replayed import
        # derives the same retained identity. A candidate that collides with
        # an already retained ID is disambiguated explicitly with a salt
        # before storing; the salt keeps that resolution deterministic.
        basis = "|".join((attempted_id, repr(position), digest))
        if salt:
            basis = f"{basis}|salt={salt}"
        return str(
            uuid.uuid5(
                cls._QUARANTINED_NAMESPACE,
                f"uvm:quarantined-id-reuse:v1:{basis}",
            )
        )

    def _retain_id_reuse_conflict(
        self, obs: SourceObservationV1, position: tuple
    ) -> SourceObservationV1:
        # Retain a reused-ID conflict exactly once per distinct parsed row.
        # The holder's evidence is kept intact; only its identity is
        # substituted with the distinct surrogate so the reused ID is never
        # retained twice.
        existing = self._retained_at(position, obs)
        if existing is not None:
            self._conflict_positions.add(position)
            return existing
        salt = 0
        surrogate = self._quarantined_id(
            obs.observation_id, position, obs.raw_evidence_sha256, salt
        )
        # Explicit pre-store collision handling: the candidate must not
        # collide with an already retained ID; disambiguate with a
        # deterministic salt rather than assuming a prefix is safe.
        while surrogate in self._by_id:
            salt += 1
            surrogate = self._quarantined_id(
                obs.observation_id, position, obs.raw_evidence_sha256, salt
            )
        retained = replace(obs, observation_id=surrogate)
        self.observations.append(retained)
        self._conflict_positions.add(position)
        self._register_id(retained)
        # Keep source-position indexing for the surrogate-retained row: it
        # still occupies this position, so a later row with different raw
        # bytes at the same position is an explicit conflict, never a
        # created row. First-retained row per (position, digest) wins in
        # _by_key, matching get() first-match semantics.
        key = position + (obs.raw_evidence_sha256,)
        self._by_key.setdefault(key, retained)
        self._by_position.setdefault(position, []).append(key)
        return retained

    def _record_id_reuse(
        self,
        attempted_id: str,
        owner_position: tuple,
        owner_retained_id: str,
        position: tuple,
        retained_id: str,
    ) -> None:
        # Explicit quarantine record for a reused observation_id; one record
        # per attempted ID, (position, retained_id) pairs accumulated
        # honestly and stably across retries in retention order (first
        # holder first), durably linking the attempted ID to both source
        # positions and the distinct identity each holder is retained under.
        entries = self._quarantine_entries.setdefault(attempted_id, [])
        for pos, rid in ((owner_position, owner_retained_id),
                         (position, retained_id)):
            if (pos, rid) not in entries:
                entries.append((pos, rid))
        self.quarantine = [
            record
            for record in self.quarantine
            if record.attempted_id != attempted_id
        ] + [
            QuarantinedIdReuse(
                attempted_id,
                tuple(rid for _, rid in entries),
                tuple(pos for pos, _ in entries),
                (
                    "observation_id retained at multiple source positions; "
                    "first holder keeps the ID, later holders retained under "
                    "distinct surrogate identities, reuse quarantined, not "
                    "merged"
                ),
            )
        ]

    def _quarantine_peer(
        self, retained: SourceObservationV1
    ) -> Optional[str]:
        """The other retained identity linked to ``retained`` in a quarantine
        record: for a quarantined surrogate this is the original ID holder,
        so a fresh-ID retry of the surrogate names the true conflict peer.
        Non-quarantined rows have no such record and return None (the
        caller keeps its own stored identity)."""
        position = (retained.source_account_id, retained.run_id,
                    retained.source_record_ordinal)
        for entries in self._quarantine_entries.values():
            if (position, retained.observation_id) not in entries:
                continue
            return next(
                (rid for _, rid in entries
                 if rid != retained.observation_id),
                None,
            )
        return None

    def _register_id(self, obs: SourceObservationV1) -> None:
        # First retained holder wins, matching get() first-match, so a
        # reused observation_id keeps resolving to the row that held it
        # when the reuse conflict was reported.
        self._by_id.setdefault(obs.observation_id, obs)

    def get(self, observation_id: str) -> Optional[SourceObservationV1]:
        """Return the retained row for ``observation_id``.

        Every retained row holds a unique identity: the first holder keeps
        a reused ID and every later holder at a different source position is
        retained under a distinct surrogate ID, so each distinct retained
        identity resolves unambiguously.
        """
        return self._by_id.get(observation_id)

    def rows(self, source_account_id: str, run_id: str) -> list[SourceObservationV1]:
        return [
            obs
            for obs in self.observations
            if obs.source_account_id == source_account_id and obs.run_id == run_id
        ]

    def successful_cohort(self, source_account_id: str, run_id: str) -> bool:
        """A failed/partial row, a retained conflict, or an empty run is
        never a successful cohort."""
        rows = self.rows(source_account_id, run_id)
        if not rows:
            return False
        if any(
            pos[0] == source_account_id and pos[1] == run_id
            for pos in self._conflict_positions
        ):
            return False
        return all(r.collection_status == COLLECTION_SUCCESS for r in rows)
