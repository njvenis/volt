"""UVM retained-observation repository (G1 CR-03/04 guarded writer slice).

Transactional writer and deterministic read-back over the observation/
provenance metadata in ``observation_schema.py`` (shared ``uvm_metadata``;
separate UVM database — never the DefectDojo database, CR-01). The
repository writes UVM tables only, through SQLAlchemy Core, and issues no
UPDATE or DELETE: retained state is append-only. A resend of an already
retained run is idempotent (``duplicate``, nothing written); changed bytes
or context under a retained identity is reported as a conflict and never
overwritten (CR-03/CR-04). The resolver's later ``occurrence_id``
assignment is out of scope for this writer.

Writer-level claims (the DDL enforces some of them too, but the writer
validates before opening its transaction so a bad payload never reaches the
database, and nothing is committed when validation fails):

* canonical UVM UUID identities (``Uuid(as_uuid=False)`` binds them
  unchanged);
* aware-UTC instants: aware non-UTC input is normalized to UTC before
  storage, naive instants are rejected (null stays unknown), and loaded
  instants are re-attached to UTC (SQLite drops the offset on read;
  PostgreSQL keeps it);
* raw evidence as ``raw_evidence_ref`` + 64-character lowercase-hex
  sha256 digest — never the raw bytes (the hex-64 shape is a writer claim;
  the DDL claims length 64 only);
* explicit ``missing_fields`` declarations: a list of ``{field, reason}``
  entries whose declared fields are exactly the NULL optional fields, each
  with a known reason (writer/DTO claim, not a DDL claim);
* retained ID order, created/conflict outcome and dense retention slots
  (the DDL claims unique non-negative slots only);
* causal order of the retained run: a ``created`` row is the first row at
  its source position, and a ``conflict`` row anchors to an earlier-
  retained row — a prior same-position holder, or a quarantine record whose
  first holder was retained earlier. The DDL accepts impossible outcome
  orders; this writer and read-back reject them (unit evidence only,
  integration-unverified);
* complete resend quarantine state: a ``duplicate`` resend must supply the
  complete quarantine records involving the run — a stored record with a
  holder position in the run, omitted from the resend, is a conflict;
* complete quarantine holder sets: every holder is retained at its declared
  position (mirroring the composite position foreign key), at least two
  holders, dense holder ordinals, the first holder keeps the attempted ID,
  and the first holder is retained before every later holder.

Honest boundaries: no row-level immutability is claimed. This is a
writer/store contract — direct SQL (until role/trigger controls exist) can
still mutate or delete retained rows. Tests use synthetic SQLite
(in-memory; a real file for the retention-slot concurrency test); no
PostgreSQL or DefectDojo CE integration is claimed (integration-
unverified).
"""

from __future__ import annotations

import re
import uuid
from dataclasses import dataclass, fields
from datetime import datetime, timezone

import sqlite3

import sqlalchemy as sa
from uvm.persistence.identity_graph_lock import lock_identity_graph
from sqlalchemy.exc import IntegrityError

from uvm.identity.observations import (
    COLLECTION_FAILED,
    COLLECTION_PARTIAL,
    COLLECTION_SUCCESS,
    MISSING_NOT_APPLICABLE,
    MISSING_NOT_SUPPLIED,
    MISSING_UNVERIFIED,
    MissingField,
    QuarantinedIdReuse,
    SourceObservationV1,
)
from uvm.persistence.observation_schema import (
    quarantined_id_reuse,
    quarantined_id_reuse_holders,
    source_observations,
)
from uvm.persistence.exception_sla_schema import source_observation_receipts

UTC = timezone.utc
_OUTCOMES = ("created", "conflict")
_COLLECTION_STATUSES = (COLLECTION_SUCCESS, COLLECTION_PARTIAL, COLLECTION_FAILED)
_MISSING_REASONS = (MISSING_NOT_SUPPLIED, MISSING_NOT_APPLICABLE, MISSING_UNVERIFIED)
_HEX64 = re.compile(r"[0-9a-f]{64}")
# Optional SourceObservationV1 fields whose NULL value must be declared in
# missing_fields (mirrors the DTO's optional-field contract).
_OPTIONAL_FIELDS = (
    "observed_at", "native_id_scheme", "native_id_authority", "native_id_value",
    "asset_locator", "component_locator", "source_record_locator",
    "source_rating", "vulnerability_refs", "source_first_seen_at",
    "report_id", "coverage_scope",
)
# Ingested fields: the comparison identity of an idempotent resend.
# ``observation_id`` and the resolver-owned ``occurrence_id`` are excluded
# (mirrors the DTO's parsed-row comparison: a resend before/after resolution
# or under a returned surrogate is not a content change).
_INGEST_FIELDS = tuple(
    f.name for f in fields(SourceObservationV1)
    if f.name not in ("observation_id", "occurrence_id")
)


class ObservationWriteError(ValueError):
    """Malformed payload or impossible causal order, rejected pre-write."""


class ObservationConflictError(ObservationWriteError):
    """Persisted state already differs under a retained identity or holder
    set: reported as a conflict, never overwritten, nothing committed."""


class ObservationSlotAllocationError(ObservationWriteError):
    """Concurrent writers raced for the same global retention slot
    (``uq_source_observations_retention_order``) and the bounded retry
    budget was exhausted: a typed failure — never a raw database
    IntegrityError, and never misclassified as a duplicate resend or
    content conflict."""


class ObservationRepositoryWriteError(ObservationWriteError):
    """A genuine, non-retriable database integrity failure of the guarded
    insert (a CHECK, FK or observation-ID primary-key violation), surfaced
    promptly — with the original database exception preserved as
    ``__cause__`` — and never retried as a retention-slot race nor
    mislabelled as a slot allocation failure."""


class ObservationReadError(ValueError):
    """Persisted state is malformed (e.g. bad missing_fields JSON)."""


@dataclass(frozen=True)
class RetainedObservation:
    """One retained row plus its persisted store state."""

    observation: SourceObservationV1
    retention_order: int
    ingest_outcome: str


@dataclass(frozen=True)
class RetainedRun:
    """The deterministic read-back of one bounded retained run
    (``source_account_id``, ``run_id``): rows in retention order plus the
    quarantine records involving the run, in first-holder retention order."""

    source_account_id: str
    run_id: str
    rows: tuple  # tuple[RetainedObservation, ...]
    quarantine: tuple  # tuple[QuarantinedIdReuse, ...]


@dataclass(frozen=True)
class RunWriteResult:
    """Outcome of a run write: ``created`` (new rows/holders retained in one
    transaction) or ``duplicate`` (identical resend, nothing written)."""

    status: str
    source_account_id: str
    run_id: str
    rows_in_run: int
    new_rows: int


def _canonical_uuid(value, name: str, exc: type = ValueError) -> str:
    try:
        parsed = uuid.UUID(value)
    except (AttributeError, TypeError, ValueError):
        raise exc(f"{name} must be a canonical UVM UUID, got {value!r}") from None
    if str(parsed) != value:
        raise exc(f"{name} must be a canonical UVM UUID, got {value!r}")
    return value


def _aware_utc(value, name: str, exc: type = ValueError):
    """Load stored instants as aware UTC: SQLite returns naive UTC
    wall-clock (offset dropped on storage), PostgreSQL returns aware."""
    if value is None:
        return None
    if not isinstance(value, datetime):
        raise exc(f"{name} is not a stored instant, got {value!r}")
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def _position(obs: SourceObservationV1) -> tuple:
    return (obs.source_account_id, obs.run_id, obs.source_record_ordinal)


def _run_of(position: tuple) -> tuple:
    return (position[0], position[1])


def _ingest_fields(obs: SourceObservationV1) -> tuple:
    """The comparison identity of a resend, with instants normalized to
    UTC (offset representations of the same instant compare equal)."""
    return tuple(
        v.astimezone(UTC) if isinstance(v, datetime) else v
        for v in (getattr(obs, name) for name in _INGEST_FIELDS))


def _row_to_observation(row) -> SourceObservationV1:
    """Reconstruct and validate one stored row: canonical UUIDs, aware-UTC
    instants, hex-64 digest, and a well-formed explicit missing_fields
    declaration (malformed stored JSON raises ObservationReadError)."""

    def bad(message: str):
        raise ObservationReadError(message)

    observation_id = _canonical_uuid(
        row.observation_id, "stored observation_id", ObservationReadError)
    occurrence_id = (
        _canonical_uuid(row.occurrence_id, "stored occurrence_id",
                        ObservationReadError)
        if row.occurrence_id is not None else None)
    if row.schema_version != 1:
        bad(f"stored schema_version must be 1, got {row.schema_version!r}")
    if not isinstance(row.revision, int) or row.revision < 1:
        bad(f"stored revision must be positive, got {row.revision!r}")
    if row.collection_status not in _COLLECTION_STATUSES:
        bad(f"stored collection_status unknown: {row.collection_status!r}")
    if (not isinstance(row.raw_evidence_sha256, str)
            or not _HEX64.fullmatch(row.raw_evidence_sha256)):
        bad("stored raw_evidence_sha256 is not a 64-char hex digest")
    if not isinstance(row.raw_evidence_ref, str) or not row.raw_evidence_ref:
        bad("stored raw_evidence_ref is missing (ref + digest, never bytes)")
    if row.collected_at is None:
        bad("stored collected_at is NULL (collection time is required)")
    declared: dict[str, str] = {}
    if not isinstance(row.missing_fields, list):
        bad(f"stored missing_fields must be a JSON list, "
            f"got {row.missing_fields!r}")
    for entry in row.missing_fields:
        if not isinstance(entry, dict) or set(entry) != {"field", "reason"}:
            bad(f"stored missing_fields entry malformed: {entry!r}")
        field_name, reason = entry["field"], entry["reason"]
        if field_name not in _OPTIONAL_FIELDS:
            bad(f"stored missing_fields declares unknown field {field_name!r}")
        if reason not in _MISSING_REASONS:
            bad(f"stored missing_fields reason unknown for {field_name!r}: "
                f"{reason!r}")
        if field_name in declared:
            bad(f"stored missing_fields declares {field_name!r} twice")
        declared[field_name] = reason
    for name in _OPTIONAL_FIELDS:
        value = getattr(row, name)
        if value is None and name not in declared:
            bad(f"stored NULL optional {name!r} undeclared in missing_fields")
        if value is not None and name in declared:
            bad(f"stored missing_fields declares {name!r} but it has a value")
    if (not isinstance(row.source_record_ordinal, int)
            or not isinstance(row.source_account_id, str)
            or not isinstance(row.run_id, str)
            or not isinstance(row.source_family, str)):
        bad("stored source identity fields malformed")
    vulnerability_refs = row.vulnerability_refs
    if vulnerability_refs is not None:
        if (not isinstance(vulnerability_refs, list)
                or not all(isinstance(v, str) for v in vulnerability_refs)):
            bad("stored vulnerability_refs is not a list of strings")
        vulnerability_refs = tuple(vulnerability_refs)
    # The DTO re-validates everything (canonical UUIDs, aware collected_at,
    # null⇒declared coverage); reaching construction means the row is sound.
    return SourceObservationV1(
        schema_version=row.schema_version,
        observation_id=observation_id,
        revision=row.revision,
        source_family=row.source_family,
        source_account_id=row.source_account_id,
        run_id=row.run_id,
        source_record_ordinal=row.source_record_ordinal,
        collection_status=row.collection_status,
        collected_at=_aware_utc(row.collected_at, "stored collected_at",
                                ObservationReadError),
        raw_evidence_ref=row.raw_evidence_ref,
        raw_evidence_sha256=row.raw_evidence_sha256,
        missing_fields=tuple(
            MissingField(m["field"], m["reason"]) for m in row.missing_fields
        ),
        observed_at=_aware_utc(row.observed_at, "stored observed_at",
                               ObservationReadError),
        native_id_scheme=row.native_id_scheme,
        native_id_authority=row.native_id_authority,
        native_id_value=row.native_id_value,
        asset_locator=row.asset_locator,
        component_locator=row.component_locator,
        source_record_locator=row.source_record_locator,
        source_rating=row.source_rating,
        vulnerability_refs=vulnerability_refs,
        source_first_seen_at=_aware_utc(row.source_first_seen_at,
                                        "stored source_first_seen_at",
                                        ObservationReadError),
        report_id=row.report_id,
        coverage_scope=row.coverage_scope,
        occurrence_id=occurrence_id,
    )


class ObservationRepository:
    """Transactional writer + deterministic read-back for the retained
    observation run, over the UVM tables only (insert-only: no UPDATE or
    DELETE is issued)."""

    def __init__(self, engine, after_pre_read=None, *, clock=None) -> None:
        self._engine = engine
        self._clock = clock or (lambda: datetime.now(UTC))
        # Test-only hook: a zero-argument callable invoked after the
        # attempt's pre-read and before any insert, so a controlled test
        # barrier can pin the vulnerable point of the slot race without a
        # production API surface. ``None`` (default) is a no-op.
        self._after_pre_read = after_pre_read

    # -- public API ---------------------------------------------------------

    # Bounded retry budget for a write attempt that lost the retention-
    # slot race to a concurrent writer (a
    # ``uq_source_observations_retention_order`` collision on insert). Each
    # retry re-reads the fresh state: the loser either lands on a distinct
    # slot or re-classifies as duplicate/conflict from the fresh state.
    # Any other integrity failure is not retried (see write_run).
    _MAX_WRITE_ATTEMPTS = 10

    def write_run(
        self,
        source_account_id: str,
        run_id: str,
        rows,
        quarantine=(),
    ) -> RunWriteResult:
        """Transactionally retain the bounded run ``run_id`` of
        ``source_account_id``.

        ``rows`` is the full retained state of the run, in retention order:
        a sequence of ``(SourceObservationV1, outcome)`` pairs where outcome
        is ``"created"`` or ``"conflict"``. New rows take the next global
        retention slots, in payload order. ``quarantine`` is a sequence of
        complete ``QuarantinedIdReuse`` records (every record must involve
        this run; the first holder's row must already be retained or be part
        of this payload). An identical resend — the same retained rows AND
        the complete quarantine records involving this run — is idempotent
        (``duplicate``); changed bytes/context under a retained identity,
        an omitted or changed quarantine record, or a holder set that
        diverges from the persisted one, raises
        ``ObservationConflictError`` and commits nothing. Malformed payloads
        and impossible causal orders raise ``ObservationWriteError`` before
        the transaction opens. Concurrent writers are safe: only a
        collision on a named retention unique
        (``uq_source_observations_retention_order`` — the slot race — or
        ``uq_source_observations_retained_position`` — the exact-resend
        race) retries from the fresh state within the bounded budget, where
        the writer either lands on a distinct slot or is re-classified from
        the fresh state; an exhausted budget raises
        ``ObservationSlotAllocationError``. Every other integrity
        violation (CHECK, FK, observation-ID primary key) is surfaced
        promptly as ``ObservationRepositoryWriteError`` with the original
        database exception preserved as the cause, never retried as a slot
        race. A raw database ``IntegrityError`` never escapes.
        """
        rows = tuple(rows)
        records = tuple(quarantine)
        run_key = (source_account_id, run_id)
        self._validate_payload(run_key, rows, records)
        last_error = None
        for _ in range(self._MAX_WRITE_ATTEMPTS):
            try:
                return self._write_once(
                    source_account_id, run_id, run_key, rows, records)
            except IntegrityError as exc:
                if not self._is_retryable_unique_collision(exc):
                    raise ObservationRepositoryWriteError(
                        f"run {(source_account_id, run_id)}: non-retriable "
                        f"integrity failure of the guarded insert "
                        f"({exc.orig})"
                    ) from exc
                # The concurrent writer committed between this attempt's
                # pre-read and its insert, taking the chosen retention
                # slot. The fresh re-read either assigns a distinct slot or
                # re-classifies the write (duplicate / conflict).
                last_error = exc
        raise ObservationSlotAllocationError(
            f"run {(source_account_id, run_id)}: concurrent writers raced "
            "for a retryable named uniqueness constraint; "
            f"{self._MAX_WRITE_ATTEMPTS} attempts exhausted "
            f"({last_error.orig})"
        ) from last_error

    def _is_retryable_unique_collision(self, exc: IntegrityError) -> bool:
        """True only for a collision on a NAMED unique that only
        a concurrent committer can violate after this attempt's pre-read:

        * ``uq_source_observations_retention_order`` — the classic slot
          race (different writers pick the same next slot);
        * ``uq_source_observations_retained_position`` — the exact-resend
          race: two writers retain the same identity/position;
        * ``quarantined_id_reuse_pkey`` — two identical quarantine-only
          writes race to insert the shared quarantine parent.

        In all cases the fresh re-read reclassifies the write (distinct
        slot, ``duplicate`` or ``conflict``). Every other integrity
        failure (CHECK, FK, the observation-ID primary key) is
        deterministic, not a race, and is surfaced promptly. The constraint
        is identified by name, not by broad error-string parsing:

        * SQLite (``sqlite3.IntegrityError``): the UNIQUE message names the
          colliding table and column(s) exactly, e.g. ``UNIQUE constraint
          failed: source_observations.retention_order`` or
          ``quarantined_id_reuse.attempted_id`` — matched against exact
          column forms of the retryable primary/unique keys.
        * PostgreSQL (``psycopg``/``psycopg2``
          ``.errors.UniqueViolation``): the driver exposes the DDL name at
          ``orig.diag.constraint_name``. Non-psycopg PostgreSQL drivers
          expose no named constraint and generic message parsing is not
          trusted, so a collision there is surfaced (not retried) as
          ``ObservationRepositoryWriteError``.
        """
        orig = exc.orig
        dialect = self._engine.dialect.name
        if dialect == "sqlite":
            if not isinstance(orig, sqlite3.IntegrityError):
                return False
            return any(marker in orig.args[0] for marker in (
                "UNIQUE constraint failed: "
                "source_observations.retention_order",
                "UNIQUE constraint failed: source_observations.observation_id, "
                "source_observations.source_account_id, "
                "source_observations.run_id, "
                "source_observations.source_record_ordinal",
                "UNIQUE constraint failed: "
                "quarantined_id_reuse.attempted_id",
            ))
        if dialect == "postgresql":
            diag = getattr(orig, "diag", None)
            constraint_name = getattr(diag, "constraint_name", None)
            return constraint_name in (
                "uq_source_observations_retention_order",
                "uq_source_observations_retained_position",
                "quarantined_id_reuse_pkey",
            )
        return False

    def _write_once(
        self,
        source_account_id: str,
        run_id: str,
        run_key: tuple,
        rows: tuple,
        records: tuple,
    ) -> RunWriteResult:
        """One write attempt: fresh pre-read, writer-level validation
        (conflict, quarantine completeness, causal order) and the single
        insert-only transaction. A retryable named uniqueness
        ``IntegrityError`` on insert means a concurrent writer won the
        race; ``write_run`` retries only those. Every other integrity
        violation propagates to ``write_run`` for prompt typed surfacing."""
        with self._engine.connect() as conn:
            stored_rows, stored_records, max_order = self._load_stored_state(conn)
        if self._after_pre_read is not None:
            self._after_pre_read()

        # A transport may assign a fresh observation UUID to the same
        # source row on resend. Resolve an exact position+digest+parsed-row
        # match to its first retained identity before the run completeness,
        # slot allocation and outcome checks below. Changed content at that
        # position deliberately stays unmatched and is reported as conflict.
        stored_by_source_key: dict[tuple, list[RetainedObservation]] = {}
        for retained in stored_rows.values():
            key = (_position(retained.observation)
                   + (retained.observation.raw_evidence_sha256,))
            stored_by_source_key.setdefault(key, []).append(retained)

        # Check supplied identities before content-based resolution. A
        # matching row elsewhere must not conceal reuse of an ID retained
        # at another source position (including another run).
        for obs, _outcome in rows:
            stored = stored_rows.get(obs.observation_id)
            if stored is not None and _position(stored.observation) != _position(obs):
                raise ObservationConflictError(
                    f"observation_id {obs.observation_id} is already retained "
                    "at another source position; conflict reported, not remapped"
                )

        # Two fresh identities for the same complete source row in one
        # payload cannot both denote the single original observation. Reject
        # before resolving either one to that holder (and before any insert).
        payload_content_keys: set[tuple] = set()
        for obs, outcome in rows:
            content_key = (
                _position(obs), obs.raw_evidence_sha256, _ingest_fields(obs),
            )
            if content_key in payload_content_keys:
                raise ObservationConflictError(
                    "payload contains multiple identities for the same "
                    "source observation; ambiguous resend, nothing committed"
                )
            payload_content_keys.add(content_key)
        supplied_ids = {obs.observation_id for obs, _ in rows}
        resolved_rows = []
        for obs, outcome in rows:
            source_key = _position(obs) + (obs.raw_evidence_sha256,)
            retained = next((candidate for candidate in
                             stored_by_source_key.get(source_key, ())
                             if candidate.observation.observation_id
                             not in supplied_ids
                             and _ingest_fields(candidate.observation)
                             == _ingest_fields(obs)), None)
            if retained is not None:
                obs = retained.observation
                # The retained outcome is part of durable state, but does
                # not change whether identical source content is a resend.
                outcome = retained.ingest_outcome
            resolved_rows.append((obs, outcome))
        rows = tuple(resolved_rows)

        # -- content / identity checks (conflict, never overwrite) ----------
        payload_ids = set(obs.observation_id for obs, _ in rows)
        for obs, outcome in rows:
            stored = stored_rows.get(obs.observation_id)
            if stored is None:
                continue
            if (
                stored.ingest_outcome != outcome
                or _position(stored.observation) != _position(obs)
                or _ingest_fields(stored.observation) != _ingest_fields(obs)
            ):
                raise ObservationConflictError(
                    f"observation_id {obs.observation_id} is already retained "
                    "with different bytes, context or outcome; conflict "
                    "reported, not overwritten"
                )
        for stored_id, stored in stored_rows.items():
            if (
                _run_of(_position(stored.observation)) == run_key
                and stored_id not in payload_ids
            ):
                raise ObservationConflictError(
                    "persisted run state diverged: a retained row of this run "
                    f"is absent from the payload ({stored_id})"
                )

        # -- retention slots for the payload ---------------------------------
        slots: dict[str, int] = {
            r.observation.observation_id: r.retention_order
            for r in stored_rows.values()
        }
        next_slot = max_order + 1
        new_count = 0
        for obs, _ in rows:
            if obs.observation_id not in slots:
                slots[obs.observation_id] = next_slot
                next_slot += 1
                new_count += 1

        # -- quarantine records: shape, holder completeness, causal order ----
        seen_records: set[str] = set()
        record_slots: dict[tuple[str, int], int] = {}
        for rec in records:
            if rec.attempted_id in seen_records:
                raise ObservationWriteError(
                    f"quarantine record for {rec.attempted_id} given twice")
            seen_records.add(rec.attempted_id)
            positions, retained_ids = rec.positions, rec.retained_ids
            if (
                len(positions) != len(retained_ids)
                or len(positions) < 2
            ):
                raise ObservationWriteError(
                    "quarantine record needs at least two aligned holders")
            if len(set(retained_ids)) != len(retained_ids):
                raise ObservationWriteError(
                    "quarantine record retains one identity twice")
            if retained_ids[0] != rec.attempted_id:
                raise ObservationWriteError(
                    "quarantine record: the first holder must keep the "
                    "attempted ID")
            involved = False
            for index, pos in enumerate(positions):
                if not (
                    isinstance(pos, tuple) and len(pos) == 3
                    and isinstance(pos[0], str) and isinstance(pos[1], str)
                    and isinstance(pos[2], int)
                ):
                    raise ObservationWriteError(
                        f"quarantine holder position malformed: {pos!r}")
                if (pos[0], pos[1]) == run_key:
                    involved = True
                holder_id = retained_ids[index]
                holder_slot = slots.get(holder_id)
                holder_row = (
                    stored_rows.get(holder_id)
                    if holder_id in stored_rows else None)
                holder_outcome = (
                    holder_row.ingest_outcome
                    if holder_row is not None else None)
                if holder_row is not None:
                    if _position(holder_row.observation) != pos:
                        raise ObservationWriteError(
                            "quarantine holder not retained at its declared "
                            "position (partial holder set)")
                else:
                    match = next(
                        ((o, outcome) for o, outcome in rows
                         if o.observation_id == holder_id),
                        None)
                    if match is None or _position(match[0]) != pos:
                        raise ObservationWriteError(
                            f"quarantine holder {holder_id} is not retained "
                            "at its declared position (partial holder set)")
                    holder_outcome = match[1]
                if index > 0 and holder_outcome != "conflict":
                    raise ObservationWriteError(
                        f"later quarantine holder {holder_id} must have "
                        "ingest_outcome 'conflict'")
                record_slots[(rec.attempted_id, index)] = holder_slot
            if not involved:
                raise ObservationWriteError(
                    "quarantine record does not involve the run being written")
            for index in range(1, len(positions)):
                if record_slots[(rec.attempted_id, 0)] >= record_slots[
                        (rec.attempted_id, index)]:
                    raise ObservationWriteError(
                        f"invalid causal order: quarantine holder {index} of "
                        f"{rec.attempted_id} is not retained after the first "
                        "holder")
            stored_rec = stored_records.get(rec.attempted_id)
            if stored_rec is not None:
                stored_reason, stored_holders = stored_rec
                if stored_reason != rec.reason:
                    raise ObservationConflictError(
                        f"persisted quarantine record for {rec.attempted_id} "
                        "has a different reason")
                if len(stored_holders) > len(positions):
                    raise ObservationConflictError(
                        f"persisted quarantine record for {rec.attempted_id} "
                        "retains holders absent from the payload")
                for index, (pos, rid) in enumerate(stored_holders):
                    if (pos, rid) != (positions[index], retained_ids[index]):
                        raise ObservationConflictError(
                            f"persisted quarantine holders for "
                            f"{rec.attempted_id} diverge from the payload")

        # -- complete quarantine records for this run (CR-03/04) -------------
        # A ``duplicate`` resend is exact matching retained rows AND the
        # complete quarantine records involving this run: a stored record
        # with a holder position in this run that the payload omits is a
        # conflict, never a silent duplicate (nothing is committed).
        for attempted_id, (_reason, stored_holders) in (
                stored_records.items()):
            if attempted_id in seen_records:
                continue  # supplied and checked above
            if any(pos[0] == source_account_id and pos[1] == run_id
                   for pos, _ in stored_holders):
                raise ObservationConflictError(
                    f"persisted quarantine record {attempted_id} involves "
                    "this run but is absent from the resend; conflict "
                    "reported, nothing committed")

        # -- causal order of the new rows ------------------------------------
        for index, (obs, outcome) in enumerate(rows):
            if obs.observation_id in stored_rows:
                continue  # resend of an already validated retained row
            pos = _position(obs)
            prior_same = any(
                _position(s.observation) == pos for s in stored_rows.values()
            ) or any(_position(o) == pos for o, _ in rows[:index])
            if outcome == "created":
                if prior_same:
                    raise ObservationWriteError(
                        "invalid causal order: 'created' row but the source "
                        f"position {pos} is already retained")
                continue
            anchored = prior_same
            if not anchored:
                for rec in records:
                    for holder_index, holder_pos in enumerate(rec.positions):
                        if holder_index == 0:
                            continue
                        if (
                            rec.retained_ids[holder_index]
                            == obs.observation_id
                            and holder_pos == pos
                            and record_slots[(rec.attempted_id, 0)]
                            < record_slots[(rec.attempted_id, holder_index)]
                        ):
                            anchored = True
                            break
                    if anchored:
                        break
            if not anchored:
                raise ObservationWriteError(
                    "invalid causal order: conflict row "
                    f"{obs.observation_id} has no earlier retained holder "
                    "(no prior same-position row and no complete quarantine "
                    "anchor)")

        # -- commit: one transaction, insert-only ----------------------------
        new_rows = [
            (obs, outcome, slots[obs.observation_id])
            for obs, outcome in rows
            if obs.observation_id not in stored_rows
        ]
        new_parents: list[QuarantinedIdReuse] = []
        new_holders: list[tuple] = []
        for rec in records:
            stored_holders = stored_records.get(rec.attempted_id, (None, []))[1]
            if rec.attempted_id not in stored_records:
                new_parents.append(rec)
                start = 0
            else:
                start = len(stored_holders)
            for index in range(start, len(rec.positions)):
                pos = rec.positions[index]
                new_holders.append((
                    rec.attempted_id, index, pos[0], pos[1], pos[2],
                    rec.retained_ids[index],
                ))

        if not new_rows and not new_parents and not new_holders:
            return RunWriteResult(
                "duplicate", source_account_id, run_id, len(rows), 0)

        with self._engine.begin() as conn:
            lock_identity_graph(conn)
            retained_at = self._clock()
            if retained_at.tzinfo is None or retained_at.utcoffset() is None:
                raise ObservationWriteError("retention clock must return an aware instant")
            retained_at = retained_at.astimezone(UTC)
            for obs, outcome, slot in new_rows:
                conn.execute(
                    source_observations.insert().values(
                        self._row_values(obs, slot, outcome)))
                conn.execute(source_observation_receipts.insert().values(
                    receipt_id=str(uuid.uuid4()),
                    source_observation_id=obs.observation_id,
                    source_account_id=obs.source_account_id, run_id=obs.run_id,
                    source_record_ordinal=obs.source_record_ordinal,
                    retention_operation_id=str(uuid.uuid4()),
                    retained_at=retained_at,
                    source_observed_at=(obs.observed_at.astimezone(UTC)
                        if obs.observed_at is not None else None),
                    source_collected_at=obs.collected_at.astimezone(UTC),
                    created_at=retained_at))
            for rec in new_parents:
                conn.execute(
                    quarantined_id_reuse.insert().values(
                        attempted_id=rec.attempted_id, reason=rec.reason))
            for (attempted_id, ordinal, account, run, ordinal_pos,
                 retained_id) in new_holders:
                conn.execute(
                    quarantined_id_reuse_holders.insert().values(
                        attempted_id=attempted_id, holder_ordinal=ordinal,
                        source_account_id=account, run_id=run,
                        source_record_ordinal=ordinal_pos,
                        retained_id=retained_id))

        return RunWriteResult(
            "created", source_account_id, run_id, len(rows), len(new_rows))

    def read_run(self, source_account_id: str, run_id: str,
                 _connection=None) -> RetainedRun:
        """Deterministic read-back of the bounded retained run: rows in
        retention order (aware-UTC instants, explicit missing-field reasons,
        ref + hex digest, no bytes) plus the quarantine records involving
        the run, ordered by first-holder retention order.

        Scoped read (CR-03): loads only the requested run's rows plus the
        quarantine/holder rows needed to reconstruct and validate it, so a
        corrupt row in an unrelated run cannot prevent a valid run read and
        the read cost does not grow with repository size. Every row the
        read depends on is still fully validated: a corrupt requested-run
        row, or a corrupt row a quarantine holder of this run points at,
        still raises ObservationReadError.

        Snapshot contract: SQLite uses an explicit read transaction because
        pysqlite's legacy transaction mode does not begin one for SELECT.
        PostgreSQL uses REPEATABLE READ so its per-statement snapshots cannot
        mix commits made while this multi-query read is in progress."""
        if _connection is not None:
            return self._read_run_on_connection(
                _connection, source_account_id, run_id)
        conn = self._engine.connect()
        if conn.dialect.name == "postgresql":
            conn = conn.execution_options(isolation_level="REPEATABLE READ")
            conn.begin()
        elif conn.dialect.name == "sqlite":
            # sqlite3's legacy mode otherwise treats each SELECT as a
            # separate snapshot even inside SQLAlchemy's autobegin scope.
            conn.exec_driver_sql("BEGIN")
        else:
            conn.begin()
        try:
            return self._read_run_on_connection(
                conn, source_account_id, run_id)
        finally:
            conn.rollback()
            conn.close()

    def _read_run_on_connection(self, conn, source_account_id: str,
                                run_id: str) -> RetainedRun:
        """Read one retained run using the caller's transaction/connection."""
        run_key = (source_account_id, run_id)
        try:
            raw_rows = conn.execute(
                sa.select(source_observations)
                .where(
                    source_observations.c.source_account_id
                    == source_account_id,
                    source_observations.c.run_id == run_id)
                .order_by(source_observations.c.retention_order)
            ).all()
            # The quarantine records involving this run: the distinct
            # attempted_ids holding a position in the requested run.
            involved = [
                h.attempted_id
                for h in conn.execute(
                    sa.select(
                        quarantined_id_reuse_holders.c.attempted_id)
                    .where(
                        quarantined_id_reuse_holders.c.source_account_id
                        == source_account_id,
                        quarantined_id_reuse_holders.c.run_id == run_id))
            ]
            holder_rows = ()
            if involved:
                holder_rows = conn.execute(
                    sa.select(
                        quarantined_id_reuse.c.attempted_id,
                        quarantined_id_reuse.c.reason,
                        quarantined_id_reuse_holders.c.holder_ordinal,
                        quarantined_id_reuse_holders.c.source_account_id,
                        quarantined_id_reuse_holders.c.run_id,
                        quarantined_id_reuse_holders.c.source_record_ordinal,
                        quarantined_id_reuse_holders.c.retained_id,
                    )
                    .select_from(
                        quarantined_id_reuse.join(
                            quarantined_id_reuse_holders,
                            quarantined_id_reuse_holders.c.attempted_id
                            == quarantined_id_reuse.c.attempted_id))
                    .where(quarantined_id_reuse.c.attempted_id.in_(involved))
                    .order_by(
                        quarantined_id_reuse.c.attempted_id,
                        quarantined_id_reuse_holders.c.holder_ordinal)
                ).all()

            run_rows: list[RetainedObservation] = []
            by_id: dict[str, RetainedObservation] = {}
            for raw in raw_rows:
                retained = RetainedObservation(
                    _row_to_observation(raw), raw.retention_order,
                    raw.ingest_outcome)
                by_id[retained.observation.observation_id] = retained
                run_rows.append(retained)

            records: dict[str, tuple[str, list]] = {}
            for h in holder_rows:
                records.setdefault(h.attempted_id, (h.reason, []))[1].append(
                    (h.holder_ordinal,
                     (h.source_account_id, h.run_id, h.source_record_ordinal),
                     h.retained_id))
            # Every holder an involved record references must be loaded and
            # validated too: the read must be able to prove each holder is
            # a retained row at its declared position.
            missing_ids = sorted({
                entry[2]
                for entries in records.values()
                for entry in entries[1]
                if entry[2] not in by_id
            })
            if missing_ids:
                for raw in conn.execute(
                        sa.select(source_observations)
                        .where(source_observations.c.observation_id
                               .in_(missing_ids))
                        .order_by(source_observations.c.retention_order)):
                    retained = RetainedObservation(
                        _row_to_observation(raw), raw.retention_order,
                        raw.ingest_outcome)
                    by_id[retained.observation.observation_id] = retained

        finally:
            pass

        # Validate every linked holder chain, not only the portion whose
        # rows happen to belong to the requested run.  A first-holder read
        # otherwise sees only a created row and can accept a direct-SQL
        # reversal that a later-holder read rejects.  The retention order is
        # the causal order and must therefore be strictly increasing from
        # the first holder regardless of which run is being read.
        for attempted_id, (_reason, holders) in records.items():
            holders.sort(key=lambda entry: entry[0])
            for earlier, later in zip(holders, holders[1:]):
                earlier_row = by_id.get(earlier[2])
                later_row = by_id.get(later[2])
                if (earlier_row is None or later_row is None
                        or earlier_row.retention_order >= later_row.retention_order):
                    raise ObservationReadError(
                        f"quarantine record {attempted_id} has reversed "
                        "causal holder retention order")

        quarantine: list[QuarantinedIdReuse] = []
        for attempted_id in sorted(records):
            reason, holders = records[attempted_id]
            holders.sort(key=lambda entry: entry[0])
            if [entry[0] for entry in holders] != list(range(len(holders))):
                raise ObservationReadError(
                    f"quarantine record {attempted_id} has non-dense holder "
                    "ordinals")
            if len(holders) < 2:
                raise ObservationReadError(
                    f"quarantine record {attempted_id} has fewer than two "
                    "holders")
            retained_ids = [entry[2] for entry in holders]
            positions = [entry[1] for entry in holders]
            if retained_ids[0] != attempted_id:
                raise ObservationReadError(
                    f"quarantine record {attempted_id}: first holder does not "
                    "keep the attempted ID")
            if len(set(retained_ids)) != len(retained_ids):
                raise ObservationReadError(
                    f"quarantine record {attempted_id} retains one identity "
                    "twice")
            for index, (pos, rid) in enumerate(zip(positions, retained_ids)):
                holder_row = by_id.get(rid)
                if holder_row is None or _position(holder_row.observation) != pos:
                    raise ObservationReadError(
                        f"quarantine holder {rid} is not a retained row at "
                        f"its declared position {pos}")
                if index > 0 and holder_row.ingest_outcome != "conflict":
                    raise ObservationReadError(
                        f"later quarantine holder {rid} has impossible "
                        f"ingest_outcome {holder_row.ingest_outcome!r}; "
                        "expected 'conflict'")
            quarantine.append(QuarantinedIdReuse(
                attempted_id, tuple(retained_ids), tuple(positions), reason))

        # Causal validation of the retained run (the DDL accepts
        # impossible outcome orders; the writer rejects them and direct
        # SQL can seed them, so retrieval must reject them too).
        seen_positions: set[tuple] = set()
        for retained in run_rows:
            pos = _position(retained.observation)
            if retained.ingest_outcome == "created":
                if pos in seen_positions:
                    raise ObservationReadError(
                        f"causally impossible retained order: 'created' "
                        f"row {retained.observation.observation_id} but the "
                        f"source position {pos} is already retained")
                seen_positions.add(pos)
                continue
            anchored = pos in seen_positions
            if not anchored:
                for rec in quarantine:
                    for holder_index, holder_pos in enumerate(rec.positions):
                        if holder_index == 0:
                            continue
                        if (
                            rec.retained_ids[holder_index]
                            == retained.observation.observation_id
                            and holder_pos == pos
                            and by_id[rec.retained_ids[0]].retention_order
                            < retained.retention_order
                        ):
                            anchored = True
                            break
                    if anchored:
                        break
            if not anchored:
                raise ObservationReadError(
                    f"causally impossible retained order: conflict row "
                    f"{retained.observation.observation_id} has no earlier "
                    "retained holder (no prior same-position row and no "
                    "complete quarantine anchor)")
            seen_positions.add(pos)
        quarantine.sort(
            key=lambda rec: (
                by_id[rec.retained_ids[0]].retention_order,
                rec.attempted_id))
        return RetainedRun(
            source_account_id, run_id, tuple(run_rows), tuple(quarantine))

    # -- internals -----------------------------------------------------------

    @staticmethod
    def _row_values(obs: SourceObservationV1, retention_order: int,
                    ingest_outcome: str) -> dict:
        return dict(
            schema_version=obs.schema_version,
            observation_id=obs.observation_id,
            revision=obs.revision,
            source_family=obs.source_family,
            source_account_id=obs.source_account_id,
            run_id=obs.run_id,
            source_record_ordinal=obs.source_record_ordinal,
            collection_status=obs.collection_status,
            collected_at=obs.collected_at.astimezone(UTC),
            raw_evidence_ref=obs.raw_evidence_ref,
            raw_evidence_sha256=obs.raw_evidence_sha256,
            missing_fields=[
                {"field": m.field, "reason": m.reason}
                for m in obs.missing_fields
            ],
            observed_at=(
                obs.observed_at.astimezone(UTC)
                if obs.observed_at is not None else None),
            native_id_scheme=obs.native_id_scheme,
            native_id_authority=obs.native_id_authority,
            native_id_value=obs.native_id_value,
            asset_locator=obs.asset_locator,
            component_locator=obs.component_locator,
            source_record_locator=obs.source_record_locator,
            source_rating=obs.source_rating,
            vulnerability_refs=(
                list(obs.vulnerability_refs)
                if obs.vulnerability_refs is not None else None),
            source_first_seen_at=(
                obs.source_first_seen_at.astimezone(UTC)
                if obs.source_first_seen_at is not None else None),
            report_id=obs.report_id,
            coverage_scope=obs.coverage_scope,
            occurrence_id=obs.occurrence_id,
            retention_order=retention_order,
            ingest_outcome=ingest_outcome,
        )

    @staticmethod
    def _validate_payload(run_key, rows, records) -> None:
        for item in rows:
            if (not isinstance(item, tuple) or len(item) != 2
                    or not isinstance(item[0], SourceObservationV1)):
                raise ObservationWriteError(
                    f"rows must be (SourceObservationV1, outcome) pairs, "
                    f"got {item!r}")
            obs, outcome = item
            if outcome not in _OUTCOMES:
                raise ObservationWriteError(
                    f"ingest outcome must be one of {_OUTCOMES}, "
                    f"got {outcome!r}")
            for name in ("collected_at", "observed_at",
                         "source_first_seen_at"):
                value = getattr(obs, name)
                if value is not None and value.tzinfo is None:
                    raise ObservationWriteError(
                        f"{name} must be a timezone-aware instant (non-UTC "
                        f"aware input is normalized to UTC on store), "
                        f"got naive {value!r}")
            if (obs.source_account_id, obs.run_id) != run_key:
                raise ObservationWriteError(
                    "every row must belong to the run being written")
            _canonical_uuid(obs.observation_id, "observation_id",
                            ObservationWriteError)
            if (not isinstance(obs.raw_evidence_sha256, str)
                    or not _HEX64.fullmatch(obs.raw_evidence_sha256)):
                raise ObservationWriteError(
                    "raw_evidence_sha256 must be a 64-char lowercase-hex "
                    "digest (ref + digest, never bytes)")
            declared: set[str] = set()
            for m in obs.missing_fields:
                if m.field not in _OPTIONAL_FIELDS:
                    raise ObservationWriteError(
                        f"missing_fields declares unknown field {m.field!r}")
                if getattr(obs, m.field) is not None:
                    raise ObservationWriteError(
                        f"missing_fields declares {m.field!r} as missing but "
                        "the field has a value")
                if m.field in declared:
                    raise ObservationWriteError(
                        f"missing_fields declares {m.field!r} twice")
                declared.add(m.field)
        seen_ids: set[str] = set()
        for obs, _ in rows:
            if obs.observation_id in seen_ids:
                raise ObservationWriteError(
                    f"observation_id {obs.observation_id} appears twice in "
                    "the payload")
            seen_ids.add(obs.observation_id)
        for rec in records:
            if not isinstance(rec, QuarantinedIdReuse):
                raise ObservationWriteError(
                    f"quarantine records must be QuarantinedIdReuse, "
                    f"got {rec!r}")

    @staticmethod
    def _load_stored_state(conn):
        raw_rows = conn.execute(
            sa.select(source_observations)
            .order_by(source_observations.c.retention_order)
        ).all()
        stored_rows: dict[str, RetainedObservation] = {}
        max_order = -1
        for raw in raw_rows:
            retained = RetainedObservation(
                _row_to_observation(raw), raw.retention_order,
                raw.ingest_outcome)
            stored_rows[retained.observation.observation_id] = retained
            max_order = max(max_order, raw.retention_order)
        holder_rows = conn.execute(
            sa.select(
                quarantined_id_reuse.c.attempted_id,
                quarantined_id_reuse.c.reason,
                quarantined_id_reuse_holders.c.holder_ordinal,
                quarantined_id_reuse_holders.c.source_account_id,
                quarantined_id_reuse_holders.c.run_id,
                quarantined_id_reuse_holders.c.source_record_ordinal,
                quarantined_id_reuse_holders.c.retained_id,
            )
            .select_from(
                quarantined_id_reuse.join(
                    quarantined_id_reuse_holders,
                    quarantined_id_reuse_holders.c.attempted_id
                    == quarantined_id_reuse.c.attempted_id))
            .order_by(
                quarantined_id_reuse.c.attempted_id,
                quarantined_id_reuse_holders.c.holder_ordinal)
        ).all()
        stored_records: dict[str, tuple[str, list]] = {}
        for h in holder_rows:
            stored_records.setdefault(h.attempted_id, (h.reason, []))[1].append(
                ((h.source_account_id, h.run_id, h.source_record_ordinal),
                 h.retained_id))
        return stored_rows, stored_records, max_order
