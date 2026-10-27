"""Guarded, atomic persistence writer for the populated-exposure membership
correction (G1, FR-ID-02 / CR-03).

Durable counterpart of ``IdentityState.apply_membership_correction``
(``uvm/identity/model.py``, unit evidence e42f6f9): one
``engine.begin()`` transaction moves a POPULATED exposure to another
workload, re-points every one of its occurrences to the reviewed
successor incarnation, updates the redundant ``occurrences.workload_id``
(CR-03), appends one ``CorrectionRecord`` per changed record (all sharing
one correlation ID, assessment/issue impact left ``unverified``) and the
correlated ``mapping_alias_events`` (activations of the retired former
values, plus retires when the corrected value is reclaimed from this
record's own history).

Guards and honest boundaries:

* Write intent BEFORE validation: on SQLite the writer takes the write
  lock (write intent) before the first validation read, so a concurrent
  writer (e.g. a resolution commit) either lands before validation runs
  (visible to it) or blocks until this transaction settles — the
  corrected records' impact can never omit a concurrently linked
  observation. On PostgreSQL the exposure, its occurrences and the
  target workloads / incarnations are loaded with ``FOR UPDATE``.
* Optimistic revision guard: every UPDATE carries
  ``WHERE revision = <loaded>`` and a zero-rowcount write is rejected, so a
  concurrent revision bump between load and update fails the whole
  transaction rather than clobbering newer state.
* DDL backstops: the composite occurrence foreign keys pin
  exposure/incarnation to one workload, ``uq_exposures_group_workload`` and
  ``uq_occurrences_exposure_incarnation_component`` reject the index
  collisions, and ``mapping_alias_events_event_sequence_unique`` backstops
  the transactionally allocated sequence (a lost race rolls back the whole
  transaction; the caller retries). Since migration 0002 the current-
  membership occurrence FK
  (``fk_occurrences_exposure_id_workload_id_exposures``) is ``DEFERRABLE
  INITIALLY IMMEDIATE`` on PostgreSQL; this writer defers ONLY that named
  FK for its transient move (``SET CONSTRAINTS ... DEFERRED``) and on
  SQLite sets ``PRAGMA defer_foreign_keys=ON`` inside the correction
  transaction, acquired together with the write lock before the first
  validation read (``foreign_keys`` stays enforced; the flag is restored to
  ``OFF`` before the connection is released, so no later transaction
  inherits the deferred window). The move's final state must be
  FK-consistent: deferred checks still fire at commit time.
* Retained historical pair (0002): the writer inserts-or-reuses the
  corrected-to ``(exposure_id, workload_id)`` pair in
  ``exposure_workload_memberships``; the former pair is retained as-is
  (never deleted), so the historical ``identity_resolutions`` composite FK
  (which references the retained pair table since 0002, not the exposure's
  current pair) stays satisfied after the move (CR-03).
* Append-only at the writer level only: no direct-SQL immutability is
  claimed (no trigger/role guard exists) and no PostgreSQL concurrency
  guarantee is claimed (unit tests are synthetic SQLite; the ``FOR UPDATE``,
  ``SET CONSTRAINTS`` and sequence behaviour on PostgreSQL remain
  integration-unverified).
* Timestamps and clocks: ``created_at``, ``first_observed_at`` and
  ``first_ingested_at`` are never rewritten (CR-03); observation links key
  off preserved occurrence IDs, so linked observations survive the move.
* ``event_sequence`` is allocated transactionally:
  ``max(existing) + n`` read inside the same transaction as the event
  inserts (alias_schema writer guarantee).

Read-back: before commit, the written exposure/occurrence rows, the
correlated correction rows, the alias-event projection and the retained
pair rows are re-read and must describe a coherent corrected state and
consistent history; on SQLite the deferred foreign keys are additionally
checked (``PRAGMA foreign_key_check``) inside the transaction, before
commit. A mismatch raises ``MembershipCorrectionReadError`` (or a deferred
FK failure at commit) and rolls the transaction back (no partial commit on
invalid member, alias collision, unique/FK failure or injected mid-write
error).
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from types import SimpleNamespace

import sqlalchemy as sa
from uvm.persistence.identity_graph_lock import lock_identity_graph

from uvm.identity.model import CorrectionRecord, Occurrence, new_id
from uvm.persistence.alias_schema import mapping_alias_events
from uvm.persistence.lineage_schema import (
    correction_records,
    identity_resolutions,
    occurrence_parent_transition_markers,
    occurrence_parent_transition_anchors,
)
from uvm.persistence.observation_schema import source_observations
from uvm.persistence.schema import (
    exposure_workload_memberships,
    exposures,
    incarnations,
    occurrences,
    workloads,
)

UTC = timezone.utc

# Frozen name of the current-membership occurrence composite FK (0001
# name; 0002 re-emits it DEFERRABLE INITIALLY IMMEDIATE on PostgreSQL).
_OCCURRENCE_FK = "fk_occurrences_exposure_id_workload_id_exposures"


class MembershipCorrectionError(ValueError):
    """Invalid membership bundle, missing/colliding references, or a
    rejected (rolled-back) atomic write."""


class MembershipCorrectionReadError(MembershipCorrectionError):
    """Written rows failed coherent read-back inside the write
    transaction; the write was rolled back."""


def _uuid(value, name) -> str:
    try:
        parsed = uuid.UUID(value)
    except (ValueError, TypeError, AttributeError):
        raise MembershipCorrectionError(f"{name} must be a canonical UUID") from None
    if str(parsed) != value:
        raise MembershipCorrectionError(f"{name} must be a canonical UUID")
    return value


def _aware_utc(value, name) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise MembershipCorrectionError(f"{name} must be timezone-aware")
    return value.astimezone(UTC)


def _utc(value, name) -> datetime:
    if not isinstance(value, datetime):
        raise MembershipCorrectionReadError(f"{name} is corrupt")
    if value.tzinfo is None:
        value = value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def _alias_condition(record_type: str, field_name: str, scope_a, scope_b,
                     old_value: str):
    c = mapping_alias_events.c
    return sa.and_(
        c.record_type == record_type,
        c.field_name == field_name,
        c.scope_a.is_(None) if scope_a is None else c.scope_a == scope_a,
        c.scope_b.is_(None) if scope_b is None else c.scope_b == scope_b,
        c.old_value == old_value,
    )


@dataclass
class _Snapshot:
    """Everything validated/loaded before mutation; the mutation and
    read-back phases only use this snapshot."""
    exposure: dict
    old_workload_id: str
    new_workload_id: str
    members: list  # dicts, ordered by occurrence_id
    targets: list  # target incarnation_id per member
    linked_observations: dict  # occurrence_id -> tuple of observation ids
    resolution_links: dict  # observation_id -> tuple of (resolution_id, occurrence_id)
    records: list  # CorrectionRecord DTOs (exposure first, then members)


class MembershipCorrectionStore:
    """One guarded atomic writer per engine (separate UVM database; no
    DefectDojo access — CR-01)."""

    def __init__(self, engine, authorisation_evaluator=None):
        self.engine = engine
        self.authorisation_evaluator = authorisation_evaluator

    # -- public API ---------------------------------------------------------

    def apply(
        self,
        exposure_id: str,
        new_workload_id: str,
        occurrence_memberships: dict,
        actor: str,
        reason: str,
        correlation_id: str,
        at: datetime,
    ) -> list:
        """Atomically move a populated exposure (and every one of its
        occurrences) to ``new_workload_id``. ``occurrence_memberships``
        maps every occurrence of the exposure to the successor incarnation
        that will hold it (the incarnation must belong to
        ``new_workload_id``). Returns the appended correction records (one
        for the exposure, one per occurrence), all sharing
        ``correlation_id``. Raises ``MembershipCorrectionError`` on any
        invalid input, missing reference, index collision or alias
        ownership conflict — with no rows written in that case.
        """
        _uuid(exposure_id, "exposure_id")
        _uuid(new_workload_id, "new_workload_id")
        if not isinstance(occurrence_memberships, dict):
            raise MembershipCorrectionError("occurrence_memberships must be a mapping")
        for occurrence_id, target_id in occurrence_memberships.items():
            _uuid(occurrence_id, "occurrence_memberships key")
            _uuid(target_id, "occurrence_memberships value")
        if not actor or not reason or not correlation_id:
            raise MembershipCorrectionError("actor, reason and correlation ID are required")
        at = _aware_utc(at, "at")
        with self.engine.connect() as conn:
            try:
                self._begin_write_intent(conn)
                lock_identity_graph(conn)
                try:
                    snapshot = self._validate(conn, exposure_id,
                                              new_workload_id,
                                              occurrence_memberships, actor,
                                              reason, correlation_id, at)
                    self._mutate(conn, snapshot)
                    self._read_back(conn, snapshot)
                except Exception:
                    conn.rollback()
                    raise
                else:
                    conn.commit()
                    return list(snapshot.records)
            finally:
                # The SQLite deferral flag is per-connection: clear it
                # before the connection is released so no later transaction
                # inherits the correction's deferred window. PostgreSQL
                # deferral is transaction-scoped and needs no statement.
                self._restore_occurrence_fk(conn)

    def correct_occurrence_component_locator(
        self, occurrence_id: str, expected_revision: int,
        new_component_locator: str | None, reason: str,
        correlation_id: str, at: datetime,
    ) -> CorrectionRecord:
        """Append an authorised, revision-guarded locator correction.

        The creation locator remains immutable proof; only the current
        locator changes. ``None`` records an unknown current locator and is
        never indexed as a correspondence key.
        """
        _uuid(occurrence_id, "occurrence_id")
        if type(expected_revision) is not int or expected_revision < 1:
            raise MembershipCorrectionError("expected_revision must be positive")
        if new_component_locator is not None and not isinstance(new_component_locator, str):
            raise MembershipCorrectionError("component locator must be a string or None")
        if not reason or not correlation_id:
            raise MembershipCorrectionError("reason and correlation ID are required")
        at = _aware_utc(at, "at")
        with self.engine.begin() as conn:
            lock_identity_graph(conn)
            query = sa.select(occurrences).where(
                occurrences.c.occurrence_id == occurrence_id)
            if self.engine.dialect.name == "postgresql":
                query = query.with_for_update()
            before = conn.execute(query).mappings().first()
            if before is None or before["revision"] != expected_revision:
                raise MembershipCorrectionError("unknown occurrence or stale revision")
            if self.authorisation_evaluator is None:
                raise MembershipCorrectionError("trusted authorisation evaluator is required")
            from uvm.persistence.identity_repository import IdentityRepository
            from uvm.persistence.identity_resolution_store import IdentityResolutionStore
            # Validate this occurrence's complete correction, alias and
            # parent provenance on this connection before mutation. A global
            # restore would make unrelated historical records a dependency.
            record_history = IdentityResolutionStore._ordered_record_history(
                conn, "occurrence", occurrence_id, before["revision"])
            if record_history is None:
                raise MembershipCorrectionError(
                    "occurrence correction history is incomplete")
            correction_rows = conn.execute(sa.select(correction_records).where(
                correction_records.c.record_type == "occurrence",
                correction_records.c.record_id == occurrence_id)).mappings().all()
            alias_rows = conn.execute(sa.select(mapping_alias_events).where(
                mapping_alias_events.c.record_type == "occurrence",
                mapping_alias_events.c.target_record_id == occurrence_id
            ).order_by(mapping_alias_events.c.event_sequence)).mappings().all()
            occurrence_record = Occurrence(
                occurrence_id, before["exposure_id"], before["incarnation_id"],
                before["component_locator"], before["first_observed_at"],
                before["first_ingested_at"], before["revision"], before["created_at"])
            IdentityRepository._validate_mapping_alias_history(
                "occurrence", occurrence_record, correction_rows, alias_rows)
            parent = conn.execute(sa.select(exposures).where(
                exposures.c.exposure_id == before["exposure_id"]
            )).mappings().first()
            if parent is None or before["birth_exposure_id"] is None \
                    or before["birth_exposure_revision"] is None:
                raise MembershipCorrectionError(
                    "occurrence birth parent/revision proof is missing")
            proof = SimpleNamespace(
                occurrence_id=occurrence_id,
                exposure_id=before["exposure_id"],
                group_id=parent["group_id"],
                workload_id=parent["workload_id"],
                incarnation_id=before["incarnation_id"],
                selected_occurrence_revision=before["revision"],
                selected_exposure_revision=parent["revision"],
            )
            fields_valid, crossed_parent = \
                IdentityResolutionStore._v2_field_history_valid(
                    conn, proof, parent, before)
            if not fields_valid:
                raise MembershipCorrectionError(
                    "occurrence birth fields do not replay from recorded history")
            if crossed_parent:
                membership_valid = \
                    IdentityResolutionStore._v2_parent_phase_membership_valid(
                        conn, proof, before)
            else:
                membership_valid = \
                    IdentityResolutionStore._repointing_history_valid(
                        conn, vars(proof), parent, before,
                        selected_revisions=(proof.selected_exposure_revision,
                                            proof.selected_occurrence_revision),
                        require_birth_proof=True)
            if not membership_valid:
                raise MembershipCorrectionError(
                    "occurrence birth workload/incarnation/parent revision proof is contradictory")
            if IdentityResolutionStore._parent_transition_status(
                    conn, occurrence_id, before["exposure_id"], before["revision"],
                    parent["revision"]) is not True:
                raise MembershipCorrectionError(
                    "occurrence parent history is incomplete or contradictory")
            if not IdentityResolutionStore._v2_locator_history_valid(conn, occurrence_id):
                raise MembershipCorrectionError(
                    "component-locator history lacks a recorded birth proof")
            old_value = before["component_locator"]
            if old_value == new_component_locator:
                raise MembershipCorrectionError("correction must change the locator")
            if new_component_locator is not None:
                collision = conn.execute(sa.select(occurrences.c.occurrence_id).where(
                    occurrences.c.exposure_id == before["exposure_id"],
                    occurrences.c.incarnation_id == before["incarnation_id"],
                    occurrences.c.component_locator == new_component_locator,
                    occurrences.c.occurrence_id != occurrence_id,
                )).first()
                if collision is not None:
                    raise MembershipCorrectionError("corrected locator collides with another occurrence")
            keys = []
            scope = (before["exposure_id"], before["incarnation_id"])
            if old_value is not None:
                keys.append(("occurrence", "component_locator", *scope, old_value))
            if new_component_locator is not None:
                keys.append(("occurrence", "component_locator", *scope,
                             new_component_locator))
            owners = self._alias_owners(conn, keys)
            old_key = ("occurrence", "component_locator", *scope, old_value)
            new_key = ("occurrence", "component_locator", *scope,
                       new_component_locator)
            if old_value is not None and owners.get(old_key) not in (None, occurrence_id):
                raise MembershipCorrectionError("historical locator alias belongs to another occurrence")
            if new_component_locator is not None and owners.get(new_key) not in (None, occurrence_id):
                raise MembershipCorrectionError("historical locator alias belongs to another occurrence")

            authority_scope = (
                f"exposure:{before['exposure_id']}/incarnation:{before['incarnation_id']}")
            context = {"occurrence_id": occurrence_id,
                "expected_revision": expected_revision, "scope": authority_scope,
                "correlation_id": correlation_id, "reason": reason}
            action = "identity.occurrence_locator_correction"
            repository = IdentityRepository(self.engine, self.authorisation_evaluator)
            decision = repository._authorise(conn, action, occurrence_id, context,
                                             persist=False)
            if (decision.correlation_id != correlation_id or decision.scope != authority_scope
                    or decision.details.get("request_context") != context):
                raise MembershipCorrectionError(
                    "authorisation decision does not bind locator correction request")
            repository._authorise(conn, action, occurrence_id, context, decision=decision)

            record = CorrectionRecord(
                correction_id=new_id(), record_type="occurrence",
                record_id=occurrence_id, old_value=old_value,
                new_value=new_component_locator, actor=decision.principal_id, reason=reason,
                correlation_id=correlation_id, affected_record_ids=(occurrence_id,),
                created_at=at, field_name="component_locator",
                previous_revision=expected_revision,
                new_revision=expected_revision + 1,
            )
            updated = conn.execute(occurrences.update().where(
                occurrences.c.occurrence_id == occurrence_id,
                occurrences.c.revision == expected_revision,
            ).values(component_locator=new_component_locator,
                     revision=expected_revision + 1))
            if updated.rowcount != 1:
                raise MembershipCorrectionError("occurrence revision changed during locator correction")
            conn.execute(correction_records.insert().values(
                correction_id=record.correction_id, record_type=record.record_type,
                record_id=record.record_id, old_value=record.old_value,
                new_value=record.new_value, actor=record.actor, reason=record.reason,
                correlation_id=record.correlation_id,
                affected_record_ids=list(record.affected_record_ids), created_at=record.created_at,
                field_name=record.field_name, previous_revision=record.previous_revision,
                new_revision=record.new_revision, assessment_impact="unverified",
                issue_impact="unverified"))

            sequence = conn.execute(sa.select(sa.func.coalesce(sa.func.max(
                mapping_alias_events.c.event_sequence), 0))).scalar_one()
            events = []
            if old_value is not None:
                events.append(("activate", old_value))
            if new_component_locator is not None and owners.get(new_key) == occurrence_id:
                events.append(("retire", new_component_locator))
            for action, value in events:
                sequence += 1
                conn.execute(mapping_alias_events.insert().values(
                    alias_event_id=new_id(), correction_id=record.correction_id,
                    action=action, record_type="occurrence",
                    field_name="component_locator", scope_a=scope[0],
                    scope_b=scope[1], old_value=value,
                    target_record_id=occurrence_id, evidence_ref=correlation_id,
                    occurred_at=at, event_sequence=sequence))

            after = conn.execute(sa.select(occurrences).where(
                occurrences.c.occurrence_id == occurrence_id)).mappings().one()
            persisted = conn.execute(sa.select(correction_records).where(
                correction_records.c.correction_id == record.correction_id
            )).mappings().one()
            if (after["component_locator"] != new_component_locator
                    or after["revision"] != expected_revision + 1
                    or after["occurrence_id"] != before["occurrence_id"]
                    or after["exposure_id"] != before["exposure_id"]
                    or after["incarnation_id"] != before["incarnation_id"]
                    or after["workload_id"] != before["workload_id"]
                    or after["created_at"] != before["created_at"]
                    or after["birth_component_locator"] != before["birth_component_locator"]
                    or after["birth_component_locator_recorded"] != before["birth_component_locator_recorded"]
                    or after["birth_exposure_id"] != before["birth_exposure_id"]
                    or after["birth_exposure_revision"] != before["birth_exposure_revision"]
                    or after["first_observed_at"] != before["first_observed_at"]
                    or after["first_ingested_at"] != before["first_ingested_at"]
                    or persisted["old_value"] != old_value
                    or persisted["new_value"] != new_component_locator
                    or persisted["actor"] != decision.principal_id
                    or persisted["reason"] != reason
                    or persisted["correlation_id"] != correlation_id
                    or persisted["previous_revision"] != expected_revision
                    or persisted["new_revision"] != expected_revision + 1):
                raise MembershipCorrectionReadError("locator correction read-back mismatch")
            alias_rows = conn.execute(sa.select(
                mapping_alias_events.c.action, mapping_alias_events.c.old_value,
            ).where(mapping_alias_events.c.correction_id == record.correction_id
            ).order_by(mapping_alias_events.c.event_sequence)).all()
            expected_aliases = []
            if old_value is not None:
                expected_aliases.append(("activate", old_value))
            if new_component_locator is not None and owners.get(new_key) == occurrence_id:
                expected_aliases.append(("retire", new_component_locator))
            if alias_rows != expected_aliases:
                raise MembershipCorrectionReadError("locator alias read-back mismatch")
            return record

    def apply_parent_transition(
        self, occurrence_id: str, to_exposure_id: str, actor: str,
        reason: str, correlation_id: str, at: datetime,
    ) -> dict:
        """Atomically reparent one occurrence between same-workload exposures.

        This is the separately approved 2.4b route.  It changes only the
        occurrence parent and revision; detection clocks and all other
        lineage remain untouched.  The correction marker and its
        independently captured parent-transition anchor are inserted in the
        same transaction as the row and alias projection changes.
        """
        _uuid(occurrence_id, "occurrence_id")
        _uuid(to_exposure_id, "to_exposure_id")
        if not actor or not reason or not correlation_id:
            raise MembershipCorrectionError("actor, reason and correlation ID are required")
        at = _aware_utc(at, "at")
        with self.engine.connect() as conn:
            try:
                self._begin_write_intent(conn)
                lock_identity_graph(conn)
                # Discover the source without taking the occurrence lock.  The
                # lock order for this route is exposure IDs, then occurrence;
                # taking the occurrence first can deadlock with the identity
                # writer, which uses exposure -> occurrence as well.
                discovered = conn.execute(sa.select(
                    occurrences.c.occurrence_id,
                    occurrences.c.exposure_id,
                    occurrences.c.revision,
                ).where(occurrences.c.occurrence_id == occurrence_id)
                ).mappings().first()
                if discovered is None:
                    raise MembershipCorrectionError("unknown occurrence")
                from_id = discovered["exposure_id"]
                if from_id == to_exposure_id:
                    raise MembershipCorrectionError("parent transition must change exposure")
                ids = sorted((from_id, to_exposure_id))
                parents = {}
                for exposure_id in ids:
                    row = conn.execute(sa.select(exposures).where(
                        exposures.c.exposure_id == exposure_id).with_for_update()
                    ).mappings().first()
                    if row is None:
                        raise MembershipCorrectionError("unknown target exposure")
                    parents[exposure_id] = dict(row)
                occ = conn.execute(sa.select(occurrences).where(
                    occurrences.c.occurrence_id == occurrence_id).with_for_update()
                ).mappings().first()
                if occ is None:
                    raise MembershipCorrectionError("unknown occurrence")
                if (occ["exposure_id"] != from_id
                        or occ["revision"] != discovered["revision"]):
                    raise MembershipCorrectionError(
                        "occurrence changed while parent transition was locking")
                source = parents[from_id]
                target = parents[to_exposure_id]
                if source["workload_id"] != target["workload_id"]:
                    raise MembershipCorrectionError("cross-workload parent transition is disabled")
                if occ["workload_id"] != source["workload_id"]:
                    raise MembershipCorrectionError("occurrence workload is incoherent")
                holder_query = sa.select(occurrences.c.occurrence_id).where(
                    occurrences.c.exposure_id == to_exposure_id,
                    occurrences.c.incarnation_id == occ["incarnation_id"],
                    occurrences.c.occurrence_id != occurrence_id)
                # NULL is an unknown locator, not a collision key.  Known
                # locators remain exclusive within exposure/incarnation.
                if occ["component_locator"] is not None:
                    holder_query = holder_query.where(
                        occurrences.c.component_locator == occ["component_locator"])
                holder = conn.execute(holder_query).first()
                if holder is not None:
                    raise MembershipCorrectionError("target occurrence locator collides")
                correction_id = new_id()
                new_revision = occ["revision"] + 1
                conn.execute(occurrences.update().where(
                    occurrences.c.occurrence_id == occurrence_id,
                    occurrences.c.revision == occ["revision"]).values(
                        exposure_id=to_exposure_id, revision=new_revision))
                record = dict(
                    correction_id=correction_id, record_type="occurrence",
                    record_id=occurrence_id, old_value=from_id,
                    new_value=to_exposure_id, actor=actor, reason=reason,
                    correlation_id=correlation_id,
                    affected_record_ids=[occurrence_id], created_at=at,
                    field_name="exposure_id", previous_revision=occ["revision"],
                    new_revision=new_revision, assessment_impact="unverified",
                    issue_impact="unverified")
                conn.execute(correction_records.insert().values(**record))
                conn.execute(occurrence_parent_transition_markers.insert().values(
                    correction_id=correction_id, schema_version=1))
                conn.execute(occurrence_parent_transition_anchors.insert().values(
                    correction_id=correction_id, occurrence_id=occurrence_id,
                    from_exposure_id=from_id, to_exposure_id=to_exposure_id,
                    previous_revision=occ["revision"], new_revision=new_revision,
                    from_exposure_revision=source["revision"],
                    to_exposure_revision=target["revision"]))
                self._insert_parent_alias_events(
                    conn, correction_id, occurrence_id, from_id, to_exposure_id,
                    correlation_id, at)
                actual = conn.execute(sa.select(occurrences).where(
                    occurrences.c.occurrence_id == occurrence_id)).mappings().one()
                if actual["exposure_id"] != to_exposure_id or actual["revision"] != new_revision:
                    raise MembershipCorrectionReadError("parent transition read-back mismatch")
            except Exception:
                conn.rollback()
                raise
            else:
                conn.commit()
                return record
            finally:
                self._restore_occurrence_fk(conn)

    def _insert_parent_alias_events(self, conn, correction_id, occurrence_id,
                                    from_id, to_id, correlation_id, at):
        keys = [("occurrence", "exposure_id", occurrence_id, None, from_id),
                ("occurrence", "exposure_id", occurrence_id, None, to_id)]
        owners = self._alias_owners(conn, keys)
        owner = owners.get(keys[1])
        base = conn.execute(sa.select(sa.func.max(
            mapping_alias_events.c.event_sequence))).scalar() or 0
        events = [("activate", from_id)]
        if owner == occurrence_id:
            events.append(("retire", to_id))
        for offset, (action, value) in enumerate(events, start=1):
            conn.execute(mapping_alias_events.insert().values(
                alias_event_id=new_id(), correction_id=correction_id,
                action=action, record_type="occurrence",
                field_name="exposure_id", scope_a=occurrence_id,
                scope_b=None, old_value=value, target_record_id=occurrence_id,
                evidence_ref=correlation_id, occurred_at=at,
                event_sequence=base + offset))

    # -- validation (all checks before any mutation) ------------------------

    def _validate(self, conn, exposure_id, new_workload_id, memberships,
                  actor, reason, correlation_id, at):
        exposure = self._load_exposure(conn, exposure_id)
        if exposure is None:
            raise MembershipCorrectionError("unknown correction target")
        if conn.execute(sa.select(workloads.c.workload_id).where(
                workloads.c.workload_id == new_workload_id)).first() is None:
            raise MembershipCorrectionError("new mapping target does not exist")
        if new_workload_id == exposure["workload_id"]:
            raise MembershipCorrectionError("correction must change the mapping")

        members = [dict(row) for row in conn.execute(
            sa.select(occurrences).where(
                occurrences.c.exposure_id == exposure_id
            ).order_by(occurrences.c.occurrence_id).with_for_update()
        ).mappings().all()]
        if not members:
            # Empty exposures use the scalar correction path, which retains
            # the scoped historical mapping (FR-ID-02).
            raise MembershipCorrectionError(
                "populated exposure required; empty exposures use scalar correction")
        if set(memberships) != {m["occurrence_id"] for m in members}:
            raise MembershipCorrectionError(
                "membership bundle must cover every exposure occurrence exactly once")

        group_id = exposure["group_id"]
        old_workload_id = exposure["workload_id"]
        # group x workload collision: another exposure already holds the
        # target (group, workload) pair.
        other = conn.execute(sa.select(exposures.c.exposure_id).where(
            exposures.c.group_id == group_id,
            exposures.c.workload_id == new_workload_id)).first()
        if other is not None:
            raise MembershipCorrectionError("corrected mapping collides with another record")

        # Resolve the target incarnations before claiming any alias state.
        targets = []
        seen_keys = set()
        for member in members:
            target_id = memberships[member["occurrence_id"]]
            incarnation = self._load_incarnation(conn, target_id)
            if incarnation is None:
                raise MembershipCorrectionError("new mapping target does not exist")
            if incarnation["workload_id"] != new_workload_id:
                raise MembershipCorrectionError(
                    "occurrence correction crosses workload membership")
            # occurrence-key collision: a known, non-null component locator
            # may name at most one occurrence per (exposure, incarnation);
            # null is never an index or match key (CR-03/04 clarification).
            if member["component_locator"] is not None:
                key = (exposure_id, target_id, member["component_locator"])
                if key in seen_keys:
                    raise MembershipCorrectionError(
                        "corrected mapping collides with another record")
                seen_keys.add(key)
                holder = conn.execute(sa.select(occurrences.c.occurrence_id).where(
                    occurrences.c.exposure_id == exposure_id,
                    occurrences.c.incarnation_id == target_id,
                    occurrences.c.component_locator == member["component_locator"]
                )).first()
                if holder is not None and holder[0] != member["occurrence_id"]:
                    raise MembershipCorrectionError(
                        "corrected mapping collides with another record")
            targets.append(target_id)

        # Historical alias ownership / reversal projection over the durable
        # mapping_alias_events log (latest event per key wins).
        exp_old_key = ("exposure", "workload_id", group_id, None, old_workload_id)
        exp_new_key = ("exposure", "workload_id", group_id, None, new_workload_id)
        keys = [exp_old_key, exp_new_key]
        for member, target_id in zip(members, targets):
            keys.append(("occurrence", "incarnation_id",
                         member["occurrence_id"], None, member["incarnation_id"]))
            keys.append(("occurrence", "incarnation_id",
                         member["occurrence_id"], None, target_id))
        owners = self._alias_owners(conn, keys)
        if owners.get(exp_old_key) not in (None, exposure_id):
            raise MembershipCorrectionError(
                "historical alias already belongs to another record")
        # The proposed active exposure mapping must not hold a value
        # historical to another exposure of the same group (scalar-path
        # resolver semantics, FR-ID-02/CR-03).
        if owners.get(exp_new_key) not in (None, exposure_id):
            raise MembershipCorrectionError(
                "historical alias already belongs to another record")
        for member in members:
            member_key = ("occurrence", "incarnation_id",
                          member["occurrence_id"], None, member["incarnation_id"])
            if owners.get(member_key) not in (None, member["occurrence_id"]):
                raise MembershipCorrectionError(
                    "historical alias already belongs to another record")

        # Linked observations: the durable observation -> occurrence link is
        # the identity_resolutions selection. Several append-only
        # resolution revisions per observation are legal (no uniqueness
        # over observation_id) and may select different occurrences — or
        # none at all (a later revision that matched nothing keeps a NULL
        # occurrence link). Each retained link is keyed by resolution_id
        # and read-back compares the COMPLETE per-observation history, so
        # the snapshot captures every revision of every linked observation,
        # not only the revisions selecting moved occurrences.
        # Linked ids must honour the UVM UUID contract BEFORE any mutation
        # (append-only lineage), and they are impact of the records that
        # own them.
        member_ids = [m["occurrence_id"] for m in members]
        rows = conn.execute(sa.select(
            identity_resolutions.c.resolution_id,
            identity_resolutions.c.observation_id,
            identity_resolutions.c.occurrence_id).where(
            identity_resolutions.c.occurrence_id.in_(member_ids)
        ).order_by(identity_resolutions.c.resolution_id)).all()
        linked = {occ_id: [] for occ_id in member_ids}
        for resolution_id, observation_id, occurrence_id in rows:
            _uuid(observation_id, "linked observation_id")
            if observation_id not in linked[occurrence_id]:
                linked[occurrence_id].append(observation_id)
        # Full-history snapshot: every revision of every linked observation,
        # including null occurrence links, keyed by resolution_id.
        observation_ids = sorted({observation_id
                                  for ids in linked.values()
                                  for observation_id in ids})
        links_by_observation = {}
        if observation_ids:
            rows = conn.execute(sa.select(
                identity_resolutions.c.resolution_id,
                identity_resolutions.c.observation_id,
                identity_resolutions.c.occurrence_id).where(
                identity_resolutions.c.observation_id.in_(observation_ids)
            ).order_by(identity_resolutions.c.resolution_id)).all()
            for resolution_id, observation_id, occurrence_id in rows:
                links_by_observation.setdefault(
                    observation_id, {})[resolution_id] = occurrence_id
        snapshot = _Snapshot(
            exposure=dict(exposure),
            old_workload_id=old_workload_id,
            new_workload_id=new_workload_id,
            members=members,
            targets=targets,
            linked_observations={k: tuple(sorted(v)) for k, v in linked.items()},
            resolution_links={k: tuple(sorted(v.items()))
                              for k, v in links_by_observation.items()},
            records=[],
        )
        snapshot.records = self._build_records(snapshot, actor, reason,
                                               correlation_id, at)
        return snapshot

    def _load_exposure(self, conn, exposure_id):
        row = conn.execute(sa.select(exposures).where(
            exposures.c.exposure_id == exposure_id).with_for_update()
        ).mappings().first()
        return dict(row) if row is not None else None

    def _load_incarnation(self, conn, incarnation_id):
        row = conn.execute(sa.select(incarnations).where(
            incarnations.c.incarnation_id == incarnation_id).with_for_update()
        ).mappings().first()
        return dict(row) if row is not None else None

    def _alias_owners(self, conn, keys):
        """Active alias owner per key: the latest event (by durable
        ``event_sequence``) per key, where only an ``activate`` is active.
        ``FOR UPDATE`` on the pinned latest rows serialises concurrent
        alias writers on the same keys in PostgreSQL (no-op on SQLite)."""
        owners = {}
        for record_type, field_name, scope_a, scope_b, old_value in keys:
            row = conn.execute(sa.select(
                mapping_alias_events.c.action,
                mapping_alias_events.c.target_record_id,
            ).where(_alias_condition(record_type, field_name, scope_a, scope_b,
                                     old_value)).order_by(
                sa.desc(mapping_alias_events.c.event_sequence)).with_for_update()
            ).first()
            if row is not None and row[0] == "activate":
                owners[(record_type, field_name, scope_a, scope_b, old_value)] = row[1]
        return owners

    def _build_records(self, snap: _Snapshot, actor, reason, correlation_id, at):
        def impact(occurrence_ids):
            ids = set(occurrence_ids)
            for occurrence_id in occurrence_ids:
                ids.update(snap.linked_observations.get(occurrence_id, ()))
            return tuple(sorted(ids))

        records = [CorrectionRecord(
            correction_id=new_id(), record_type="exposure",
            record_id=snap.exposure["exposure_id"],
            old_value=snap.old_workload_id, new_value=snap.new_workload_id,
            actor=actor, reason=reason, correlation_id=correlation_id,
            affected_record_ids=impact([m["occurrence_id"] for m in snap.members]),
            created_at=at, field_name="workload_id",
            previous_revision=snap.exposure["revision"],
            new_revision=snap.exposure["revision"] + 1,
        )]
        for member, target_id in zip(snap.members, snap.targets):
            records.append(CorrectionRecord(
                correction_id=new_id(), record_type="occurrence",
                record_id=member["occurrence_id"],
                old_value=member["incarnation_id"], new_value=target_id,
                actor=actor, reason=reason, correlation_id=correlation_id,
                affected_record_ids=impact([member["occurrence_id"]]),
                created_at=at, field_name="incarnation_id",
                previous_revision=member["revision"],
                new_revision=member["revision"] + 1,
            ))
        return records

    def _begin_write_intent(self, conn) -> None:
        """Open the write transaction. PostgreSQL: a plain transaction
        plus the ``FOR UPDATE`` row loads serialise writers (unchanged).
        SQLite: pysqlite defers the write lock to the first DML and only
        applies ``defer_foreign_keys`` at the implicit transaction start,
        holding the flag until the next statement — so issue the PRAGMA
        and then a no-op UPDATE: the UPDATE fires the implicit BEGIN
        with deferral active AND acquires the write lock (RESERVED)
        before any validation read. A concurrent writer therefore
        commits before validation runs (visible) or blocks until this
        transaction settles (CR-03: impact never omits an observation)."""
        dialect = conn.dialect.name
        if dialect == "postgresql":
            return
        if dialect == "sqlite":
            conn.exec_driver_sql("PRAGMA defer_foreign_keys=ON")
            conn.exec_driver_sql(
                "UPDATE workloads SET workload_id = workload_id WHERE 1 = 0")
            return
        raise MembershipCorrectionError(
            f"membership correction does not support {dialect}")

    # -- deferral route (0002) -------------------------------------------------

    def _defer_occurrence_fk(self, conn) -> None:
        """Defer ONLY the current-membership occurrence FK for the write
        (the 0002 correction deferral route). PostgreSQL deferral is
        transaction-scoped and is issued here, inside the transaction.
        On SQLite the deferral is acquired together with the write lock
        in ``_begin_write_intent`` (the pysqlite flag only applies at
        the implicit transaction start, which must also precede every
        validation read), so there is nothing to issue at write time."""
        if conn.dialect.name == "postgresql":
            conn.execute(sa.text(f"SET CONSTRAINTS {_OCCURRENCE_FK} DEFERRED"))

    def _restore_occurrence_fk(self, conn) -> None:
        if conn.dialect.name != "sqlite":
            return
        try:
            conn.exec_driver_sql("PRAGMA defer_foreign_keys=OFF")
        except sa.exc.DBAPIError:
            # The write transaction is already gone (connection error);
            # the flag cannot matter. Never mask the original failure.
            pass

    def _retain_pair(self, conn, exposure_id: str, workload_id: str) -> None:
        """Insert-or-reuse the retained ``(exposure_id, workload_id)`` pair.
        The corrected-to pair must exist for resolutions that select this
        exposure going forward; the former pair is never touched (the
        writer deletes no pair rows). Concurrent corrections of this
        exposure are serialised by the exposure row lock, so the
        select-then-insert cannot race."""
        existing = conn.execute(sa.select(
            exposure_workload_memberships.c.workload_id).where(
            exposure_workload_memberships.c.exposure_id == exposure_id,
            exposure_workload_memberships.c.workload_id == workload_id
        )).first()
        if existing is None:
            conn.execute(exposure_workload_memberships.insert().values(
                exposure_id=exposure_id, workload_id=workload_id))

    # -- mutation -------------------------------------------------------------

    def _mutate(self, conn, snap: _Snapshot) -> None:
        # Defer the current-membership occurrence FK for the transient
        # move (PostgreSQL; the SQLite deferral was already acquired with
        # the write lock in _begin_write_intent).
        self._defer_occurrence_fk(conn)
        # Optimistic revision guard (compare-and-swap on the loaded
        # revision): a concurrent bump between load and update makes the
        # rowcount zero and fails the whole transaction.
        result = conn.execute(exposures.update().where(
            exposures.c.exposure_id == snap.exposure["exposure_id"],
            exposures.c.revision == snap.exposure["revision"],
        ).values(workload_id=snap.new_workload_id,
                 revision=snap.exposure["revision"] + 1))
        if result.rowcount != 1:
            raise MembershipCorrectionError(
                "concurrent modification detected: exposure revision guard failed")
        for member, target_id in zip(snap.members, snap.targets):
            result = conn.execute(occurrences.update().where(
                occurrences.c.occurrence_id == member["occurrence_id"],
                occurrences.c.revision == member["revision"],
            ).values(incarnation_id=target_id,
                      workload_id=snap.new_workload_id,
                      revision=member["revision"] + 1))
            if result.rowcount != 1:
                raise MembershipCorrectionError(
                    "concurrent modification detected: occurrence revision guard failed")
        # Retained pair (0002): the corrected-to pair is inserted or
        # reused; the former pair is retained as-is for append-only
        # history (the 0002 identity_resolutions composite FK references
        # the retained pair table, not the exposure's current pair).
        self._retain_pair(conn, snap.exposure["exposure_id"],
                          snap.new_workload_id)
        self._insert_correction_rows(conn, snap)
        self._insert_alias_events(conn, snap)

    def _insert_correction_rows(self, conn, snap: _Snapshot) -> None:
        for record in snap.records:
            conn.execute(correction_records.insert().values(
                correction_id=record.correction_id,
                record_type=record.record_type,
                record_id=record.record_id,
                old_value=record.old_value,
                new_value=record.new_value,
                actor=record.actor,
                reason=record.reason,
                correlation_id=record.correlation_id,
                affected_record_ids=list(record.affected_record_ids),
                created_at=record.created_at,
                field_name=record.field_name,
                previous_revision=record.previous_revision,
                new_revision=record.new_revision,
                assessment_impact=record.assessment_impact,
                issue_impact=record.issue_impact,
            ))

    def _insert_alias_events(self, conn, snap: _Snapshot) -> None:
        # Transactional event_sequence allocation (alias_schema writer
        # guarantee): max existing + n within THIS transaction. The DDL
        # unique over event_sequence is the backstop; a lost concurrent
        # allocation rolls back the whole write transaction (caller
        # retries) — no partial commit.
        base = conn.execute(sa.select(sa.func.max(
            mapping_alias_events.c.event_sequence))).scalar() or 0
        events = []
        sequence = base
        for record in snap.records:
            # Activation: the corrected former value is now historical for
            # this record. Exposure scope_a = untouched counterpart (the
            # group for a workload mapping); occurrence scope_a = the
            # occurrence record ID (per-record parent-mapping history).
            if record.record_type == "exposure":
                scope_a, scope_b = snap.exposure["group_id"], None
            else:
                scope_a, scope_b = record.record_id, None
            events.append(dict(correction_id=record.correction_id,
                               action="activate",
                               record_type=record.record_type,
                               field_name=record.field_name,
                               scope_a=scope_a, scope_b=scope_b,
                               old_value=record.old_value,
                               target_record_id=record.record_id,
                               evidence_ref=record.correlation_id,
                               occurred_at=record.created_at))
            # Retire: the corrected-to value was historical for THIS record
            # (an earlier correction retired it and the correction reclaims
            # it), so the active alias entry is retired — a retained event,
            # never a rewrite.
            reclaim_key = (record.record_type, record.field_name,
                           scope_a, scope_b, record.new_value)
            # First corrections have no prior durable alias history: an
            # unknown key is an empty/None ownership result, not a KeyError.
            owner = self._alias_owners(conn, [reclaim_key]).get(reclaim_key)
            if owner == record.record_id:
                sequence += 1
                events.append(dict(correction_id=record.correction_id,
                                   action="retire",
                                   record_type=record.record_type,
                                   field_name=record.field_name,
                                   scope_a=scope_a, scope_b=scope_b,
                                   old_value=record.new_value,
                                   target_record_id=record.record_id,
                                   evidence_ref=record.correlation_id,
                                   occurred_at=record.created_at))
        for event in events:
            sequence += 1
            # Every event gets its own fresh canonical UUID primary key.
            event["alias_event_id"] = new_id()
            event["event_sequence"] = sequence
            conn.execute(mapping_alias_events.insert().values(**event))

    # -- read-back (inside the write transaction, before commit) --------------

    def _read_back(self, conn, snap: _Snapshot) -> None:
        try:
            exposure = conn.execute(sa.select(exposures).where(
                exposures.c.exposure_id == snap.exposure["exposure_id"]
            )).mappings().one()
            self._assert_same_clocks(
                snap.exposure, dict(exposure),
                ("created_at", "first_observed_at"), "exposure")
            if exposure["workload_id"] != snap.new_workload_id:
                raise ValueError("exposure did not move to the reviewed workload")
            if exposure["revision"] != snap.exposure["revision"] + 1:
                raise ValueError("exposure revision did not bump by one")
            for member, target_id in zip(snap.members, snap.targets):
                row = conn.execute(sa.select(occurrences).where(
                    occurrences.c.occurrence_id == member["occurrence_id"]
                )).mappings().one()
                self._assert_same_clocks(
                    member, dict(row),
                    ("created_at", "first_observed_at", "first_ingested_at"),
                    "occurrence")
                if (row["incarnation_id"] != target_id
                        or row["workload_id"] != snap.new_workload_id
                        or row["exposure_id"] != snap.exposure["exposure_id"]
                        or row["revision"] != member["revision"] + 1):
                    raise ValueError("occurrence membership is incoherent")
            rows = conn.execute(sa.select(correction_records).where(
                correction_records.c.correlation_id ==
                snap.records[0].correlation_id
            ).order_by(correction_records.c.record_type,
                       correction_records.c.record_id)).mappings().all()
            if len(rows) != len(snap.records):
                raise ValueError("correlated correction history is incomplete")
            for row, expected in zip(rows, snap.records):
                if (row["record_id"] != expected.record_id
                        or row["old_value"] != expected.old_value
                        or row["new_value"] != expected.new_value
                        or row["field_name"] != expected.field_name
                        or row["previous_revision"] != expected.previous_revision
                        or row["new_revision"] != expected.new_revision
                        or row["assessment_impact"] != "unverified"
                        or row["issue_impact"] != "unverified"
                        or set(row["affected_record_ids"])
                        != set(expected.affected_record_ids)):
                    raise ValueError("correlated correction row is inconsistent")
            keys = [("exposure", "workload_id", snap.exposure["group_id"], None,
                     snap.old_workload_id)]
            for record in snap.records:
                scope_a = (snap.exposure["group_id"] if record.record_type
                           == "exposure" else record.record_id)
                keys.append((record.record_type, record.field_name, scope_a,
                             None, record.old_value))
            for key in keys:
                latest = conn.execute(sa.select(
                    mapping_alias_events.c.action,
                    mapping_alias_events.c.target_record_id).where(
                    _alias_condition(*key)).order_by(
                    sa.desc(mapping_alias_events.c.event_sequence))).first()
                if latest is None or latest[0] != "activate":
                    raise ValueError("alias activation history is missing")
            for record in snap.records:
                scope_a = (snap.exposure["group_id"] if record.record_type
                           == "exposure" else record.record_id)
                reclamation = conn.execute(sa.select(
                    mapping_alias_events.c.action).where(
                    _alias_condition(record.record_type, record.field_name,
                                     scope_a, None, record.new_value)).order_by(
                    sa.desc(mapping_alias_events.c.event_sequence))).first()
                if reclamation is not None and reclamation[0] != "retire":
                    raise ValueError("reclaimed value alias history is inconsistent")
            # Observation links survive: each linked observation still
            # exists and its complete append-only resolution history is
            # unchanged (every retained resolution_id still selects the
            # same occurrence — multi-revision observations are legal
            # and may name different occurrences per revision).
            for observation_id, expected in snap.resolution_links.items():
                if conn.execute(sa.select(
                        source_observations.c.observation_id).where(
                        source_observations.c.observation_id == observation_id
                )).first() is None:
                    raise ValueError("linked observation no longer exists")
                links = conn.execute(sa.select(
                    identity_resolutions.c.resolution_id,
                    identity_resolutions.c.occurrence_id).where(
                    identity_resolutions.c.observation_id == observation_id
                ).order_by(identity_resolutions.c.resolution_id)).all()
                if tuple((r[0], r[1]) for r in links) != expected:
                    raise ValueError(
                        "observation resolution links changed during correction")
            # Retained-pair invariants: the corrected-to pair exists and
            # the former pair was not removed (append-only, CR-03).
            for workload_id in (snap.old_workload_id, snap.new_workload_id):
                if conn.execute(sa.select(
                        exposure_workload_memberships.c.workload_id).where(
                        exposure_workload_memberships.c.exposure_id ==
                        snap.exposure["exposure_id"],
                        exposure_workload_memberships.c.workload_id ==
                        workload_id
                )).first() is None:
                    raise ValueError(
                        "retained exposure/workload membership pair is missing")
            # Deferred foreign keys are only checked at commit: run the
            # check now, before commit, so a violation fails the
            # transaction here (SQLite route; PostgreSQL deferral is
            # integration-unverified and has no equivalent pragma).
            if conn.dialect.name == "sqlite":
                violations = conn.exec_driver_sql(
                    "PRAGMA foreign_key_check").fetchall()
                if violations:
                    raise ValueError(
                        f"deferred foreign key check failed: {violations[:3]}")
        except MembershipCorrectionReadError:
            raise
        except Exception as exc:
            raise MembershipCorrectionReadError(
                f"correction failed coherent read-back: {exc}") from exc

    @staticmethod
    def _assert_same_clocks(before, after, columns, kind) -> None:
        for column in columns:
            expected = _utc(before[column], f"{kind}.{column}")
            actual = _utc(after[column], f"{kind}.{column}")
            if expected != actual:
                raise ValueError(f"{kind}.{column} clock was rewritten")


class OccurrenceParentTransitionStore(MembershipCorrectionStore):
    """Named facade for the approved cross-exposure writer route."""

    def apply(self, occurrence_id: str, to_exposure_id: str, actor: str,
              reason: str, correlation_id: str, at: datetime) -> dict:
        return self.apply_parent_transition(
            occurrence_id, to_exposure_id, actor, reason, correlation_id, at)
