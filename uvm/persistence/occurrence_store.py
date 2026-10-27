"""Atomic creation and read-back of anchored UVM occurrences.

The writer captures the exposure revision while holding the exposure lock.  It
therefore records the exposure phase in which an occurrence was born, rather
than trying to infer that phase from later correction history.  This module is
deliberately SQLite-unit-testable; PostgreSQL uses the same exposure-first
lock order with ``FOR UPDATE``.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime, timezone

import sqlalchemy as sa
from uvm.persistence.identity_graph_lock import lock_identity_graph
from sqlalchemy.exc import IntegrityError

from uvm.persistence.lineage_schema import correction_records
from uvm.persistence.schema import (
    exposure_workload_memberships,
    exposures,
    incarnations,
    occurrences,
)

UTC = timezone.utc


class OccurrenceWriteError(ValueError):
    """Invalid input, stale membership, or an immutable-content conflict."""


class OccurrenceReadError(OccurrenceWriteError):
    """A requested occurrence does not exist or is not readable."""


@dataclass(frozen=True)
class OccurrenceCreate:
    """Caller-owned immutable fields for one occurrence creation."""

    occurrence_id: str
    exposure_id: str
    incarnation_id: str
    workload_id: str
    component_locator: str | None
    first_observed_at: datetime | None
    first_ingested_at: datetime
    revision: int
    created_at: datetime


@dataclass(frozen=True)
class OccurrenceRecord:
    """Persisted occurrence, including its derived birth anchor."""

    occurrence_id: str
    exposure_id: str
    incarnation_id: str
    workload_id: str
    component_locator: str | None
    birth_exposure_id: str | None
    birth_exposure_revision: int | None
    birth_component_locator: str | None
    birth_component_locator_recorded: bool
    first_observed_at: datetime | None
    first_ingested_at: datetime
    revision: int
    created_at: datetime


def _uuid(value: object, name: str) -> str:
    try:
        parsed = uuid.UUID(value)  # type: ignore[arg-type]
    except (ValueError, TypeError, AttributeError):
        raise OccurrenceWriteError(f"{name} must be a canonical UUID") from None
    if str(parsed) != value:
        raise OccurrenceWriteError(f"{name} must be a canonical UUID")
    return value  # type: ignore[return-value]


def _utc(value: object, name: str, *, nullable: bool = False) -> datetime | None:
    if value is None and nullable:
        return None
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise OccurrenceWriteError(f"{name} must be timezone-aware")
    return value.astimezone(UTC)


def _stored_utc(value: datetime | None) -> datetime | None:
    """SQLite returns a naive datetime for a timezone-aware column."""
    if value is None:
        return None
    if value.tzinfo is None or value.utcoffset() is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


class OccurrenceStore:
    """Create anchored occurrences transactionally and read them back."""

    def __init__(self, engine):
        self.engine = engine

    def write(self, request: OccurrenceCreate) -> OccurrenceRecord:
        values = self._validate(request)
        if self.engine.dialect.name == "sqlite":
            # SQLite has no row-level FOR UPDATE.  BEGIN IMMEDIATE acquires
            # the write-intent lock before the exposure read.
            conn = self.engine.connect().execution_options(isolation_level="AUTOCOMMIT")
            try:
                conn.exec_driver_sql("BEGIN IMMEDIATE")
                result = self._write_inner(conn, request, values)
            except Exception:
                try:
                    conn.rollback()
                except sa.exc.DBAPIError:
                    pass
                raise
            else:
                conn.commit()
                return result
            finally:
                conn.close()
        with self.engine.begin() as conn:
            return self._write_inner(conn, request, values)

    def read(self, occurrence_id: str) -> OccurrenceRecord:
        _uuid(occurrence_id, "occurrence_id")
        with self.engine.connect() as conn:
            row = conn.execute(sa.select(occurrences).where(
                occurrences.c.occurrence_id == occurrence_id)).mappings().first()
            if row is None:
                raise OccurrenceReadError("occurrence not found")
            return self._record(row)

    @staticmethod
    def _validate(request: OccurrenceCreate) -> dict:
        for name in ("occurrence_id", "exposure_id", "incarnation_id", "workload_id"):
            _uuid(getattr(request, name), name)
        if (not isinstance(request.revision, int)
                or isinstance(request.revision, bool)
                or request.revision != 1):
            raise OccurrenceWriteError("first occurrence revision must be 1")
        first_observed = _utc(request.first_observed_at, "first_observed_at", nullable=True)
        first_ingested = _utc(request.first_ingested_at, "first_ingested_at")
        created = _utc(request.created_at, "created_at")
        if request.component_locator is not None and not isinstance(
                request.component_locator, str):
            raise OccurrenceWriteError("component_locator must be a string or None")
        return dict(
            occurrence_id=request.occurrence_id,
            exposure_id=request.exposure_id,
            incarnation_id=request.incarnation_id,
            workload_id=request.workload_id,
            component_locator=request.component_locator,
            first_observed_at=first_observed,
            first_ingested_at=first_ingested,
            revision=request.revision,
            created_at=created,
        )

    def _write_inner(self, conn, request: OccurrenceCreate, values: dict) -> OccurrenceRecord:
        lock_identity_graph(conn)
        if not {"birth_component_locator", "birth_component_locator_recorded"}.issubset(
                {column["name"] for column in sa.inspect(conn).get_columns("occurrences")}):
            raise OccurrenceWriteError("0004 birth locator storage is required")
        exposure_query = sa.select(exposures).where(
            exposures.c.exposure_id == request.exposure_id)
        if self.engine.dialect.name == "postgresql":
            exposure_query = exposure_query.with_for_update()
        exposure = conn.execute(exposure_query).mappings().first()
        if exposure is None:
            raise OccurrenceWriteError("exposure not found")

        # Check a retry by stable ID before current-membership validation.
        # A correction may have moved the exposure after the original commit;
        # an exact resend must still read back the immutable original row.
        existing = conn.execute(sa.select(occurrences).where(
            occurrences.c.occurrence_id == request.occurrence_id)).mappings().first()
        if existing is not None:
            if self._same_birth_request(conn, existing, exposure, values):
                return self._record(existing)
            raise OccurrenceWriteError("occurrence ID already exists with different content")
        if exposure["workload_id"] != request.workload_id:
            raise OccurrenceWriteError("exposure is not current for workload")
        membership = conn.execute(sa.select(exposure_workload_memberships).where(
            exposure_workload_memberships.c.exposure_id == request.exposure_id,
            exposure_workload_memberships.c.workload_id == request.workload_id,
        )).first()
        if membership is None:
            raise OccurrenceWriteError("exposure has no current membership")
        incarnation = conn.execute(sa.select(incarnations).where(
            incarnations.c.incarnation_id == request.incarnation_id)).mappings().first()
        if incarnation is None:
            raise OccurrenceWriteError("incarnation not found")
        if incarnation["workload_id"] != request.workload_id:
            raise OccurrenceWriteError("incarnation is not current for workload")

        anchored = dict(values, birth_exposure_id=request.exposure_id,
                        birth_exposure_revision=exposure["revision"],
                        birth_component_locator=request.component_locator,
                        birth_component_locator_recorded=True)
        # NULL is an unknown locator, not a natural-key value.  The schema's
        # nullable unique constraint consequently permits multiple unknown
        # occurrences; mirror that rule here and only pre-check known keys.
        if request.component_locator is not None:
            natural = conn.execute(sa.select(occurrences).where(
                occurrences.c.exposure_id == request.exposure_id,
                occurrences.c.incarnation_id == request.incarnation_id,
                occurrences.c.component_locator == request.component_locator
            )).mappings().first()
            if natural is not None:
                raise OccurrenceWriteError(
                    "occurrence identity already exists with different content")
        try:
            conn.execute(occurrences.insert().values(**anchored))
        except IntegrityError as exc:
            raise OccurrenceWriteError("occurrence creation violated a persistence constraint") from exc
        row = conn.execute(sa.select(occurrences).where(
            occurrences.c.occurrence_id == request.occurrence_id)).mappings().one()
        if not self._matches_created_row(row, values, anchored):
            raise OccurrenceWriteError(
                "persisted occurrence differs from validated creation content")
        return self._record(row)

    @staticmethod
    def _matches_created_row(row, values: dict, anchored: dict) -> bool:
        """Ensure insert triggers cannot make an inconsistent write succeed."""
        for name in (
                "occurrence_id", "exposure_id", "incarnation_id", "workload_id",
                "component_locator", "revision", "birth_exposure_id",
                "birth_exposure_revision", "birth_component_locator",
                "birth_component_locator_recorded"):
            if row[name] != anchored[name]:
                return False
        for name in ("first_observed_at", "first_ingested_at", "created_at"):
            if _stored_utc(row[name]) != _stored_utc(values[name]):
                return False
        return True

    @staticmethod
    def _ordered_history(conn, record_type: str, record_id: str, revision: int):
        rows = conn.execute(sa.select(correction_records).where(
            correction_records.c.record_type == record_type,
            correction_records.c.record_id == record_id)).mappings().all()
        transitions = [r for r in rows if
                       (r["previous_revision"], r["new_revision"]) != (0, 0)]
        if (not isinstance(revision, int) or revision < 1
                or len(transitions) != revision - 1):
            return None
        transitions.sort(key=lambda r: r["previous_revision"])
        if any(r["previous_revision"] != index
               or r["new_revision"] != index + 1
               for index, r in enumerate(transitions, start=1)):
            return None
        return rows, transitions

    @classmethod
    def _same_birth_request(cls, conn, row, exposure, values: dict) -> bool:
        """Compare only immutable creation-event content for an ID retry.

        Membership and locator can change after birth.  The birth exposure
        revision, recorded locator and correlated correction chains prove the
        original request; current values alone do not.
        """
        if (row["birth_exposure_id"] != values["exposure_id"]
                or row["exposure_id"] != values["exposure_id"]):
            # Cross-exposure reassignment has no approved parent-transition
            # proof contract yet.
            return False
        birth_revision = row["birth_exposure_revision"]
        if (not isinstance(birth_revision, int) or birth_revision < 1
                or birth_revision > exposure["revision"]):
            return False
        for name in ("first_observed_at", "first_ingested_at", "created_at"):
            expected = values[name]
            actual = row[name]
            actual = _stored_utc(actual)
            expected = _stored_utc(expected)
            if actual != expected:
                return False
        exp_history = cls._ordered_history(
            conn, "exposure", values["exposure_id"], exposure["revision"])
        occ_history = cls._ordered_history(
            conn, "occurrence", values["occurrence_id"], row["revision"])
        if exp_history is None or occ_history is None:
            return False
        exp_rows, exp_transitions = exp_history
        occ_rows, occ_transitions = occ_history
        if any(r["field_name"] == "workload_id" for r in exp_rows
               if r["previous_revision"] == 0):
            return False
        if any(r["field_name"] in ("incarnation_id", "component_locator")
               for r in occ_rows if r["previous_revision"] == 0):
            return False
        if any(r["field_name"] in ("exposure_id", "workload_id")
               for r in occ_rows):
            # Cross-exposure transitions have no approved proof contract;
            # the membership writer changes workload with incarnation.
            return False

        exp_moves = [r for r in exp_transitions
                     if r["field_name"] == "workload_id"]
        workload = (exp_moves[0]["old_value"] if exp_moves
                    else exposure["workload_id"])
        birth_workload = workload if birth_revision == 1 else None
        for step in exp_transitions:
            if step["field_name"] == "workload_id":
                if step["old_value"] != workload:
                    return False
                workload = step["new_value"]
            if step["new_revision"] == birth_revision:
                birth_workload = workload
        if birth_workload is None or workload != exposure["workload_id"] \
                or birth_workload != values["workload_id"]:
            return False

        occ_moves = [r for r in occ_transitions
                     if r["field_name"] == "incarnation_id"]
        birth_incarnation = (occ_moves[0]["old_value"] if occ_moves
                             else row["incarnation_id"])
        if birth_incarnation != values["incarnation_id"]:
            return False
        paired_exp_moves = [r for r in exp_moves
                            if r["new_revision"] > birth_revision]
        if len(paired_exp_moves) != len(occ_moves):
            return False
        current_incarnation = birth_incarnation
        seen_correlations = set()
        for occ_step, exp_step in zip(occ_moves, paired_exp_moves):
            correlation = occ_step["correlation_id"]
            if (not correlation or correlation != exp_step["correlation_id"]
                    or correlation in seen_correlations
                    or occ_step["old_value"] != current_incarnation):
                return False
            seen_correlations.add(correlation)
            current_incarnation = occ_step["new_value"]
        if current_incarnation != row["incarnation_id"] \
                or row["workload_id"] != exposure["workload_id"]:
            return False
        incarnation_ids = list({birth_incarnation} |
                               {r["new_value"] for r in occ_moves})
        membership = {}
        for offset in range(0, len(incarnation_ids), 500):
            membership.update(conn.execute(sa.select(
                incarnations.c.incarnation_id,
                incarnations.c.workload_id).where(
                incarnations.c.incarnation_id.in_(
                    incarnation_ids[offset:offset + 500]))).all())
        if membership.get(birth_incarnation) != birth_workload:
            return False
        for occ_step, exp_step in zip(occ_moves, paired_exp_moves):
            if membership.get(occ_step["new_value"]) != exp_step["new_value"]:
                return False

        locator_steps = [r for r in occ_transitions
                         if r["field_name"] == "component_locator"]
        if row["birth_component_locator_recorded"]:
            locator = row["birth_component_locator"]
        elif locator_steps:
            # 0003 legacy rows have no independent first old value.
            return False
        else:
            locator = row["component_locator"]
        if locator != values["component_locator"]:
            return False
        for step in locator_steps:
            if step["old_value"] != locator:
                return False
            locator = step["new_value"]
        return locator == row["component_locator"]

    @staticmethod
    def _record(row) -> OccurrenceRecord:
        return OccurrenceRecord(
            occurrence_id=row["occurrence_id"], exposure_id=row["exposure_id"],
            incarnation_id=row["incarnation_id"], workload_id=row["workload_id"],
            component_locator=row["component_locator"],
            birth_exposure_id=row["birth_exposure_id"],
            birth_exposure_revision=row["birth_exposure_revision"],
            birth_component_locator=row["birth_component_locator"],
            birth_component_locator_recorded=bool(row["birth_component_locator_recorded"]),
            first_observed_at=_stored_utc(row["first_observed_at"]),
            first_ingested_at=_stored_utc(row["first_ingested_at"]),
            revision=row["revision"], created_at=_stored_utc(row["created_at"]),
        )
