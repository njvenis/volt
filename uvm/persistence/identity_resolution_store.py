"""Append-only persistence for IdentityResolutionV1 (FR-ID-01/02).

This store validates writer-level membership and history rules and reads
records back through the shared UVM SQLAlchemy metadata. It does not claim
database-level immutability.

Historical vs current chain (FR-ID-02/CR-03, migration 0002): read-back of a
persisted ``matched``/``new`` selection validates against the RETAINED
``exposure_workload_memberships`` pair and the correlated correction history,
never against today's exposure/occurrence membership — a guarded correction
may have moved the exposure and re-pointed its occurrences since the
selection was issued, and the retained row must stay readable (including the
exact-resend read-back inside ``write``). The re-pointing is admitted only by
an ordered, contiguous, correlated correction history: the membership steps
are correlated 1:1 by correlation ID (each occurrence ``incarnation_id``
step has the exposure ``workload_id`` step in the same chronological
position with the same correlation ID and coherent old/new membership — the two
records may carry DIFFERENT revision numbers because an independent
field correction, e.g. a component-locator fix, bumps one record's
revision independently), and each record is held to its OWN ordered,
contiguous revision chain: the recorded transitions (any field) must be
exactly {1→2, …, R-1→R} up to the record's persisted revision, and each
step of the occurrence chain links on ``previous_revision``/``new_revision``
(so reversals such as A→B→A→C follow the recorded sequence, never an
unordered first-edge walk). The chain must end at the current occurrence
incarnation and the exposure's current workload — a fabricated or
unrelated record revision (e.g. 99→100 with no exposure correction)
cannot back the move.
Newly issued selections (new rows in ``write``) must match the CURRENT chain:
the check loads the exposure row with ``FOR UPDATE`` (PostgreSQL, the same
row the correction writer locks). On SQLite the whole write transaction
starts with ``BEGIN IMMEDIATE`` so the write-intent lock is held from
transaction start and a concurrent correction cannot commit between the
chain check and the insert; a revision re-check immediately before insert is
the additional optimistic guard. The DDL composite foreign key onto the
retained pair table is the backstop.
At the 0002 and 0003 heads this V1 writer rejects new selected rows before
insertion: V1 has no selected-revision fields, so it cannot issue verified
temporal proof.
Retained V1 rows remain readable through the status-aware and strict paths.
"""
from __future__ import annotations

import json
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone

import sqlalchemy as sa
from uvm.persistence.identity_graph_lock import lock_identity_graph

from uvm.identity.model import (
    IdentityResolutionV1, IdentityResolutionV2, OUTCOMES, SCHEMA_VERSION_V2,
)
from uvm.persistence.lineage_schema import (
    correction_records,
    identity_resolutions,
    occurrence_parent_transition_markers,
    occurrence_parent_transition_anchors,
    resolution_temporal_assessments,
)
from uvm.persistence.observation_schema import source_observations
from uvm.persistence.schema import (
    exposure_workload_memberships,
    exposures,
    groups,
    incarnations,
    occurrences,
    workloads,
)

UTC = timezone.utc

# ``identity_resolutions`` is shared with the additive 0003 V2 shape.  V1
# reads must remain insulated from columns owned by that later contract.
_V1_FIELDS = (
    "schema_version", "resolution_id", "revision", "observation_id",
    "rule_id", "rule_version", "matching_inputs", "candidate_workload_ids",
    "outcome", "evaluated_at", "group_id", "workload_id", "incarnation_id",
    "exposure_id", "occurrence_id", "candidate_explanations", "reason",
    "supersedes_resolution_id",
)
_V2_FIELDS = _V1_FIELDS + (
    "selected_exposure_revision", "selected_occurrence_revision",
    "known_group_revision",
)


class IdentityResolutionError(ValueError):
    """Invalid resolution, missing references, or incompatible history."""


class IdentityResolutionReadError(IdentityResolutionError):
    """Persisted resolution failed validation during read-back."""


@dataclass(frozen=True)
class IdentityResolutionReadResult:
    """A resolution plus its explicit temporal-selection status."""

    resolution: IdentityResolutionV1 | IdentityResolutionV2
    status: str
    proof_reference: str | None = None


class IdentityResolutionTemporalUnverified(IdentityResolutionReadError):
    """A selected V1 row has no verified temporal proof for strict reads."""

    def __init__(self, resolution_id: str, proof_reference: str | None = None):
        self.resolution_id = resolution_id
        self.status = "legacy_unverified"
        self.proof_reference = proof_reference
        super().__init__(
            f"resolution {resolution_id} has temporally unverified selected history")


def _uuid(value, name):
    try:
        parsed = uuid.UUID(value)
    except (ValueError, TypeError, AttributeError):
        raise IdentityResolutionError(f"{name} must be a canonical UUID") from None
    if str(parsed) != value:
        raise IdentityResolutionError(f"{name} must be a canonical UUID")
    return value


def _json(value, name, expected):
    if not isinstance(value, expected):
        raise IdentityResolutionError(f"{name} has invalid container type")
    def check_object_keys(item):
        if isinstance(item, dict):
            if any(not isinstance(key, str) for key in item):
                raise IdentityResolutionError(f"{name} object keys must be strings")
            for child in item.values():
                check_object_keys(child)
        elif isinstance(item, (list, tuple)):
            for child in item:
                check_object_keys(child)
    try:
        check_object_keys(value)
        result = json.loads(json.dumps(value, allow_nan=False))
    except (TypeError, ValueError):
        raise IdentityResolutionError(f"{name} is not valid JSON content") from None
    return result


def _utc(value, name):
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise IdentityResolutionError(f"{name} must be timezone-aware")
    return value.astimezone(UTC)


class IdentityResolutionStore:
    def __init__(self, engine):
        self.engine = engine

    def write_v2(self, resolution: IdentityResolutionV2) -> IdentityResolutionV2:
        """Persist one anchored V2 resolution and its proof atomically."""
        self._validate_v2(resolution)
        values = self._v2_values(resolution)
        if self.engine.dialect.name == "sqlite":
            conn = self.engine.connect().execution_options(isolation_level="AUTOCOMMIT")
            try:
                conn.exec_driver_sql("BEGIN IMMEDIATE")
                result = self._write_v2_inner(conn, resolution, values)
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
            return self._write_v2_inner(conn, resolution, values)

    def _write_v2_inner(self, conn, resolution, values):
        lock_identity_graph(conn)
        self._validate_v2_references(conn, resolution)
        existing = conn.execute(self._v2_select().where(
            identity_resolutions.c.resolution_id == resolution.resolution_id
        )).mappings().first()
        if existing is not None:
            if self._same_content(existing, values):
                return self._read_v2_row(conn, existing)
            raise IdentityResolutionError(
                "resolution ID already exists with different content")

        locked = None
        if resolution.outcome in ("matched", "new"):
            # Every identity writer uses exposure -> occurrence lock order.
            locked = self._lock_v2_selection(conn, resolution)
            if (resolution.selected_exposure_revision != locked["exposure"]["revision"]
                    or resolution.selected_occurrence_revision != locked["occurrence"]["revision"]):
                raise IdentityResolutionError(
                    "selected revision anchor does not match locked rows")
            if not self._v2_locator_history_valid(conn, resolution.occurrence_id):
                raise IdentityResolutionTemporalUnverified(resolution.resolution_id)
        self._validate_resolution_history(conn, resolution)
        conn.execute(identity_resolutions.insert().values(**values))
        persisted = conn.execute(self._v2_select().where(
            identity_resolutions.c.resolution_id == resolution.resolution_id
        )).mappings().one()
        if not self._same_content(persisted, values):
            raise IdentityResolutionError(
                "persisted resolution differs from validated request")
        if resolution.outcome in ("matched", "new"):
            assessment_id = str(uuid.uuid4())
            conn.execute(resolution_temporal_assessments.insert().values(
                assessment_id=assessment_id,
                resolution_id=resolution.resolution_id,
                event_sequence=1,
                status="verified",
                proof_reference=self._v2_proof_reference(resolution),
                origin="reviewed",
                assessed_at=_utc(datetime.now(UTC), "assessed_at"),
                supersedes_assessment_id=None,
            ))
        row = conn.execute(self._v2_select().where(
            identity_resolutions.c.resolution_id == resolution.resolution_id
        )).mappings().one()
        if not self._same_content(row, values):
            raise IdentityResolutionError(
                "persisted resolution differs from validated request")
        return self._read_v2_row(conn, row)

    @staticmethod
    def _v2_proof_reference(resolution):
        return (f"identity-resolution-v2/{resolution.resolution_id}/"
                f"exposure-{resolution.selected_exposure_revision}/"
                f"occurrence-{resolution.selected_occurrence_revision}")

    def _lock_v2_selection(self, conn, resolution):
        query = sa.select(exposures).where(
            exposures.c.exposure_id == resolution.exposure_id)
        if self.engine.dialect.name == "postgresql":
            query = query.with_for_update()
        exposure = conn.execute(query).mappings().first()
        if exposure is None or exposure["workload_id"] != resolution.workload_id \
                or exposure["group_id"] != resolution.group_id:
            raise IdentityResolutionError(
                "new selection does not match the current exposure chain")
        if not self._retained_pair(conn, resolution.exposure_id,
                                   resolution.workload_id):
            raise IdentityResolutionError(
                "selected exposure/workload pair is not retained")
        query = self._occurrence_select(conn).where(
            occurrences.c.occurrence_id == resolution.occurrence_id
        )
        if self.engine.dialect.name == "postgresql":
            query = query.with_for_update()
        occurrence = conn.execute(query).mappings().first()
        if occurrence is None or occurrence["exposure_id"] != resolution.exposure_id \
                or occurrence["incarnation_id"] != resolution.incarnation_id \
                or occurrence["workload_id"] != resolution.workload_id:
            raise IdentityResolutionError(
                "new selection does not match the current occurrence chain")
        incarnation = conn.execute(sa.select(incarnations).where(
            incarnations.c.incarnation_id == resolution.incarnation_id
        )).mappings().first()
        if incarnation is None or incarnation["workload_id"] != resolution.workload_id:
            raise IdentityResolutionError(
                "selected incarnation does not belong to the current chain")
        return {"exposure": exposure, "occurrence": occurrence}

    @staticmethod
    def _v2_select():
        return sa.select(*(identity_resolutions.c[name] for name in _V2_FIELDS))

    def _validate_v2(self, resolution):
        if not isinstance(resolution, IdentityResolutionV2):
            raise IdentityResolutionError("resolution must be IdentityResolutionV2")

    def _v2_values(self, resolution):
        value = resolution.to_primitives()
        value["evaluated_at"] = _utc(resolution.evaluated_at, "evaluated_at")
        value["matching_inputs"] = _json(dict(resolution.matching_inputs),
                                          "matching_inputs", dict)
        value["candidate_workload_ids"] = list(resolution.candidate_workload_ids)
        value["candidate_explanations"] = [dict(item)
                                            for item in resolution.candidate_explanations]
        return value

    def _validate_v2_references(self, conn, resolution):
        # V2's DTO validates shape; use the V1 reference checks after mapping
        # the shared fields, without permitting a V2 row to enter the V1 path.
        plain = json.loads(json.dumps(resolution.to_primitives(), allow_nan=False))
        self._validate_references(conn, IdentityResolutionV1(
            schema_version=1, resolution_id=resolution.resolution_id,
            revision=resolution.revision, observation_id=resolution.observation_id,
            rule_id=resolution.rule_id, rule_version=resolution.rule_version,
            matching_inputs=plain["matching_inputs"],
            candidate_workload_ids=tuple(resolution.candidate_workload_ids),
            outcome=resolution.outcome, evaluated_at=resolution.evaluated_at,
            group_id=resolution.group_id, workload_id=resolution.workload_id,
            incarnation_id=resolution.incarnation_id, exposure_id=resolution.exposure_id,
            occurrence_id=resolution.occurrence_id,
            candidate_explanations=tuple(plain["candidate_explanations"]),
            reason=resolution.reason,
            supersedes_resolution_id=resolution.supersedes_resolution_id))

    def _validate_resolution_history(self, conn, resolution):
        history = conn.execute(sa.select(
            identity_resolutions.c.resolution_id,
            identity_resolutions.c.revision,
            identity_resolutions.c.supersedes_resolution_id,
        ).where(
            identity_resolutions.c.observation_id == resolution.observation_id
        ).order_by(identity_resolutions.c.revision)).mappings().all()
        if not history:
            if resolution.revision != 1 or resolution.supersedes_resolution_id is not None:
                raise IdentityResolutionError(
                    "first resolution must be revision 1 without supersession")
        else:
            previous = history[-1]
            if (resolution.revision != previous["revision"] + 1
                    or resolution.supersedes_resolution_id != previous["resolution_id"]):
                raise IdentityResolutionError(
                    "resolution must increment and supersede immediate prior observation history")

    def _read_v2_row(self, conn, row, *, enforce_temporal=True):
        try:
            d = dict(row)
            if d["schema_version"] != SCHEMA_VERSION_V2:
                raise ValueError("unsupported persisted resolution schema version")
            evaluated = d["evaluated_at"]
            if evaluated.tzinfo is None:
                evaluated = evaluated.replace(tzinfo=UTC)
            result = IdentityResolutionV2(**{
                **d,
                "matching_inputs": dict(d["matching_inputs"]),
                "candidate_workload_ids": tuple(d["candidate_workload_ids"]),
                "candidate_explanations": tuple(dict(x) for x in d["candidate_explanations"]),
                "evaluated_at": evaluated.astimezone(UTC),
            })
            self._validate_v2_references(conn, result)
            history = conn.execute(self._v2_select().where(
                identity_resolutions.c.observation_id == result.observation_id
            ).order_by(identity_resolutions.c.revision)).mappings().all()
            if [item["revision"] for item in history] != list(range(1, len(history) + 1)):
                raise ValueError("resolution revisions are not contiguous")
            for index, historical in enumerate(history):
                previous = None if index == 0 else history[index - 1]["resolution_id"]
                if historical["supersedes_resolution_id"] != previous:
                    raise ValueError("invalid resolution supersession history")
            if enforce_temporal:
                temporal = self._v2_temporal_result(conn, d, result)
                if result.outcome in ("matched", "new") \
                        and temporal.status != "verified":
                    raise IdentityResolutionTemporalUnverified(
                        result.resolution_id, temporal.proof_reference)
            return result
        except IdentityResolutionReadError:
            raise
        except Exception as exc:
            raise IdentityResolutionReadError(
                f"corrupt persisted V2 resolution: {exc}") from exc

    def _v2_temporal_result(self, conn, row, resolution):
        if resolution.outcome not in ("matched", "new"):
            if (resolution.outcome == "unresolved" and resolution.group_id is not None
                    and resolution.known_group_revision is not None):
                if not self._known_group_key_valid(conn, resolution):
                    raise IdentityResolutionReadError(
                        "grouped-unresolved native key does not replay from captured group revision")
            return IdentityResolutionReadResult(resolution, "not_applicable")
        self._reject_changed_birth_history(conn, resolution.occurrence_id)
        events = conn.execute(sa.select(resolution_temporal_assessments).where(
            resolution_temporal_assessments.c.resolution_id == resolution.resolution_id
        ).order_by(resolution_temporal_assessments.c.event_sequence)).mappings().all()
        expected = None
        for index, event in enumerate(events, 1):
            if event["event_sequence"] != index or event["supersedes_assessment_id"] != expected:
                raise IdentityResolutionReadError("corrupt temporal assessment sequence")
            if event["status"] not in ("verified", "legacy_unverified"):
                raise IdentityResolutionReadError("unknown temporal assessment status")
            if event["status"] == "verified" and not event["proof_reference"]:
                raise IdentityResolutionReadError("verified temporal assessment lacks proof reference")
            expected = event["assessment_id"]
        if not events or events[-1]["status"] != "verified":
            return IdentityResolutionReadResult(resolution, "legacy_unverified",
                                                events[-1]["proof_reference"] if events else None)
        exposure = conn.execute(sa.select(exposures).where(
            exposures.c.exposure_id == resolution.exposure_id)).mappings().one()
        occurrence = conn.execute(sa.select(occurrences).where(
            occurrences.c.occurrence_id == resolution.occurrence_id)).mappings().one()
        parent_status = self._parent_transition_status(
            conn, resolution.occurrence_id, resolution.exposure_id,
            resolution.selected_occurrence_revision,
            resolution.selected_exposure_revision)
        if parent_status == "legacy_unverified":
            return IdentityResolutionReadResult(resolution, "legacy_unverified")
        if parent_status is not True:
            raise IdentityResolutionReadError(
                "V2 parent-transition anchor does not replay from captured phase")
        if self._v2_unpositioned_membership_history(
                conn, resolution.occurrence_id, occurrence, resolution.exposure_id):
            return IdentityResolutionReadResult(
                resolution, "legacy_unverified", events[-1]["proof_reference"])
        # V2 cannot infer the phase in which a pre-0003 occurrence was born.
        # Check marked parent proof first so its corruption is never hidden
        # behind this legacy status.
        if occurrence.get("birth_exposure_id") is None \
                or occurrence.get("birth_exposure_revision") is None:
            return IdentityResolutionReadResult(
                resolution, "legacy_unverified", events[-1]["proof_reference"])
        valid_fields, crossed_exposure = self._v2_field_history_valid(
            conn, resolution, exposure, occurrence)
        if not valid_fields:
            raise IdentityResolutionReadError(
                "V2 correction fields do not replay from captured anchors")
        if not self._v2_locator_history_valid(conn, resolution.occurrence_id):
            # 0003 stores the birth exposure/revision, but not the birth
            # component locator. A corrected legacy occurrence therefore
            # remains unverified on either side of the selected revision.
            return IdentityResolutionReadResult(resolution, "legacy_unverified")
        if crossed_exposure:
            membership_valid = self._v2_parent_phase_membership_valid(
                conn, resolution, occurrence)
        else:
            membership_valid = self._repointing_history_valid(
                conn, row, exposure, occurrence,
                selected_revisions=(resolution.selected_exposure_revision,
                                    resolution.selected_occurrence_revision))
        if not membership_valid:
            raise IdentityResolutionReadError(
                "V2 temporal assessment does not replay from captured anchors")
        return IdentityResolutionReadResult(
            resolution, "verified", events[-1]["proof_reference"])

    @staticmethod
    def _known_group_key_valid(conn, resolution):
        """Replay the complete native-key correction chain to the captured
        group revision; never compare only the current group key."""
        group = conn.execute(sa.select(groups).where(
            groups.c.group_id == resolution.group_id)).mappings().first()
        if group is None or group["revision"] < resolution.known_group_revision:
            return False
        fields = ("source_family", "native_id_scheme", "native_id_authority",
                  "native_id_value")
        observation = conn.execute(sa.select(source_observations).where(
            source_observations.c.observation_id == resolution.observation_id
        )).mappings().first()
        if observation is None or any(observation[field] is None for field in fields):
            return False
        retained_key = tuple(observation[field] for field in fields)
        state = {field: group[field] for field in fields}
        rows = conn.execute(sa.select(correction_records).where(
            correction_records.c.record_type == "group",
            correction_records.c.record_id == resolution.group_id,
        ).order_by(correction_records.c.previous_revision,
                   correction_records.c.correction_id)).mappings().all()
        transitions = [r for r in rows if (r["previous_revision"], r["new_revision"]) != (0, 0)]
        if len(rows) != group["revision"] - 1 or len(transitions) != len(rows):
            return False
        transitions.sort(key=lambda r: r["previous_revision"])
        if any(r["previous_revision"] != index or r["new_revision"] != index + 1
               for index, r in enumerate(transitions, 1)):
            return False
        snapshots = {group["revision"]: dict(state)}
        for step in reversed(transitions):
            if step["field_name"] not in fields or state[step["field_name"]] != step["new_value"]:
                return False
            state[step["field_name"]] = step["old_value"]
            snapshots[step["previous_revision"]] = dict(state)
        captured = snapshots.get(resolution.known_group_revision)
        if captured is None:
            return False
        return retained_key == tuple(captured[name] for name in fields)

    @staticmethod
    def _reject_changed_birth_history(conn, occurrence_id):
        """A correction cannot change an occurrence's captured birth proof.

        Inspect raw rows before ordered replay discards unpositioned legacy
        corrections or another proof gap returns an unverified status.
        """
        rows = conn.execute(sa.select(
            correction_records.c.old_value,
            correction_records.c.new_value,
        ).where(
            correction_records.c.record_type == "occurrence",
            correction_records.c.record_id == occurrence_id,
            correction_records.c.field_name.in_((
                "birth_exposure_id", "birth_exposure_revision",
                "birth_component_locator", "birth_component_locator_recorded")),
        )).mappings().all()
        if any(row["old_value"] != row["new_value"] for row in rows):
            raise IdentityResolutionReadError(
                "correction claims changed immutable occurrence birth proof")

    @staticmethod
    def _v2_unpositioned_membership_history(conn, occurrence_id, occurrence,
                                             selected_exposure_id):
        """An unpositioned membership correction leaves its phase unproved.

        Keep unrelated legacy field records available to their own readers;
        only fields that can change this occurrence's selected identity
        prevent a V2 temporal verification.
        """
        rows = conn.execute(sa.select(
            correction_records.c.field_name,
            correction_records.c.old_value,
            correction_records.c.new_value,
        ).where(
            correction_records.c.record_type == "occurrence",
            correction_records.c.record_id == occurrence_id,
            correction_records.c.previous_revision == 0,
            correction_records.c.new_revision == 0,
        )).mappings().all()
        if any(row["field_name"] in (
                "exposure_id", "incarnation_id", "workload_id") for row in rows):
            return True
        parent_ids = {occurrence["birth_exposure_id"],
                      occurrence["exposure_id"], selected_exposure_id}
        parent_rows = conn.execute(sa.select(
            correction_records.c.old_value,
            correction_records.c.new_value,
        ).where(
            correction_records.c.record_type == "occurrence",
            correction_records.c.record_id == occurrence_id,
            correction_records.c.field_name == "exposure_id",
        )).mappings().all()
        for row in parent_rows:
            parent_ids.update((row["old_value"], row["new_value"]))
        parent_ids.discard(None)
        if not parent_ids:
            return False
        parent_ids = list(parent_ids)
        for offset in range(0, len(parent_ids), 500):
            if conn.execute(sa.select(correction_records.c.correction_id).where(
                correction_records.c.record_type == "exposure",
                correction_records.c.record_id.in_(
                    parent_ids[offset:offset + 500]),
                correction_records.c.field_name.in_(("group_id", "workload_id")),
                correction_records.c.previous_revision == 0,
                correction_records.c.new_revision == 0,
            ).limit(1)).first() is not None:
                return True
        return False

    @staticmethod
    def _v2_locator_history_valid(conn, occurrence_id):
        """Prove the complete component-locator correction chain.

        ``False`` means a legacy corrected occurrence has no birth anchor and
        must stay explicitly unverified.  A recorded birth value makes every
        locator correction independently checkable, including SQL NULL.
        Contradictory recorded history is corrupt rather than merely legacy.
        """
        occurrence = conn.execute(sa.select(
            occurrences.c.component_locator,
            occurrences.c.birth_component_locator,
            occurrences.c.birth_component_locator_recorded,
            occurrences.c.revision,
        ).where(occurrences.c.occurrence_id == occurrence_id)).mappings().one()
        raw_locator_history = conn.execute(sa.select(
            correction_records.c.field_name,
            correction_records.c.previous_revision,
            correction_records.c.new_revision,
        ).where(
            correction_records.c.record_type == "occurrence",
            correction_records.c.record_id == occurrence_id,
            correction_records.c.field_name == "component_locator",
        )).mappings().all()
        if any((step["previous_revision"], step["new_revision"]) == (0, 0)
               for step in raw_locator_history):
            # An unpositioned correction cannot establish where the legacy
            # locator was born.  Do not let _ordered_record_history discard
            # it and accidentally promote the remaining row to verified.
            return False
        history = IdentityResolutionStore._ordered_record_history(
            conn, "occurrence", occurrence_id, occurrence["revision"])
        if history is None:
            raise IdentityResolutionReadError(
                "occurrence correction history is not ordered and contiguous")
        _, transitions = history
        locator_steps = [step for step in transitions
                         if step["field_name"] == "component_locator"]
        if not locator_steps:
            if (occurrence["birth_component_locator_recorded"]
                    and occurrence["birth_component_locator"]
                    != occurrence["component_locator"]):
                raise IdentityResolutionReadError(
                    "recorded birth locator does not match current value")
            return True
        if not occurrence["birth_component_locator_recorded"]:
            # A legacy row has no value for the first old locator, so that
            # first edge remains unproved.  Later edges are nevertheless
            # affirmative history: they must link to the preceding new
            # value and the chain must reach the current persisted value.
            for previous, step in zip(locator_steps, locator_steps[1:]):
                if step["old_value"] != previous["new_value"]:
                    raise IdentityResolutionReadError(
                        "component-locator correction does not link to prior value")
            if (locator_steps[-1]["new_value"]
                    != occurrence["component_locator"]):
                raise IdentityResolutionReadError(
                    "component-locator correction chain does not reach current value")
            return False
        locator = occurrence["birth_component_locator"]
        for step in locator_steps:
            if step["old_value"] != locator:
                raise IdentityResolutionReadError(
                    "component-locator correction does not link to prior value")
            locator = step["new_value"]
        if locator != occurrence["component_locator"]:
            raise IdentityResolutionReadError(
                "component-locator correction chain does not reach current value")
        return True

    @staticmethod
    def _v2_field_history_valid(conn, resolution, exposure, occurrence):
        """Replay recorded field transitions against today's row and anchors.

        Revision continuity alone cannot establish that a purported locator
        or parent correction reached the persisted field value. Keep the V1
        historical reader's legacy inference separate from this V2 proof.
        """
        def replay(record_type, record_id, row, fields):
            history = IdentityResolutionStore._ordered_record_history(
                conn, record_type, record_id, row["revision"])
            if history is None:
                return None
            state = {field: row[field] for field in fields}
            snapshots = {row["revision"]: state.copy()}
            for step in reversed(history[1]):
                field = step["field_name"]
                if field not in state or step["new_value"] != state[field]:
                    return None
                state[field] = step["old_value"]
                snapshots[step["previous_revision"]] = state.copy()
            return snapshots

        exp = replay("exposure", resolution.exposure_id, exposure,
                     ("group_id", "workload_id"))
        occ = replay("occurrence", resolution.occurrence_id, occurrence,
                     ("exposure_id", "incarnation_id", "component_locator"))
        selected_exp = exp.get(resolution.selected_exposure_revision) if exp else None
        selected_occ = occ.get(resolution.selected_occurrence_revision) if occ else None
        if (selected_exp is None or selected_occ is None
                or selected_exp["group_id"] != resolution.group_id
                or selected_exp["workload_id"] != resolution.workload_id
                or selected_occ["exposure_id"] != resolution.exposure_id
                or selected_occ["incarnation_id"] != resolution.incarnation_id
                or occ[1]["exposure_id"] != occurrence["birth_exposure_id"]):
            return False, False
        parent_moves = conn.execute(sa.select(correction_records.c.correction_id).where(
            correction_records.c.record_type == "occurrence",
            correction_records.c.record_id == resolution.occurrence_id,
            correction_records.c.field_name == "exposure_id",
            correction_records.c.previous_revision > 0).limit(1)).first()
        return True, parent_moves is not None

    def write(self, resolution: IdentityResolutionV1) -> IdentityResolutionV1:
        self._validate(resolution)
        values = self._values(resolution)
        if self.engine.dialect.name == "sqlite":
            # BEGIN IMMEDIATE at transaction start: the write-intent lock is
            # acquired before the current-chain check, so a concurrent
            # correction commit cannot interleave between the check and the
            # insert and turn a stale selection into a committed one (the
            # SQLite equivalent of serialising on the exposure row; on
            # PostgreSQL the FOR UPDATE route below keeps the guarantee).
            conn = self.engine.connect().execution_options(
                isolation_level="AUTOCOMMIT")
            try:
                conn.exec_driver_sql("BEGIN IMMEDIATE")
                result = self._write_inner(conn, resolution, values)
            except Exception:
                try:
                    conn.rollback()
                except sa.exc.DBAPIError:
                    pass  # no open transaction (BEGIN failed); never mask the original failure
                raise
            else:
                conn.commit()
                return result
            finally:
                conn.close()
        with self.engine.begin() as conn:
            return self._write_inner(conn, resolution, values)

    def _write_inner(self, conn, resolution, values):
        lock_identity_graph(conn)
        table = identity_resolutions
        self._validate_references(conn, resolution)
        existing = conn.execute(self._v1_select().where(
            table.c.resolution_id == resolution.resolution_id)).mappings().first()
        if existing is not None:
            if self._same_content(existing, values):
                # Exact resend: read back the retained row under the
                # historical (retained-pair) validation rules.
                return self._read_row(conn, existing)
            raise IdentityResolutionError("resolution ID already exists with different content")
        guard_revision = None
        if resolution.outcome in ("matched", "new"):
            # Newly issued selections must match the CURRENT chain, and
            # the check serialises on the exposure row the correction
            # writer locks (FOR UPDATE on PostgreSQL).
            guard_revision = self._validate_current_chain(conn, resolution)
        history = conn.execute(self._v1_select().where(
            table.c.observation_id == resolution.observation_id
        ).order_by(table.c.revision)).mappings().all()
        if not history:
            if resolution.revision != 1 or resolution.supersedes_resolution_id is not None:
                raise IdentityResolutionError("first resolution must be revision 1 without supersession")
        else:
            previous = history[-1]
            if resolution.revision != previous["revision"] + 1 or resolution.supersedes_resolution_id != previous["resolution_id"]:
                raise IdentityResolutionError("resolution must increment and supersede immediate prior observation history")
        if guard_revision is not None:
            # SQLite optimistic equivalent of the row lock: a correction
            # that committed a move between the chain check and this
            # insert bumped the exposure revision, so the selection is
            # stale and must not commit.
            self._assert_exposure_unchanged(conn, resolution, guard_revision)
            # V1 cannot supply selected revisions at either database head.
            # Reject before insertion, including on 0002 where a selected
            # row would otherwise fail its strict read-back and roll back.
            raise IdentityResolutionTemporalUnverified(resolution.resolution_id)
        conn.execute(table.insert().values(**values))
        row = conn.execute(self._v1_select().where(
            table.c.resolution_id == resolution.resolution_id)).mappings().one()
        return self._read_row(conn, row)

    def read(self, resolution_id: str) -> IdentityResolutionV1 | IdentityResolutionV2:
        _uuid(resolution_id, "resolution_id")
        with self.engine.connect() as conn:
            row = conn.execute(self._available_resolution_select(conn).where(
                identity_resolutions.c.resolution_id == resolution_id)).mappings().first()
            if row is None:
                raise IdentityResolutionReadError("resolution not found")
            if row["schema_version"] == SCHEMA_VERSION_V2 and all(
                    name in row for name in _V2_FIELDS):
                return self._read_v2_row(conn, row)
            row = {name: row[name] for name in _V1_FIELDS}
            return self._read_row(conn, row)

    def read_status(self, resolution_id: str) -> IdentityResolutionReadResult:
        """Read a resolution with its derived temporal-selection status.

        ``not_applicable`` is derived for ambiguous/unresolved outcomes. A
        selected V1 row is never promoted to verified without a valid 0003
        assessment stream and uniquely provable selected anchors.
        """
        _uuid(resolution_id, "resolution_id")
        with self.engine.connect() as conn:
            row = conn.execute(self._available_resolution_select(conn).where(
                identity_resolutions.c.resolution_id == resolution_id)).mappings().first()
            if row is None:
                raise IdentityResolutionReadError("resolution not found")
            if row["schema_version"] == SCHEMA_VERSION_V2 and all(
                    name in row for name in _V2_FIELDS):
                resolution = self._read_v2_row(conn, row, enforce_temporal=False)
                return self._v2_temporal_result(conn, row, resolution)
            row = {name: row[name] for name in _V1_FIELDS}
            resolution = self._read_row(conn, row, enforce_temporal=False)
            result = self._temporal_result(conn, row, resolution)
            if result.status == "verified":
                self._require_verified_anchors(conn, row, resolution)
            return result

    def read_status_on_connection(self, conn, resolution_id: str) -> IdentityResolutionReadResult:
        """Read and validate identity evidence inside a caller's transaction.

        Assessment reconciliation uses this method while it holds the target
        assessment row and current policy lock, so the resolution proof and
        derived coverage decision share one guarded write transaction.
        """
        _uuid(resolution_id, "resolution_id")
        row = conn.execute(self._available_resolution_select(conn).where(
            identity_resolutions.c.resolution_id == resolution_id)).mappings().first()
        if row is None:
            raise IdentityResolutionReadError("resolution not found")
        if row["schema_version"] == SCHEMA_VERSION_V2 and all(
                name in row for name in _V2_FIELDS):
            resolution = self._read_v2_row(conn, row, enforce_temporal=False)
            result = self._v2_temporal_result(conn, row, resolution)
        else:
            resolution = self._read_row(
                conn, {name: row[name] for name in _V1_FIELDS},
                enforce_temporal=False)
            result = self._temporal_result(conn, row, resolution)
        if result.status == "verified" and row["schema_version"] != SCHEMA_VERSION_V2:
            self._require_verified_anchors(conn, row, resolution)
        return result

    def read_observation_history(self, conn, observation_ids):
        """Read all resolution history for observations on ``conn``.

        This is deliberately connection-scoped: callers composing a
        historical run snapshot must not acquire a second connection or
        transaction between the retained observations and their resolution
        records.  The returned mapping contains an entry for every requested
        observation, including observations with no resolution yet.
        """
        requested = tuple(observation_ids)
        if len(set(requested)) != len(requested):
            raise IdentityResolutionReadError("duplicate observation scope")
        result = {observation_id: ((), (), None) for observation_id in requested}
        if not requested:
            return result
        rows = conn.execute(self._available_resolution_select(conn).where(
            identity_resolutions.c.observation_id.in_(requested)
        ).order_by(
            identity_resolutions.c.observation_id,
            identity_resolutions.c.revision,
        )).mappings().all()
        grouped = {observation_id: [] for observation_id in requested}
        for row in rows:
            observation_id = row["observation_id"]
            if observation_id not in grouped:
                raise IdentityResolutionReadError(
                    "resolution row crosses requested observation scope")
            grouped[observation_id].append(row)
        for observation_id, history_rows in grouped.items():
            if not history_rows:
                continue
            revisions = [row["revision"] for row in history_rows]
            if revisions != list(range(1, len(revisions) + 1)):
                raise IdentityResolutionReadError(
                    f"resolution history for {observation_id} is not contiguous")
            if len(set(revisions)) != len(revisions):
                raise IdentityResolutionReadError(
                    f"resolution history for {observation_id} has duplicate heads")
            history = []
            statuses = []
            for row in history_rows:
                if row["schema_version"] == SCHEMA_VERSION_V2 and all(
                        name in row for name in _V2_FIELDS):
                    resolution = self._read_v2_row(
                        conn, row, enforce_temporal=False)
                    status = self._v2_temporal_result(conn, row, resolution)
                else:
                    resolution = self._read_row(
                        conn, {name: row[name] for name in _V1_FIELDS},
                        enforce_temporal=False)
                    status = self._temporal_result(conn, row, resolution)
                if (status.status == "verified"
                        and row["schema_version"] != SCHEMA_VERSION_V2):
                    self._require_verified_anchors(conn, row, resolution)
                history.append(resolution)
                statuses.append(status)
            result[observation_id] = (tuple(history), tuple(statuses), statuses[-1])
        return result

    @staticmethod
    def _v1_select():
        return sa.select(*(identity_resolutions.c[name] for name in _V1_FIELDS))

    @staticmethod
    def _available_resolution_select(conn):
        columns = {column["name"] for column in sa.inspect(conn).get_columns(
            identity_resolutions.name)}
        if set(_V2_FIELDS).issubset(columns):
            return sa.select(identity_resolutions)
        return IdentityResolutionStore._v1_select()

    @staticmethod
    def _occurrence_select(conn):
        """Read the V1 fields present at either the 0002 or 0003 head."""
        fields = ["occurrence_id", "exposure_id", "incarnation_id",
                  "workload_id", "revision"]
        available = {column["name"] for column in sa.inspect(conn).get_columns(
            occurrences.name)}
        fields.extend(name for name in ("birth_exposure_id",
                                        "birth_exposure_revision")
                      if name in available)
        return sa.select(*(occurrences.c[name] for name in fields))

    def _validate(self, r):
        if not isinstance(r, IdentityResolutionV1):
            raise IdentityResolutionError("resolution must be IdentityResolutionV1")
        if r.schema_version != 1 or r.revision < 1 or r.rule_version < 1 or r.outcome not in OUTCOMES:
            raise IdentityResolutionError("invalid schema, revision, rule version, or outcome")
        for name in ("resolution_id", "observation_id", "group_id", "workload_id", "incarnation_id", "exposure_id", "occurrence_id", "supersedes_resolution_id"):
            value = getattr(r, name)
            if value is not None:
                _uuid(value, name)
        if not isinstance(r.rule_id, str) or not r.rule_id:
            raise IdentityResolutionError("rule_id is required")
        inputs = _json(r.matching_inputs, "matching_inputs", dict)
        if not all(isinstance(k, str) and isinstance(v, str) for k, v in inputs.items()):
            raise IdentityResolutionError("matching_inputs must contain string keys and values")
        candidates = _json(r.candidate_workload_ids, "candidate_workload_ids", (tuple, list))
        for x in candidates: _uuid(x, "candidate_workload_ids")
        explanations = _json(r.candidate_explanations, "candidate_explanations", (tuple, list))
        if not all(isinstance(x, dict) for x in explanations):
            raise IdentityResolutionError("candidate_explanations must contain objects")
        if r.outcome in ("matched", "new"):
            if any(getattr(r, x) is None for x in ("group_id", "workload_id", "incarnation_id", "exposure_id", "occurrence_id")):
                raise IdentityResolutionError("matched/new requires selected group, workload, incarnation, exposure and occurrence")
        elif any(getattr(r, x) is not None for x in ("workload_id", "incarnation_id", "exposure_id", "occurrence_id")) or (r.outcome == "unresolved" and r.group_id is not None):
            raise IdentityResolutionError("ambiguous/unresolved cannot select membership")
        if r.outcome == "ambiguous":
            candidate_ids = tuple(r.candidate_workload_ids)
            explanation_ids = tuple(x.get("workload_id") for x in explanations)
            if (len(candidate_ids) < 2 or len(set(candidate_ids)) != len(candidate_ids)
                    or len(explanations) < 2 or len(set(explanation_ids)) != len(explanation_ids)
                    or set(explanation_ids) != set(candidate_ids)):
                raise IdentityResolutionError(
                    "ambiguous resolution requires distinct workload candidates with matching explanations")
            for candidate_id in explanation_ids:
                _uuid(candidate_id, "candidate_explanations.workload_id")
        _utc(r.evaluated_at, "evaluated_at")

    def _values(self, r):
        return dict(schema_version=r.schema_version, resolution_id=r.resolution_id, revision=r.revision,
                    observation_id=r.observation_id, rule_id=r.rule_id, rule_version=r.rule_version,
                    matching_inputs=_json(r.matching_inputs, "matching_inputs", dict),
                    candidate_workload_ids=list(r.candidate_workload_ids), outcome=r.outcome,
                    evaluated_at=_utc(r.evaluated_at, "evaluated_at"), group_id=r.group_id,
                    workload_id=r.workload_id, incarnation_id=r.incarnation_id, exposure_id=r.exposure_id,
                    occurrence_id=r.occurrence_id, candidate_explanations=list(r.candidate_explanations),
                    reason=r.reason, supersedes_resolution_id=r.supersedes_resolution_id)

    def _same_content(self, row, values):
        for key, value in values.items():
            stored = row[key]
            if key in ("candidate_workload_ids", "candidate_explanations"):
                stored = list(stored)
            elif key == "evaluated_at":
                if stored.tzinfo is None:
                    stored = stored.replace(tzinfo=UTC)
                stored = stored.astimezone(UTC)
            if key in ("matching_inputs", "candidate_workload_ids", "candidate_explanations"):
                # JSON text preserves distinctions Python equality erases (e.g. true == 1).
                if json.dumps(stored, sort_keys=True, separators=(",", ":"), allow_nan=False) != json.dumps(
                        value, sort_keys=True, separators=(",", ":"), allow_nan=False):
                    return False
            elif stored != value:
                return False
        return True

    def _read_row(self, conn, row, *, enforce_temporal=True):
        try:
            d = dict(row)
            if d.get("schema_version") != 1:
                raise ValueError(
                    f"unsupported persisted resolution schema version: "
                    f"{d.get('schema_version')!r}")
            # The 0003 head adds V2-only revision anchors to this table.  Do
            # not pass additive columns into the frozen V1 DTO; V2 read/status
            # policy is a separate contract and unsupported rows fail closed
            # above.
            d = {name: d[name] for name in _V1_FIELDS}
            # Validate persisted reference existence and selected chain coherence.
            for table, key in ((source_observations, "observation_id"),):
                if conn.execute(sa.select(table.c[key]).where(table.c[key] == d[key])).first() is None:
                    raise ValueError(f"missing {key}")
            evaluated = d["evaluated_at"]
            if evaluated.tzinfo is None: evaluated = evaluated.replace(tzinfo=UTC)
            result = IdentityResolutionV1(**{**d, "candidate_workload_ids": tuple(d["candidate_workload_ids"]), "candidate_explanations": tuple(d["candidate_explanations"]), "evaluated_at": evaluated.astimezone(UTC)})
            self._validate(result)
            self._validate_references(conn, result, read=True)
            # Establish temporal status before replaying the membership
            # history. A valid late-created legacy selection is unverified
            # even though an exposure move has no occurrence-side partner.
            temporal = self._temporal_result(conn, d, result)
            if d["outcome"] in ("matched", "new"):
                lookups = ((workloads, "workload_id"), (groups, "group_id"), (incarnations, "incarnation_id"), (exposures, "exposure_id"), (occurrences, "occurrence_id"))
                objs = {}
                for table, key in lookups:
                    selection = (self._occurrence_select(conn) if table is occurrences
                                 else sa.select(table))
                    objs[key] = conn.execute(selection.where(
                        table.c[key] == d[key])).mappings().one()
                # Historical selection (FR-ID-02/CR-03): validate against the
                # retained membership pair and the correlated correction
                # history, never against today's exposure/occurrence
                # membership — a guarded correction may have moved the
                # exposure (retaining this pair) and re-pointed its
                # occurrences since this selection was issued.
                if not self._retained_pair(conn, d["exposure_id"], d["workload_id"]):
                    raise ValueError("selected exposure/workload pair is not retained")
                if objs["incarnation_id"]["workload_id"] != d["workload_id"] or objs["exposure_id"]["group_id"] != d["group_id"] or objs["occurrence_id"]["exposure_id"] != d["exposure_id"]:
                    raise ValueError("selected membership is incoherent")
                if not self._repointing_history_valid(
                        conn, d, objs["exposure_id"], objs["occurrence_id"]):
                    raise ValueError(
                        "occurrence re-pointing lacks ordered, contiguous, "
                        "correlated correction history")
            history = conn.execute(self._v1_select().where(
                identity_resolutions.c.observation_id == result.observation_id
            ).order_by(identity_resolutions.c.revision)).mappings().all()
            if [x["revision"] for x in history] != list(range(1, len(history) + 1)):
                raise ValueError("resolution revisions are not contiguous")
            for index, historical in enumerate(history):
                expected = None if index == 0 else history[index - 1]["resolution_id"]
                if historical["supersedes_resolution_id"] != expected:
                    raise ValueError("invalid resolution supersession history")
            if temporal.status == "verified":
                self._require_verified_anchors(conn, d, result)
            elif enforce_temporal and result.outcome in ("matched", "new"):
                raise IdentityResolutionTemporalUnverified(
                    result.resolution_id, temporal.proof_reference)
            return result
        except Exception as exc:
            if isinstance(exc, IdentityResolutionReadError): raise
            raise IdentityResolutionReadError(f"corrupt persisted resolution: {exc}") from exc

    def _temporal_result(self, conn, row, resolution):
        if resolution.outcome not in ("matched", "new"):
            return IdentityResolutionReadResult(resolution, "not_applicable")
        try:
            if not sa.inspect(conn).has_table(resolution_temporal_assessments.name):
                return IdentityResolutionReadResult(
                    resolution, "legacy_unverified")
            events = conn.execute(sa.select(resolution_temporal_assessments).where(
                resolution_temporal_assessments.c.resolution_id ==
                resolution.resolution_id
            ).order_by(resolution_temporal_assessments.c.event_sequence
                       )).mappings().all()
        except sa.exc.SQLAlchemyError as exc:
            return IdentityResolutionReadResult(
                resolution, "legacy_unverified")
        if not events:
            return IdentityResolutionReadResult(
                resolution, "legacy_unverified")
        expected_previous = None
        for index, event in enumerate(events, start=1):
            if event["event_sequence"] != index:
                raise IdentityResolutionReadError(
                    "corrupt temporal assessment sequence")
            if event["resolution_id"] != resolution.resolution_id:
                raise IdentityResolutionReadError(
                    "temporal assessment has mismatched resolution")
            if event["supersedes_assessment_id"] != expected_previous:
                raise IdentityResolutionReadError(
                    "temporal assessment does not supersede the immediate prior event")
            if event["status"] not in ("verified", "legacy_unverified"):
                raise IdentityResolutionReadError("unknown temporal assessment status")
            if event["status"] == "verified" and not event["proof_reference"]:
                raise IdentityResolutionReadError(
                    "verified temporal assessment lacks proof reference")
            expected_previous = event["assessment_id"]
        latest = events[-1]
        if latest["status"] == "verified":
            try:
                parent_change = conn.execute(sa.select(
                    correction_records.c.correction_id).where(
                    correction_records.c.record_type == "occurrence",
                    correction_records.c.record_id == resolution.occurrence_id,
                    correction_records.c.field_name == "exposure_id"
                ).limit(1)).first()
            except sa.exc.SQLAlchemyError:
                return IdentityResolutionReadResult(
                    resolution, "legacy_unverified")
            if parent_change is not None:
                # V1 has no parent-transition anchor. Even an E->F->E
                # history ending on the selected exposure cannot prove
                # which exposure contained the occurrence at selection.
                return IdentityResolutionReadResult(
                    resolution, "legacy_unverified")
        return IdentityResolutionReadResult(
            resolution, latest["status"], latest["proof_reference"])

    @staticmethod
    def _parent_transition_status(conn, occurrence_id, selected_exposure_id,
                                  selected_occurrence_revision,
                                  selected_exposure_revision):
        """Replay marked parent transitions without inferring legacy history.

        Returns True for a proved phase, ``legacy_unverified`` for an
        unmarked legacy correction once all marked proof is sound, and False
        for malformed or contradictory marked proof.
        """
        rows = conn.execute(sa.select(correction_records).where(
            correction_records.c.record_type == "occurrence",
            correction_records.c.record_id == occurrence_id,
            correction_records.c.field_name == "exposure_id",
        ).order_by(correction_records.c.new_revision)).mappings().all()
        if not rows:
            extra_anchor = conn.execute(sa.select(
                occurrence_parent_transition_anchors.c.correction_id).where(
                occurrence_parent_transition_anchors.c.occurrence_id == occurrence_id
            ).limit(1)).first()
            return extra_anchor is None
        anchors = conn.execute(sa.select(occurrence_parent_transition_anchors).where(
            occurrence_parent_transition_anchors.c.occurrence_id == occurrence_id
        ).order_by(occurrence_parent_transition_anchors.c.new_revision)
        ).mappings().all()
        # Unmarked historical corrections are legacy data, while any marked
        # correction still has to carry sound proof even in a mixed history.
        legacy = False
        markers = {}
        for row in rows:
            marker = conn.execute(sa.select(occurrence_parent_transition_markers).where(
                occurrence_parent_transition_markers.c.correction_id == row["correction_id"]
            )).mappings().first()
            if marker is None:
                legacy = True
            else:
                markers[row["correction_id"]] = marker
        row_correction_ids = {row["correction_id"] for row in rows}
        if (len(anchors) > len(rows)
                or any(anchor["correction_id"] not in row_correction_ids
                       for anchor in anchors)):
            return False
        by_correction = {a["correction_id"]: a for a in anchors}
        marked = []
        for row in rows:
            marker = markers.get(row["correction_id"])
            if marker is None:
                continue
            if marker["schema_version"] != 1:
                return False
            anchor = by_correction.get(row["correction_id"])
            if anchor is None or anchor["correction_id"] != row["correction_id"]:
                return False
            if (anchor["occurrence_id"] != occurrence_id
                    or anchor["from_exposure_id"] != row["old_value"]
                    or anchor["to_exposure_id"] != row["new_value"]
                    or anchor["previous_revision"] != row["previous_revision"]
                    or anchor["new_revision"] != row["new_revision"]):
                return False
            if (anchor["previous_revision"] < 1
                    or anchor["new_revision"] != anchor["previous_revision"] + 1
                    or anchor["from_exposure_revision"] < 1
                    or anchor["to_exposure_revision"] < 1
                    or anchor["from_exposure_id"] == anchor["to_exposure_id"]):
                return False
            marked.append(anchor)
        if len(anchors) != len(marked):
            return False
        marked.sort(key=lambda a: a["new_revision"])
        if any(marked[index]["new_revision"] >= marked[index + 1]["new_revision"]
               for index in range(len(marked) - 1)):
            return False

        # Reconstruct each parent independently at every captured revision.
        # The anchor's parent ID/revision is not proof by itself: a fabricated
        # revision on the other parent must fail closed too.
        parent_states = {}
        for anchor in marked:
            for parent_id, parent_revision in (
                    (anchor["from_exposure_id"],
                     anchor["from_exposure_revision"]),
                    (anchor["to_exposure_id"],
                     anchor["to_exposure_revision"])):
                state = IdentityResolutionStore._exposure_state_at_revision(
                    conn, parent_id, parent_revision)
                if state is None:
                    return False
                parent_states[(parent_id, parent_revision)] = state
            source = parent_states[(anchor["from_exposure_id"],
                                    anchor["from_exposure_revision"])]
            target = parent_states[(anchor["to_exposure_id"],
                                    anchor["to_exposure_revision"])]
            if source["workload_id"] != target["workload_id"]:
                return False

        occurrence = conn.execute(sa.select(
            occurrences.c.exposure_id,
            occurrences.c.revision,
            occurrences.c.birth_exposure_id,
            occurrences.c.birth_exposure_revision,
        ).where(occurrences.c.occurrence_id == occurrence_id)
        ).mappings().first()
        if occurrence is None:
            return False
        history = IdentityResolutionStore._ordered_record_history(
            conn, "occurrence", occurrence_id, occurrence["revision"])
        if history is None:
            return False
        current_parent = occurrence["exposure_id"]
        for step in reversed(history[1]):
            if step["field_name"] == "exposure_id":
                if step["new_value"] != current_parent:
                    return False
                current_parent = step["old_value"]
        if (occurrence["birth_exposure_id"] is not None
                and current_parent != occurrence["birth_exposure_id"]):
            return False

        # A genuine unmarked correction leaves a gap in the phase chain, but
        # cannot excuse a malformed marked edge elsewhere in that history.
        if legacy:
            return "legacy_unverified"
        if len(marked) != len(rows):
            return False

        if occurrence["birth_exposure_id"] != marked[0]["from_exposure_id"]:
            return False
        current = None
        phases = []
        for index, anchor in enumerate(marked):
            if current is None:
                current = anchor["from_exposure_id"]
            if current != anchor["from_exposure_id"]:
                return False
            if phases and phases[-1]["occurrence_end"] >= anchor["previous_revision"]:
                return False
            phases.append({
                "exposure_id": anchor["from_exposure_id"],
                "exposure_start": (
                    occurrence["birth_exposure_revision"]
                    if not phases else marked[index - 1]["to_exposure_revision"]),
                "exposure_end": anchor["from_exposure_revision"],
                "occurrence_start": (
                    1 if not phases else phases[-1]["occurrence_end"] + 1),
                "occurrence_end": anchor["previous_revision"],
            })
            current = anchor["to_exposure_id"]
        phases.append({
            "exposure_id": marked[-1]["to_exposure_id"],
            "exposure_start": marked[-1]["to_exposure_revision"],
            "exposure_end": None,
            "occurrence_start": marked[-1]["new_revision"],
            "occurrence_end": None,
        })
        phase = next((item for item in phases
                      if item["occurrence_start"] <= selected_occurrence_revision
                      and (item["occurrence_end"] is None
                           or selected_occurrence_revision <= item["occurrence_end"])),
                     None)
        if phase is None or phase["exposure_id"] != selected_exposure_id:
            return False
        if selected_exposure_revision < phase["exposure_start"]:
            return False
        if (phase["exposure_end"] is not None
                and selected_exposure_revision > phase["exposure_end"]):
            return False
        return IdentityResolutionStore._exposure_state_at_revision(
            conn, selected_exposure_id, selected_exposure_revision) is not None

    @staticmethod
    def _exposure_state_at_revision(conn, exposure_id, revision):
        """Replay one exposure's independent correction chain to a revision."""
        if not isinstance(revision, int) or revision < 1:
            return None
        exposure = conn.execute(sa.select(exposures).where(
            exposures.c.exposure_id == exposure_id)).mappings().first()
        if exposure is None:
            return None
        history = IdentityResolutionStore._ordered_record_history(
            conn, "exposure", exposure_id, exposure["revision"])
        if history is None or revision > exposure["revision"]:
            return None
        state = {"group_id": exposure["group_id"],
                 "workload_id": exposure["workload_id"]}
        snapshots = {exposure["revision"]: state.copy()}
        for step in reversed(history[1]):
            if (step["field_name"] not in state
                    or step["new_value"] != state[step["field_name"]]):
                return None
            state[step["field_name"]] = step["old_value"]
            snapshots[step["previous_revision"]] = state.copy()
        return snapshots.get(revision)

    @staticmethod
    def _v2_parent_phase_membership_valid(conn, resolution, occurrence):
        """Pair workload moves only while the occurrence belongs to a parent.

        Exposure revisions are local to their exposure.  In particular, the
        birth revision on A cannot be used as the starting revision on B.
        The parent-anchor and field replays run before this check; this check
        preserves the correlated workload/incarnation proof in each phase.
        """
        occ_history = IdentityResolutionStore._ordered_record_history(
            conn, "occurrence", resolution.occurrence_id, occurrence["revision"])
        if occ_history is None:
            return False
        occ_steps = occ_history[1]
        incarnation_at = {occurrence["revision"]: occurrence["incarnation_id"]}
        incarnation = occurrence["incarnation_id"]
        for step in reversed(occ_steps):
            if step["field_name"] == "incarnation_id":
                if step["new_value"] != incarnation:
                    return False
                incarnation = step["old_value"]
            incarnation_at[step["previous_revision"]] = incarnation

        parent_steps = [step for step in occ_steps
                        if step["field_name"] == "exposure_id"]
        anchors = conn.execute(sa.select(occurrence_parent_transition_anchors).where(
            occurrence_parent_transition_anchors.c.occurrence_id ==
            resolution.occurrence_id).order_by(
            occurrence_parent_transition_anchors.c.new_revision)
        ).mappings().all()
        if not parent_steps or len(parent_steps) != len(anchors):
            return False
        phases = []
        parent_id = occurrence["birth_exposure_id"]
        exposure_start = occurrence["birth_exposure_revision"]
        occurrence_start = 1
        for step, anchor in zip(parent_steps, anchors):
            if (anchor["new_revision"] != step["new_revision"]
                    or anchor["previous_revision"] != step["previous_revision"]
                    or anchor["from_exposure_id"] != parent_id
                    or anchor["previous_revision"] < occurrence_start):
                return False
            phases.append((parent_id, exposure_start,
                           anchor["from_exposure_revision"],
                           occurrence_start, anchor["previous_revision"]))
            parent_id = anchor["to_exposure_id"]
            exposure_start = anchor["to_exposure_revision"]
            occurrence_start = anchor["new_revision"]
        parent = conn.execute(sa.select(exposures).where(
            exposures.c.exposure_id == parent_id)).mappings().first()
        if parent is None:
            return False
        phases.append((parent_id, exposure_start, parent["revision"],
                       occurrence_start, occurrence["revision"]))

        incarnation_ids = list(set(incarnation_at.values()))
        incarnation_workloads = {}
        for offset in range(0, len(incarnation_ids), 500):
            batch = incarnation_ids[offset:offset + 500]
            incarnation_workloads.update(conn.execute(sa.select(
                incarnations.c.incarnation_id, incarnations.c.workload_id).where(
                incarnations.c.incarnation_id.in_(batch))).all())

        selected_phase_found = False
        seen_membership_correlations = set()
        for exposure_id, exp_start, exp_end, occ_start, occ_end in phases:
            if (exp_start > exp_end or occ_start > occ_end
                    or occ_start not in incarnation_at
                    or occ_end not in incarnation_at):
                return False
            exposure = conn.execute(sa.select(exposures).where(
                exposures.c.exposure_id == exposure_id)).mappings().first()
            if exposure is None:
                return False
            exp_history = IdentityResolutionStore._ordered_record_history(
                conn, "exposure", exposure_id, exposure["revision"])
            if exp_history is None:
                return False
            start_state = IdentityResolutionStore._exposure_state_at_revision(
                conn, exposure_id, exp_start)
            end_state = IdentityResolutionStore._exposure_state_at_revision(
                conn, exposure_id, exp_end)
            if (start_state is None or end_state is None
                    or incarnation_workloads.get(incarnation_at[occ_start])
                    != start_state["workload_id"]
                    or incarnation_workloads.get(incarnation_at[occ_end])
                    != end_state["workload_id"]):
                return False
            exposure_moves = [step for step in exp_history[1]
                              if step["field_name"] == "workload_id"
                              and exp_start < step["new_revision"] <= exp_end]
            occurrence_moves = [step for step in occ_steps
                                if step["field_name"] == "incarnation_id"
                                and occ_start < step["new_revision"] <= occ_end]
            if len(exposure_moves) != len(occurrence_moves):
                return False
            for exp_move, occ_move in zip(exposure_moves, occurrence_moves):
                if (not exp_move["correlation_id"]
                        or exp_move["correlation_id"] != occ_move["correlation_id"]
                        or exp_move["correlation_id"] in seen_membership_correlations
                        or incarnation_workloads.get(occ_move["old_value"])
                        != exp_move["old_value"]
                        or incarnation_workloads.get(occ_move["new_value"])
                        != exp_move["new_value"]):
                    return False
                seen_membership_correlations.add(exp_move["correlation_id"])
            if occ_start <= resolution.selected_occurrence_revision <= occ_end:
                if (selected_phase_found or exposure_id != resolution.exposure_id
                        or not exp_start <= resolution.selected_exposure_revision <= exp_end):
                    return False
                selected_phase_found = True
                selected_state = IdentityResolutionStore._exposure_state_at_revision(
                    conn, exposure_id, resolution.selected_exposure_revision)
                if (selected_state is None
                        or incarnation_workloads.get(incarnation_at.get(
                            resolution.selected_occurrence_revision))
                        != selected_state["workload_id"]):
                    return False
        return (selected_phase_found
                and incarnation_workloads.get(occurrence["incarnation_id"])
                == occurrence["workload_id"])

    def _require_verified_anchors(self, conn, row, resolution):
        """Recheck a proved V1 revision-1 selection through current history."""
        try:
            columns = {column["name"] for column in sa.inspect(conn).get_columns(
                identity_resolutions.name)}
            if not {"selected_exposure_revision",
                    "selected_occurrence_revision"}.issubset(columns):
                raise IdentityResolutionReadError(
                    "verified selected history requires 0003 revision anchors")
            anchors = conn.execute(sa.select(
                identity_resolutions.c.selected_exposure_revision,
                identity_resolutions.c.selected_occurrence_revision).where(
                identity_resolutions.c.resolution_id == resolution.resolution_id
            )).first()
            if anchors is None or anchors[0] != 1 or anchors[1] != 1:
                raise IdentityResolutionReadError(
                    "V1 verified history lacks uniquely proved revision-1 anchors")
            exposure = conn.execute(sa.select(exposures).where(
                exposures.c.exposure_id == resolution.exposure_id)).mappings().one()
            occurrence = conn.execute(self._occurrence_select(conn).where(
                occurrences.c.occurrence_id == resolution.occurrence_id)).mappings().one()
            if not self._repointing_history_valid(
                    conn, row, exposure, occurrence,
                    selected_revisions=(anchors[0], anchors[1]),
                    require_birth_proof=True):
                raise IdentityResolutionReadError(
                    "V1 verified history does not replay from its revision-1 anchors")
        except IdentityResolutionReadError:
            raise
        except sa.exc.SQLAlchemyError as exc:
            raise IdentityResolutionReadError(
                "cannot validate V1 temporal anchors") from exc

    @staticmethod
    def _retained_pair(conn, exposure_id: str, workload_id: str) -> bool:
        """Whether the (exposure_id, workload_id) pair is a retained
        membership pair (migration 0002): the historical key that stays
        valid after a correction moves the exposure."""
        return conn.execute(sa.select(exposure_workload_memberships.c.exposure_id).where(
            exposure_workload_memberships.c.exposure_id == exposure_id,
            exposure_workload_memberships.c.workload_id == workload_id
        )).first() is not None

    @staticmethod
    def _ordered_record_history(conn, record_type: str, record_id: str,
                                revision: int):
        """Return the complete correction chain in revision order, or None.

        Check the number of actual records against the persisted revision
        before sorting or walking. A corrupt, enormous revision cannot cause
        allocation proportional to its claimed value.
        """
        rows = conn.execute(sa.select(
            correction_records.c.field_name,
            correction_records.c.old_value,
            correction_records.c.new_value,
            correction_records.c.correlation_id,
            correction_records.c.previous_revision,
            correction_records.c.new_revision).where(
            correction_records.c.record_type == record_type,
            correction_records.c.record_id == record_id)).mappings().all()
        transitions = [row for row in rows if (
            row["previous_revision"], row["new_revision"]) != (0, 0)]
        if not isinstance(revision, int) or revision < 1 \
                or len(transitions) != revision - 1:
            return None
        transitions.sort(key=lambda row: row["previous_revision"])
        if any(row["previous_revision"] != index
               or row["new_revision"] != index + 1
               for index, row in enumerate(transitions, start=1)):
            return None
        return rows, transitions

    @staticmethod
    def _repointing_history_valid(conn, d, exposure, occurrence, *,
                                  selected_revisions=None,
                                  require_birth_proof=False) -> bool:
        """Check both complete membership histories in chronological order.

        Revision numbers are local to each record. Independent field
        corrections may interleave, but the sequence of membership moves and
        their correlation IDs must be the same after occurrence birth. A
        retained legacy row without a birth anchor can use only a value-
        consistent inferred prefix; that inference never verifies selection
        time. Pairing by ID alone loses order on repeated reversals.
        """
        occ_history = IdentityResolutionStore._ordered_record_history(
            conn, "occurrence", d["occurrence_id"], occurrence["revision"])
        exp_history = IdentityResolutionStore._ordered_record_history(
            conn, "exposure", d["exposure_id"], exposure["revision"])
        if occ_history is None or exp_history is None:
            return False
        occ_rows, occ_transitions = occ_history
        exp_rows, exp_transitions = exp_history
        # A membership record without a revision transition has no
        # chronological position and cannot prove a move.
        if any(row["field_name"] == "incarnation_id" for row in occ_rows
               if row["previous_revision"] == 0):
            return False
        if any(row["field_name"] == "workload_id" for row in exp_rows
               if row["previous_revision"] == 0):
            return False
        occ_steps = [row for row in occ_transitions
                     if row["field_name"] == "incarnation_id"]
        exp_steps = [row for row in exp_transitions
                     if row["field_name"] == "workload_id"]
        exp_correlations = [step["correlation_id"] for step in exp_steps]
        if (any(not correlation for correlation in exp_correlations)
                or len(set(exp_correlations)) != len(exp_correlations)):
            return False
        birth_id = occurrence.get("birth_exposure_id")
        birth_revision = occurrence.get("birth_exposure_revision")
        if (birth_id is None) != (birth_revision is None):
            return False
        if birth_id is not None:
            if birth_id != d["exposure_id"] or not isinstance(birth_revision, int) \
                    or not 1 <= birth_revision <= exposure["revision"]:
                return False
            prefix_count = sum(step["new_revision"] <= birth_revision
                               for step in exp_steps)
        elif require_birth_proof:
            # A selected V1 1/1 candidate predates the recorded moves;
            # uniqueness is checked against every subsequent phase below.
            birth_revision = 1
            prefix_count = 0
        else:
            # A retained, unverified V1 selection may predate 0003 and lack
            # its creation anchor. Its suffix can still be checked, but the
            # inferred prefix never constitutes temporal proof.
            prefix_count = len(exp_steps) - len(occ_steps)
        if prefix_count < 0 or len(exp_steps) - prefix_count != len(occ_steps):
            return False
        incarnation = (occ_steps[0]["old_value"] if occ_steps
                       else occurrence["incarnation_id"])
        workload = (exp_steps[0]["old_value"] if exp_steps
                    else exposure["workload_id"])
        incarnation_ids = {incarnation, occurrence["incarnation_id"]}
        for step in occ_steps:
            incarnation_ids.add(step["old_value"])
            incarnation_ids.add(step["new_value"])
        incarnation_workloads = {}
        # Bound each IN clause for SQLite as well as PostgreSQL. The total
        # work is proportional to the actual recorded steps, never to a
        # revision value supplied by a corrupt persisted row.
        incarnation_ids = list(incarnation_ids)
        for offset in range(0, len(incarnation_ids), 500):
            incarnation_workloads.update(conn.execute(sa.select(
                incarnations.c.incarnation_id,
                incarnations.c.workload_id).where(
                incarnations.c.incarnation_id.in_(
                    incarnation_ids[offset:offset + 500]))).all())
        exp_values = {1: workload}
        for step in exp_transitions:
            if step["field_name"] == "workload_id":
                if step["old_value"] != workload:
                    return False
                workload = step["new_value"]
            exp_values[step["new_revision"]] = workload
        if workload != exposure["workload_id"]:
            return False
        workload = exp_values[birth_revision] if birth_revision is not None \
            else (exp_steps[prefix_count - 1]["new_value"] if prefix_count
                  else exp_values[1])
        if incarnation_workloads.get(incarnation) != workload:
            return False
        occ_values = {1: incarnation}
        current_incarnation = incarnation
        for step in occ_transitions:
            if step["field_name"] == "incarnation_id":
                if step["old_value"] != current_incarnation:
                    return False
                current_incarnation = step["new_value"]
            occ_values[step["new_revision"]] = current_incarnation
        if current_incarnation != occurrence["incarnation_id"]:
            return False
        if selected_revisions is not None:
            selected_exp, selected_occ = selected_revisions
            if (selected_exp not in exp_values or selected_occ not in occ_values
                    or selected_exp < birth_revision
                    or exp_values[selected_exp] != d["workload_id"]
                    or occ_values[selected_occ] != d["incarnation_id"]):
                return False
        selected_phases = int(incarnation == d["incarnation_id"]
                              and workload == d["workload_id"])
        # The two lists are already ordered by their own record revisions.
        # Checking them positionally is linear and preserves the relative
        # order even where IDs and old/new values recur after reversals.
        seen_correlations = set()
        for occ_step, exp_step in zip(occ_steps, exp_steps[prefix_count:]):
            if (occ_step["correlation_id"] != exp_step["correlation_id"]
                    or not occ_step["correlation_id"]
                    or occ_step["correlation_id"] in seen_correlations
                    or occ_step["old_value"] != incarnation
                    or exp_step["old_value"] != workload):
                return False
            seen_correlations.add(occ_step["correlation_id"])
            incarnation, workload = (occ_step["new_value"],
                                     exp_step["new_value"])
            if incarnation_workloads.get(incarnation) != workload:
                return False
            selected_phases += (incarnation == d["incarnation_id"]
                                and workload == d["workload_id"])
        # A V1 row never recorded its actual selection phase. Revision-1
        # anchors and a proof string cannot choose between identical phases
        # after a reversal, even if both correction chains replay.
        return ((selected_phases == 1 if require_birth_proof else selected_phases > 0)
                and incarnation == occurrence["incarnation_id"]
                and workload == exposure["workload_id"]
                and occurrence["workload_id"] == workload)

    def _validate_current_chain(self, conn, r) -> int:
        """Newly issued matched/new selections must match the CURRENT
        chain. The exposure row is loaded with ``FOR UPDATE`` — the same
        row the correction writer locks — so PostgreSQL serialises the
        current-chain check against a concurrent correction; SQLite
        serialises writes at database level and the revision re-check in
        ``_assert_exposure_unchanged`` is the optimistic equivalent.
        Returns the loaded exposure revision for that re-check."""
        exp = conn.execute(sa.select(exposures).where(
            exposures.c.exposure_id == r.exposure_id).with_for_update()).mappings().first()
        if exp is None:
            raise IdentityResolutionError("missing referenced exposure_id")
        if exp["workload_id"] != r.workload_id or exp["group_id"] != r.group_id:
            raise IdentityResolutionError(
                "new selection does not match the current exposure chain")
        if not self._retained_pair(conn, r.exposure_id, r.workload_id):
            raise IdentityResolutionError(
                "selected exposure/workload pair is not retained")
        inc = conn.execute(sa.select(incarnations).where(
            incarnations.c.incarnation_id == r.incarnation_id)).mappings().first()
        if inc is None or inc["workload_id"] != r.workload_id:
            raise IdentityResolutionError(
                "selected incarnation does not belong to the current chain")
        occ = conn.execute(self._occurrence_select(conn).where(
            occurrences.c.occurrence_id == r.occurrence_id)).mappings().first()
        if occ is None or occ["exposure_id"] != r.exposure_id \
                or occ["incarnation_id"] != r.incarnation_id \
                or occ["workload_id"] != r.workload_id:
            raise IdentityResolutionError(
                "new selection does not match the current occurrence chain")
        return exp["revision"]

    def _assert_exposure_unchanged(self, conn, r, guard_revision: int) -> None:
        """Optimistic re-check immediately before insert: if a correction
        committed a move after ``_validate_current_chain`` ran, the exposure
        revision/workload changed and this newly issued write must fail
        rather than commit as a stale selection (SQLite equivalent of the
        PostgreSQL ``FOR UPDATE`` serialisation)."""
        exp = conn.execute(sa.select(
            exposures.c.revision, exposures.c.workload_id).where(
            exposures.c.exposure_id == r.exposure_id)).first()
        if exp is None or exp[0] != guard_revision or exp[1] != r.workload_id:
            raise IdentityResolutionError(
                "exposure chain changed during write; selection is stale")

    def _validate_references(self, conn, r, read=False):
        error = IdentityResolutionReadError if read else IdentityResolutionError
        def require(table, key, value):
            if conn.execute(sa.select(table.c[key]).where(table.c[key] == value)).first() is None:
                raise error(f"missing referenced {key}")
        require(source_observations, "observation_id", r.observation_id)
        if r.supersedes_resolution_id is not None:
            prior = conn.execute(sa.select(
                identity_resolutions.c.resolution_id,
                identity_resolutions.c.observation_id,
                identity_resolutions.c.revision,
                identity_resolutions.c.supersedes_resolution_id,
            ).where(
                identity_resolutions.c.resolution_id == r.supersedes_resolution_id
            )).mappings().first()
            if prior is None or prior["observation_id"] != r.observation_id:
                raise error("superseded resolution must exist for the same observation")
        for value in r.candidate_workload_ids:
            require(workloads, "workload_id", value)
        if r.outcome in ("matched", "new"):
            for table, key in ((groups, "group_id"), (workloads, "workload_id"),
                               (incarnations, "incarnation_id"), (exposures, "exposure_id"),
                               (occurrences, "occurrence_id")):
                require(table, key, getattr(r, key))
