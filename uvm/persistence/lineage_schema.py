"""UVM identity lineage persistence slice (G1, versions 1 and 2).

Additive slice for the append-only resolution history
(``IdentityResolutionV1``) and the identity correction history
(``CorrectionRecord``) from ``uvm/identity/model.py``, in the separate UVM
database, plus the append-only ``resolution_temporal_assessments`` events
of the reviewed V2 revision-anchor amendment. It registers its tables on the same ``uvm_metadata`` as
``schema.py`` and imports ``observation_schema`` so its ``source_observations``
table is registered for the ``observation_id`` foreign key. Its
historical exposure selection references the retained
``exposure_workload_memberships`` pair table defined in ``schema.py``
(G1 membership-correction amendment). It does not
define its own metadata, engine, writer, migration or UPDATE/DELETE path.

Semantics carried into DDL:

* ``resolution_id`` and ``correction_id`` are canonical UVM UUID string
  primary keys (``Uuid(as_uuid=False)``, same convention as ``schema.py``).
* History is append-only: ``identity_resolutions`` has NO uniqueness over
  ``observation_id`` ALONE — multiple versioned resolutions per
  observation are permitted and a ``supersedes_resolution_id``
  self-foreign key links a newer record to the one it supersedes. The
  resolution version key IS unique over the pair
  (``observation_id``, ``revision``): one revision per observation per
  versioned rule run. ``correction_records`` has NO uniqueness over
  ``record_id`` — multiple corrections for one record remain as
  distinct rows. ``supersedes_resolution_id`` is a link, not a
  replacement: the superseded row is never deleted or rewritten by this
  slice.
* ``outcome`` is one of the committed DTO outcomes
  (``matched`` / ``new`` / ``ambiguous`` / ``unresolved``).
  ``matched`` or ``new`` names exactly one group, workload, incarnation,
  exposure and occurrence (all five refs NOT NULL); ``ambiguous`` selects
  no workload, incarnation, exposure or occurrence (each of those implies
  a selected workload; the group ref may remain selected because the
  group key resolves independently of the workload match); ``unresolved``
  selects no group, workload, incarnation, exposure or occurrence. NULL
  selection refs are retained as NULL — never coerced to a guessed
  value (FR-ID-01).
* ``schema_version IN (1, 2)``, ``revision > 0`` and ``rule_version > 0``
  (positive versions, consistent with the core tables). Version 2 is the
  reviewed revision-anchor amendment (FR-ID-01/02, CR-03; approved at
  d5fe24d, ``evidence/G1/revision-anchor-v2-approval.md``): a V2
  ``matched``/``new`` selection carries the positive revision anchors
  ``selected_exposure_revision`` and ``selected_occurrence_revision`` — the
  exact revisions of the selected exposure and occurrence at selection, not
  interchangeable counters. A retained V1 ``matched``/``new`` row allows the
  anchors to be both NULL (legacy, temporally unverified) or both positive
  (uniquely proved); no partial anchor is admissible at either version.
  ``ambiguous``/``unresolved`` rows carry no anchors (both NULL); their
  temporal-selection status ``not_applicable`` is derived by the later
  reader, never persisted as a fabricated assessment row.
* ``resolution_temporal_assessments`` mirrors the amendment's append-only
  temporal-assessment events (FR-ID-01/02): canonical UUID string primary
  key ``assessment_id``, required foreign key onto the retained
  ``identity_resolutions`` row, ``event_sequence > 0`` unique per resolution
  (append-only event stream: a reassessment appends an event that
  ``supersedes`` the prior assessment, which is never deleted or rewritten),
  ``status`` restricted to ``verified`` / ``legacy_unverified`` (there is no
  ``not_applicable`` row — ambiguous/unresolved selections are assessed by
  no event at all), a non-empty ``proof_reference`` required for every
  ``verified`` event, ``origin`` distinguishing ``migration_backfill``
  (0003 legacy backfill) from ``reviewed`` (future writer-issued) events,
  and the UTC-stored ``assessed_at`` instant. The DDL does not claim
  row-level immutability (no UPDATE/DELETE writer exists in this slice); the
  writer must enforce contiguous sequences and append-only retention.
* ``matching_inputs``, ``candidate_workload_ids``,
  ``candidate_explanations`` and ``affected_record_ids`` are JSONB on
  PostgreSQL / JSON elsewhere: provenance-bearing matching inputs,
  candidate UUID lists and per-candidate explanations (FR-ID-01
  explainable matching). They are ``NOT NULL`` at the SQL level and
  reject the SEMANTIC JSON null robustly on both engines:
  ``json_type(...) IS NOT NULL AND json_type(...) <> 'null'`` on SQLite
  and ``jsonb_typeof(...) IS NOT NULL AND jsonb_typeof(...) <> 'null'``
  on PostgreSQL (the JSONB-type function: ``json_typeof`` takes a
  ``json`` value and does not type-check a ``jsonb`` column). Both
  functions parse/normalise the stored value, so a
  whitespace-padded JSON null written as raw text (bypassing the JSON
  bind processor, e.g. a raw SQL insert or backfill) is normalised to
  the JSON null and rejected, and malformed JSON is rejected by the
  ``IS NOT NULL`` half. Legitimate empty lists/maps (an unresolved names
  no candidates) stay admissible. The two dialect variants render
  through dialect-filtered CHECKs, so no single portable expression is
  claimed.
* A row cannot supersede itself: ``supersedes_resolution_id`` is NULL
  or a DIFFERENT ``resolution_id`` (portable CHECK). This is necessary
  because the immediate self-foreign-key passes at insert time — the
  referencing row's own primary key already exists.
* Selection coherence is bound where a unique key exists and only
  there: the composite foreign key ``(incarnation_id, workload_id) ->
  incarnations(incarnation_id, workload_id)`` rejects a selected
  incarnation that does not belong to the selected workload (CR-03),
  and the composite foreign key
  ``(exposure_id, workload_id) ->
  exposure_workload_memberships(exposure_id, workload_id)`` rejects a
  selected exposure/workload pair that was never retained as a
  membership pair (G1 membership-correction amendment: the retained
  pair table, NOT the exposure's current pair, is the reference
  target, so a historical resolution keeps pointing at a valid pair
  after a correction moves the exposure).
  NULL pairs (ambiguous/unresolved rows) skip the FK per SQL standard.
  The core tables carry no unique key over
  ``(occurrence_id, exposure_id)`` or ``(exposure_id, group_id)``, so
  the DDL does not claim occurrence or group coherence (and does not
  invent one).
* ``correction_records`` mirrors the ``CorrectionRecord`` DTO: actor,
  reason and correlation ID are required, non-empty (audited correction,
  FR-ID-02); ``record_id`` is a plain UUID column with no single-table
  foreign key because the corrected record may be a group, workload,
  incarnation, exposure or occurrence; ``record_type`` is NOT NULL with no
  closed value policy in the committed DTO (the engine validates the
  target bucket; the DDL does not invent a closed set);
  ``affected_record_ids`` is a JSONB UUID list (semantic null rejected);
  ``previous_revision`` / ``new_revision`` are non-negative with a
  strictly increasing transition except the committed (0, 0)
  not-applicable default; ``assessment_impact`` / ``issue_impact`` are
  restricted to the committed DTO value ``unverified`` (the in-memory
  engine cannot assess downstream stores); extending the impact
  vocabulary is a versioned contract change.

Honest DDL boundaries (no writer/trigger in this slice):

* A ``supersedes_resolution_id`` pointing at a resolution of a DIFFERENT
  observation is NOT blocked: a single-table CHECK/index cannot compare
  two rows. The writer must enforce same-observation supersession.
  (Self-supersession, by contrast, IS blocked by the portable CHECK
  above, because the self-FK alone would pass.)
* Occurrence/group coherence of a ``matched``/``new`` selection is a
  writer invariant: the selected occurrence's own exposure/group may
  differ from the selected exposure/group, and the core tables carry
  no unique key over ``(occurrence_id, exposure_id)`` or
  ``(exposure_id, group_id)`` to ground a composite FK. The writer
  must reject such rows (no new core-table unique keys are invented).
* ``ambiguous`` naming at least two candidate explanations is a writer
  invariant: a portable array-length CHECK is not expressible (SQLite
  ``json_array_length`` vs PostgreSQL jsonb typing differ), and the
  DDL only requires the candidate evidence columns to be present and
  not JSON null.

This module only defines metadata; it does not create a writer/store, a
write guard, or a database, and it claims no row-level immutability (no
UPDATE/DELETE writer exists in this slice).
"""

from __future__ import annotations

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    Column,
    ForeignKeyConstraint,
    UniqueConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    JSON,
    String,
    Text,
    Table,
    text,
    Uuid,
)
from sqlalchemy.dialects.postgresql import JSONB

from uvm.persistence.observation_schema import source_observations  # noqa: F401
from uvm.persistence.schema import (
    exposures,
    groups,
    incarnations,
    occurrences,
    uvm_metadata,
    workloads,
)

# UTC stored timestamps, explicit display timezone later (project convention).
_TZ = DateTime(timezone=True)
# Canonical string IDs (new_id()); as_uuid=False so strings bind/round-trip
# unchanged.
_ID = Uuid(as_uuid=False)
# JSONB on PostgreSQL, JSON elsewhere (same convention as schema.py).
_JSON = JSONB().with_variant(JSON, "sqlite")

identity_rule_definitions = Table(
    "identity_rule_definitions", uvm_metadata,
    Column("rule_id", String, primary_key=True),
    Column("rule_version", Integer, primary_key=True),
    Column("workload_match_fields", _JSON, nullable=False),
    Column("workload_context_fields", _JSON, nullable=False, server_default=text("'[]'")),
    Column("verified_asset_locator", Boolean, nullable=False),
    Column("definition_digest", String, nullable=False),
    Column("authorisation_decision_id", _ID, ForeignKey("identity_authorisation_decisions.decision_id"), nullable=True),
    Column("created_at", _TZ, nullable=False),
    UniqueConstraint("rule_id", "rule_version", name="uq_identity_rule_definition"),
)

identity_resolution_requests = Table(
    "identity_resolution_requests", uvm_metadata,
    Column("resolution_request_id", _ID, primary_key=True),
    Column("observation_id", _ID, ForeignKey("source_observations.observation_id"), nullable=False),
    Column("observation_revision", Integer, nullable=False),
    Column("request_fingerprint", String, nullable=False),
    Column("authorisation_decision_id", _ID, ForeignKey("identity_authorisation_decisions.decision_id"), nullable=True),
    Column("resolution_id", _ID, ForeignKey("identity_resolutions.resolution_id"), nullable=False),
    Column("resolution_revision", Integer, nullable=False),
    Column("created_at", _TZ, nullable=False),
    UniqueConstraint("resolution_request_id", name="uq_identity_resolution_request"),
)

identity_authorisation_decisions = Table(
    "identity_authorisation_decisions", uvm_metadata,
    Column("decision_id", _ID, primary_key=True),
    Column("action", String, nullable=False),
    Column("target_id", _ID, nullable=False),
    Column("principal_id", String, nullable=False),
    Column("scope", String, nullable=False),
    Column("policy_revision", String, nullable=False),
    Column("reason", String, nullable=False),
    Column("evidence_ref", String, nullable=False),
    Column("correlation_id", String, nullable=False),
    Column("decided_at", _TZ, nullable=False),
    Column("decision_details", _JSON, nullable=False),
    # NULL is retained legacy evidence, never inferred from normalised JSONB.
    Column("decision_semantics_canonical", Text, nullable=True),
)


def _json_not_null_checks(col: str, name: str) -> list[CheckConstraint]:
    """Reject the semantic JSON null in a required JSON column on BOTH
    engines without a false single-expression portability claim:
    ``json_type`` (SQLite) / ``jsonb_typeof`` (PostgreSQL, the
    JSONB-type function) parse the stored
    value, so a whitespace-padded `` null `` raw-text write is normalised
    to the JSON null and rejected, and malformed JSON is rejected by the
    ``IS NOT NULL`` half. Each variant is dialect-filtered (``_create_rule``)
    so only the function its engine knows is emitted or enforced."""
    return [
        CheckConstraint(
            f"json_type({col}) IS NOT NULL AND json_type({col}) <> 'null'",
            name=name,
            _create_rule=lambda compiler: compiler.dialect.name == "sqlite",
        ),
        CheckConstraint(
            f"jsonb_typeof({col}) IS NOT NULL "
            f"AND jsonb_typeof({col}) <> 'null'",
            name=name,
            _create_rule=lambda compiler:
            compiler.dialect.name == "postgresql",
        ),
    ]

identity_resolutions = Table(
    "identity_resolutions",
    uvm_metadata,
    Column("schema_version", Integer, nullable=False),
    Column("resolution_id", _ID, primary_key=True),
    Column("revision", Integer, nullable=False),
    # FK onto the retained source observation (append-only history: several
    # versioned resolutions per observation are permitted — no uniqueness).
    Column("observation_id", _ID,
           ForeignKey("source_observations.observation_id"),
           nullable=False),
    Column("rule_id", String, nullable=False),
    Column("rule_version", Integer, nullable=False),
    # Provenance-bearing matching inputs (FR-ID-01).
    Column("matching_inputs", _JSON, nullable=False),
    Column("candidate_workload_ids", _JSON, nullable=False),
    Column("outcome", String, nullable=False),
    Column("evaluated_at", _TZ, nullable=False),
    # Selected membership: exactly one of each for matched/new, none
    # selected for ambiguous/unresolved (null outcome refs stay NULL).
    Column("group_id", _ID, ForeignKey("groups.group_id"), nullable=True),
    Column("workload_id", _ID, ForeignKey("workloads.workload_id"),
           nullable=True),
    Column("incarnation_id", _ID,
           ForeignKey("incarnations.incarnation_id"), nullable=True),
    Column("exposure_id", _ID, ForeignKey("exposures.exposure_id"),
           nullable=True),
    Column("occurrence_id", _ID,
           ForeignKey("occurrences.occurrence_id"), nullable=True),
    # V2 selection revision anchors (FR-ID-01/02, CR-03 amendment): the
    # exact exposure/occurrence revisions at selection, captured under the
    # guarded selection transaction (writer route; this slice carries
    # metadata only). Nullable for retained V1 rows and for
    # ambiguous/unresolved selections; see the anchor-coherence CHECK.
    Column("selected_exposure_revision", Integer, nullable=True),
    Column("selected_occurrence_revision", Integer, nullable=True),
    Column("known_group_revision", Integer, nullable=True),
    Column("candidate_explanations", _JSON, nullable=False),
    Column("reason", String, nullable=True),
    # Append-only supersession link: points at a retained row, never
    # deletes or rewrites it.
    Column("supersedes_resolution_id", _ID,
           ForeignKey("identity_resolutions.resolution_id"), nullable=True),
    # Coherence (CR-03): the selected incarnation belongs to the
    # selected workload, grounded on the existing core unique key.
    # NULL pairs skip the FK per SQL standard (ambiguous/unresolved
    # rows select no workload); outcome selection already forces both
    # refs NOT NULL together for matched/new.
    ForeignKeyConstraint(
        ["incarnation_id", "workload_id"],
        ["incarnations.incarnation_id", "incarnations.workload_id"],
        name="fk_identity_resolutions_incarnation_id_workload_id_incarnations",
    ),
    # Historical exposure pair: references the retained membership pair
    # table (stable-ID key), not the exposure's current pair — after a
    # correction moves the exposure, this resolution's old pair stays a
    # valid retained reference (G1 membership-correction amendment).
    ForeignKeyConstraint(
        ["exposure_id", "workload_id"],
        ["exposure_workload_memberships.exposure_id",
         "exposure_workload_memberships.workload_id"],
        name="fk_identity_resolutions_exposure_memberships",
    ),
    Index(
        "ix_identity_resolutions_observation_evaluated",
        "observation_id", "evaluated_at",
    ),
    Index("ix_identity_resolutions_supersedes", "supersedes_resolution_id"),
    CheckConstraint("schema_version IN (1, 2)",
                    name="identity_resolutions_schema_version_known"),
    CheckConstraint("revision > 0",
                    name="identity_resolutions_revision_positive"),
    CheckConstraint("rule_version > 0",
                    name="identity_resolutions_rule_version_positive"),
    CheckConstraint(
        "outcome IN ('matched', 'new', 'ambiguous', 'unresolved')",
        name="identity_resolutions_outcome_known",
    ),
    # Outcome/selection consistency (FR-ID-01): matched/new name exactly
    # one group/workload/incarnation/exposure/occurrence; ambiguous
    # selects no workload/incarnation/exposure/occurrence (each of those
    # implies a selected workload); V2 unresolved may retain a known group
    # only with its positive group revision.
    CheckConstraint(
        "((outcome IN ('matched', 'new') AND group_id IS NOT NULL "
        "AND workload_id IS NOT NULL AND incarnation_id IS NOT NULL "
        "AND exposure_id IS NOT NULL AND occurrence_id IS NOT NULL "
        "AND known_group_revision IS NULL) "
        "OR (outcome = 'ambiguous' AND workload_id IS NULL "
        "AND incarnation_id IS NULL AND exposure_id IS NULL "
        "AND occurrence_id IS NULL AND known_group_revision IS NULL) "
        "OR (outcome = 'unresolved' "
        "AND ((schema_version = 1 AND known_group_revision IS NULL) "
        "OR (schema_version = 2 AND group_id IS NULL AND known_group_revision IS NULL) "
        "OR (schema_version = 2 AND group_id IS NOT NULL AND known_group_revision IS NOT NULL "
        "AND known_group_revision > 0)) "
        "AND workload_id IS NULL AND incarnation_id IS NULL "
        "AND exposure_id IS NULL AND occurrence_id IS NULL))",
        name="identity_resolutions_outcome_selection_consistent",
    ),
    # Required JSON columns reject the semantic JSON null robustly
    # (SQL NULL is already rejected by NOT NULL; whitespace-padded and
    # malformed raw-text values are normalised via json_type (SQLite) /
    # jsonb_typeof (PostgreSQL), one dialect-filtered CHECK per engine).
    *(_json_not_null_checks("matching_inputs",
                            "identity_resolutions_matching_inputs_not_json_null")),
    *(_json_not_null_checks("candidate_workload_ids",
                            "identity_resolutions_candidates_not_json_null")),
    *(_json_not_null_checks("candidate_explanations",
                            "identity_resolutions_explanations_not_json_null")),
    # A row cannot supersede itself: the immediate self-FK would pass at
    # insert time (the row's own PK already exists), so the portable
    # CHECK is the guard (FR-ID-01 lineage integrity).
    CheckConstraint(
        "supersedes_resolution_id IS NULL "
        "OR supersedes_resolution_id <> resolution_id",
        name="identity_resolutions_no_self_supersession",
    ),
    # V2 selection anchor coherence (FR-ID-01/02, CR-03 amendment):
    # a V2 matched/new row requires BOTH positive anchors; a retained
    # V1 matched/new row allows both NULL (legacy unverified) or both
    # positive (uniquely proved); ambiguous/unresolved rows carry no
    # anchors at all. No partial anchor is admissible. Every arm is
    # NULL-safe: presence is tested with IS NOT NULL (never a bare
    # ``> 0``, which evaluates NULL on a missing anchor and would
    # satisfy the CHECK on SQLite's three-valued logic), so a
    # violation is a definite 0 on BOTH engines.
    CheckConstraint(
        "((outcome IN ('matched', 'new') "
        "AND ((schema_version = 2 "
        "AND selected_exposure_revision IS NOT NULL "
        "AND selected_occurrence_revision IS NOT NULL "
        "AND selected_exposure_revision > 0 "
        "AND selected_occurrence_revision > 0) "
        "OR (schema_version = 1 "
        "AND ((selected_exposure_revision IS NULL "
        "AND selected_occurrence_revision IS NULL) "
        "OR (selected_exposure_revision IS NOT NULL "
        "AND selected_occurrence_revision IS NOT NULL "
        "AND selected_exposure_revision > 0 "
        "AND selected_occurrence_revision > 0))))) "
        "OR (outcome IN ('ambiguous', 'unresolved') "
        "AND selected_exposure_revision IS NULL "
        "AND selected_occurrence_revision IS NULL))",
        name="identity_resolutions_selection_anchors_consistent",
    ),
    # Resolution version key: no two rows may claim the same
    # (observation_id, revision) — the versioned resolution is unique
    # per observation per revision, while the history stays append-only
    # (no uniqueness over observation_id alone).
    UniqueConstraint("observation_id", "revision",
                     name="identity_resolutions_observation_revision"),
)

# Append-only temporal-assessment events for retained selections
# (FR-ID-01/02, CR-03 amendment). One row per assessment EVENT: the 0003
# backfill appends exactly one event per retained V1 matched/new
# resolution (verified only where existing evidence uniquely proves the
# revision anchors, else legacy_unverified), and a later reviewed
# reassessment appends a NEW event superseding the prior one — never
# editing, deleting or rewriting it. Ambiguous/unresolved resolutions
# get NO event: their not_applicable selection status is reader-derived,
# not a fabricated row. No writer/UPDATE/DELETE path exists in this
# slice, so no row-level immutability is claimed (the writer must
# enforce contiguous per-resolution sequences and append-only retention).
resolution_temporal_assessments = Table(
    "resolution_temporal_assessments",
    uvm_metadata,
    # Canonical UVM UUID string primary key (same convention as the rest
    # of this slice).
    Column("assessment_id", _ID, primary_key=True),
    # The assessed retained resolution (append-only: events attach to a
    # specific historical row and never mutate it).
    Column("resolution_id", _ID,
           ForeignKey("identity_resolutions.resolution_id"),
           nullable=False),
    # Stable append-only event position within this resolution's
    # assessment stream (positive; one event per sequence per resolution).
    Column("event_sequence", Integer, nullable=False),
    # verified requires a uniquely proved revision anchor plus a
    # versioned proof reference; every other event starts
    # legacy_unverified. NOT_APPLICABLE is deliberately absent.
    Column("status", String, nullable=False),
    # Versioned proof reference; required (and non-empty) for verified
    # events. The reference names the proof; it is not the proof.
    Column("proof_reference", String, nullable=True),
    # migration_backfill: the 0003 legacy backfill event. reviewed:
    # writer-issued or reviewed reassessment after cutover.
    Column("origin", String, nullable=False),
    # UTC stored assessment instant (explicit display timezone later).
    Column("assessed_at", _TZ, nullable=False),
    # Append-only supersession link: a reassessment appends an event
    # pointing at the event it supersedes; the superseded row is never
    # deleted or rewritten (same pattern as identity_resolutions).
    Column("supersedes_assessment_id", _ID,
           ForeignKey("resolution_temporal_assessments.assessment_id"),
           nullable=True),
    Index("ix_rta_resolution_event", "resolution_id", "event_sequence"),
    Index("ix_rta_supersedes", "supersedes_assessment_id"),
    CheckConstraint("event_sequence > 0",
                    name="rta_event_sequence_positive"),
    CheckConstraint(
        "status IN ('verified', 'legacy_unverified')",
        name="rta_status_known",
    ),
    CheckConstraint(
        "origin IN ('migration_backfill', 'reviewed')",
        name="rta_origin_known",
    ),
    # Verified events carry a non-empty proof reference (FR-ID-01/02).
    CheckConstraint(
        "status <> 'verified' "
        "OR (proof_reference IS NOT NULL AND length(proof_reference) > 0)",
        name="rta_verified_requires_proof",
    ),
    # A row cannot supersede itself: the immediate self-FK would pass at
    # insert time, so the portable CHECK is the guard (same pattern as
    # identity_resolutions).
    CheckConstraint(
        "supersedes_assessment_id IS NULL "
        "OR supersedes_assessment_id <> assessment_id",
        name="rta_no_self_supersession",
    ),
    # Append-only event key: one event per (resolution_id, event_sequence);
    # the stream itself has no uniqueness over assessment_id alone beyond
    # the primary key, and NO uniqueness over resolution_id (several
    # retained events per resolution).
    UniqueConstraint("resolution_id", "event_sequence",
                     name="rta_resolution_event"),
)

correction_records = Table(
    "correction_records",
    uvm_metadata,
    Column("correction_id", _ID, primary_key=True),
    Column("record_type", String, nullable=False),
    # The corrected record. No single-table foreign key: record_type
    # selects which core table the ID belongs to (group, workload,
    # incarnation, exposure or occurrence).
    Column("record_id", _ID, nullable=False),
    Column("old_value", String, nullable=True),
    Column("new_value", String, nullable=True),
    # Audited correction (FR-ID-02): actor, reason and correlation ID
    # are required and never backfilled.
    Column("actor", String, nullable=False),
    Column("reason", String, nullable=False),
    Column("correlation_id", String, nullable=False),
    Column("affected_record_ids", _JSON, nullable=False),
    Column("created_at", _TZ, nullable=False),
    Column("field_name", String, nullable=False),
    # Revisions around the correction; 0 means not applicable.
    Column("previous_revision", Integer, nullable=False),
    Column("new_revision", Integer, nullable=False),
    Column("assessment_impact", String, nullable=False),
    Column("issue_impact", String, nullable=False),
    # Append-only correction history: NO uniqueness over record_id —
    # several corrections for one record are distinct retained rows.
    Index("ix_correction_records_record_id", "record_id"),
    Index("ix_correction_records_correlation", "correlation_id"),
    # Audited correction (FR-ID-02): actor, reason and correlation ID are
    # not just NOT NULL — an empty string is not audited evidence.
    CheckConstraint(
        "length(actor) > 0 AND length(reason) > 0 "
        "AND length(correlation_id) > 0",
        name="correction_records_audited_fields_non_empty",
    ),
    # affected_record_ids is a UUID list (empty list admissible): reject
    # the semantic JSON null robustly, same dialect-filtered approach as
    # the resolution JSON columns.
    *(_json_not_null_checks("affected_record_ids",
                            "correction_records_affected_ids_not_json_null")),
    # Revision transition: non-negative, strictly increasing, except the
    # committed (0, 0) not-applicable default (the DTO carries 0/0 for a
    # plain field correction without revision evidence).
    CheckConstraint(
        "previous_revision >= 0 AND new_revision >= 0 "
        "AND ((previous_revision = 0 AND new_revision = 0) "
        "OR (new_revision > previous_revision))",
        name="correction_records_revision_transition_valid",
    ),
    # Impact values from the committed DTO contract: the in-memory engine
    # can only assert 'unverified' (it cannot assess downstream
    # assessment/issue stores). A wider vocabulary is a versioned
    # contract change, not a DDL edit.
    CheckConstraint(
        "assessment_impact IN ('unverified') "
        "AND issue_impact IN ('unverified')",
        name="correction_records_impact_committed_values",
    ),
)

occurrence_parent_transition_markers = Table(
    "occurrence_parent_transition_markers",
    uvm_metadata,
    Column("correction_id", _ID,
           ForeignKey("correction_records.correction_id"), primary_key=True),
    Column("schema_version", Integer, nullable=False),
    CheckConstraint("schema_version = 1",
                    name="parent_transition_marker_schema_version_v1"),
)

occurrence_parent_transition_anchors = Table(
    "occurrence_parent_transition_anchors",
    uvm_metadata,
    Column("correction_id", _ID,
           ForeignKey("correction_records.correction_id"), primary_key=True),
    Column("occurrence_id", _ID,
           ForeignKey("occurrences.occurrence_id"), nullable=False),
    Column("from_exposure_id", _ID,
           ForeignKey("exposures.exposure_id"), nullable=False),
    Column("to_exposure_id", _ID,
           ForeignKey("exposures.exposure_id"), nullable=False),
    Column("previous_revision", Integer, nullable=False),
    Column("new_revision", Integer, nullable=False),
    Column("from_exposure_revision", Integer, nullable=False),
    Column("to_exposure_revision", Integer, nullable=False),
    UniqueConstraint("occurrence_id", "new_revision",
                     name="uq_parent_transition_anchor_occurrence_revision"),
    CheckConstraint("from_exposure_id <> to_exposure_id",
                    name="parent_transition_anchor_distinct_parents"),
    CheckConstraint(
        "previous_revision > 0 AND new_revision = previous_revision + 1 "
        "AND from_exposure_revision > 0 AND to_exposure_revision > 0",
        name="parent_transition_anchor_revisions_valid"),
)

ALL_LINEAGE_TABLES = (
    identity_resolutions,
    correction_records,
    resolution_temporal_assessments,
)
