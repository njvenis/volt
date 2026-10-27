"""Initial additive G1 migration: the 13-table UVM identity/observation/
lineage/alias metadata (FR-ID-01/02, CR-03/04; D-07 pins).

Revision ID: 0001
Revises:
Create Date: 2026-01-15

FROZEN, self-contained DDL (revision-immutability pin). Every CREATE/DROP
is emitted from the frozen type/constraint/index definitions defined in
THIS module — the revision never imports ``uvm/persistence`` metadata, so
later product-metadata changes (a new column, a new index) cannot alter
what a later ``upgrade head`` creates on a fresh database (two databases
stamped 0001 must stay identical) or what a later ``downgrade base``
removes (a database must only drop what 0001 created). Model changes
ship as NEW later revisions (e.g. 0002); they never edit this one.

The frozen definitions below equal the approved G1 metadata DDL at the
moment of the freeze (parity is guarded by
``tests/persistence/test_migration.py::RevisionImmutabilityTestCase``).
``migrations/env.py`` may import the current product metadata; it is
reserved for future autogenerate of LATER revisions only and is never
executed by this revision's upgrade/downgrade.

Separate UVM database: no DefectDojo CE tables, no data migration
(CR-01). Upgrade creates the 13 tables in dependency order (referenced
tables first, so composite-FK targets such as
exposures(exposure_id, workload_id) exist before dependents) plus all
named indexes; downgrade drops indexes then tables in the reverse order.
Dialect-filtered JSON CHECKs (SQLite json_type / PostgreSQL jsonb_typeof),
JSONB/JSON variants and Uuid rendering are emitted by the dialect
compiler. PostgreSQL migration execution is labelled unverified here
(later independent proof); this migration is exercised on SQLite only.
"""

from alembic import op
from sqlalchemy import (
    BigInteger,
    CheckConstraint,
    Column,
    DateTime,
    ForeignKey,
    ForeignKeyConstraint,
    Index,
    Integer,
    JSON,
    MetaData,
    PrimaryKeyConstraint,
    String,
    Table,
    UniqueConstraint,
    Uuid,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.schema import CreateIndex, CreateTable, DropIndex, DropTable

# UTC stored timestamps, explicit display timezone later (project
# convention).
_TZ = DateTime(timezone=True)
# Canonical string IDs (new_id()); as_uuid=False so strings bind/round-
# trip unchanged. Renders as native UUID on PostgreSQL, CHAR(32) on
# SQLite.
_ID = Uuid(as_uuid=False)
# JSONB on PostgreSQL, JSON elsewhere (frozen convention).
_JSON = JSONB().with_variant(JSON, "sqlite")

# Frozen metadata: same naming convention as the approved G1 metadata so
# the frozen DDL renders byte-for-byte identically (constraint names,
# inline PK naming). This is a frozen copy, not the product metadata.
uvm_metadata = MetaData(
    naming_convention={
        "pk": "pk_%(table_name)s",
        "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
        "uq": "uq_%(table_name)s_%(column_0_name)s",
        "ix": "ix_%(table_name)s_%(column_0_name)s",
        "ck": "ck_%(table_name)s",
    }
)


def _json_not_null_checks(col: str, name: str) -> list:
    """Dialect-filtered JSON-null CHECK pair (frozen): ``json_type``
    (SQLite) / ``jsonb_typeof`` (PostgreSQL) under ONE constraint name,
    only the function its engine knows is emitted."""
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


groups = Table(
    "groups",
    uvm_metadata,
    Column("group_id", _ID, primary_key=True),
    Column("source_family", String, nullable=False),
    Column("native_id_scheme", String, nullable=False),
    Column("native_id_authority", String, nullable=False),
    Column("native_id_value", String, nullable=False),
    Column("revision", Integer, nullable=False),
    Column("created_at", _TZ, nullable=False),
    # The complete namespace is the identity; no shorter prefix is.
    UniqueConstraint(
        "source_family", "native_id_scheme", "native_id_authority",
        "native_id_value",
        name="uq_groups_native_key",
    ),
    CheckConstraint("revision > 0", name="groups_revision_positive"),
)

workloads = Table(
    "workloads",
    uvm_metadata,
    Column("workload_id", _ID, primary_key=True),
    Column("stable_attrs", _JSON, nullable=False),
    Column("revision", Integer, nullable=False),
    Column("created_at", _TZ, nullable=False),
    CheckConstraint("revision > 0", name="workloads_revision_positive"),
)

incarnations = Table(
    "incarnations",
    uvm_metadata,
    Column("incarnation_id", _ID, primary_key=True),
    Column("workload_id", _ID, ForeignKey("workloads.workload_id"),
           nullable=False),
    Column("host_locator", String, nullable=True),
    Column("image_ref", String, nullable=True),
    # None means unknown; never the collection time.
    Column("first_observed_at", _TZ, nullable=True),
    Column("revision", Integer, nullable=False),
    Column("created_at", _TZ, nullable=False),
    UniqueConstraint("workload_id", "host_locator",
                     name="uq_incarnations_workload_locator"),
    # Parent pair for the composite occurrence FK.
    UniqueConstraint("incarnation_id", "workload_id",
                     name="uq_incarnations_id_workload"),
    CheckConstraint("revision > 0", name="incarnations_revision_positive"),
)

exposures = Table(
    "exposures",
    uvm_metadata,
    Column("exposure_id", _ID, primary_key=True),
    Column("group_id", _ID, ForeignKey("groups.group_id"), nullable=False),
    Column("workload_id", _ID, ForeignKey("workloads.workload_id"),
           nullable=False),
    # Earliest supported detection; retained on succession, never reset.
    Column("first_observed_at", _TZ, nullable=True),
    Column("revision", Integer, nullable=False),
    Column("created_at", _TZ, nullable=False),
    UniqueConstraint("group_id", "workload_id",
                     name="uq_exposures_group_workload"),
    # Parent pair for the composite occurrence FK.
    UniqueConstraint("exposure_id", "workload_id",
                     name="uq_exposures_id_workload"),
    CheckConstraint("revision > 0", name="exposures_revision_positive"),
)

occurrences = Table(
    "occurrences",
    uvm_metadata,
    Column("occurrence_id", _ID, primary_key=True),
    Column("exposure_id", _ID, nullable=False),
    Column("incarnation_id", _ID, nullable=False),
    Column("workload_id", _ID, nullable=False),
    Column("component_locator", String, nullable=True),
    Column("first_observed_at", _TZ, nullable=True),
    Column("first_ingested_at", _TZ, nullable=False),
    Column("revision", Integer, nullable=False),
    Column("created_at", _TZ, nullable=False),
    ForeignKeyConstraint(
        ["exposure_id", "workload_id"],
        ["exposures.exposure_id", "exposures.workload_id"],
        name="fk_occurrences_exposure_id_workload_id_exposures",
    ),
    ForeignKeyConstraint(
        ["incarnation_id", "workload_id"],
        ["incarnations.incarnation_id", "incarnations.workload_id"],
        name="fk_occurrences_incarnation_id_workload_id_incarnations",
    ),
    UniqueConstraint("exposure_id", "incarnation_id", "component_locator",
                     name="uq_occurrences_exposure_incarnation_component"),
    CheckConstraint("revision > 0", name="occurrences_revision_positive"),
)

group_cve_refs = Table(
    "group_cve_refs",
    uvm_metadata,
    Column("group_id", _ID, ForeignKey("groups.group_id"),
           primary_key=True),
    # External reference string (e.g. "CVE-2024-12345"); not a UVM record.
    Column("cve_ref", String, nullable=False, primary_key=True),
    Index("ix_group_cve_refs_cve_ref", "cve_ref"),
)

source_observations = Table(
    "source_observations",
    uvm_metadata,
    Column("schema_version", Integer, nullable=False),
    Column("observation_id", _ID, primary_key=True),
    Column("revision", Integer, nullable=False),
    Column("source_family", String, nullable=False),
    Column("source_account_id", String, nullable=False),
    Column("run_id", String, nullable=False),
    Column("source_record_ordinal", Integer, nullable=False),
    Column("collection_status", String, nullable=False),
    # Collection time: required, never the scanner observation time.
    Column("collected_at", _TZ, nullable=False),
    Column("raw_evidence_ref", String, nullable=False),
    # DDL claim: length 64 only (hex-ness is a writer-level claim).
    Column("raw_evidence_sha256", String, nullable=False),
    Column("missing_fields", _JSON, nullable=False),
    Column("observed_at", _TZ, nullable=True),
    Column("native_id_scheme", String, nullable=True),
    Column("native_id_authority", String, nullable=True),
    Column("native_id_value", String, nullable=True),
    Column("asset_locator", String, nullable=True),
    Column("component_locator", String, nullable=True),
    Column("source_record_locator", String, nullable=True),
    Column("source_rating", String, nullable=True),
    # Optional JSON. FROZEN DDL NOTE: the product metadata renders this
    # column through a None-as-SQL-NULL TypeDecorator whose DDL is
    # identical to _JSON on both supported dialects (verified by the
    # migration parity tests); the frozen DDL therefore names the plain
    # JSONB/JSON variant here.
    Column("vulnerability_refs", _JSON, nullable=True),
    Column("source_first_seen_at", _TZ, nullable=True),
    Column("report_id", String, nullable=True),
    Column("coverage_scope", String, nullable=True),
    Column("occurrence_id", _ID,
           ForeignKey("occurrences.occurrence_id"), nullable=True),
    Column("retention_order", Integer, nullable=False),
    Column("ingest_outcome", String, nullable=False),
    Index(
        "ix_source_observations_source_position",
        "source_account_id", "run_id", "source_record_ordinal",
    ),
    UniqueConstraint("retention_order",
                     name="uq_source_observations_retention_order"),
    UniqueConstraint("observation_id", "source_account_id", "run_id",
                     "source_record_ordinal",
                     name="uq_source_observations_retained_position"),
    CheckConstraint("schema_version = 1",
                    name="source_observations_schema_version_v1"),
    CheckConstraint("revision > 0",
                    name="source_observations_revision_positive"),
    CheckConstraint(
        "collection_status IN ('success', 'partial', 'failed')",
        name="source_observations_collection_status_known",
    ),
    CheckConstraint(
        "ingest_outcome IN ('created', 'conflict')",
        name="source_observations_ingest_outcome_known",
    ),
    CheckConstraint("retention_order >= 0",
                    name="source_observations_retention_order_nonnegative"),
    CheckConstraint("length(raw_evidence_sha256) = 64",
                    name="source_observations_raw_digest_length"),
)

identity_resolutions = Table(
    "identity_resolutions",
    uvm_metadata,
    Column("schema_version", Integer, nullable=False),
    Column("resolution_id", _ID, primary_key=True),
    Column("revision", Integer, nullable=False),
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
    Column("group_id", _ID, ForeignKey("groups.group_id"), nullable=True),
    Column("workload_id", _ID, ForeignKey("workloads.workload_id"),
           nullable=True),
    Column("incarnation_id", _ID,
           ForeignKey("incarnations.incarnation_id"), nullable=True),
    Column("exposure_id", _ID, ForeignKey("exposures.exposure_id"),
           nullable=True),
    Column("occurrence_id", _ID,
           ForeignKey("occurrences.occurrence_id"), nullable=True),
    Column("candidate_explanations", _JSON, nullable=False),
    Column("reason", String, nullable=True),
    Column("supersedes_resolution_id", _ID,
           ForeignKey("identity_resolutions.resolution_id"), nullable=True),
    ForeignKeyConstraint(
        ["incarnation_id", "workload_id"],
        ["incarnations.incarnation_id", "incarnations.workload_id"],
        name="fk_identity_resolutions_incarnation_id_workload_id_incarnations",
    ),
    ForeignKeyConstraint(
        ["exposure_id", "workload_id"],
        ["exposures.exposure_id", "exposures.workload_id"],
        name="fk_identity_resolutions_exposure_id_workload_id_exposures",
    ),
    Index(
        "ix_identity_resolutions_observation_evaluated",
        "observation_id", "evaluated_at",
    ),
    Index("ix_identity_resolutions_supersedes", "supersedes_resolution_id"),
    CheckConstraint("schema_version = 1",
                    name="identity_resolutions_schema_version_v1"),
    CheckConstraint("revision > 0",
                    name="identity_resolutions_revision_positive"),
    CheckConstraint("rule_version > 0",
                    name="identity_resolutions_rule_version_positive"),
    CheckConstraint(
        "outcome IN ('matched', 'new', 'ambiguous', 'unresolved')",
        name="identity_resolutions_outcome_known",
    ),
    CheckConstraint(
        "((outcome IN ('matched', 'new') AND group_id IS NOT NULL "
        "AND workload_id IS NOT NULL AND incarnation_id IS NOT NULL "
        "AND exposure_id IS NOT NULL AND occurrence_id IS NOT NULL) "
        "OR (outcome = 'ambiguous' AND workload_id IS NULL "
        "AND incarnation_id IS NULL AND exposure_id IS NULL "
        "AND occurrence_id IS NULL) "
        "OR (outcome = 'unresolved' AND group_id IS NULL "
        "AND workload_id IS NULL AND incarnation_id IS NULL "
        "AND exposure_id IS NULL AND occurrence_id IS NULL))",
        name="identity_resolutions_outcome_selection_consistent",
    ),
    *(_json_not_null_checks("matching_inputs",
                            "identity_resolutions_matching_inputs_not_json_null")),
    *(_json_not_null_checks("candidate_workload_ids",
                            "identity_resolutions_candidates_not_json_null")),
    *(_json_not_null_checks("candidate_explanations",
                            "identity_resolutions_explanations_not_json_null")),
    CheckConstraint(
        "supersedes_resolution_id IS NULL "
        "OR supersedes_resolution_id <> resolution_id",
        name="identity_resolutions_no_self_supersession",
    ),
    UniqueConstraint("observation_id", "revision",
                     name="identity_resolutions_observation_revision"),
)

correction_records = Table(
    "correction_records",
    uvm_metadata,
    Column("correction_id", _ID, primary_key=True),
    Column("record_type", String, nullable=False),
    Column("record_id", _ID, nullable=False),
    Column("old_value", String, nullable=True),
    Column("new_value", String, nullable=True),
    Column("actor", String, nullable=False),
    Column("reason", String, nullable=False),
    Column("correlation_id", String, nullable=False),
    Column("affected_record_ids", _JSON, nullable=False),
    Column("created_at", _TZ, nullable=False),
    Column("field_name", String, nullable=False),
    Column("previous_revision", Integer, nullable=False),
    Column("new_revision", Integer, nullable=False),
    Column("assessment_impact", String, nullable=False),
    Column("issue_impact", String, nullable=False),
    Index("ix_correction_records_record_id", "record_id"),
    Index("ix_correction_records_correlation", "correlation_id"),
    CheckConstraint(
        "length(actor) > 0 AND length(reason) > 0 "
        "AND length(correlation_id) > 0",
        name="correction_records_audited_fields_non_empty",
    ),
    *(_json_not_null_checks("affected_record_ids",
                            "correction_records_affected_ids_not_json_null")),
    CheckConstraint(
        "previous_revision >= 0 AND new_revision >= 0 "
        "AND ((previous_revision = 0 AND new_revision = 0) "
        "OR (new_revision > previous_revision))",
        name="correction_records_revision_transition_valid",
    ),
    CheckConstraint(
        "assessment_impact IN ('unverified') "
        "AND issue_impact IN ('unverified')",
        name="correction_records_impact_committed_values",
    ),
)

quarantined_id_reuse = Table(
    "quarantined_id_reuse",
    uvm_metadata,
    Column("attempted_id", _ID, primary_key=True),
    Column("reason", String, nullable=False),
)

quarantined_id_reuse_holders = Table(
    "quarantined_id_reuse_holders",
    uvm_metadata,
    Column("attempted_id", _ID,
           ForeignKey("quarantined_id_reuse.attempted_id"), nullable=False),
    Column("holder_ordinal", Integer, nullable=False),
    Column("source_account_id", String, nullable=False),
    Column("run_id", String, nullable=False),
    Column("source_record_ordinal", Integer, nullable=False),
    Column("retained_id", _ID, nullable=False),
    PrimaryKeyConstraint("attempted_id", "holder_ordinal"),
    UniqueConstraint("attempted_id", "retained_id",
                     name="uq_quarantined_id_reuse_holders_retained"),
    ForeignKeyConstraint(
        ["retained_id", "source_account_id", "run_id",
         "source_record_ordinal"],
        ["source_observations.observation_id",
         "source_observations.source_account_id",
         "source_observations.run_id",
         "source_observations.source_record_ordinal"],
        name="fk_quarantined_id_reuse_holders_retained_position"),
    CheckConstraint("holder_ordinal >= 0",
                    name="quarantined_id_reuse_holders_ordinal_nonnegative"),
    CheckConstraint(
        "holder_ordinal > 0 OR retained_id = attempted_id",
        name="quarantined_id_reuse_holders_first_keeps_attempted_id",
    ),
)

# Closed alias-event vocabulary (FR-ID-02): activate / retire.
_ALIAS_ACTIONS = "action IN ('activate', 'retire')"

group_key_alias_events = Table(
    "group_key_alias_events",
    uvm_metadata,
    Column("alias_event_id", _ID, primary_key=True),
    Column("correction_id", _ID,
           ForeignKey("correction_records.correction_id"), nullable=False),
    Column("action", String, nullable=False),
    Column("source_family", String, nullable=False),
    Column("native_id_scheme", String, nullable=False),
    Column("native_id_authority", String, nullable=False),
    Column("native_id_value", String, nullable=False),
    Column("target_group_id", _ID, ForeignKey("groups.group_id"),
           nullable=False),
    Column("evidence_ref", String, nullable=False),
    Column("occurred_at", _TZ, nullable=False),
    Column("event_sequence", BigInteger, nullable=False),
    CheckConstraint("event_sequence > 0",
                    name="group_key_alias_events_event_sequence_positive"),
    UniqueConstraint("event_sequence",
                     name="group_key_alias_events_event_sequence_unique"),
    Index("ix_group_key_alias_events_native_key",
          "source_family", "native_id_scheme", "native_id_authority",
          "native_id_value"),
    Index("ix_group_key_alias_events_correction_time",
          "correction_id", "occurred_at"),
    CheckConstraint(_ALIAS_ACTIONS,
                    name="group_key_alias_events_action_known"),
    CheckConstraint("length(evidence_ref) > 0",
                    name="group_key_alias_events_evidence_ref_non_empty"),
)

mapping_alias_events = Table(
    "mapping_alias_events",
    uvm_metadata,
    Column("alias_event_id", _ID, primary_key=True),
    Column("correction_id", _ID,
           ForeignKey("correction_records.correction_id"), nullable=False),
    Column("action", String, nullable=False),
    Column("record_type", String, nullable=False),
    Column("field_name", String, nullable=False),
    Column("scope_a", _ID, nullable=True),
    Column("scope_b", _ID, nullable=True),
    Column("old_value", String, nullable=False),
    Column("target_record_id", _ID, nullable=False),
    Column("evidence_ref", String, nullable=False),
    Column("occurred_at", _TZ, nullable=False),
    Column("event_sequence", BigInteger, nullable=False),
    CheckConstraint("event_sequence > 0",
                    name="mapping_alias_events_event_sequence_positive"),
    UniqueConstraint("event_sequence",
                     name="mapping_alias_events_event_sequence_unique"),
    Index("ix_mapping_alias_events_alias_key",
          "record_type", "field_name", "scope_a", "scope_b", "old_value"),
    Index("ix_mapping_alias_events_correction_time",
          "correction_id", "occurred_at"),
    CheckConstraint(_ALIAS_ACTIONS,
                    name="mapping_alias_events_action_known"),
    CheckConstraint("length(evidence_ref) > 0",
                    name="mapping_alias_events_evidence_ref_non_empty"),
    CheckConstraint("scope_b IS NULL OR scope_a IS NOT NULL",
                    name="mapping_alias_events_scope_b_requires_scope_a"),
)

# Dependency order: referenced tables first, so every (composite) FK
# target exists before its dependent. This order is frozen; a new table
# is added by a NEW revision, never by re-ordering this one.
_TABLE_ORDER = (
    groups, workloads, incarnations, exposures, occurrences,
    group_cve_refs, source_observations, identity_resolutions,
    correction_records, quarantined_id_reuse,
    quarantined_id_reuse_holders, group_key_alias_events,
    mapping_alias_events,
)

# revision identifiers, used by Alembic.
revision = "0001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    assert len(_TABLE_ORDER) == 13, (
        f"expected the 13 approved G1 tables, found {len(_TABLE_ORDER)}: "
        f"{[t.name for t in _TABLE_ORDER]}")
    for table in _TABLE_ORDER:
        op.execute(CreateTable(table))
    for table in _TABLE_ORDER:
        for index in table.indexes:
            op.execute(CreateIndex(index))


def downgrade() -> None:
    # Reverse of upgrade: dependent tables and their indexes first.
    for table in reversed(_TABLE_ORDER):
        for index in table.indexes:
            op.execute(DropIndex(index))
        op.execute(DropTable(table))
