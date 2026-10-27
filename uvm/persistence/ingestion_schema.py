"""Durable G2 ingestion accounting metadata (UVM database only)."""

from sqlalchemy import (BigInteger, Boolean, CheckConstraint, Column, DateTime, ForeignKey, Index, Integer,
                        JSON, String, Table, Uuid, UniqueConstraint,
                        ForeignKeyConstraint)

from uvm.persistence.schema import uvm_metadata

# Focused callers may import this module directly; register the pre-existing
# G1 tables before SQLAlchemy sorts the shared metadata graph.
import uvm.persistence.alias_schema  # noqa: F401,E402

_ID = Uuid(as_uuid=False)
_TZ = DateTime(timezone=True)

collection_schedules = Table(
    "collection_schedules", uvm_metadata,
    Column("schedule_id", String, nullable=False),
    Column("revision", Integer, nullable=False),
    Column("source_family", String, nullable=False),
    Column("source_account_id", String, nullable=False),
    Column("scope_key", String, nullable=False),
    Column("enabled", Boolean, nullable=False),
    Column("timezone_name", String, nullable=False),
    Column("cadence", String, nullable=False),
    Column("expected_run_grace_microseconds", BigInteger, nullable=False),
    Column("max_attempts", Integer, nullable=False),
    Column("max_page_attempts", Integer, nullable=False),
    Column("total_deadline_microseconds", BigInteger, nullable=False),
    Column("freshness_rule_ref", String, nullable=False),
    Column("recorded_at", _TZ, nullable=False),
    UniqueConstraint("schedule_id", "revision", name="uq_collection_schedules_revision"),
    CheckConstraint("revision > 0 AND max_attempts > 0 AND max_page_attempts > 0", name="collection_schedules_positive_limits"),
    CheckConstraint("expected_run_grace_microseconds >= 0 AND total_deadline_microseconds > 0", name="collection_schedules_durations_valid"),
)

expected_runs = Table(
    "expected_runs", uvm_metadata,
    Column("expected_run_id", _ID, primary_key=True),
    Column("schedule_id", String, nullable=False),
    Column("schedule_revision", Integer, nullable=False),
    Column("scope_key", String, nullable=False),
    Column("due_at", _TZ, nullable=False),
    Column("grace_deadline", _TZ, nullable=False),
    Column("state", String, nullable=False),
    Column("run_id", _ID, nullable=True),
    ForeignKeyConstraint(["schedule_id", "schedule_revision"], ["collection_schedules.schedule_id", "collection_schedules.revision"], name="fk_expected_runs_schedule"),
    UniqueConstraint("schedule_id", "schedule_revision", "due_at", name="uq_expected_runs_occurrence"),
    CheckConstraint("state IN ('due','started','missed','completed','failed')", name="expected_runs_state_known"),
)

# Append-only transition history for due/claimed/terminal scheduler state.
# `expected_runs` remains the G2 current-state index; reports consume these
# committed events to reconstruct as-of state without rewriting G2 identity.
expected_run_events = Table(
    "expected_run_events", uvm_metadata,
    Column("event_id", _ID, primary_key=True),
    Column("expected_run_id", _ID, ForeignKey("expected_runs.expected_run_id"), nullable=False),
    Column("revision", Integer, nullable=False),
    Column("state", String, nullable=False),
    Column("run_id", _ID),
    Column("run_revision", Integer),
    Column("effective_at", _TZ, nullable=False),
    Column("recorded_at", _TZ, nullable=False),
    UniqueConstraint("expected_run_id", "revision", name="uq_expected_run_event_revision"),
    CheckConstraint("revision > 0 AND state IN ('due','started','missed','completed','failed')",
        name="expected_run_event_state_known"),
    Index("ix_expected_run_event_context", "expected_run_id", "effective_at", "recorded_at"),
)

collection_runs = Table(
    "collection_runs", uvm_metadata,
    Column("run_id", _ID, nullable=False),
    Column("revision", Integer, nullable=False),
    Column("schema_version", Integer, nullable=False),
    Column("expected_run_id", _ID, nullable=True),
    Column("manual_origin", String, nullable=True),
    Column("schedule_id", String, nullable=False),
    Column("schedule_revision", Integer, nullable=False),
    Column("source_family", String, nullable=False),
    Column("source_account_id", String, nullable=False),
    Column("scope_key", String, nullable=False),
    Column("source_report_id", String, nullable=True),
    Column("expected_at", _TZ, nullable=True),
    Column("started_at", _TZ, nullable=True),
    Column("ended_at", _TZ, nullable=True),
    Column("state", String, nullable=False),
    Column("retrieval_status", String, nullable=False),
    Column("retrieval_reasons", JSON, nullable=False),
    Column("coverage_status", String, nullable=False),
    Column("coverage_reasons", JSON, nullable=False),
    Column("freshness_status", String, nullable=False),
    Column("freshness_reasons", JSON, nullable=False),
    # Immutable replay material.  Quality labels are only a projection of
    # these facts; callers cannot later replace the inputs behind a label.
    Column("facts_snapshot", JSON, nullable=False),
    Column("provenance_snapshot", JSON, nullable=False),
    Column("created_at", _TZ, nullable=False),
    UniqueConstraint("run_id", "revision", name="uq_collection_runs_revision"),
    ForeignKeyConstraint(["expected_run_id"], ["expected_runs.expected_run_id"], name="fk_collection_runs_expected"),
    CheckConstraint("schema_version = 1 AND revision > 0", name="collection_runs_version_positive"),
    CheckConstraint("state IN ('expected','running','completed','partial','failed','missed')", name="collection_runs_state_known"),
)

run_attempts = Table(
    "run_attempts", uvm_metadata,
    Column("run_id", _ID, nullable=False), Column("run_revision", Integer, nullable=False),
    Column("attempt_no", Integer, nullable=False), Column("started_at", _TZ, nullable=False),
    Column("finished_at", _TZ, nullable=True), Column("response_class", String, nullable=False),
    Column("success", Boolean, nullable=False), Column("retry_after_microseconds", BigInteger, nullable=True),
    Column("error_code", String, nullable=True),
    ForeignKeyConstraint(["run_id", "run_revision"], ["collection_runs.run_id", "collection_runs.revision"], name="fk_run_attempts_run"),
    UniqueConstraint("run_id", "run_revision", "attempt_no", name="uq_run_attempts_position"),
    CheckConstraint("attempt_no > 0 AND (retry_after_microseconds IS NULL OR retry_after_microseconds >= 0)", name="run_attempts_values_valid"),
)

run_pages = Table(
    "run_pages", uvm_metadata,
    Column("run_id", _ID, nullable=False), Column("run_revision", Integer, nullable=False),
    Column("ordinal", Integer, nullable=False), Column("cursor", String, nullable=True),
    Column("page_ref", String, nullable=False), Column("attempt_no", Integer, nullable=False),
    Column("response_class", String, nullable=False), Column("record_count", Integer, nullable=False),
    Column("evidence_digest", String, nullable=False), Column("next_cursor", String, nullable=True),
    Column("is_terminal", Boolean, nullable=False), Column("failed", Boolean, nullable=False),
    Column("request_identity", String, nullable=False), Column("report_id", String, nullable=True),
    Column("query_scope", String, nullable=True),
    Column("evidence_ref", String, nullable=False),
    ForeignKeyConstraint(["run_id", "run_revision"], ["collection_runs.run_id", "collection_runs.revision"], name="fk_run_pages_run"),
    UniqueConstraint("run_id", "run_revision", "ordinal", name="uq_run_pages_position"),
    CheckConstraint("ordinal > 0 AND attempt_no > 0 AND record_count >= 0", name="run_pages_values_valid"),
)

ingestion_evidence = Table(
    "ingestion_evidence", uvm_metadata,
    Column("evidence_id", _ID, primary_key=True), Column("schema_version", Integer, nullable=False),
    Column("run_id", _ID, nullable=False), Column("run_revision", Integer, nullable=False),
    Column("evidence_ref", String, nullable=False), Column("sha256", String, nullable=False),
    Column("kind", String, nullable=False), Column("registered_at", _TZ, nullable=False),
    ForeignKeyConstraint(["run_id", "run_revision"], ["collection_runs.run_id", "collection_runs.revision"], name="fk_ingestion_evidence_run"),
    UniqueConstraint("run_id", "run_revision", "evidence_ref", "sha256", name="uq_ingestion_evidence_exact"),
    CheckConstraint("schema_version = 1 AND length(sha256) = 64", name="ingestion_evidence_shape"),
)

import_context_revisions = Table(
    "import_context_revisions", uvm_metadata,
    Column("context_key", String, nullable=False), Column("revision", Integer, nullable=False),
    Column("source_family", String, nullable=False), Column("source_account_id", String, nullable=False),
    Column("scope_key", String, nullable=False), Column("parser_config_version", String, nullable=False),
    Column("product_ref", String, nullable=False), Column("engagement_ref", String, nullable=False),
    Column("test_id", Integer, nullable=True), Column("mapping_history", JSON, nullable=False),
    # Exact references into the G1 CE registration/verification/binding
    # records.  These are references, never a second Test authority.
    Column("g1_registration_id", _ID, nullable=True),
    Column("g1_verification_id", _ID, nullable=True),
    Column("g1_test_binding_id", _ID, nullable=True),
    Column("deployment_key", String, nullable=True),
    Column("deployment_config_revision", Integer, nullable=True),
    Column("registered_at", _TZ, nullable=False),
    UniqueConstraint("context_key", "revision", name="uq_import_context_revisions_revision"),
    UniqueConstraint("source_family", "source_account_id", "scope_key", "revision", name="uq_import_context_revisions_scope"),
    CheckConstraint("revision > 0 AND (test_id IS NULL OR test_id > 0)", name="import_context_revisions_values_valid"),
)

ALL_INGESTION_TABLES = (collection_schedules, expected_runs, collection_runs,
                        run_attempts, run_pages, ingestion_evidence,
                        import_context_revisions)
