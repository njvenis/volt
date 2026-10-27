"""0005 durable CE operation reservations (G1, CR-01/04/10).

The migration is deliberately self-contained and creates no DefectDojo
tables.  It is online-only: a later writer must quiesce reservations while
applying state transitions.  Downgrade refuses if any ledger row exists.
"""

from alembic import context, op
from alembic.util.exc import CommandError
from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Integer, JSON, String, Uuid, text

revision = "0005"
down_revision = "0004"
branch_labels = None
depends_on = None

_ID = Uuid(as_uuid=False)
_TZ = DateTime(timezone=True)


def _dialect() -> str:
    name = op.get_bind().dialect.name
    if name not in ("sqlite", "postgresql"):
        raise CommandError(f"0005 does not support {name}")
    return name


def _table(name, *columns, **constraints):
    op.create_table(name, *columns, **constraints)


def upgrade() -> None:
    if context.is_offline_mode():
        raise CommandError("0005 upgrade requires online reservation quiescence")
    _dialect()
    _table(
        "engine_operation_requests",
        Column("operation_id", _ID, primary_key=True),
        Column("schema_version", Integer, nullable=False),
        Column("context_key", String, nullable=False),
        Column("source_run_id", String, nullable=False),
        Column("scan_type", String, nullable=False),
        Column("payload_sha256", String, nullable=False),
        Column("parser_config_version", String, nullable=False),
        Column("engine_release", String, nullable=False),
        Column("request_kind", String, nullable=False),
        Column("requested_at", _TZ, nullable=False),
        Column("close_old_findings", Boolean, nullable=False),
        Column("test_id", String),
        sa_check("schema_version > 0", "engine_operation_requests_schema_version_positive"),
        sa_check("request_kind IN ('import', 'reimport')", "engine_operation_requests_request_kind_known"),
        sa_check("close_old_findings = false", "engine_operation_requests_close_old_findings_false"),
        sa_check("request_kind <> 'reimport' OR (test_id IS NOT NULL AND length(test_id) > 0)", "engine_operation_requests_reimport_test_required"),
    )
    _table(
        "engine_operation_manifests",
        Column("operation_id", _ID, ForeignKey("engine_operation_requests.operation_id"), primary_key=True),
        Column("manifest_sha256", String, nullable=False, unique=True),
        Column("manifest_ref", String, nullable=False),
        Column("bound_at", _TZ, nullable=False),
        sa_check("length(manifest_sha256) > 0", "engine_operation_manifests_digest_non_empty"),
        sa_check("length(manifest_ref) > 0", "engine_operation_manifests_ref_non_empty"),
    )
    _table(
        "engine_operation_states",
        Column("operation_id", _ID, ForeignKey("engine_operation_requests.operation_id"), primary_key=True),
        Column("context_key", String, nullable=False), Column("test_id", String),
        Column("bound_test_id", String), Column("revision", Integer, nullable=False),
        Column("status", String, nullable=False), Column("response_deduplication_complete", Boolean),
        Column("response_ref", String), Column("response_test_id", String),
        Column("deduplication_complete", Boolean), Column("deduplication_evidence_ref", String),
        Column("settle_readback_ref", String), Column("reconciliation_evidence_ref", String),
        Column("first_import_baseline_ref", String), Column("finding_ids", JSON, nullable=False),
        Column("endpoint_ids", JSON, nullable=False), Column("mapping_revision", Integer),
        Column("prior_mapping_revision", Integer), Column("error_code", String),
        Column("error_detail_ref", String),
        Column("supersedes_operation_id", _ID, ForeignKey("engine_operation_requests.operation_id")),
        Column("post_issued", Boolean, nullable=False), Column("reconciled", Boolean, nullable=False),
        Column("changed_at", _TZ, nullable=False),
        sa_check("revision > 0", "engine_operation_states_revision_positive"),
        sa_check("status IN ('pending', 'settled', 'failed', 'quarantined', 'conflict')", "engine_operation_states_status_known"),
        sa_check("mapping_revision IS NULL OR mapping_revision > 0", "engine_operation_states_mapping_revision_positive"),
        sa_check("prior_mapping_revision IS NULL OR prior_mapping_revision > 0", "engine_operation_states_prior_mapping_revision_positive"),
        sa_check("test_id IS NULL OR length(test_id) > 0", "engine_operation_states_test_non_empty"),
        sa_check("bound_test_id IS NULL OR length(bound_test_id) > 0", "engine_operation_states_bound_test_non_empty"),
    )
    _table(
        "engine_operation_transitions",
        Column("transition_id", _ID, primary_key=True),
        Column("operation_id", _ID, ForeignKey("engine_operation_requests.operation_id"), nullable=False),
        Column("from_revision", Integer), Column("to_revision", Integer, nullable=False),
        Column("from_status", String), Column("to_status", String, nullable=False),
        Column("evidence_ref", String, nullable=False), Column("occurred_at", _TZ, nullable=False),
        Column("transition_reason", String, nullable=False),
        sa_check("from_revision IS NULL OR from_revision > 0", "engine_operation_transitions_from_revision_positive"),
        sa_check("to_revision > 0", "engine_operation_transitions_to_revision_positive"),
        sa_check("from_status IS NULL OR from_status IN ('pending', 'settled', 'failed', 'quarantined', 'conflict')", "engine_operation_transitions_from_status_known"),
        sa_check("to_status IN ('pending', 'settled', 'failed', 'quarantined', 'conflict')", "engine_operation_transitions_to_status_known"),
        sa_check("from_revision IS NULL OR to_revision > from_revision", "engine_operation_transitions_revision_increases"),
        sa_check("length(evidence_ref) > 0", "engine_operation_transitions_evidence_non_empty"),
        sa_check("length(transition_reason) > 0", "engine_operation_transitions_reason_non_empty"),
    )
    op.create_index("ix_engine_operation_states_context", "engine_operation_states", ["context_key"])
    op.create_index("ix_engine_operation_states_test", "engine_operation_states", ["test_id"])
    op.create_index("ix_engine_operation_states_bound_test", "engine_operation_states", ["bound_test_id"])
    op.create_index("uq_engine_operation_states_active_context", "engine_operation_states", ["context_key"], unique=True,
                    sqlite_where=text("status IN ('pending', 'quarantined', 'conflict')"),
                    postgresql_where=text("status IN ('pending', 'quarantined', 'conflict')"))
    op.create_index("uq_engine_operation_states_active_test", "engine_operation_states", ["test_id"], unique=True,
                    sqlite_where=text("status IN ('pending', 'quarantined', 'conflict') AND test_id IS NOT NULL"),
                    postgresql_where=text("status IN ('pending', 'quarantined', 'conflict') AND test_id IS NOT NULL"))
    op.create_index("uq_engine_operation_transitions_operation_revision", "engine_operation_transitions", ["operation_id", "to_revision"], unique=True)


def sa_check(sql: str, name: str):
    from sqlalchemy import CheckConstraint
    return CheckConstraint(sql, name=name)


def _downgrade_guard() -> None:
    counts = [op.get_bind().execute(text(f"SELECT count(*) FROM {name}")).scalar_one()
              for name in ("engine_operation_requests", "engine_operation_manifests",
                           "engine_operation_states", "engine_operation_transitions")]
    if any(counts):
        raise CommandError("refusing 0005 downgrade: operation reservation ledger rows exist")


def downgrade() -> None:
    if context.is_offline_mode():
        raise CommandError("0005 downgrade requires online ledger safety checks")
    _dialect()
    _downgrade_guard()
    for name in ("engine_operation_transitions", "engine_operation_states",
                 "engine_operation_manifests", "engine_operation_requests"):
        op.drop_table(name)
