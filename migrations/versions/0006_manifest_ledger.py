"""0006 strict V1 manifest inventory and payload-membership ledger.

Additive storage only.  The migration never reads 0005 digest/reference
rows as manifest bodies and does not alter any earlier table.  Exhaustive
inventory capture, append-only immutability and payload-link verification
remain guarded writer/read-back responsibilities; this DDL stores their
inputs and conservative shape constraints.
"""

from alembic import context, op
from alembic.util.exc import CommandError
from sqlalchemy import (
    BigInteger, CheckConstraint, Column, DateTime, ForeignKey,
    ForeignKeyConstraint, Integer, PrimaryKeyConstraint, String, UniqueConstraint,
    Uuid, text,
)

revision = "0006"
down_revision = "0005"
branch_labels = None
depends_on = None

_ID = Uuid(as_uuid=False)
_TZ = DateTime(timezone=True)


def _dialect() -> str:
    name = op.get_bind().dialect.name
    if name not in ("sqlite", "postgresql"):
        raise CommandError(f"0006 does not support {name}")
    return name


def sa_check(sql: str, name: str):
    return CheckConstraint(sql, name=name)


def upgrade() -> None:
    if context.is_offline_mode():
        raise CommandError("0006 upgrade requires online manifest-ledger preflight")
    _dialect()
    op.create_table(
        "manifest_ledger_headers",
        Column("manifest_id", _ID, primary_key=True),
        Column("operation_id", _ID, ForeignKey("engine_operation_requests.operation_id"), nullable=False, unique=True),
        Column("schema_version", Integer, nullable=False),
        Column("source_family", String, nullable=False),
        Column("source_account_id", String, nullable=False),
        Column("run_id", String, nullable=False),
        Column("context_key", String, nullable=False),
        Column("bound_test_id", String),
        Column("inventory_seal_ref", String, nullable=False),
        Column("inventory_high_watermark", BigInteger, nullable=False),
        Column("retained_row_count", BigInteger, nullable=False),
        Column("conflict_holder_count", BigInteger, nullable=False),
        Column("payload_sha256", String, nullable=False),
        Column("manifest_sha256", String, nullable=False, unique=True),
        Column("sealed_at", _TZ, nullable=False),
        sa_check("schema_version = 1", "manifest_ledger_headers_schema_version_v1"),
        sa_check("inventory_high_watermark >= 0", "manifest_ledger_headers_high_watermark_nonnegative"),
        sa_check("retained_row_count >= 0", "manifest_ledger_headers_retained_row_count_nonnegative"),
        sa_check("conflict_holder_count >= 0", "manifest_ledger_headers_conflict_holder_count_nonnegative"),
        sa_check("conflict_holder_count <= retained_row_count", "manifest_ledger_headers_conflict_holder_count_bounded"),
        sa_check("length(payload_sha256) = 64", "manifest_ledger_headers_payload_digest_length"),
        sa_check("length(manifest_sha256) = 64", "manifest_ledger_headers_manifest_digest_length"),
        sa_check("length(inventory_seal_ref) > 0", "manifest_ledger_headers_seal_ref_non_empty"),
        sa_check("bound_test_id IS NULL OR length(bound_test_id) > 0", "manifest_ledger_headers_test_non_empty"),
    )
    op.create_table(
        "manifest_ledger_rows",
        Column("manifest_row_id", _ID, primary_key=True),
        Column("manifest_id", _ID, ForeignKey("manifest_ledger_headers.manifest_id"), nullable=False),
        Column("observation_id", _ID, nullable=False),
        Column("source_account_id", String, nullable=False),
        Column("run_id", String, nullable=False),
        Column("source_record_ordinal", Integer, nullable=False),
        Column("disposition_ordinal", Integer, nullable=False),
        Column("retained_evidence_sha256", String, nullable=False),
        Column("disposition", String, nullable=False),
        Column("resolution_id", _ID, ForeignKey("identity_resolutions.resolution_id")),
        Column("resolution_revision", Integer),
        Column("occurrence_id", _ID, ForeignKey("occurrences.occurrence_id")),
        Column("exclusion_rule_id", String),
        Column("exclusion_rule_version", Integer),
        Column("exclusion_evidence_ref", String),
        Column("exclusion_reason", String),
        Column("excluded_by_actor_id", String),
        Column("blocked_reason", String),
        ForeignKeyConstraint(
            ["observation_id", "source_account_id", "run_id", "source_record_ordinal"],
            ["source_observations.observation_id", "source_observations.source_account_id", "source_observations.run_id", "source_observations.source_record_ordinal"],
            name="fk_manifest_ledger_rows_retained_observation_position",
        ),
        UniqueConstraint("manifest_id", "observation_id", name="uq_manifest_ledger_rows_observation"),
        UniqueConstraint("manifest_id", "manifest_row_id", name="uq_manifest_ledger_rows_manifest_row"),
        UniqueConstraint("manifest_id", "disposition_ordinal", name="uq_manifest_ledger_rows_disposition_ordinal"),
        sa_check("source_record_ordinal >= 0", "manifest_ledger_rows_ordinal_nonnegative"),
        sa_check("disposition_ordinal >= 0", "manifest_ledger_rows_disposition_ordinal_nonnegative"),
        sa_check("length(retained_evidence_sha256) = 64", "manifest_ledger_rows_evidence_digest_length"),
        sa_check("disposition IN ('included', 'excluded_reviewed', 'blocked')", "manifest_ledger_rows_disposition_known"),
        sa_check("resolution_revision IS NULL OR resolution_revision > 0", "manifest_ledger_rows_resolution_revision_positive"),
        sa_check("exclusion_rule_version IS NULL OR exclusion_rule_version > 0", "manifest_ledger_rows_exclusion_rule_version_positive"),
        sa_check("disposition <> 'included' OR (resolution_id IS NOT NULL AND resolution_revision IS NOT NULL AND occurrence_id IS NOT NULL)", "manifest_ledger_rows_included_resolution_required"),
        sa_check("disposition <> 'excluded_reviewed' OR (exclusion_rule_id IS NOT NULL AND exclusion_rule_version IS NOT NULL AND exclusion_evidence_ref IS NOT NULL AND exclusion_reason IS NOT NULL AND excluded_by_actor_id IS NOT NULL)", "manifest_ledger_rows_reviewed_exclusion_required"),
        sa_check("disposition <> 'blocked' OR (blocked_reason IS NOT NULL AND length(blocked_reason) > 0)", "manifest_ledger_rows_blocked_reason_required"),
    )
    op.create_table(
        "manifest_payload_records",
        Column("payload_record_id", String, nullable=False),
        Column("manifest_id", _ID, ForeignKey("manifest_ledger_headers.manifest_id"), nullable=False),
        Column("payload_ordinal", Integer, nullable=False),
        Column("transformation_version", Integer, nullable=False),
        PrimaryKeyConstraint("manifest_id", "payload_record_id"),
        UniqueConstraint("manifest_id", "payload_ordinal", name="uq_manifest_payload_records_ordinal"),
        sa_check("payload_ordinal >= 0", "manifest_payload_records_ordinal_nonnegative"),
        sa_check("length(payload_record_id) > 0", "manifest_payload_records_id_non_empty"),
        sa_check("transformation_version > 0", "manifest_payload_records_transformation_positive"),
    )
    op.create_table(
        "manifest_payload_memberships",
        Column("manifest_id", _ID, nullable=False),
        Column("payload_record_id", String, nullable=False),
        Column("manifest_row_id", _ID, nullable=False),
        Column("membership_ordinal", Integer, nullable=False),
        ForeignKeyConstraint(
            ["manifest_id", "payload_record_id"],
            ["manifest_payload_records.manifest_id", "manifest_payload_records.payload_record_id"],
            name="fk_manifest_payload_memberships_payload_manifest",
        ),
        ForeignKeyConstraint(
            ["manifest_id", "manifest_row_id"],
            ["manifest_ledger_rows.manifest_id", "manifest_ledger_rows.manifest_row_id"],
            name="fk_manifest_payload_memberships_row_manifest",
        ),
        PrimaryKeyConstraint("manifest_id", "payload_record_id", "manifest_row_id"),
        UniqueConstraint("manifest_id", "payload_record_id", "membership_ordinal", name="uq_manifest_payload_memberships_ordinal"),
        sa_check("membership_ordinal >= 0", "manifest_payload_memberships_ordinal_nonnegative"),
    )
    op.create_index("ix_manifest_ledger_rows_manifest", "manifest_ledger_rows", ["manifest_id"])
    op.create_index("ix_manifest_payload_records_manifest", "manifest_payload_records", ["manifest_id"])


def _downgrade_guard() -> None:
    names = ("manifest_payload_memberships", "manifest_payload_records", "manifest_ledger_rows", "manifest_ledger_headers")
    counts = [op.get_bind().execute(text(f"SELECT count(*) FROM {name}")).scalar_one() for name in names]
    if any(counts):
        raise CommandError("refusing 0006 downgrade: manifest ledger data exists")


def downgrade() -> None:
    if context.is_offline_mode():
        raise CommandError("0006 downgrade requires online manifest-ledger safety checks")
    _dialect()
    _downgrade_guard()
    op.drop_index("ix_manifest_payload_records_manifest", table_name="manifest_payload_records")
    op.drop_index("ix_manifest_ledger_rows_manifest", table_name="manifest_ledger_rows")
    for name in ("manifest_payload_memberships", "manifest_payload_records", "manifest_ledger_rows", "manifest_ledger_headers"):
        op.drop_table(name)
