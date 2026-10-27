"""Persist settled CE Finding/Endpoint associations for retained occurrences."""

from alembic import context, op
from alembic.util.exc import CommandError
from sqlalchemy import (
    CheckConstraint, Column, DateTime, ForeignKey, Integer, String, Text,
    UniqueConstraint, Uuid, text,
)

revision = "0015"
down_revision = "0014"
branch_labels = None
depends_on = None

_ID = Uuid(as_uuid=False)
_TZ = DateTime(timezone=True)


def _online_dialect():
    if context.is_offline_mode():
        raise CommandError("0015 requires online occurrence-link safety checks")
    dialect = op.get_bind().dialect.name
    if dialect not in ("sqlite", "postgresql"):
        raise CommandError(f"0015 does not support {dialect}")
    return dialect


def upgrade():
    dialect = _online_dialect()
    digest_check = (
        "readback_sha256 ~ '^[0-9a-f]{64}$'" if dialect == "postgresql"
        else "length(readback_sha256) = 64 AND readback_sha256 NOT GLOB '*[^0-9a-f]*'"
    )
    op.create_table(
        "engine_occurrence_links",
        Column("link_id", _ID, primary_key=True),
        Column("operation_id", _ID, ForeignKey("engine_operation_requests.operation_id"), nullable=False),
        Column("manifest_id", _ID, ForeignKey("manifest_ledger_headers.manifest_id"), nullable=False),
        Column("mapping_revision", Integer, nullable=False),
        Column("occurrence_id", _ID, ForeignKey("occurrences.occurrence_id"), nullable=False),
        Column("test_id", Integer, nullable=False),
        Column("finding_id", Integer, nullable=False),
        Column("endpoint_id", Integer, nullable=True),
        Column("component_name", String, nullable=True),
        Column("component_version", String, nullable=True),
        Column("readback_ref", Text, nullable=False),
        Column("readback_sha256", String, nullable=False),
        Column("recorded_at", _TZ, nullable=False),
        UniqueConstraint(
            "operation_id", "mapping_revision", "occurrence_id", "finding_id",
            "endpoint_id", "component_name", "component_version",
            name="uq_engine_occurrence_links_mapping_pair",
        ),
        CheckConstraint("mapping_revision > 0", name="engine_occurrence_links_mapping_revision_positive"),
        CheckConstraint("test_id > 0", name="engine_occurrence_links_test_positive"),
        CheckConstraint("finding_id > 0", name="engine_occurrence_links_finding_positive"),
        CheckConstraint("endpoint_id IS NULL OR endpoint_id > 0", name="engine_occurrence_links_endpoint_positive"),
        CheckConstraint("length(readback_ref) > 0", name="engine_occurrence_links_readback_ref_non_empty"),
        CheckConstraint(digest_check, name="engine_occurrence_links_readback_sha256"),
    )


def downgrade():
    _online_dialect()
    count = op.get_bind().execute(
        text("SELECT count(*) FROM engine_occurrence_links")
    ).scalar_one()
    if count:
        raise CommandError("refusing 0015 downgrade: settled occurrence links exist")
    op.drop_table("engine_occurrence_links")
