"""Additive cross-exposure occurrence-parent transition proof (G2 2.4b)."""

from alembic import context, op
from alembic.util.exc import CommandError
from sqlalchemy import CheckConstraint, Column, ForeignKey, Integer, Uuid, UniqueConstraint, text

revision = "0010"
down_revision = "0009"
branch_labels = None
depends_on = None
_ID = Uuid(as_uuid=False)


def _dialect():
    name = op.get_bind().dialect.name
    if name not in ("sqlite", "postgresql"):
        raise CommandError(f"0010 does not support {name}")


def upgrade():
    if context.is_offline_mode():
        raise CommandError("0010 upgrade requires an online additive migration")
    _dialect()
    op.create_table(
        "occurrence_parent_transition_markers",
        Column("correction_id", _ID, ForeignKey("correction_records.correction_id"), primary_key=True),
        Column("schema_version", Integer, nullable=False),
        CheckConstraint("schema_version = 1", name="parent_transition_marker_schema_version_v1"),
    )
    op.create_table(
        "occurrence_parent_transition_anchors",
        Column("correction_id", _ID, ForeignKey("correction_records.correction_id"), primary_key=True),
        Column("occurrence_id", _ID, ForeignKey("occurrences.occurrence_id"), nullable=False),
        Column("from_exposure_id", _ID, ForeignKey("exposures.exposure_id"), nullable=False),
        Column("to_exposure_id", _ID, ForeignKey("exposures.exposure_id"), nullable=False),
        Column("previous_revision", Integer, nullable=False),
        Column("new_revision", Integer, nullable=False),
        Column("from_exposure_revision", Integer, nullable=False),
        Column("to_exposure_revision", Integer, nullable=False),
        UniqueConstraint("occurrence_id", "new_revision", name="uq_parent_transition_anchor_occurrence_revision"),
        CheckConstraint("from_exposure_id <> to_exposure_id", name="parent_transition_anchor_distinct_parents"),
        CheckConstraint("previous_revision > 0 AND new_revision = previous_revision + 1 AND from_exposure_revision > 0 AND to_exposure_revision > 0", name="parent_transition_anchor_revisions_valid"),
    )


def downgrade():
    if context.is_offline_mode():
        raise CommandError("0010 downgrade requires online anchor safety checks")
    _dialect()
    if op.get_bind().execute(text("SELECT count(*) FROM occurrence_parent_transition_anchors")).scalar_one():
        raise CommandError("refusing 0010 downgrade: parent transition anchors exist")
    op.drop_table("occurrence_parent_transition_anchors")
    op.drop_table("occurrence_parent_transition_markers")
