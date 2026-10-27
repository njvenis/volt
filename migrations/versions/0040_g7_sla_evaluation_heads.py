"""Separate G7 ingestion-based evaluation lineage from historical G5 heads."""
from alembic import op
import sqlalchemy as sa

revision = "0040"
down_revision = "0039"
branch_labels = None
depends_on = None


def upgrade():
    uuid = sa.Uuid(as_uuid=False)
    timestamp = sa.DateTime(timezone=True)
    json_value = sa.JSON().with_variant(sa.dialects.postgresql.JSONB(), "postgresql")
    op.create_table("g7_sla_evaluations",
        sa.Column("evaluation_id", uuid, primary_key=True),
        sa.Column("episode_id", uuid, nullable=False),
        sa.Column("occurrence_id", uuid, nullable=False),
        sa.Column("revision", sa.Integer(), nullable=False),
        sa.Column("policy_id", sa.String()), sa.Column("policy_version", sa.Integer()),
        sa.Column("reference_binding_id", uuid), sa.Column("started_at", timestamp),
        sa.Column("original_deadline_at", timestamp), sa.Column("current_deadline_at", timestamp),
        sa.Column("deadline_basis", sa.String(), nullable=False),
        sa.Column("gap_reasons", json_value, nullable=False),
        sa.Column("predecessor_evaluation_id", uuid), sa.Column("head_decision_id", uuid),
        sa.Column("is_authoritative", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("derivation_kind", sa.String(), nullable=False, server_default="writer"),
        sa.Column("clock_reset_event_id", uuid),
        sa.Column("clock_reset_absorbed", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("effective_at", timestamp, nullable=False),
        sa.Column("known_at", timestamp, nullable=False),
        sa.UniqueConstraint("episode_id", "occurrence_id", "revision", name="uq_g7_sla_evaluation_revision"))
    op.create_index("ix_g7_sla_evaluation_atom_head", "g7_sla_evaluations",
        ["episode_id", "occurrence_id", "revision"])


def downgrade():
    bind = op.get_bind()
    if bind.execute(sa.text("SELECT count(*) FROM g7_sla_evaluations")).scalar_one():
        from alembic.util.exc import CommandError
        raise CommandError("refusing 0040 downgrade: retained G7 evaluation history requires forward repair")
    op.drop_index("ix_g7_sla_evaluation_atom_head", table_name="g7_sla_evaluations")
    op.drop_table("g7_sla_evaluations")
