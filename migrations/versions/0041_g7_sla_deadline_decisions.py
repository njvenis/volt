"""Keep authorised G7 deadline revisions in the G7 evaluation lineage."""
from alembic import op
import sqlalchemy as sa

revision = "0041"
down_revision = "0040"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table("g7_sla_deadline_decisions",
        sa.Column("decision_id", sa.Uuid(as_uuid=False), primary_key=True),
        sa.Column("episode_id", sa.Uuid(as_uuid=False), nullable=False),
        sa.Column("occurrence_id", sa.Uuid(as_uuid=False), nullable=False),
        sa.Column("evaluation_id", sa.Uuid(as_uuid=False),
            sa.ForeignKey("g7_sla_evaluations.evaluation_id"), nullable=False),
        sa.Column("predecessor_decision_id", sa.Uuid(as_uuid=False)),
        sa.Column("original_deadline_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revised_deadline_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("actor_id", sa.String(), nullable=False),
        sa.Column("rationale", sa.Text(), nullable=False),
        sa.Column("evidence_ref", sa.Text(), nullable=False),
        sa.Column("audit_event_id", sa.Uuid(as_uuid=False), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False))


def downgrade():
    bind = op.get_bind()
    if bind.execute(sa.text("SELECT count(*) FROM g7_sla_deadline_decisions")).scalar_one():
        from alembic.util.exc import CommandError
        raise CommandError("refusing 0041 downgrade: retained G7 deadline decisions require forward repair")
    op.drop_table("g7_sla_deadline_decisions")
