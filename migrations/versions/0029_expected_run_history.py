"""Retain append-only expected-run scheduler transitions."""
from alembic import op
import sqlalchemy as sa

revision = "0029"
down_revision = "0028"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "expected_run_events",
        sa.Column("event_id", sa.Uuid(as_uuid=False), nullable=False),
        sa.Column("expected_run_id", sa.Uuid(as_uuid=False), nullable=False),
        sa.Column("revision", sa.Integer(), nullable=False),
        sa.Column("state", sa.String(), nullable=False),
        sa.Column("run_id", sa.Uuid(as_uuid=False), nullable=True),
        sa.Column("run_revision", sa.Integer(), nullable=True),
        sa.Column("effective_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("recorded_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("revision > 0 AND state IN ('due','started','missed','completed','failed')",
            name="expected_run_event_state_known"),
        sa.ForeignKeyConstraint(["expected_run_id"], ["expected_runs.expected_run_id"],
            name="fk_expected_run_event_expected_run"),
        sa.PrimaryKeyConstraint("event_id"),
        sa.UniqueConstraint("expected_run_id", "revision", name="uq_expected_run_event_revision"),
    )
    op.create_index("ix_expected_run_event_context", "expected_run_events",
        ["expected_run_id", "effective_at", "recorded_at"])


def downgrade():
    bind = op.get_bind()
    count = bind.execute(sa.text("SELECT count(*) FROM expected_run_events")).scalar_one()
    if count:
        from alembic.util.exc import CommandError
        raise CommandError("refusing 0029 downgrade: expected-run transition history is retained evidence")
    op.drop_index("ix_expected_run_event_context", table_name="expected_run_events")
    op.drop_table("expected_run_events")
