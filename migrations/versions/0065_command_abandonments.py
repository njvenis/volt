"""Persist actor and payload-bound definitive noncommit dispositions."""
from alembic import op
import sqlalchemy as sa

revision = "0065"
down_revision = "0064"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table("assessment_command_abandonments",
        sa.Column("command_id", sa.Uuid(as_uuid=False), primary_key=True),
        sa.Column("principal_id", sa.String(), nullable=False),
        sa.Column("action", sa.String(), nullable=False),
        sa.Column("request_digest", sa.String(64), nullable=False),
        sa.Column("audit_event_id", sa.Uuid(as_uuid=False),
            sa.ForeignKey("assessment_audit_events.event_id"), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False))


def downgrade():
    bind = op.get_bind()
    if bind.execute(sa.text("SELECT count(*) FROM assessment_command_abandonments")).scalar_one():
        raise RuntimeError("refusing 0065 downgrade: command dispositions are retained")
    op.drop_table("assessment_command_abandonments")
