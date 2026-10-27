"""Bind reporting refresh intents to their committing audit event."""
from alembic import op
import sqlalchemy as sa

revision = "0027"
down_revision = "0026"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("reporting_projection_intents", sa.Column("audit_event_id", sa.Uuid(as_uuid=False), nullable=True))
    op.execute(sa.text("""
        UPDATE reporting_projection_intents AS i
        SET audit_event_id = r.audit_event_id
        FROM assessment_command_receipts AS r
        WHERE i.intent_id = r.intent_id AND i.audit_event_id IS NULL
    """))


def downgrade():
    bind = op.get_bind()
    if bind.execute(sa.text("""
        SELECT count(*) FROM reporting_projection_intents
        WHERE kind = 'reporting.sla.refresh' AND status = 'complete'
    """)).scalar_one():
        from alembic.util.exc import CommandError
        raise CommandError("refusing 0027 downgrade: completed SLA refresh intents require their audit binding")
    op.drop_column("reporting_projection_intents", "audit_event_id")
