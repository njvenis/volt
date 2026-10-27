"""Persist native access and ownership reconciliation intents atomically."""
from alembic import op
import sqlalchemy as sa

revision = "0044"
down_revision = "0043"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "administration_reconciliation_intents",
        sa.Column("intent_id", sa.Uuid(as_uuid=False), nullable=False),
        sa.Column("audit_event_id", sa.Uuid(as_uuid=False), nullable=False),
        sa.Column("kind", sa.String(), nullable=False),
        sa.Column("target_id", sa.Uuid(as_uuid=False), nullable=False),
        sa.Column("authority_revision", sa.Integer(), nullable=False),
        sa.Column("status", sa.String(), nullable=False),
        sa.Column("attempts", sa.Integer(), nullable=False),
        sa.Column("last_error", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["audit_event_id"], ["assessment_audit_events.event_id"]),
        sa.PrimaryKeyConstraint("intent_id"),
        sa.UniqueConstraint("audit_event_id", "kind", name="uq_admin_reconcile_event_kind"),
        sa.CheckConstraint("kind IN ('administration.authority.reconcile','administration.ownership.reconcile')",
            name="ck_admin_reconcile_kind"),
        sa.CheckConstraint("status IN ('pending','running','complete','failed')",
            name="ck_admin_reconcile_status"),
        sa.CheckConstraint("attempts >= 0", name="ck_admin_reconcile_attempts"),
    )
    op.create_index("ix_admin_reconcile_status",
        "administration_reconciliation_intents", ["status", "created_at"])


def downgrade():
    op.drop_index("ix_admin_reconcile_status", table_name="administration_reconciliation_intents")
    op.drop_table("administration_reconciliation_intents")
