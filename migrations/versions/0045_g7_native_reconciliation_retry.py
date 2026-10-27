"""Retry and completion metadata for native administration reconciliation."""
from alembic import op
import sqlalchemy as sa

revision = "0045"
down_revision = "0044"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("administration_reconciliation_intents",
        sa.Column("next_attempt_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("administration_reconciliation_intents",
        sa.Column("claimed_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("administration_reconciliation_intents",
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True))


def downgrade():
    op.drop_column("administration_reconciliation_intents", "completed_at")
    op.drop_column("administration_reconciliation_intents", "claimed_at")
    op.drop_column("administration_reconciliation_intents", "next_attempt_at")
