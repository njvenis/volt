"""Retain verified effects of native administration reconciliation."""
from alembic import op
import sqlalchemy as sa

revision = "0046"
down_revision = "0045"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("administration_reconciliation_intents",
        sa.Column("result", sa.JSON(), nullable=True))


def downgrade():
    op.drop_column("administration_reconciliation_intents", "result")
