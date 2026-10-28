"""Bind current backup evidence to projection-admitted immutable records."""
from alembic import op
import sqlalchemy as sa

revision = "0059"
down_revision = "0058"
branch_labels = None
depends_on = None


def upgrade():
    # Legacy history cannot identify which statuses advanced a projection.
    # Preserve state/history and leave provenance unknown until admission.
    op.create_table("g7_backup_projection_evidence",
        sa.Column("deployment_id", sa.String(256), primary_key=True),
        sa.Column("application_evidence_record_id", sa.String(36)),
        sa.Column("effective_evidence_record_id", sa.String(36)))


def downgrade():
    op.drop_table("g7_backup_projection_evidence")
