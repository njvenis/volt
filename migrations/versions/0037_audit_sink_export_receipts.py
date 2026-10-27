"""Keep export receipts independently for each audit sink.

Revision ID: 0037
Revises: 0036
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "0037"
down_revision = "0036"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "assessment_sink_export_receipts",
        sa.Column("event_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("sink_id", sa.String(), nullable=False),
        sa.Column("sink_receipt", sa.String(), nullable=False),
        sa.Column("acknowledged_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["event_id"], ["assessment_audit_events.event_id"]),
        sa.PrimaryKeyConstraint("event_id", "sink_id"),
    )


def downgrade():
    op.drop_table("assessment_sink_export_receipts")
