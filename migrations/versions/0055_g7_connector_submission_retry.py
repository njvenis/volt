"""Track retryability only after a confirmed statement rollback.

Revision ID: 0055
Revises: 0054
"""
from alembic import op
import sqlalchemy as sa

revision = "0055"
down_revision = "0054"
branch_labels = None
depends_on = None


def upgrade():
    columns = {item["name"] for item in sa.inspect(op.get_bind()).get_columns(
        "g7_connector_submissions")}
    if "retry_allowed" not in columns:
        op.add_column("g7_connector_submissions", sa.Column(
            "retry_allowed", sa.Boolean(), nullable=False, server_default=sa.false()))


def downgrade():
    columns = {item["name"] for item in sa.inspect(op.get_bind()).get_columns(
        "g7_connector_submissions")}
    if "retry_allowed" in columns:
        op.drop_column("g7_connector_submissions", "retry_allowed")
