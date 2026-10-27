"""Bind setup callbacks to the exact App credential revisions.

Revision ID: 0054
Revises: 0053
"""
from alembic import op
import sqlalchemy as sa

revision = "0054"
down_revision = "0053"
branch_labels = None
depends_on = None


def upgrade():
    columns = {item["name"] for item in sa.inspect(op.get_bind()).get_columns(
        "g7_connector_setup_flows")}
    if "credential_binding" not in columns:
        op.add_column("g7_connector_setup_flows",
            sa.Column("credential_binding", sa.JSON(), nullable=True))


def downgrade():
    columns = {item["name"] for item in sa.inspect(op.get_bind()).get_columns(
        "g7_connector_setup_flows")}
    if "credential_binding" in columns:
        op.drop_column("g7_connector_setup_flows", "credential_binding")
