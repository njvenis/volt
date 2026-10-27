"""Persist single-use, session-bound local GitHub App setup flows.

Revision ID: 0052
Revises: 0051
"""
from alembic import op

revision = "0052"
down_revision = "0051"
branch_labels = None
depends_on = None


def upgrade():
    from uvm.persistence.connector_schema import connector_setup_flows
    connector_setup_flows.create(op.get_bind(), checkfirst=True)


def downgrade():
    op.drop_index("ix_g7_connector_setup_flows_expiry", table_name="g7_connector_setup_flows")
    op.drop_table("g7_connector_setup_flows")
