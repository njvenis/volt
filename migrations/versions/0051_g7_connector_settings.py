"""Persist scoped connector configuration, secret versions and outcomes.

Revision ID: 0051
Revises: 0050
"""
from alembic import op
import sqlalchemy as sa

revision = "0051"
down_revision = "0050"
branch_labels = None
depends_on = None


def upgrade():
    from uvm.persistence.connector_schema import (connectors, connector_secret_heads,
        connector_configurations, connector_secrets, connector_receipts,
        connector_intents, connector_submissions)
    bind = op.get_bind()
    for table in (connectors, connector_secret_heads, connector_configurations, connector_secrets,
                  connector_receipts, connector_intents, connector_submissions):
        table.create(bind=bind, checkfirst=True)


def downgrade():
    op.drop_table("g7_connector_submissions")
    op.drop_index("ix_g7_connector_intents_pending", table_name="g7_connector_intents")
    op.drop_table("g7_connector_intents")
    op.drop_table("g7_connector_receipts")
    op.drop_index("ix_g7_connector_secrets_current", table_name="g7_connector_secrets")
    op.drop_table("g7_connector_secrets")
    op.drop_table("g7_connector_configurations")
    op.drop_table("g7_connector_secret_heads")
    op.drop_table("g7_connectors")
