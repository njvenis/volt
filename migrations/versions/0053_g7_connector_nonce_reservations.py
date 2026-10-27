"""Reserve AES-GCM nonces across connector credentials and setup flows.

Revision ID: 0053
Revises: 0052
"""
from alembic import op

revision = "0053"
down_revision = "0052"
branch_labels = None
depends_on = None


def upgrade():
    from uvm.persistence.connector_schema import connector_nonce_reservations
    connector_nonce_reservations.create(op.get_bind(), checkfirst=True)


def downgrade():
    op.drop_table("g7_connector_nonce_reservations")
