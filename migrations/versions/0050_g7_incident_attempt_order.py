"""Index delivery attempts in causal order without rewriting retained history.

Revision ID: 0050
Revises: 0049
"""
from alembic import op

revision = "0050"
down_revision = "0049"
branch_labels = None
depends_on = None


def upgrade():
    op.create_index("ix_g7_incident_attempt_order",
        "g7_incident_notification_attempts",
        ["transition_id", "attempted_at", "attempt_id"])


def downgrade():
    # The index carries no history. Attempts and projection receipts remain
    # retained and readable if this additive lookup optimisation is rolled back.
    op.drop_index("ix_g7_incident_attempt_order",
        table_name="g7_incident_notification_attempts")
