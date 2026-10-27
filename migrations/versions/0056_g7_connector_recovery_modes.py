"""Persist rollback mode history and canonical retryable tombstones.

Revision ID: 0056
Revises: 0055
"""
from alembic import op
import sqlalchemy as sa

revision = "0056"
down_revision = "0055"
branch_labels = None
depends_on = None


def upgrade():
    bind = op.get_bind()
    connector_columns = {item["name"] for item in sa.inspect(bind).get_columns(
        "g7_connectors")}
    if "last_activated_authentication_mode" not in connector_columns:
        op.add_column("g7_connectors", sa.Column(
            "last_activated_authentication_mode", sa.String(32), nullable=True))
    # Existing active rows can be bound precisely. Historical disabled or
    # staged rows have no durable activation ledger, so unknown is fail-closed
    # for an App-to-legacy transition until the operator uses rollback.
    bind.execute(sa.text("""
        UPDATE g7_connectors AS c
        SET last_activated_authentication_mode = cfg.settings->>'authentication_mode'
        FROM g7_connector_configurations AS cfg
        WHERE c.lifecycle = 'active'
          AND cfg.connector_id = c.connector_id
          AND cfg.configuration_revision = c.active_configuration_revision
          AND cfg.settings->>'authentication_mode' IS NOT NULL
    """))
    bind.execute(sa.text("""
        UPDATE g7_connectors
        SET last_activated_authentication_mode = 'unknown'
        WHERE configuration_revision > 0
          AND last_activated_authentication_mode IS NULL
    """))
    bind.execute(sa.text("""
        UPDATE g7_connector_submissions
        SET retry_allowed = TRUE
        WHERE outcome = 'not_committed' AND retry_allowed = FALSE
    """))
    constraints = {item["name"] for item in sa.inspect(bind).get_check_constraints(
        "g7_connector_submissions")}
    if "ck_g7_connector_submission_retry_state" not in constraints:
        op.create_check_constraint(
            "ck_g7_connector_submission_retry_state", "g7_connector_submissions",
            "(outcome = 'not_committed' AND retry_allowed) OR "
            "(outcome <> 'not_committed' AND NOT retry_allowed)")


def downgrade():
    op.drop_constraint("ck_g7_connector_submission_retry_state",
                       "g7_connector_submissions", type_="check")
    columns = {item["name"] for item in sa.inspect(op.get_bind()).get_columns(
        "g7_connectors")}
    if "last_activated_authentication_mode" in columns:
        op.drop_column("g7_connectors", "last_activated_authentication_mode")
