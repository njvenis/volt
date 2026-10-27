"""Add durable UVM projection for independently journalled G7 incidents.

Revision ID: 0049
Revises: 0048
"""
from alembic import op
import sqlalchemy as sa


revision = "0049"
down_revision = "0048"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "g7_incident_service_bindings",
        sa.Column("principal_id", sa.String(), primary_key=True),
        sa.Column("deployment_id", sa.String(), primary_key=True),
        sa.Column("subject_id", sa.String(), primary_key=True),
        sa.Column("condition", sa.String(), primary_key=True),
        sa.Column("subject_type", sa.String(), nullable=False),
        sa.Column("producer_id", sa.String(), nullable=False),
        sa.Column("producer_revision", sa.Integer(), nullable=False),
        sa.Column("configuration_revision", sa.Integer(), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.CheckConstraint("configuration_revision > 0",
                           name="g7_incident_binding_revision_valid"),
    )
    op.create_table(
        "g7_incident_routes",
        sa.Column("route_id", sa.String(), nullable=False),
        sa.Column("revision", sa.Integer(), nullable=False),
        sa.Column("deployment_id", sa.String(), nullable=False),
        sa.Column("subject_id", sa.String(), nullable=True),
        sa.Column("recipient_access_group_id", sa.String(), nullable=False),
        sa.Column("vulnerability_group_id", sa.Uuid(as_uuid=False), nullable=True),
        sa.Column("source_family", sa.String(), nullable=False),
        sa.Column("source_account_id", sa.String(), nullable=False),
        sa.Column("scope_key", sa.String(), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.ForeignKeyConstraint(["vulnerability_group_id"], ["groups.group_id"],
                                name="fk_g7_incident_route_vulnerability_group"),
        sa.PrimaryKeyConstraint("route_id", "revision"),
        sa.CheckConstraint("revision > 0", name="g7_incident_route_revision_valid"),
    )
    op.create_index("uq_g7_incident_route_current", "g7_incident_routes", ["route_id"],
        unique=True, postgresql_where=sa.text("enabled IS TRUE"),
        sqlite_where=sa.text("enabled IS 1"))
    op.create_table(
        "g7_incident_streams",
        sa.Column("deployment_id", sa.String(), primary_key=True),
        sa.Column("subject_id", sa.String(), primary_key=True),
        sa.Column("condition", sa.String(), primary_key=True),
        sa.Column("last_sequence", sa.BigInteger(), nullable=False),
        sa.Column("last_transition_id", sa.String(), nullable=True),
        sa.Column("active_episode_id", sa.String(), nullable=True),
        sa.Column("episode_generation", sa.BigInteger(), nullable=False),
        sa.Column("producer_id", sa.String(), nullable=False),
        sa.Column("producer_revision", sa.Integer(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("last_sequence >= 0 AND episode_generation >= 0",
                           name="g7_incident_stream_position_valid"),
    )
    op.create_table(
        "g7_incident_transitions",
        sa.Column("transition_id", sa.String(), primary_key=True),
        sa.Column("deployment_id", sa.String(), nullable=False),
        sa.Column("subject_id", sa.String(), nullable=False),
        sa.Column("condition", sa.String(), nullable=False),
        sa.Column("transition_sequence", sa.BigInteger(), nullable=False),
        sa.Column("predecessor_id", sa.String(), nullable=True),
        sa.Column("episode_id", sa.String(), nullable=False),
        sa.Column("opening_transition_id", sa.String(), nullable=False),
        sa.Column("episode_generation", sa.BigInteger(), nullable=False),
        sa.Column("transition_kind", sa.String(), nullable=False),
        sa.Column("configuration_revision", sa.Integer(), nullable=False),
        sa.Column("first_detected_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("recovered_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("evidence_refs", sa.JSON(), nullable=False),
        sa.Column("payload_digest", sa.String(64), nullable=False),
        sa.Column("producer_id", sa.String(), nullable=False),
        sa.UniqueConstraint("deployment_id", "subject_id", "condition",
                            "transition_sequence", name="uq_g7_incident_stream_sequence"),
        sa.CheckConstraint("transition_sequence > 0 AND episode_generation > 0",
                           name="g7_incident_transition_position_valid"),
        sa.CheckConstraint("transition_kind IN ('opened','observed','recovered')",
                           name="g7_incident_transition_kind_known"),
    )
    op.create_index("ix_g7_incident_transition_observed", "g7_incident_transitions",
                    ["observed_at", "transition_id"])
    op.create_table(
        "g7_incident_projection_receipts",
        sa.Column("transition_id", sa.String(), nullable=False),
        sa.Column("payload_digest", sa.String(64), nullable=False),
        sa.Column("received_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("result", sa.JSON(), nullable=False),
        sa.ForeignKeyConstraint(["transition_id"], ["g7_incident_transitions.transition_id"],
                                name="fk_g7_incident_receipt_transition"),
        sa.PrimaryKeyConstraint("transition_id"),
    )
    op.create_table(
        "g7_incident_notification_intents",
        sa.Column("transition_id", sa.String(), nullable=False),
        sa.Column("state", sa.String(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("receipt_basis", sa.String(), nullable=False),
        sa.ForeignKeyConstraint(["transition_id"], ["g7_incident_transitions.transition_id"],
                                name="fk_g7_incident_intent_transition"),
        sa.PrimaryKeyConstraint("transition_id"),
        sa.CheckConstraint("state IN ('pending','accepted','failed','uncertain')",
                           name="g7_incident_notification_state_known"),
    )
    op.create_table(
        "g7_incident_notification_attempts",
        sa.Column("attempt_id", sa.String(), primary_key=True),
        sa.Column("transition_id", sa.String(), nullable=False),
        sa.Column("attempted_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("outcome", sa.String(), nullable=False),
        sa.Column("receipt_ref", sa.String(), nullable=True),
        sa.Column("failure_detail", sa.String(), nullable=True),
        sa.ForeignKeyConstraint(["transition_id"], ["g7_incident_transitions.transition_id"],
                                name="fk_g7_incident_attempt_transition"),
        sa.CheckConstraint("outcome IN ('accepted','failed','uncertain')",
                           name="g7_incident_notification_attempt_known"),
    )


def downgrade():
    bind = op.get_bind()
    tables = ("g7_incident_notification_attempts", "g7_incident_notification_intents",
              "g7_incident_projection_receipts", "g7_incident_transitions",
              "g7_incident_streams", "g7_incident_routes", "g7_incident_service_bindings")
    if bind.dialect.name == "sqlite":
        quote = '"'
    else:
        quote = '"'
    for table in tables:
        count = bind.execute(sa.text(f"SELECT count(*) FROM {quote}{table}{quote}")).scalar_one()
        if count:
            from alembic.util.exc import CommandError
            raise CommandError("refusing 0049 downgrade: incident and projection history is retained")
    op.drop_table("g7_incident_notification_attempts")
    op.drop_table("g7_incident_notification_intents")
    op.drop_table("g7_incident_projection_receipts")
    op.drop_index("ix_g7_incident_transition_observed", table_name="g7_incident_transitions")
    op.drop_table("g7_incident_transitions")
    op.drop_table("g7_incident_streams")
    op.drop_index("uq_g7_incident_route_current", table_name="g7_incident_routes")
    op.drop_table("g7_incident_routes")
    op.drop_table("g7_incident_service_bindings")
