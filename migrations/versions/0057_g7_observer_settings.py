"""Persist immutable observer timing revisions and independent host outcomes."""
from alembic import op
import sqlalchemy as sa

revision = "0057"
down_revision = "0056"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "g7_observer_settings_revisions",
        sa.Column("deployment_id", sa.String(256), primary_key=True),
        sa.Column("revision", sa.Integer(), primary_key=True),
        sa.Column("values", sa.JSON(), nullable=False),
        sa.Column("digest", sa.String(64), nullable=False),
        sa.Column("command_id", sa.String(36), nullable=False),
        sa.Column("actor_id", sa.String(256), nullable=False),
        sa.Column("action", sa.String(64), nullable=False),
        sa.Column("copied_from_revision", sa.Integer()),
        sa.Column("rationale", sa.Text(), nullable=False),
        sa.Column("evidence_ref", sa.Text()),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("deployment_id", "command_id",
            name="uq_g7_observer_revision_command"),
        sa.CheckConstraint("revision > 0", name="ck_g7_observer_revision_positive"),
    )
    op.create_table(
        "g7_observer_status",
        sa.Column("deployment_id", sa.String(256), primary_key=True),
        sa.Column("effective_revision", sa.Integer()),
        sa.Column("effective_digest", sa.String(64)),
        sa.Column("application_status", sa.String(16), nullable=False),
        sa.Column("latest_report_id", sa.String(36)),
        sa.Column("latest_report_sequence", sa.BigInteger(), nullable=False,
            server_default="0"),
        sa.Column("latest_report_at", sa.DateTime(timezone=True)),
        sa.Column("latest_failure_code", sa.String(64)),
        sa.Column("host_policy_revision", sa.Integer()),
        sa.Column("host_policy_bounds", sa.JSON()),
        sa.Column("host_policy_digest", sa.String(64)),
        sa.Column("host_policy_key_id", sa.String(128)),
        sa.Column("host_policy_observed_at", sa.DateTime(timezone=True)),
        sa.Column("host_policy_freshness_seconds", sa.Integer()),
        sa.CheckConstraint("application_status IN ('pending','applied','failed','uncertain')",
            name="ck_g7_observer_application_status"),
        sa.CheckConstraint("latest_report_sequence >= 0",
            name="ck_g7_observer_report_sequence"),
    )
    op.create_table(
        "g7_observer_host_reports",
        sa.Column("report_id", sa.String(36), primary_key=True),
        sa.Column("deployment_id", sa.String(256), nullable=False),
        sa.Column("sequence", sa.BigInteger(), nullable=False),
        sa.Column("controller_instance", sa.String(128), nullable=False),
        sa.Column("requested_revision", sa.Integer()),
        sa.Column("requested_digest", sa.String(64)),
        sa.Column("active_revision", sa.Integer()),
        sa.Column("active_digest", sa.String(64)),
        sa.Column("policy_revision", sa.Integer(), nullable=False),
        sa.Column("policy_bounds", sa.JSON(), nullable=False),
        sa.Column("policy_digest", sa.String(64), nullable=False),
        sa.Column("policy_key_id", sa.String(128), nullable=False),
        sa.Column("policy_freshness_seconds", sa.Integer(), nullable=False),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("outcome", sa.String(16), nullable=False),
        sa.Column("failure_code", sa.String(64)),
        sa.Column("report_digest", sa.String(64), nullable=False),
        sa.Column("signature", sa.LargeBinary(), nullable=False),
        sa.Column("report", sa.JSON(), nullable=False),
        sa.Column("received_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("deployment_id", "sequence",
            name="uq_g7_observer_report_sequence"),
        sa.CheckConstraint("sequence > 0",
            name="ck_g7_observer_report_sequence_positive"),
        sa.CheckConstraint("policy_revision > 0 AND policy_freshness_seconds > 0",
            name="ck_g7_observer_policy_revision_valid"),
        sa.CheckConstraint("outcome IN ('applied','failed','uncertain')",
            name="ck_g7_observer_report_outcome"),
    )
    op.create_table(
        "g7_observer_application_intents",
        sa.Column("intent_id", sa.String(36), primary_key=True),
        sa.Column("deployment_id", sa.String(256), nullable=False),
        sa.Column("command_id", sa.String(36), nullable=False),
        sa.Column("revision", sa.Integer(), nullable=False),
        sa.Column("digest", sa.String(64), nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("result", sa.JSON()),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("deployment_id", "command_id",
            name="uq_g7_observer_intent_command"),
        sa.CheckConstraint("revision > 0",
            name="ck_g7_observer_intent_revision_positive"),
        sa.CheckConstraint("status IN ('pending','applied','failed','uncertain')",
            name="ck_g7_observer_intent_status"),
    )
    op.create_index("uq_g7_observer_open_intent", "g7_observer_application_intents",
        ["deployment_id"], unique=True,
        postgresql_where=sa.text("status IN ('pending','uncertain')"),
        sqlite_where=sa.text("status IN ('pending','uncertain')"))


def downgrade():
    # Observer timing history, receipts and signed host outcomes are retained
    # audit state. Refuse a destructive downgrade once any deployment has used
    # this feature; operators must export and explicitly migrate it first.
    from sqlalchemy import inspect, text
    bind = op.get_bind()
    inspector = inspect(bind)
    for table in ("g7_observer_settings_revisions", "g7_observer_status",
                  "g7_observer_host_reports", "g7_observer_application_intents"):
        if table in inspector.get_table_names() and bind.execute(
                text(f"SELECT 1 FROM {table} LIMIT 1")).first() is not None:
            raise RuntimeError(
                f"refusing 0057 downgrade: retained observer settings history exists in {table}")
    op.drop_index("uq_g7_observer_open_intent",
        table_name="g7_observer_application_intents")
    op.drop_table("g7_observer_application_intents")
    op.drop_table("g7_observer_host_reports")
    op.drop_table("g7_observer_status")
    op.drop_table("g7_observer_settings_revisions")
