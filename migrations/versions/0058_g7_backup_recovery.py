"""Add immutable backup settings and coordinated recovery records."""
from alembic import op
import sqlalchemy as sa

revision = "0058"
down_revision = "0057"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table("g7_backup_settings_revisions",
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
        sa.Column("policy_revision", sa.Integer(), nullable=False),
        sa.Column("authority_revision", sa.Integer(), nullable=False),
        sa.Column("host_policy_revision", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("deployment_id", "command_id", name="uq_g7_backup_revision_command"),
        sa.CheckConstraint("revision > 0", name="ck_g7_backup_revision_positive"))
    op.create_table("g7_backup_state",
        sa.Column("deployment_id", sa.String(256), primary_key=True),
        sa.Column("effective_revision", sa.Integer()),
        sa.Column("effective_digest", sa.String(64)),
        sa.Column("application_status", sa.String(16)),
        sa.Column("requested_revision", sa.Integer()),
        sa.Column("requested_digest", sa.String(64)),
        sa.Column("application_intent_id", sa.String(36)),
        sa.Column("host_policy_revision", sa.Integer()),
        sa.Column("host_policy_digest", sa.String(64)),
        sa.Column("host_policy_document", sa.JSON()),
        sa.Column("host_policy_key_id", sa.String(128)),
        sa.Column("host_policy_observed_at", sa.DateTime(timezone=True)),
        sa.Column("host_policy_max_age_seconds", sa.Integer()),
        sa.Column("host_policy_future_skew_seconds", sa.Integer()),
        sa.Column("latest_report_id", sa.String(36)),
        sa.Column("latest_sequence", sa.BigInteger(), nullable=False, server_default="0"),
        sa.Column("latest_report_at", sa.DateTime(timezone=True)),
        sa.Column("latest_failure_code", sa.String(64)),
        sa.Column("archive_id", sa.String(36)),
        sa.Column("archive_completed_at", sa.DateTime(timezone=True)),
        sa.Column("archive_manifest_digest", sa.String(64)),
        sa.Column("archive_outcome", sa.String(16)),
        sa.Column("freshness_state", sa.String(16), nullable=False, server_default="unknown"),
        sa.Column("freshness_age_seconds", sa.BigInteger()),
        sa.Column("freshness_max_age_seconds", sa.Integer()),
        sa.Column("recovery_epoch", sa.BigInteger(), nullable=False, server_default="0"),
        sa.Column("restore_state", sa.String(16), nullable=False, server_default="unknown"),
        sa.Column("restore_archive_id", sa.String(36)),
        sa.Column("restore_verified_at", sa.DateTime(timezone=True)),
        sa.Column("restore_failure_code", sa.String(64)),
        sa.Column("updated_at", sa.DateTime(timezone=True)),
        sa.CheckConstraint("latest_sequence >= 0", name="ck_g7_backup_sequence_nonnegative"),
        sa.CheckConstraint("recovery_epoch >= 0", name="ck_g7_backup_epoch_nonnegative"))
    op.create_table("g7_backup_host_records",
        sa.Column("record_id", sa.String(36), primary_key=True),
        sa.Column("deployment_id", sa.String(256), nullable=False),
        sa.Column("record_kind", sa.String(32), nullable=False),
        sa.Column("sequence", sa.BigInteger()),
        sa.Column("recovery_epoch", sa.BigInteger()),
        sa.Column("record_digest", sa.String(64), nullable=False),
        sa.Column("signature", sa.LargeBinary()),
        sa.Column("document", sa.JSON(), nullable=False),
        sa.Column("response", sa.JSON()),
        sa.Column("received_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("deployment_id", "record_kind", "sequence",
            name="uq_g7_backup_host_record_sequence"),
        sa.CheckConstraint("record_kind IN ('policy','status','ack','recovery','resync','quarantine')",
            name="ck_g7_backup_record_kind"))
    op.create_table("g7_backup_connector_quarantine",
        sa.Column("deployment_id", sa.String(256), primary_key=True),
        sa.Column("intent_id", sa.String(36), primary_key=True),
        sa.Column("connector_id", sa.String(256), nullable=False),
        sa.Column("recovery_epoch", sa.BigInteger(), nullable=False),
        sa.Column("connector_recovery_id", sa.String(36), nullable=False),
        sa.Column("event_id", sa.String(36), nullable=False),
        sa.Column("reason_code", sa.String(64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False))


def downgrade():
    bind = op.get_bind()
    for table in ("g7_backup_settings_revisions", "g7_backup_state",
                  "g7_backup_host_records", "g7_backup_connector_quarantine"):
        if bind.execute(sa.text(f"SELECT 1 FROM {table} LIMIT 1")).first() is not None:
            raise RuntimeError(f"refusing destructive 0058 downgrade: retained backup state in {table}")
    op.drop_table("g7_backup_connector_quarantine")
    op.drop_table("g7_backup_host_records")
    op.drop_table("g7_backup_state")
    op.drop_table("g7_backup_settings_revisions")
