"""Persist idempotent bounded Qualys test and collection operations."""
from alembic import op
import sqlalchemy as sa

revision = "0066"
down_revision = "0065"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table("qualys_vm_operations",
        sa.Column("operation_id", sa.Uuid(as_uuid=False), primary_key=True),
        sa.Column("connector_id", sa.String(36), sa.ForeignKey("g7_connectors.connector_id", ondelete="CASCADE"), nullable=False),
        sa.Column("source_id", sa.String(36), nullable=False),
        sa.Column("command_id", sa.String(36), nullable=False),
        sa.Column("principal_id", sa.String(256), nullable=False),
        sa.Column("action", sa.String(32), nullable=False),
        sa.Column("request_digest", sa.String(64), nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("configuration_revision", sa.Integer(), nullable=False),
        sa.Column("credential_version_id", sa.String(36), nullable=False),
        sa.Column("restore_epoch_id", sa.String(36), nullable=False),
        sa.Column("run_id", sa.Uuid(as_uuid=False)),
        sa.Column("finalization_stage", sa.String(24), nullable=False),
        sa.Column("intent_id", sa.String(36)),
        sa.Column("receipt_id", sa.String(36)),
        sa.Column("error_code", sa.String(64)),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("finished_at", sa.DateTime(timezone=True)),
        sa.UniqueConstraint("connector_id", "command_id", name="uq_qualys_vm_command"),
        sa.CheckConstraint("action IN ('test','collect')", name="ck_qualys_vm_operation_action"),
        sa.CheckConstraint("status IN ('running','succeeded','partial','failed','interrupted')", name="ck_qualys_vm_operation_status"),
        sa.CheckConstraint("finalization_stage IN ('admitted','evidence','observations','resolution','published')", name="ck_qualys_vm_finalization_stage"),
        sa.CheckConstraint("configuration_revision >= 0", name="ck_qualys_vm_configuration_revision"),
        sa.CheckConstraint("length(request_digest) = 64", name="ck_qualys_vm_request_digest"),
        sa.CheckConstraint("(status = 'running' AND finished_at IS NULL) OR (status <> 'running' AND finished_at IS NOT NULL)", name="ck_qualys_vm_operation_terminal_time"),
    )
    op.create_index("uq_qualys_vm_running_connector", "qualys_vm_operations",
        ["connector_id"], unique=True, postgresql_where=sa.text("status = 'running'"),
        sqlite_where=sa.text("status = 'running'"))
    op.create_table("qualys_vm_http_attempts",
        sa.Column("operation_id", sa.Uuid(as_uuid=False), sa.ForeignKey("qualys_vm_operations.operation_id", ondelete="CASCADE"), primary_key=True),
        sa.Column("attempt_no", sa.Integer(), primary_key=True),
        sa.Column("page_ordinal", sa.Integer(), nullable=False),
        sa.Column("request_identity_sha256", sa.String(64), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("finished_at", sa.DateTime(timezone=True)),
        sa.Column("response_class", sa.String(32)),
        sa.Column("http_status", sa.Integer()),
        sa.Column("success", sa.Boolean()),
        sa.Column("error_code", sa.String(64)),
        sa.Column("retry_after_seconds", sa.Float()),
        sa.CheckConstraint("attempt_no > 0 AND page_ordinal > 0", name="ck_qualys_vm_attempt_position"),
        sa.CheckConstraint("length(request_identity_sha256) = 64", name="ck_qualys_vm_attempt_digest"),
        sa.CheckConstraint("(finished_at IS NULL AND success IS NULL) OR (finished_at IS NOT NULL AND success IS NOT NULL)", name="ck_qualys_vm_attempt_terminal"),
    )
    op.create_table("qualys_vm_operation_pages",
        sa.Column("operation_id", sa.Uuid(as_uuid=False), sa.ForeignKey("qualys_vm_operations.operation_id", ondelete="CASCADE"), primary_key=True),
        sa.Column("page_ordinal", sa.Integer(), primary_key=True),
        sa.Column("request_identity_sha256", sa.String(64), nullable=False),
        sa.Column("continuation_sha256", sa.String(64)),
        sa.Column("evidence_ref", sa.String(256)),
        sa.Column("response_sha256", sa.String(64)),
        sa.Column("byte_count", sa.Integer(), nullable=False),
        sa.Column("host_count", sa.Integer(), nullable=False),
        sa.Column("detection_count", sa.Integer(), nullable=False),
        sa.Column("response_class", sa.String(32), nullable=False),
        sa.Column("attempt_count", sa.Integer(), nullable=False),
        sa.Column("recorded_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("page_ordinal > 0 AND byte_count >= 0 AND host_count >= 0 AND detection_count >= 0 AND attempt_count > 0", name="ck_qualys_vm_page_counts"),
        sa.CheckConstraint("length(request_identity_sha256) = 64", name="ck_qualys_vm_page_request_digest"),
    )
    op.create_index("ix_qualys_vm_operation_status", "qualys_vm_operations",
        ["connector_id", "status", "started_at"])


    op.create_table('qualys_vm_configurations',
        sa.Column('connector_id', sa.String(36), sa.ForeignKey('g7_connectors.connector_id', ondelete='CASCADE'), primary_key=True),
        sa.Column('source_id', sa.String(36), nullable=False),
        sa.Column('configuration_revision', sa.Integer(), nullable=False),
        sa.Column('settings', sa.JSON(), nullable=False),
        sa.Column('validation', sa.JSON()),
        sa.Column('active_snapshot', sa.JSON()),
        sa.Column('latest_attempt_run_id', sa.String(36)),
        sa.Column('latest_complete_run_id', sa.String(36)))
    op.create_table('qualys_vm_detections',
        sa.Column('operation_id', sa.Uuid(as_uuid=False), sa.ForeignKey('qualys_vm_operations.operation_id', ondelete='CASCADE'), primary_key=True),
        sa.Column('ordinal', sa.Integer(), primary_key=True),
        sa.Column('observation_id', sa.String(36), nullable=False),
        sa.Column('payload', sa.JSON(), nullable=False),
        sa.CheckConstraint('ordinal > 0', name='ck_qualys_vm_detection_ordinal'))
    op.create_table('qualys_vm_publications',
        sa.Column('run_id', sa.Uuid(as_uuid=False), primary_key=True),
        sa.Column('operation_id', sa.Uuid(as_uuid=False), sa.ForeignKey('qualys_vm_operations.operation_id', ondelete='CASCADE'), nullable=False, unique=True),
        sa.Column('connector_id', sa.String(36), nullable=False),
        sa.Column('source_id', sa.String(36), nullable=False),
        sa.Column('published_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('retrieval', sa.JSON(), nullable=False),
        sa.Column('coverage', sa.JSON(), nullable=False),
        sa.Column('source_freshness', sa.JSON(), nullable=False))
    op.create_table('qualys_vm_read_cursors',
        sa.Column('token_hash', sa.String(64), primary_key=True),
        sa.Column('binding_hash', sa.String(64), nullable=False),
        sa.Column('run_id', sa.Uuid(as_uuid=False), sa.ForeignKey('qualys_vm_publications.run_id', ondelete='CASCADE'), nullable=False),
        sa.Column('after_ordinal', sa.Integer(), nullable=False),
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=False))


def downgrade():
    bind = op.get_bind()
    if (bind.execute(sa.text("SELECT count(*) FROM qualys_vm_operations")).scalar_one()
            or bind.execute(sa.text("SELECT count(*) FROM qualys_vm_configurations")).scalar_one()):
        raise RuntimeError("refusing 0066 downgrade: scanner operation history is retained")
    op.drop_table('qualys_vm_read_cursors')
    op.drop_table('qualys_vm_publications')
    op.drop_table('qualys_vm_detections')
    op.drop_table('qualys_vm_configurations')
    op.drop_index("ix_qualys_vm_operation_status", table_name="qualys_vm_operations")
    op.drop_table("qualys_vm_operation_pages")
    op.drop_table("qualys_vm_http_attempts")
    op.drop_index("uq_qualys_vm_running_connector", table_name="qualys_vm_operations")
    op.drop_table("qualys_vm_operations")
