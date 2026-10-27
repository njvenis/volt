"""H4 additive canonical scalar receipts and server report sequence boundary."""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

revision = "0032"
down_revision = "0031"
branch_labels = None
depends_on = None


def upgrade():
    identifier = sa.Uuid(as_uuid=False)
    document = JSONB().with_variant(sa.JSON(), "sqlite")
    op.create_table("identity_scalar_correction_receipts",
        sa.Column("request_id", identifier, primary_key=True),
        sa.Column("schema_version", sa.Integer(), nullable=False),
        sa.Column("request_digest", sa.String(64), nullable=False),
        sa.Column("canonical_request", sa.Text(), nullable=False),
        sa.Column("principal_id", sa.String(), nullable=False),
        sa.Column("action", sa.String(), nullable=False),
        sa.Column("record_type", sa.String(), nullable=False),
        sa.Column("record_id", identifier, nullable=False),
        sa.Column("field_name", sa.String(), nullable=False),
        sa.Column("previous_revision", sa.Integer(), nullable=False),
        sa.Column("new_revision", sa.Integer(), nullable=False),
        sa.Column("correction_id", identifier, sa.ForeignKey("correction_records.correction_id"), nullable=False, unique=True),
        sa.Column("decision_id", identifier, sa.ForeignKey("identity_authorisation_decisions.decision_id"), nullable=False, unique=True),
        sa.Column("knowledge_sequence", sa.BigInteger(), nullable=False, unique=True),
        sa.Column("recorded_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("scope_contexts", document, nullable=False),
        sa.Column("result", document, nullable=False),
        sa.UniqueConstraint("record_type", "record_id", "new_revision", name="uq_scalar_target_revision"),
        sa.CheckConstraint("schema_version = 1", name="scalar_receipt_version"),
        sa.CheckConstraint("previous_revision > 0 AND new_revision = previous_revision + 1", name="scalar_receipt_revision"),
        sa.CheckConstraint("knowledge_sequence > 0", name="scalar_receipt_sequence"),
        sa.CheckConstraint("(record_type = 'workload' AND action = 'identity.workload_field_correct') OR (record_type = 'incarnation' AND action = 'identity.incarnation_locator_correct' AND field_name = 'host_locator')", name="scalar_receipt_action"))
    op.add_column("metrics_report_requests", sa.Column("identity_scalar_sequence", sa.BigInteger(), nullable=False, server_default="0"))


def downgrade():
    if op.get_bind().execute(sa.text("SELECT count(*) FROM identity_scalar_correction_receipts")).scalar_one():
        from alembic.util.exc import CommandError
        raise CommandError("refusing 0032 downgrade: scalar correction receipts are retained")
    op.drop_column("metrics_report_requests", "identity_scalar_sequence")
    op.drop_table("identity_scalar_correction_receipts")
