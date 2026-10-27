"""Atomically bind retained-run CLI requests to CE operation reservations."""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

revision = "0033"
down_revision = "0032"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "ce_import_request_bindings",
        sa.Column("operation_id", sa.Uuid(as_uuid=False),
                  sa.ForeignKey("engine_operation_requests.operation_id"), primary_key=True),
        sa.Column("schema_version", sa.Integer(), nullable=False),
        sa.Column("request_sha256", sa.String(64), nullable=False),
        sa.Column("canonical_request", sa.Text(), nullable=False),
        sa.Column("binding", JSONB().with_variant(sa.JSON(), "sqlite"), nullable=False),
        sa.Column("recorded_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("schema_version = 1", name="ce_import_binding_version"),
        sa.CheckConstraint("length(request_sha256) = 64", name="ce_import_binding_digest_length"),
    )


def downgrade():
    count = op.get_bind().execute(sa.text(
        "SELECT count(*) FROM ce_import_request_bindings")).scalar_one()
    if count:
        from alembic.util.exc import CommandError
        raise CommandError("refusing 0033 downgrade: immutable CLI bindings are retained")
    op.drop_table("ce_import_request_bindings")
