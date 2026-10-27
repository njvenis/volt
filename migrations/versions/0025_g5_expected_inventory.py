"""Retain versioned expected estate and required-source configuration."""
from alembic import op
import sqlalchemy as sa

revision = "0025"
down_revision = "0024"
branch_labels = None
depends_on = None


def upgrade():
    uuid = sa.Uuid(as_uuid=False)
    timestamp = sa.DateTime(timezone=True)
    json_value = sa.JSON().with_variant(sa.dialects.postgresql.JSONB(), "postgresql")
    op.create_table("inventory_policy_heads",
        sa.Column("head_id", sa.Integer(), primary_key=True),
        sa.Column("revision", sa.Integer(), nullable=False),
        sa.Column("updated_at", timestamp, nullable=False),
        sa.CheckConstraint("head_id = 1 AND revision >= 0", name="inventory_policy_head_singleton"))
    op.create_table("inventory_policy_versions",
        sa.Column("revision", sa.Integer(), primary_key=True),
        sa.Column("command_id", uuid, nullable=False, unique=True),
        sa.Column("document", json_value, nullable=False),
        sa.Column("created_at", timestamp, nullable=False),
        sa.Column("created_by", sa.String(), nullable=False),
        sa.Column("audit_event_id", uuid, nullable=False))
    op.execute(sa.text("INSERT INTO inventory_policy_heads (head_id, revision, updated_at) VALUES (1, 0, CURRENT_TIMESTAMP)"))


def downgrade():
    bind = op.get_bind()
    if bind.execute(sa.text("SELECT count(*) FROM inventory_policy_versions")).scalar_one():
        from alembic.util.exc import CommandError
        raise CommandError("refusing 0025 downgrade: retained inventory configuration requires forward repair")
    from uvm.persistence.metrics_schema import inventory_policy_heads, inventory_policy_versions
    inventory_policy_versions.drop(bind, checkfirst=True)
    inventory_policy_heads.drop(bind, checkfirst=True)
