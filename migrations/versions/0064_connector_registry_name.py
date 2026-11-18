"""Add display labels and unique exact-source connector binding identities."""
from alembic import op
import sqlalchemy as sa

revision = "0064"
down_revision = "0063"
branch_labels = None
depends_on = None


def upgrade():
    duplicate = op.get_bind().execute(sa.text("""
        SELECT source_family, source_account_id, scope_key
        FROM g7_connectors
        GROUP BY source_family, source_account_id, scope_key
        HAVING count(*) > 1
        LIMIT 1
    """)).first()
    if duplicate:
        raise RuntimeError("refusing connector registry migration: duplicate exact-source bindings are retained")
    op.create_index("uq_g7_connector_source_tuple", "g7_connectors",
        ["source_family", "source_account_id", "scope_key"], unique=True)
    op.create_table("g7_connector_bindings",
        sa.Column("connector_id", sa.String(36), sa.ForeignKey("g7_connectors.connector_id"), primary_key=True),
        sa.Column("display_name", sa.String(120), nullable=False),
        sa.Column("registration", sa.JSON(), nullable=True))


def downgrade():
    bind = op.get_bind()
    if bind.execute(sa.text("SELECT count(*) FROM g7_connector_bindings")).scalar_one():
        raise RuntimeError("refusing 0064 downgrade: connector display labels are retained")
    op.drop_table("g7_connector_bindings")
    op.drop_index("uq_g7_connector_source_tuple", table_name="g7_connectors")
