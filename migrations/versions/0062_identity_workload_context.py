"""Persist immutable workload context selectors for SLA policy evaluation."""
from alembic import op
from alembic.util.exc import CommandError
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

revision = "0062"
down_revision = "0061"
branch_labels = None
depends_on = None


def _dialect_type():
    name = op.get_bind().dialect.name
    if name == "postgresql":
        return JSONB()
    if name == "sqlite":
        return sa.JSON()
    raise CommandError(f"0062 does not support {name}")


def upgrade():
    op.add_column("identity_rule_definitions", sa.Column(
        "workload_context_fields", _dialect_type(), nullable=False,
        server_default=sa.text("'[]'")))


def downgrade():
    bind = op.get_bind()
    table = sa.Table("identity_rule_definitions", sa.MetaData(),
        sa.Column("rule_id", sa.String, primary_key=True),
        sa.Column("rule_version", sa.Integer, primary_key=True),
        sa.Column("workload_context_fields", _dialect_type()))
    for (value,) in bind.execute(sa.select(table.c.workload_context_fields)):
        if type(value) is not list or value:
            raise CommandError("refusing 0062 downgrade: workload context is retained or malformed")
    op.drop_column("identity_rule_definitions", "workload_context_fields")
