"""Additive G2 ingestion run, evidence and import-context storage."""

from alembic import context, op
from alembic.util.exc import CommandError
from sqlalchemy import CheckConstraint, Column, ForeignKeyConstraint, UniqueConstraint

from uvm.persistence.ingestion_schema import ALL_INGESTION_TABLES

revision = "0011"
down_revision = "0010"
branch_labels = None
depends_on = None

def _dialect():
    name = op.get_bind().dialect.name
    if name not in ("sqlite", "postgresql"):
        raise CommandError(f"0011 does not support {name}")

def _create(table):
    cols = [column.copy() for column in table.columns]
    original_constraints = tuple(table.constraints)
    constraints = [constraint.copy() for constraint in original_constraints
                   if not isinstance(constraint, (UniqueConstraint, CheckConstraint, ForeignKeyConstraint))]
    # Keep named table constraints explicit; this avoids relying on metadata
    # create_all and makes the migration's additive order auditable.
    constraints.extend(constraint.copy() for constraint in original_constraints
                       if isinstance(constraint, (UniqueConstraint, CheckConstraint, ForeignKeyConstraint)))
    op.create_table(table.name, *cols, *constraints)

def upgrade():
    if context.is_offline_mode():
        raise CommandError("0011 upgrade requires an online additive migration")
    _dialect()
    for table in ALL_INGESTION_TABLES:
        _create(table)

def downgrade():
    if context.is_offline_mode():
        raise CommandError("0011 downgrade requires online ingestion-data safety checks")
    _dialect()
    bind = op.get_bind()
    for table in reversed(ALL_INGESTION_TABLES):
        if bind.execute(table.select().limit(1)).first() is not None:
            raise CommandError(f"refusing 0011 downgrade: {table.name} contains data")
    for table in reversed(ALL_INGESTION_TABLES):
        op.drop_table(table.name)
