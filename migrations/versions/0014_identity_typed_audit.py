"""Retain typed identity decision semantics before JSONB normalisation (CR-09)."""

from alembic import context, op
from alembic.util.exc import CommandError
from sqlalchemy import Column, Text, text

revision = "0014"
down_revision = "0013"
branch_labels = None
depends_on = None


def _online_dialect():
    if context.is_offline_mode():
        raise CommandError("0014 requires online retained-evidence safety checks")
    dialect = op.get_bind().dialect.name
    if dialect not in ("sqlite", "postgresql"):
        raise CommandError(f"0014 does not support {dialect}")
    return dialect


def upgrade():
    _online_dialect()
    # Legacy JSONB cannot establish historical numeric types. No backfill.
    op.add_column("identity_authorisation_decisions",
                  Column("decision_semantics_canonical", Text, nullable=True))


def downgrade():
    dialect = _online_dialect()
    if op.get_bind().execute(text(
            "SELECT count(*) FROM identity_authorisation_decisions "
            "WHERE decision_semantics_canonical IS NOT NULL")).scalar_one():
        raise CommandError("refusing 0014 downgrade: typed authorisation evidence is retained")
    if dialect == "sqlite":
        with op.batch_alter_table("identity_authorisation_decisions") as batch:
            batch.drop_column("decision_semantics_canonical")
    else:
        op.drop_column("identity_authorisation_decisions", "decision_semantics_canonical")
