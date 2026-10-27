"""Retain exact G5 supplied-deadline binding on SLA evaluations."""
from alembic import op
import sqlalchemy as sa

revision = "0024"
down_revision = "0023"
branch_labels = None
depends_on = None


def upgrade():
    # The frozen 0023 schema intentionally predates reference bindings.
    if not any(column["name"] == "reference_binding_id"
            for column in sa.inspect(op.get_bind()).get_columns("sla_evaluations")):
        op.add_column("sla_evaluations", sa.Column("reference_binding_id", sa.Uuid(as_uuid=False), nullable=True))


def downgrade():
    from alembic.util.exc import CommandError
    bind = op.get_bind()
    if bind.execute(sa.text("SELECT count(*) FROM sla_evaluations WHERE reference_binding_id IS NOT NULL")).scalar_one():
        raise CommandError("refusing 0024 downgrade: retained SLA reference bindings require forward repair")
    if any(column["name"] == "reference_binding_id"
            for column in sa.inspect(bind).get_columns("sla_evaluations")):
        op.drop_column("sla_evaluations", "reference_binding_id")
