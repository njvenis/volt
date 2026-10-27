"""Retain authenticated GitHub webhook delivery inputs for replay."""
from alembic import op
import sqlalchemy as sa

revision = "0036"
down_revision = "0035"
branch_labels = None
depends_on = None


def upgrade():
    from uvm.persistence.g4_schema import uvm_metadata
    uvm_metadata.tables["github_webhook_deliveries"].create(
        bind=op.get_bind(), checkfirst=False)


def downgrade():
    bind = op.get_bind()
    if bind.execute(sa.text("SELECT count(*) FROM github_webhook_deliveries")).scalar_one():
        from alembic.util.exc import CommandError
        raise CommandError("refusing 0036 downgrade while webhook delivery inputs are retained")
    from uvm.persistence.g4_schema import uvm_metadata
    uvm_metadata.tables["github_webhook_deliveries"].drop(bind=bind, checkfirst=False)
