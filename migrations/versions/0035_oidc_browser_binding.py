"""Bind one-use OIDC state to the initiating browser cookie."""
from alembic import op
import sqlalchemy as sa

revision = "0035"
down_revision = "0034"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("oidc_authorization_states",
        sa.Column("browser_binding_hash", sa.String(length=64), nullable=True))


def downgrade():
    bind = op.get_bind()
    if bind.execute(sa.text("SELECT count(*) FROM oidc_authorization_states")).scalar_one():
        from alembic.util.exc import CommandError
        raise CommandError("refusing 0035 downgrade while browser-bound OIDC states are retained")
    op.drop_column("oidc_authorization_states", "browser_binding_hash")
