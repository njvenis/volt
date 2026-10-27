"""Retain paginated GitHub issue events before advancing poll checkpoints."""

from alembic import op

revision = "0020"
down_revision = "0019"
branch_labels = None
depends_on = None


def upgrade():
    from uvm.persistence.g4_schema import github_external_events
    github_external_events.create(bind=op.get_bind(), checkfirst=False)


def downgrade():
    import sqlalchemy as sa
    from uvm.persistence.g4_schema import github_external_events
    bind = op.get_bind()
    if bind.execute(sa.text("SELECT count(*) FROM github_external_events")).scalar_one():
        from alembic.util.exc import CommandError
        raise CommandError("refusing 0020 downgrade: GitHub external event history exists")
    github_external_events.drop(bind=bind, checkfirst=False)
