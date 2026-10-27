"""Append-only history for configured GitHub audience/repository policy."""

from alembic import op

revision = "0019"
down_revision = "0018"
branch_labels = None
depends_on = None


def upgrade():
    from uvm.persistence.g4_schema import github_repository_events
    github_repository_events.create(bind=op.get_bind(), checkfirst=False)


def downgrade():
    import sqlalchemy as sa
    from uvm.persistence.g4_schema import github_repository_events
    bind = op.get_bind()
    if bind.execute(sa.text("SELECT count(*) FROM github_repository_events")).scalar_one():
        from alembic.util.exc import CommandError
        raise CommandError("refusing 0019 downgrade: GitHub repository history exists")
    github_repository_events.drop(bind=bind, checkfirst=False)
