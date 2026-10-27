"""Separate authorised SLA heads from historical report derivations."""
from alembic import op
import sqlalchemy as sa

revision = "0030"
down_revision = "0029"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("sla_evaluations", sa.Column(
        "is_authoritative", sa.Boolean(), nullable=False, server_default=sa.true()))
    # Before this marker existed, historical as-of reports could append a
    # later revision that pointed back to an older evaluation while a newer
    # effective/known row already existed. Mark only such context-dominated
    # forks as report derivations; ordinary retroactive writers remain
    # authoritative when their known_at is later than the earlier row.
    op.execute(sa.text("""
        UPDATE sla_evaluations AS branch
        SET is_authoritative = false
        WHERE EXISTS (
            SELECT 1
            FROM sla_evaluations AS prior
            WHERE prior.episode_id = branch.episode_id
              AND prior.occurrence_id = branch.occurrence_id
              AND prior.revision < branch.revision
              AND prior.effective_at >= branch.effective_at
              AND prior.known_at >= branch.known_at
              AND (prior.effective_at > branch.effective_at
                   OR prior.known_at > branch.known_at)
        )
    """))


def downgrade():
    bind = op.get_bind()
    count = bind.execute(sa.text(
        "SELECT count(*) FROM sla_evaluations WHERE is_authoritative = false")).scalar_one()
    if count:
        from alembic.util.exc import CommandError
        raise CommandError("refusing 0030 downgrade: historical evaluation branches are retained")
    op.drop_column("sla_evaluations", "is_authoritative")
