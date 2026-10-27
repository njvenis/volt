"""Pin report calculation authority at accepted command time."""
from alembic import op
import sqlalchemy as sa

revision = "0028"
down_revision = "0027"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("metrics_report_requests", sa.Column("assessment_policy_snapshot", sa.JSON(), nullable=True))


def downgrade():
    bind = op.get_bind()
    retained = bind.execute(sa.text("""
        SELECT count(*) FROM metrics_report_requests
        WHERE assessment_policy_snapshot IS NOT NULL
    """)).scalar_one()
    if retained:
        from alembic.util.exc import CommandError
        raise CommandError("refusing 0028 downgrade: report authority snapshots are retained evidence")
    op.drop_column("metrics_report_requests", "assessment_policy_snapshot")
