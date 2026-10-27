"""Pin the retained source-observation boundary for report projection retries."""
from alembic import op
import sqlalchemy as sa

revision = "0026"
down_revision = "0025"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("metrics_report_requests", sa.Column(
        "source_retention_watermark", sa.BigInteger(), nullable=False, server_default="0"))


def downgrade():
    bind = op.get_bind()
    if bind.execute(sa.text(
            "SELECT count(*) FROM metrics_report_requests WHERE source_retention_watermark > 0"
    )).scalar_one():
        from alembic.util.exc import CommandError
        raise CommandError("refusing 0026 downgrade: report source snapshot boundaries are retained")
    op.drop_column("metrics_report_requests", "source_retention_watermark")
