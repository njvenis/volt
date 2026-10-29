"""Record bounded raw byte sizes for registered scanner evidence."""
from alembic import op
import sqlalchemy as sa

revision = "0061"
down_revision = "0060"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("ingestion_evidence", sa.Column("byte_size", sa.BigInteger(), nullable=True))
    op.create_check_constraint("ingestion_evidence_byte_size_valid", "ingestion_evidence",
        "byte_size IS NULL OR byte_size BETWEEN 0 AND 16777216")


def downgrade():
    bind = op.get_bind()
    if bind.execute(sa.text("SELECT count(*) FROM ingestion_evidence WHERE byte_size IS NOT NULL")).scalar_one():
        from alembic.util.exc import CommandError
        raise CommandError("refusing 0061 downgrade: verified scanner evidence sizes are retained")
    op.drop_constraint("ingestion_evidence_byte_size_valid", "ingestion_evidence", type_="check")
    op.drop_column("ingestion_evidence", "byte_size")
