"""Persist exact scanner request reservations before outbound calls."""
from alembic import op
import sqlalchemy as sa

revision = "0060"
down_revision = "0059"
branch_labels = None
depends_on = None


def upgrade():
    uuid = sa.Uuid(as_uuid=False)
    op.create_table("collection_request_reservations",
        sa.Column("reservation_id", uuid, primary_key=True),
        sa.Column("run_id", uuid, nullable=False),
        sa.Column("run_revision", sa.Integer(), nullable=False),
        sa.Column("attempt_no", sa.Integer(), nullable=False),
        sa.Column("page_ordinal", sa.Integer(), nullable=False),
        sa.Column("request_identity_sha256", sa.String(64), nullable=False),
        sa.Column("reserved_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["run_id", "run_revision"],
            ["collection_runs.run_id", "collection_runs.revision"],
            name="fk_collection_request_reservation_run"),
        sa.UniqueConstraint("run_id", "attempt_no",
            name="uq_collection_request_reservation_attempt"),
        sa.CheckConstraint("attempt_no > 0 AND page_ordinal > 0",
            name="collection_request_reservation_position_valid"),
        sa.CheckConstraint("length(request_identity_sha256) = 64",
            name="collection_request_reservation_digest_valid"))


def downgrade():
    bind = op.get_bind()
    if bind.execute(sa.text("SELECT count(*) FROM collection_request_reservations")).scalar_one():
        from alembic.util.exc import CommandError
        raise CommandError("refusing 0060 downgrade: scanner request reservations are immutable history")
    op.drop_table("collection_request_reservations")
