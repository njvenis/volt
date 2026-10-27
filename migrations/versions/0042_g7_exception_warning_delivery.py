"""Durable retry scheduling and uncertainty for G7 warning deliveries."""
from alembic import op
import sqlalchemy as sa

revision = "0042"
down_revision = "0041"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("exception_warning_intents", sa.Column("next_attempt_at", sa.DateTime(timezone=True)))
    op.add_column("exception_warning_intents", sa.Column("max_attempts", sa.Integer(), nullable=False, server_default="5"))
    op.add_column("exception_warning_intents", sa.Column("retry_base_seconds", sa.Integer(), nullable=False, server_default="60"))
    op.add_column("exception_warning_intents", sa.Column("acknowledged_at", sa.DateTime(timezone=True)))
    op.add_column("exception_warning_intents", sa.Column("acknowledged_by", sa.String()))
    op.add_column("exception_warning_attempts", sa.Column("finished_at", sa.DateTime(timezone=True)))
    op.drop_constraint("exception_warning_status", "exception_warning_intents", type_="check")
    op.create_check_constraint("exception_warning_status", "exception_warning_intents",
        "status IN ('pending','sending','sent','failed','uncertain','missed','suppressed')")
    op.create_check_constraint("exception_warning_retry_bounds", "exception_warning_intents",
        "max_attempts BETWEEN 1 AND 20 AND retry_base_seconds BETWEEN 1 AND 3600")
    op.create_check_constraint("exception_warning_attempt_outcome", "exception_warning_attempts",
        "outcome IN ('sending','sent','failed','uncertain')")
    op.create_index("ix_exception_warning_due", "exception_warning_intents", ["status", "next_attempt_at"])


def downgrade():
    bind = op.get_bind()
    count = bind.execute(sa.text("SELECT count(*) FROM exception_warning_attempts WHERE outcome IN ('sending','uncertain')")).scalar_one()
    count += bind.execute(sa.text("SELECT count(*) FROM exception_warning_intents WHERE status IN ('sending','uncertain')")).scalar_one()
    if count:
        from alembic.util.exc import CommandError
        raise CommandError("refusing 0042 downgrade: ambiguous warning delivery history requires forward repair")
    op.drop_index("ix_exception_warning_due", table_name="exception_warning_intents")
    op.drop_constraint("exception_warning_attempt_outcome", "exception_warning_attempts", type_="check")
    op.drop_constraint("exception_warning_status", "exception_warning_intents", type_="check")
    op.drop_constraint("exception_warning_retry_bounds", "exception_warning_intents", type_="check")
    op.create_check_constraint("exception_warning_status", "exception_warning_intents",
        "status IN ('pending','sent','failed','missed','suppressed')")
    op.drop_column("exception_warning_attempts", "finished_at")
    op.drop_column("exception_warning_intents", "max_attempts")
    op.drop_column("exception_warning_intents", "retry_base_seconds")
    op.drop_column("exception_warning_intents", "acknowledged_at")
    op.drop_column("exception_warning_intents", "acknowledged_by")
    op.drop_column("exception_warning_intents", "next_attempt_at")
