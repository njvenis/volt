"""Retain approved warning envelopes, authority snapshots and callback retries."""
from alembic import op
import sqlalchemy as sa

revision = "0048"
down_revision = "0047"
branch_labels = None
depends_on = None

_INTENT_COLUMNS = (
    ("route_id", sa.Uuid(as_uuid=False)),
    ("destination_revision", sa.Integer()),
    ("approved_destination", sa.JSON()),
    ("approved_failure_alert_group_ids", sa.JSON()),
    ("rendered_payload", sa.JSON()),
    ("rendered_digest", sa.String()),
    ("template_version", sa.String()),
    ("acknowledged_policy_revision", sa.Integer()),
    ("acknowledged_group_revision", sa.Integer()),
    ("acknowledged_link_revision", sa.Integer()),
)


def upgrade():
    for name, column_type in _INTENT_COLUMNS:
        op.add_column("exception_warning_intents", sa.Column(name, column_type, nullable=True))
    for name in ("evaluated_policy_revision", "evaluated_group_revision",
                 "evaluated_route_revision", "evaluated_link_revision",
                 "evaluated_recipient_revision"):
        op.add_column("exception_warning_attempts", sa.Column(name, sa.Integer(), nullable=True))
    op.add_column("exception_warning_callback_inbox",
        sa.Column("attempt_count", sa.Integer(), nullable=False, server_default="0"))
    op.add_column("exception_warning_callback_inbox", sa.Column("next_attempt_at",
        sa.DateTime(timezone=True), nullable=True))
    op.add_column("exception_warning_callback_inbox", sa.Column("last_error", sa.String(), nullable=True))
    op.create_check_constraint("warning_callback_attempt_bounds",
        "exception_warning_callback_inbox", "attempt_count >= 0")


def downgrade():
    bind = op.get_bind()
    used = bind.execute(sa.text("""
        SELECT count(*) FROM exception_warning_intents
        WHERE route_id IS NOT NULL OR destination_revision IS NOT NULL
          OR approved_destination IS NOT NULL OR approved_failure_alert_group_ids IS NOT NULL
          OR rendered_payload IS NOT NULL
          OR rendered_digest IS NOT NULL OR template_version IS NOT NULL
          OR acknowledged_policy_revision IS NOT NULL
          OR acknowledged_group_revision IS NOT NULL
          OR acknowledged_link_revision IS NOT NULL
    """)).scalar_one()
    used += bind.execute(sa.text("""
        SELECT count(*) FROM exception_warning_attempts
        WHERE evaluated_policy_revision IS NOT NULL OR evaluated_group_revision IS NOT NULL
          OR evaluated_route_revision IS NOT NULL OR evaluated_link_revision IS NOT NULL
          OR evaluated_recipient_revision IS NOT NULL
    """)).scalar_one()
    used += bind.execute(sa.text("""
        SELECT count(*) FROM exception_warning_callback_inbox
        WHERE attempt_count > 0 OR next_attempt_at IS NOT NULL OR last_error IS NOT NULL
    """)).scalar_one()
    if used:
        from alembic.util.exc import CommandError
        raise CommandError("refusing 0048 downgrade: warning authority and delivery metadata is retained")
    op.drop_constraint("warning_callback_attempt_bounds", "exception_warning_callback_inbox",
        type_="check")
    op.drop_column("exception_warning_callback_inbox", "last_error")
    op.drop_column("exception_warning_callback_inbox", "next_attempt_at")
    op.drop_column("exception_warning_callback_inbox", "attempt_count")
    for name in ("evaluated_recipient_revision", "evaluated_link_revision",
                 "evaluated_route_revision", "evaluated_group_revision",
                 "evaluated_policy_revision"):
        op.drop_column("exception_warning_attempts", name)
    for name, _column_type in reversed(_INTENT_COLUMNS):
        op.drop_column("exception_warning_intents", name)
