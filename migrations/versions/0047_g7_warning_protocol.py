"""Persist versioned warning routes, Slack receipts, callback inbox and alerts.

Legacy pending/failed intents cannot be safely redirected to a newly configured
provider. In-flight legacy sends become uncertain; completed fixture receipts
retain their historical meaning.
"""
from alembic import op
import sqlalchemy as sa

revision = "0047"
down_revision = "0046"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("exception_warning_intents", sa.Column("route_revision", sa.Integer(), nullable=True))
    op.add_column("exception_warning_intents", sa.Column("recipient_id", sa.String(), nullable=True))
    op.add_column("exception_warning_intents", sa.Column("provider_receipt_basis", sa.String(), nullable=True))
    op.add_column("exception_warning_intents", sa.Column("provider_channel_id", sa.String(), nullable=True))
    op.add_column("exception_warning_intents", sa.Column("provider_message_id", sa.String(), nullable=True))
    op.add_column("exception_warning_intents", sa.Column("action_token", sa.String(), nullable=True))
    op.add_column("exception_warning_intents", sa.Column("action_token_hash", sa.String(), nullable=True))
    op.add_column("exception_warning_intents", sa.Column("payload_digest", sa.String(), nullable=True))
    op.drop_constraint("exception_warning_status", "exception_warning_intents", type_="check")
    op.create_check_constraint("exception_warning_status", "exception_warning_intents",
        "status IN ('pending','sending','sent','failed','uncertain','missed','suppressed','legacy_route_unresolved')")
    op.execute(sa.text("""
        UPDATE exception_warning_intents
        SET status = CASE WHEN status IN ('pending','failed') THEN 'legacy_route_unresolved'
                          WHEN status = 'sending' THEN 'uncertain' ELSE status END,
            suppression_reason = CASE WHEN status IN ('pending','failed')
                THEN 'legacy_route_unresolved' WHEN status = 'sending'
                THEN 'legacy_send_outcome_uncertain' ELSE suppression_reason END,
            next_attempt_at = CASE WHEN status IN ('pending','failed','sending') THEN NULL ELSE next_attempt_at END,
            updated_at = now()
        WHERE status IN ('pending','failed','sending')
    """))
    op.execute(sa.text("""
        UPDATE exception_warning_attempts SET outcome='uncertain',
            error=COALESCE(error, 'legacy send outcome uncertain; reconcile before retry'),
            finished_at=COALESCE(finished_at, now()) WHERE outcome='sending'
    """))
    op.create_table("exception_warning_routes",
        sa.Column("route_id", sa.Uuid(as_uuid=False), nullable=False),
        sa.Column("revision", sa.Integer(), nullable=False),
        sa.Column("installation_id", sa.String(), nullable=False),
        sa.Column("workspace_id", sa.String(), nullable=False),
        sa.Column("channel_id", sa.String(), nullable=False),
        sa.Column("recipient_id", sa.String(), nullable=False),
        sa.Column("destination_ref", sa.String(), nullable=False),
        sa.Column("access_group_ids", sa.JSON(), nullable=False),
        sa.Column("configuration", sa.JSON(), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("route_id", "revision", name="pk_exception_warning_route_revision"),
        sa.CheckConstraint("revision > 0", name="ck_exception_warning_route_revision"))
    op.create_table("exception_warning_actor_links",
        sa.Column("link_id", sa.Uuid(as_uuid=False), nullable=False),
        sa.Column("installation_id", sa.String(), nullable=False),
        sa.Column("workspace_id", sa.String(), nullable=False),
        sa.Column("slack_user_id", sa.String(), nullable=False),
        sa.Column("principal_id", sa.String(), nullable=False),
        sa.Column("revision", sa.Integer(), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("link_id"),
        sa.UniqueConstraint("installation_id", "workspace_id", "slack_user_id", "revision",
                            name="uq_warning_actor_link_revision"),
        sa.CheckConstraint("revision > 0", name="ck_warning_actor_link_revision"))
    op.create_table("exception_warning_callback_inbox",
        sa.Column("inbox_id", sa.Uuid(as_uuid=False), nullable=False),
        sa.Column("installation_id", sa.String(), nullable=False),
        sa.Column("body_sha256", sa.String(), nullable=False),
        sa.Column("payload", sa.JSON(), nullable=False),
        sa.Column("state", sa.String(), nullable=False),
        sa.Column("result", sa.JSON()),
        sa.Column("received_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("processed_at", sa.DateTime(timezone=True)),
        sa.PrimaryKeyConstraint("inbox_id"),
        sa.UniqueConstraint("installation_id", "body_sha256", name="uq_warning_callback_replay"),
        sa.CheckConstraint("state IN ('received','processed','denied')", name="warning_callback_state"))
    op.create_table("exception_warning_failure_alerts",
        sa.Column("alert_id", sa.Uuid(as_uuid=False), nullable=False),
        sa.Column("intent_id", sa.Uuid(as_uuid=False), nullable=False),
        sa.Column("attempt_id", sa.Uuid(as_uuid=False), nullable=False),
        sa.Column("group_id", sa.Uuid(as_uuid=False), nullable=False),
        sa.Column("reason", sa.String(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["intent_id"], ["exception_warning_intents.intent_id"]),
        sa.ForeignKeyConstraint(["attempt_id"], ["exception_warning_attempts.attempt_id"]),
        sa.PrimaryKeyConstraint("alert_id"),
        sa.UniqueConstraint("attempt_id", name="uq_warning_failure_alert_attempt"))


def downgrade():
    count = op.get_bind().execute(sa.text("SELECT count(*) FROM exception_warning_routes")).scalar_one()
    count += op.get_bind().execute(sa.text("SELECT count(*) FROM exception_warning_actor_links")).scalar_one()
    count += op.get_bind().execute(sa.text("SELECT count(*) FROM exception_warning_callback_inbox")).scalar_one()
    count += op.get_bind().execute(sa.text("SELECT count(*) FROM exception_warning_failure_alerts")).scalar_one()
    count += op.get_bind().execute(sa.text("""
        SELECT count(*) FROM exception_warning_intents
        WHERE route_revision IS NOT NULL
           OR recipient_id IS NOT NULL
           OR provider_receipt_basis IS NOT NULL
           OR provider_channel_id IS NOT NULL
           OR provider_message_id IS NOT NULL
           OR action_token IS NOT NULL
           OR action_token_hash IS NOT NULL
           OR payload_digest IS NOT NULL
    """)).scalar_one()
    if count:
        from alembic.util import CommandError
        raise CommandError("refusing 0047 downgrade: warning protocol history is retained")
    op.drop_table("exception_warning_failure_alerts")
    op.drop_table("exception_warning_callback_inbox")
    op.drop_table("exception_warning_actor_links")
    op.drop_table("exception_warning_routes")
    op.drop_column("exception_warning_intents", "payload_digest")
    op.drop_column("exception_warning_intents", "action_token_hash")
    op.drop_column("exception_warning_intents", "action_token")
    op.drop_column("exception_warning_intents", "provider_message_id")
    op.drop_column("exception_warning_intents", "provider_channel_id")
    op.drop_column("exception_warning_intents", "provider_receipt_basis")
    op.drop_column("exception_warning_intents", "recipient_id")
    op.drop_column("exception_warning_intents", "route_revision")
    op.drop_constraint("exception_warning_status", "exception_warning_intents", type_="check")
    op.create_check_constraint("exception_warning_status", "exception_warning_intents",
        "status IN ('pending','sending','sent','failed','uncertain','missed','suppressed')")
