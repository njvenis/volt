"""Add durable independent health condition episodes and delivery outcomes."""

from alembic import context, op
from alembic.util.exc import CommandError
from sqlalchemy import BigInteger, CheckConstraint, Column, DateTime, ForeignKey, ForeignKeyConstraint, Integer, JSON, String, Uuid, UniqueConstraint, text

revision = "0012"
down_revision = "0011"
branch_labels = None
depends_on = None
_ID = Uuid(as_uuid=False)
_TZ = DateTime(timezone=True)

def _dialect():
    name = op.get_bind().dialect.name
    if name not in ("sqlite", "postgresql"):
        raise CommandError(f"0012 does not support {name}")

def upgrade():
    if context.is_offline_mode():
        raise CommandError("0012 upgrade requires an online additive migration")
    _dialect()
    op.create_table("health_occurrence_configs",
        Column("schedule_id", String, nullable=False), Column("schedule_revision", Integer, nullable=False),
        Column("source_family", String, nullable=False), Column("source_account_id", String, nullable=False),
        Column("scope_key", String, nullable=False), Column("anchor_at", _TZ, nullable=False),
        Column("effective_from", _TZ, nullable=False), Column("effective_until", _TZ),
        Column("interval_microseconds", BigInteger, nullable=False), Column("grace_microseconds", BigInteger, nullable=False),
        Column("notification_deadline_microseconds", BigInteger, nullable=False), Column("notification_policy_ref", String, nullable=False),
        Column("recorded_at", _TZ, nullable=False),
        ForeignKeyConstraint(["schedule_id", "schedule_revision"], ["collection_schedules.schedule_id", "collection_schedules.revision"], name="fk_health_occurrence_schedule"),
        UniqueConstraint("schedule_id", "schedule_revision", name="uq_health_occurrence_config_revision"),
        CheckConstraint("schedule_revision > 0 AND interval_microseconds > 0 AND grace_microseconds >= 0 AND notification_deadline_microseconds > 0", name="health_occurrence_config_durations_valid"))
    op.create_table("health_condition_episodes",
        Column("episode_id", _ID, primary_key=True), Column("schema_version", Integer, nullable=False),
        Column("subject_key", String, nullable=False), Column("condition", String, nullable=False),
        Column("severity", String, nullable=False), Column("detected_at", _TZ, nullable=False),
        Column("last_observed_at", _TZ, nullable=False), Column("recovered_at", _TZ),
        Column("state", String, nullable=False), Column("expected_run_id", _ID, ForeignKey("expected_runs.expected_run_id")),
        Column("run_id", _ID), Column("run_revision", Integer), Column("evidence", JSON, nullable=False),
        ForeignKeyConstraint(["run_id", "run_revision"], ["collection_runs.run_id", "collection_runs.revision"], name="fk_health_episode_run"),
        CheckConstraint("schema_version = 1", name="health_episode_schema_version_v1"),
        CheckConstraint("state IN ('open','recovered')", name="health_episode_state_known"),
        CheckConstraint("severity IN ('info','warning','critical')", name="health_episode_severity_known"))
    op.create_index("uq_health_condition_active_episode", "health_condition_episodes",
                    ["subject_key", "condition"], unique=True,
                    postgresql_where=text("state = 'open'"), sqlite_where=text("state = 'open'"))
    op.create_table("health_events",
        Column("event_id", _ID, primary_key=True), Column("schema_version", Integer, nullable=False),
        Column("episode_id", _ID, ForeignKey("health_condition_episodes.episode_id"), nullable=False),
        Column("condition", String, nullable=False), Column("severity", String, nullable=False),
        Column("detected_at", _TZ, nullable=False), Column("observed_at", _TZ, nullable=False),
        Column("state", String, nullable=False), Column("expected_run_id", _ID), Column("run_id", _ID), Column("run_revision", Integer),
        Column("evidence", JSON, nullable=False), UniqueConstraint("episode_id", "observed_at", name="uq_health_event_episode_observation"),
        ForeignKeyConstraint(["run_id", "run_revision"], ["collection_runs.run_id", "collection_runs.revision"], name="fk_health_event_run"),
        CheckConstraint("schema_version = 1", name="health_event_schema_version_v1"),
        CheckConstraint("state IN ('open','recovered')", name="health_event_state_known"))
    op.create_table("health_notification_intents",
        Column("intent_id", _ID, primary_key=True), Column("schema_version", Integer, nullable=False),
        Column("event_id", _ID, ForeignKey("health_events.event_id"), nullable=False),
        Column("created_at", _TZ, nullable=False), Column("state", String, nullable=False),
        Column("deadline_at", _TZ, nullable=False), Column("policy_ref", String, nullable=False),
        UniqueConstraint("event_id", name="uq_health_notification_intent_event"),
        CheckConstraint("schema_version = 1", name="health_notification_intent_schema_version_v1"),
        CheckConstraint("state IN ('pending','sent','cancelled')", name="health_notification_intent_state_known"))
    op.create_table("health_notification_deliveries",
        Column("delivery_id", _ID, primary_key=True), Column("schema_version", Integer, nullable=False),
        Column("event_id", _ID, ForeignKey("health_events.event_id"), nullable=False), Column("attempted_at", _TZ, nullable=False),
        Column("outcome", String, nullable=False), Column("failure_detail", String), Column("provider_ref", String),
        UniqueConstraint("event_id", "attempted_at", name="uq_health_notification_attempt"),
        CheckConstraint("schema_version = 1", name="health_notification_schema_version_v1"),
        CheckConstraint("outcome IN ('pending','delivered','failed')", name="health_notification_outcome_known"))

def downgrade():
    if context.is_offline_mode():
        raise CommandError("0012 downgrade requires online health history safety checks")
    _dialect()
    bind = op.get_bind()
    for table in ("health_notification_deliveries", "health_notification_intents", "health_events", "health_condition_episodes", "health_occurrence_configs"):
        if bind.execute(text(f"SELECT count(*) FROM {table}")).scalar_one():
            raise CommandError(f"refusing 0012 downgrade: {table} contains retained health data")
    op.drop_table("health_notification_deliveries")
    op.drop_table("health_notification_intents")
    op.drop_table("health_events")
    op.drop_index("uq_health_condition_active_episode", table_name="health_condition_episodes")
    op.drop_table("health_condition_episodes")
    op.drop_table("health_occurrence_configs")
