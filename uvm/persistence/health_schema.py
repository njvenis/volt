"""Durable, source-neutral health condition and notification records."""

from sqlalchemy import (BigInteger, CheckConstraint, Column, DateTime, Integer,
                        JSON, String, Table, Uuid, UniqueConstraint, Index, and_,
                        ForeignKeyConstraint)

from uvm.persistence.schema import uvm_metadata
import uvm.persistence.ingestion_schema  # noqa: F401,E402

_ID = Uuid(as_uuid=False)
_TZ = DateTime(timezone=True)

health_occurrence_configs = Table(
    "health_occurrence_configs", uvm_metadata,
    Column("schedule_id", String, nullable=False), Column("schedule_revision", Integer, nullable=False),
    Column("source_family", String, nullable=False), Column("source_account_id", String, nullable=False),
    Column("scope_key", String, nullable=False), Column("anchor_at", _TZ, nullable=False),
    Column("effective_from", _TZ, nullable=False), Column("effective_until", _TZ, nullable=True),
    Column("interval_microseconds", BigInteger, nullable=False), Column("grace_microseconds", BigInteger, nullable=False),
    Column("notification_deadline_microseconds", BigInteger, nullable=False), Column("notification_policy_ref", String, nullable=False),
    Column("recorded_at", _TZ, nullable=False),
    ForeignKeyConstraint(["schedule_id", "schedule_revision"], ["collection_schedules.schedule_id", "collection_schedules.revision"], name="fk_health_occurrence_schedule"),
    UniqueConstraint("schedule_id", "schedule_revision", name="uq_health_occurrence_config_revision"),
    CheckConstraint("schedule_revision > 0 AND interval_microseconds > 0 AND grace_microseconds >= 0 AND notification_deadline_microseconds > 0", name="health_occurrence_config_durations_valid"),
)

health_condition_episodes = Table(
    "health_condition_episodes", uvm_metadata,
    Column("episode_id", _ID, primary_key=True),
    Column("schema_version", Integer, nullable=False),
    Column("subject_key", String, nullable=False),
    Column("condition", String, nullable=False),
    Column("severity", String, nullable=False),
    Column("detected_at", _TZ, nullable=False),
    Column("last_observed_at", _TZ, nullable=False),
    Column("recovered_at", _TZ, nullable=True),
    Column("state", String, nullable=False),
    Column("expected_run_id", _ID, nullable=True),
    Column("run_id", _ID, nullable=True),
    Column("run_revision", Integer, nullable=True),
    Column("evidence", JSON, nullable=False),
    ForeignKeyConstraint(["expected_run_id"], ["expected_runs.expected_run_id"], name="fk_health_episode_expected"),
    ForeignKeyConstraint(["run_id", "run_revision"], ["collection_runs.run_id", "collection_runs.revision"], name="fk_health_episode_run"),
    CheckConstraint("schema_version = 1", name="health_episode_schema_version_v1"),
    CheckConstraint("state IN ('open','recovered')", name="health_episode_state_known"),
    CheckConstraint("severity IN ('info','warning','critical')", name="health_episode_severity_known"),
)
Index("uq_health_condition_active_episode", health_condition_episodes.c.subject_key,
      health_condition_episodes.c.condition, unique=True,
      postgresql_where=health_condition_episodes.c.state == "open",
      sqlite_where=health_condition_episodes.c.state == "open")

health_events = Table(
    "health_events", uvm_metadata,
    Column("event_id", _ID, primary_key=True),
    Column("schema_version", Integer, nullable=False),
    Column("episode_id", _ID, nullable=False),
    Column("condition", String, nullable=False),
    Column("severity", String, nullable=False),
    Column("detected_at", _TZ, nullable=False),
    Column("observed_at", _TZ, nullable=False),
    Column("state", String, nullable=False),
    Column("expected_run_id", _ID, nullable=True),
    Column("run_id", _ID, nullable=True), Column("run_revision", Integer, nullable=True),
    Column("evidence", JSON, nullable=False),
    UniqueConstraint("episode_id", "observed_at", name="uq_health_event_episode_observation"),
    ForeignKeyConstraint(["episode_id"], ["health_condition_episodes.episode_id"], name="fk_health_event_episode"),
    ForeignKeyConstraint(["run_id", "run_revision"], ["collection_runs.run_id", "collection_runs.revision"], name="fk_health_event_run"),
    CheckConstraint("schema_version = 1", name="health_event_schema_version_v1"),
    CheckConstraint("state IN ('open','recovered')", name="health_event_state_known"),
)

notification_intents = Table(
    "health_notification_intents", uvm_metadata,
    Column("intent_id", _ID, primary_key=True), Column("schema_version", Integer, nullable=False),
    Column("event_id", _ID, nullable=False), Column("created_at", _TZ, nullable=False),
    Column("state", String, nullable=False),
    Column("deadline_at", _TZ, nullable=False), Column("policy_ref", String, nullable=False),
    ForeignKeyConstraint(["event_id"], ["health_events.event_id"], name="fk_health_notification_intent_event"),
    UniqueConstraint("event_id", name="uq_health_notification_intent_event"),
    CheckConstraint("schema_version = 1", name="health_notification_intent_schema_version_v1"),
    CheckConstraint("state IN ('pending','sent','cancelled')", name="health_notification_intent_state_known"),
)

notification_deliveries = Table(
    "health_notification_deliveries", uvm_metadata,
    Column("delivery_id", _ID, primary_key=True),
    Column("schema_version", Integer, nullable=False),
    Column("event_id", _ID, nullable=False),
    Column("attempted_at", _TZ, nullable=False),
    Column("outcome", String, nullable=False),
    Column("failure_detail", String, nullable=True),
    Column("provider_ref", String, nullable=True),
    UniqueConstraint("event_id", "attempted_at", name="uq_health_notification_attempt"),
    ForeignKeyConstraint(["event_id"], ["health_events.event_id"], name="fk_health_notification_event"),
    CheckConstraint("schema_version = 1", name="health_notification_schema_version_v1"),
    CheckConstraint("outcome IN ('pending','delivered','failed')", name="health_notification_outcome_known"),
)

ALL_HEALTH_TABLES = (health_occurrence_configs, health_condition_episodes, health_events, notification_intents, notification_deliveries)
