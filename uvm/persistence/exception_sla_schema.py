"""Versioned G7 per-atom ingestion receipts, exception clocks and warnings."""
from sqlalchemy import (BigInteger, Boolean, CheckConstraint, Column, DateTime, ForeignKey,
                        Index, Integer, JSON, String, Table, Text, Uuid,
                        UniqueConstraint)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.types import TypeDecorator

from uvm.persistence.schema import uvm_metadata


class _PortableJSON(TypeDecorator):
    impl = JSON
    cache_ok = True

    def load_dialect_impl(self, dialect):
        return dialect.type_descriptor(JSONB() if dialect.name == "postgresql" else JSON())


_ID = Uuid(as_uuid=False)
_TZ = DateTime(timezone=True)
_JSON = _PortableJSON()

source_observation_receipts = Table(
    "source_observation_receipts", uvm_metadata,
    Column("receipt_id", _ID, primary_key=True),
    Column("source_observation_id", _ID, ForeignKey("source_observations.observation_id"),
           nullable=False, unique=True),
    Column("source_account_id", String, nullable=False),
    Column("run_id", String, nullable=False),
    Column("source_record_ordinal", Integer, nullable=False),
    Column("retention_operation_id", _ID, nullable=False),
    Column("retained_at", _TZ, nullable=False),
    Column("source_observed_at", _TZ),
    Column("source_collected_at", _TZ, nullable=False),
    Column("created_at", _TZ, nullable=False),
    UniqueConstraint("source_observation_id", "source_account_id", "run_id",
        "source_record_ordinal", name="uq_source_observation_receipt_position"),
    Index("ix_source_observation_receipt_retained_at", "retained_at"),
)

sla_ingest_receipts = Table(
    "sla_ingest_receipts", uvm_metadata,
    Column("receipt_id", _ID, primary_key=True),
    Column("retention_receipt_id", _ID,
        ForeignKey("source_observation_receipts.receipt_id"), unique=True),
    Column("episode_id", _ID, nullable=False),
    Column("occurrence_id", _ID, nullable=False),
    Column("ingested_at", _TZ, nullable=False),
    Column("source_observation_id", _ID),
    Column("source_observed_at", _TZ),
    Column("source_collected_at", _TZ),
    Column("ingest_operation_id", _ID, nullable=False),
    Column("policy_id", String),
    Column("policy_version", Integer),
    Column("created_at", _TZ, nullable=False),
    UniqueConstraint("episode_id", "occurrence_id", name="uq_sla_ingest_receipt_atom"),
    UniqueConstraint("ingest_operation_id", "occurrence_id", name="uq_sla_ingest_receipt_operation"),
    Index("ix_sla_ingest_receipt_context", "episode_id", "ingested_at"),
)

sla_episode_contracts = Table(
    "sla_episode_contracts", uvm_metadata,
    Column("episode_id", _ID, primary_key=True),
    Column("contract_version", Integer, nullable=False),
    Column("start_source", String, nullable=False),
    Column("retention_receipt_id", _ID,
        ForeignKey("source_observation_receipts.receipt_id")),
    Column("policy_id", String),
    Column("policy_version", Integer),
    Column("pinned_at", _TZ, nullable=False),
    Column("created_at", _TZ, nullable=False),
    CheckConstraint("contract_version IN (5,7)", name="sla_episode_contract_version"),
    CheckConstraint("(contract_version = 7 AND start_source = 'uvm_ingest_commit_v1' AND policy_id IS NOT NULL AND policy_version IS NOT NULL) OR (contract_version = 5 AND start_source = 'source_observation_v1')",
        name="sla_episode_contract_consistency"),
)

sla_clock_events = Table(
    "sla_clock_events", uvm_metadata,
    Column("event_id", _ID, primary_key=True),
    Column("episode_id", _ID, nullable=False),
    Column("occurrence_id", _ID, nullable=False),
    Column("sequence", BigInteger, nullable=False),
    Column("event_type", String, nullable=False),
    Column("effective_at", _TZ, nullable=False),
    Column("recorded_at", _TZ, nullable=False),
    Column("ingest_receipt_id", _ID, ForeignKey("sla_ingest_receipts.receipt_id")),
    Column("decision_id", _ID),
    Column("membership_ids", _JSON, nullable=False),
    Column("policy_id", String),
    Column("policy_version", Integer),
    Column("evaluation_revision", Integer, nullable=False),
    Column("predecessor_event_id", _ID),
    Column("data", _JSON, nullable=False),
    UniqueConstraint("episode_id", "occurrence_id", "sequence", name="uq_sla_clock_atom_sequence"),
    CheckConstraint("event_type IN ('started','paused','resumed','revoked','suspended','completed')",
                    name="sla_clock_event_type"),
    Index("ix_sla_clock_atom_time", "episode_id", "occurrence_id", "effective_at", "sequence"),
)

exception_warning_intents = Table(
    "exception_warning_intents", uvm_metadata,
    Column("intent_id", _ID, primary_key=True),
    Column("decision_id", _ID, nullable=False),
    Column("expiry_revision", Integer, nullable=False),
    Column("offset_seconds", Integer, nullable=False),
    Column("channel", String, nullable=False),
    Column("destination_ref", Text, nullable=False),
    Column("status", String, nullable=False),
    Column("suppression_reason", String),
    Column("due_at", _TZ, nullable=False),
    Column("next_attempt_at", _TZ),
    Column("max_attempts", Integer, nullable=False, server_default="5"),
    Column("retry_base_seconds", Integer, nullable=False, server_default="60"),
    Column("acknowledged_at", _TZ),
    Column("acknowledged_by", String),
    Column("created_at", _TZ, nullable=False),
    Column("updated_at", _TZ, nullable=False),
    Column("route_revision", Integer),
    Column("recipient_id", String),
    Column("provider_receipt_basis", String),
    Column("provider_channel_id", String),
    Column("provider_message_id", String),
    Column("action_token", String),
    Column("action_token_hash", String),
    Column("payload_digest", String),
    Column("route_id", _ID),
    Column("destination_revision", Integer),
    Column("approved_destination", _JSON),
    Column("approved_failure_alert_group_ids", _JSON),
    Column("rendered_payload", _JSON),
    Column("rendered_digest", String),
    Column("template_version", String),
    Column("acknowledged_policy_revision", Integer),
    Column("acknowledged_group_revision", Integer),
    Column("acknowledged_link_revision", Integer),
    UniqueConstraint("decision_id", "expiry_revision", "offset_seconds", "channel", "destination_ref",
                     name="uq_exception_warning_key"),
    CheckConstraint("channel IN ('slack','email')", name="exception_warning_channel"),
    CheckConstraint("status IN ('pending','sending','sent','failed','uncertain','missed','suppressed','legacy_route_unresolved')", name="exception_warning_status"),
    CheckConstraint("max_attempts BETWEEN 1 AND 20 AND retry_base_seconds BETWEEN 1 AND 3600",
                    name="exception_warning_retry_bounds"),
)

exception_warning_attempts = Table(
    "exception_warning_attempts", uvm_metadata,
    Column("attempt_id", _ID, primary_key=True),
    Column("intent_id", _ID, ForeignKey("exception_warning_intents.intent_id"), nullable=False),
    Column("attempt_number", Integer, nullable=False),
    Column("attempted_at", _TZ, nullable=False),
    Column("outcome", String, nullable=False),
    Column("receipt", Text),
    Column("error", Text),
    Column("finished_at", _TZ),
    Column("evaluated_policy_revision", Integer),
    Column("evaluated_group_revision", Integer),
    Column("evaluated_route_revision", Integer),
    Column("evaluated_link_revision", Integer),
    Column("evaluated_recipient_revision", Integer),
    UniqueConstraint("intent_id", "attempt_number", name="uq_exception_warning_attempt"),
    CheckConstraint("outcome IN ('sending','sent','failed','uncertain')",
                    name="exception_warning_attempt_outcome"),
)

# Versioned native delivery configuration and signed Slack receipt ingress.
# Connector secrets are referenced by name and are never stored in these rows.
exception_warning_routes = Table(
    "exception_warning_routes", uvm_metadata,
    Column("route_id", _ID, primary_key=True),
    Column("revision", Integer, primary_key=True),
    Column("installation_id", String, nullable=False),
    Column("workspace_id", String, nullable=False),
    Column("channel_id", String, nullable=False),
    Column("recipient_id", String, nullable=False),
    Column("destination_ref", String, nullable=False),
    Column("access_group_ids", _JSON, nullable=False),
    Column("configuration", _JSON, nullable=False),
    Column("enabled", Boolean, nullable=False),
    Column("created_at", _TZ, nullable=False),
    Column("updated_at", _TZ, nullable=False),
    UniqueConstraint("route_id", "revision", name="uq_exception_warning_route_revision"),
)

exception_warning_actor_links = Table(
    "exception_warning_actor_links", uvm_metadata,
    Column("link_id", _ID, primary_key=True),
    Column("installation_id", String, nullable=False),
    Column("workspace_id", String, nullable=False),
    Column("slack_user_id", String, nullable=False),
    Column("principal_id", String, nullable=False),
    Column("revision", Integer, nullable=False),
    Column("enabled", Boolean, nullable=False),
    Column("created_at", _TZ, nullable=False),
    Column("updated_at", _TZ, nullable=False),
    UniqueConstraint("installation_id", "workspace_id", "slack_user_id", "revision",
                     name="uq_warning_actor_link_revision"),
)

exception_warning_callback_inbox = Table(
    "exception_warning_callback_inbox", uvm_metadata,
    Column("inbox_id", _ID, primary_key=True),
    Column("installation_id", String, nullable=False),
    Column("body_sha256", String, nullable=False),
    Column("payload", _JSON, nullable=False),
    Column("state", String, nullable=False),
    Column("result", _JSON),
    Column("received_at", _TZ, nullable=False),
    Column("processed_at", _TZ),
    Column("attempt_count", Integer, nullable=False, server_default="0"),
    Column("next_attempt_at", _TZ),
    Column("last_error", String),
    UniqueConstraint("installation_id", "body_sha256", name="uq_warning_callback_replay"),
    CheckConstraint("state IN ('received','processed','denied')", name="warning_callback_state"),
)

exception_warning_failure_alerts = Table(
    "exception_warning_failure_alerts", uvm_metadata,
    Column("alert_id", _ID, primary_key=True),
    Column("intent_id", _ID, ForeignKey("exception_warning_intents.intent_id"), nullable=False),
    Column("attempt_id", _ID, ForeignKey("exception_warning_attempts.attempt_id"), nullable=False),
    Column("group_id", _ID, nullable=False),
    Column("reason", String, nullable=False),
    Column("created_at", _TZ, nullable=False),
    UniqueConstraint("attempt_id", name="uq_warning_failure_alert_attempt"),
)

ALL_EXCEPTION_SLA_TABLES = (source_observation_receipts, sla_ingest_receipts, sla_episode_contracts, sla_clock_events,
                             exception_warning_intents, exception_warning_attempts,
                             exception_warning_routes, exception_warning_actor_links,
                             exception_warning_callback_inbox, exception_warning_failure_alerts)
