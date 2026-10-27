"""Durable projection of independently journalled G7 operational incidents."""
from sqlalchemy import (BigInteger, Boolean, CheckConstraint, Column, DateTime, Integer,
                        JSON, String, Table, UniqueConstraint, Index, Uuid,
                        ForeignKeyConstraint)
from uvm.persistence.schema import groups, uvm_metadata


g7_incident_streams = Table(
    "g7_incident_streams", uvm_metadata,
    Column("deployment_id", String, primary_key=True),
    Column("subject_id", String, primary_key=True),
    Column("condition", String, primary_key=True),
    Column("last_sequence", BigInteger, nullable=False),
    Column("last_transition_id", String, nullable=True),
    Column("active_episode_id", String, nullable=True),
    Column("episode_generation", BigInteger, nullable=False),
    Column("producer_id", String, nullable=False),
    Column("producer_revision", Integer, nullable=False),
    Column("updated_at", DateTime(timezone=True), nullable=False),
    CheckConstraint("last_sequence >= 0 AND episode_generation >= 0",
                    name="g7_incident_stream_position_valid"),
)

g7_incident_service_bindings = Table(
    "g7_incident_service_bindings", uvm_metadata,
    Column("principal_id", String, primary_key=True),
    Column("deployment_id", String, primary_key=True),
    Column("subject_id", String, primary_key=True),
    Column("condition", String, primary_key=True),
    Column("subject_type", String, nullable=False),
    Column("producer_id", String, nullable=False),
    Column("producer_revision", Integer, nullable=False),
    Column("configuration_revision", Integer, nullable=False),
    Column("enabled", Boolean, nullable=False),
    CheckConstraint("configuration_revision > 0", name="g7_incident_binding_revision_valid"),
)

g7_incident_routes = Table(
    "g7_incident_routes", uvm_metadata,
    Column("route_id", String, primary_key=True),
    Column("revision", Integer, primary_key=True),
    Column("deployment_id", String, nullable=False),
    Column("subject_id", String, nullable=True),
    Column("recipient_access_group_id", String, nullable=False),
    Column("vulnerability_group_id", Uuid(as_uuid=False), nullable=True),
    Column("source_family", String, nullable=False),
    Column("source_account_id", String, nullable=False),
    Column("scope_key", String, nullable=False),
    Column("enabled", Boolean, nullable=False),
    ForeignKeyConstraint(["vulnerability_group_id"], ["groups.group_id"],
                         name="fk_g7_incident_route_vulnerability_group"),
    CheckConstraint("revision > 0", name="g7_incident_route_revision_valid"),
)
Index("uq_g7_incident_route_current", g7_incident_routes.c.route_id, unique=True,
      postgresql_where=g7_incident_routes.c.enabled.is_(True),
      sqlite_where=g7_incident_routes.c.enabled.is_(True))

g7_incident_transitions = Table(
    "g7_incident_transitions", uvm_metadata,
    Column("transition_id", String, primary_key=True),
    Column("deployment_id", String, nullable=False),
    Column("subject_id", String, nullable=False),
    Column("condition", String, nullable=False),
    Column("transition_sequence", BigInteger, nullable=False),
    Column("predecessor_id", String, nullable=True),
    Column("episode_id", String, nullable=False),
    Column("opening_transition_id", String, nullable=False),
    Column("episode_generation", BigInteger, nullable=False),
    Column("transition_kind", String, nullable=False),
    Column("configuration_revision", Integer, nullable=False),
    Column("first_detected_at", DateTime(timezone=True), nullable=False),
    Column("observed_at", DateTime(timezone=True), nullable=False),
    Column("recovered_at", DateTime(timezone=True), nullable=True),
    Column("evidence_refs", JSON, nullable=False),
    Column("payload_digest", String(64), nullable=False),
    Column("producer_id", String, nullable=False),
    UniqueConstraint("deployment_id", "subject_id", "condition", "transition_sequence",
                     name="uq_g7_incident_stream_sequence"),
    CheckConstraint("transition_sequence > 0 AND episode_generation > 0",
                    name="g7_incident_transition_position_valid"),
    CheckConstraint("transition_kind IN ('opened','observed','recovered')",
                    name="g7_incident_transition_kind_known"),
)
Index("ix_g7_incident_transition_observed", g7_incident_transitions.c.observed_at,
      g7_incident_transitions.c.transition_id)

g7_incident_projection_receipts = Table(
    "g7_incident_projection_receipts", uvm_metadata,
    Column("transition_id", String, primary_key=True),
    Column("payload_digest", String(64), nullable=False),
    Column("received_at", DateTime(timezone=True), nullable=False),
    Column("result", JSON, nullable=False),
    ForeignKeyConstraint(["transition_id"], ["g7_incident_transitions.transition_id"],
                         name="fk_g7_incident_receipt_transition"),
)

g7_incident_notification_intents = Table(
    "g7_incident_notification_intents", uvm_metadata,
    Column("transition_id", String, primary_key=True),
    Column("state", String, nullable=False),
    Column("created_at", DateTime(timezone=True), nullable=False),
    Column("updated_at", DateTime(timezone=True), nullable=False),
    Column("receipt_basis", String, nullable=False),
    ForeignKeyConstraint(["transition_id"], ["g7_incident_transitions.transition_id"],
                         name="fk_g7_incident_intent_transition"),
    CheckConstraint("state IN ('pending','accepted','failed','uncertain')",
                    name="g7_incident_notification_state_known"),
)

g7_incident_notification_attempts = Table(
    "g7_incident_notification_attempts", uvm_metadata,
    Column("attempt_id", String, primary_key=True),
    Column("transition_id", String, nullable=False),
    Column("attempted_at", DateTime(timezone=True), nullable=False),
    Column("outcome", String, nullable=False),
    Column("receipt_ref", String, nullable=True),
    Column("failure_detail", String, nullable=True),
    ForeignKeyConstraint(["transition_id"], ["g7_incident_transitions.transition_id"],
                         name="fk_g7_incident_attempt_transition"),
    CheckConstraint("outcome IN ('accepted','failed','uncertain')",
                    name="g7_incident_notification_attempt_known"),
    Index("ix_g7_incident_attempt_order", "transition_id", "attempted_at", "attempt_id"),
)

ALL_G7_INCIDENT_TABLES = (g7_incident_service_bindings, g7_incident_streams, g7_incident_transitions,
    g7_incident_projection_receipts, g7_incident_notification_intents,
    g7_incident_notification_attempts)
