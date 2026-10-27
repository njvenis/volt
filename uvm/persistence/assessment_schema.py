"""Durable G3 assessment command, audit, intent and replay metadata."""

from sqlalchemy import (BigInteger, Column, DateTime, ForeignKey, Index, Integer,
                        JSON, String, Table, Text, Uuid, UniqueConstraint)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.types import TypeDecorator

from uvm.persistence.schema import groups, uvm_metadata
from uvm.persistence.native_authority_schema import administration_reconciliation_intents


class _PortableJSON(TypeDecorator):
    impl = JSON
    cache_ok = True

    def load_dialect_impl(self, dialect):
        return dialect.type_descriptor(JSONB() if dialect.name == "postgresql" else JSON())


_ID = Uuid(as_uuid=False)
_TZ = DateTime(timezone=True)
_JSON = _PortableJSON()

assessment_policy = Table(
    "assessment_policy", uvm_metadata,
    Column("policy_id", Integer, primary_key=True),
    Column("revision", Integer, nullable=False),
    Column("document", _JSON, nullable=False),
    Column("updated_at", _TZ, nullable=False),
    Column("updated_by", String, nullable=False),
)

assessment_group_state = Table(
    "assessment_group_state", uvm_metadata,
    Column("group_id", _ID, ForeignKey("groups.group_id"), primary_key=True),
    Column("revision", Integer, nullable=False),
    Column("document", _JSON, nullable=False),
    Column("updated_at", _TZ, nullable=False),
)

assessment_audit_events = Table(
    "assessment_audit_events", uvm_metadata,
    Column("event_id", _ID, primary_key=True),
    Column("event_sequence", BigInteger, nullable=False, unique=True),
    Column("actor_id", String, nullable=False),
    Column("actor_kind", String, nullable=False),
    Column("origin", String, nullable=False),
    Column("action", String, nullable=False),
    Column("target_id", _ID, nullable=False),
    Column("before_value", _JSON, nullable=False),
    Column("after_value", _JSON, nullable=False),
    Column("membership_ids", _JSON, nullable=False),
    Column("membership_revision", Integer, nullable=False),
    Column("rationale", Text, nullable=False),
    Column("evidence_ref", Text, nullable=False),
    Column("policy_revision", Integer, nullable=False),
    Column("identity_revision", Integer, nullable=False),
    Column("occurred_at", _TZ, nullable=False),
    Column("received_at", _TZ, nullable=False),
    Column("correlation_id", _ID, nullable=False),
    Column("command_id", _ID, nullable=False),
    # Separate evaluated OIDC/session/group revisions.  The older
    # identity_revision above remains workload membership only.
    Column("authorization_context", _JSON, nullable=True),
    Index("ix_assessment_audit_target_sequence", "target_id", "event_sequence"),
)

assessment_command_receipts = Table(
    "assessment_command_receipts", uvm_metadata,
    Column("command_id", _ID, primary_key=True),
    Column("principal_id", String, nullable=False),
    Column("action", String, nullable=False),
    Column("target_id", _ID, nullable=False),
    Column("request_digest", String(64), nullable=False),
    Column("decision_id", _ID, nullable=False),
    Column("audit_event_id", _ID, ForeignKey("assessment_audit_events.event_id"), nullable=False),
    Column("intent_id", _ID, nullable=True),
    Column("result", _JSON, nullable=False),
    Column("created_at", _TZ, nullable=False),
    Column("authorization_context", _JSON, nullable=True),
)

assessment_projection_intents = Table(
    "assessment_projection_intents", uvm_metadata,
    Column("intent_id", _ID, primary_key=True),
    Column("event_id", _ID, ForeignKey("assessment_audit_events.event_id"), nullable=False),
    Column("target_id", _ID, nullable=False),
    Column("membership_ids", _JSON, nullable=False),
    Column("status", String, nullable=False),
    Column("created_at", _TZ, nullable=False),
    UniqueConstraint("event_id", name="uq_assessment_intent_event"),
)

assessment_export_acknowledgements = Table(
    "assessment_export_acknowledgements", uvm_metadata,
    Column("event_id", _ID, ForeignKey("assessment_audit_events.event_id"), primary_key=True),
    Column("sink_receipt", String, nullable=False),
    Column("acknowledged_at", _TZ, nullable=False),
)

# Independent sink receipts coexist with the legacy host archive receipt above.
# A composite key keeps each destination's durable acknowledgement separate.
assessment_sink_export_receipts = Table(
    "assessment_sink_export_receipts", uvm_metadata,
    Column("event_id", _ID, ForeignKey("assessment_audit_events.event_id"), primary_key=True),
    Column("sink_id", String, primary_key=True),
    Column("sink_receipt", String, nullable=False),
    Column("acknowledged_at", _TZ, nullable=False),
)

ALL_ASSESSMENT_TABLES = (assessment_policy, assessment_group_state,
                         assessment_audit_events, assessment_command_receipts,
                         assessment_projection_intents,
                         assessment_export_acknowledgements,
                         assessment_sink_export_receipts,
                         administration_reconciliation_intents)
