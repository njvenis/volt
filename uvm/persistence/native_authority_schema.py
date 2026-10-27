"""Durable reconciliation work created by native administration commands."""

from sqlalchemy import Column, DateTime, ForeignKey, Index, Integer, JSON, String, Table, Text, Uuid, UniqueConstraint

from uvm.persistence.schema import uvm_metadata

_ID = Uuid(as_uuid=False)
_TZ = DateTime(timezone=True)

administration_reconciliation_intents = Table(
    "administration_reconciliation_intents", uvm_metadata,
    Column("intent_id", _ID, primary_key=True),
    Column("audit_event_id", _ID, ForeignKey("assessment_audit_events.event_id"), nullable=False),
    Column("kind", String, nullable=False),
    Column("target_id", _ID, nullable=False),
    Column("authority_revision", Integer, nullable=False),
    Column("status", String, nullable=False),
    Column("attempts", Integer, nullable=False),
    Column("last_error", Text),
    Column("next_attempt_at", _TZ),
    Column("claimed_at", _TZ),
    Column("completed_at", _TZ),
    Column("result", JSON),
    Column("created_at", _TZ, nullable=False),
    Column("updated_at", _TZ, nullable=False),
    UniqueConstraint("audit_event_id", "kind", name="uq_admin_reconcile_event_kind"),
    Index("ix_admin_reconcile_status", "status", "created_at"),
)

__all__ = ["administration_reconciliation_intents"]
