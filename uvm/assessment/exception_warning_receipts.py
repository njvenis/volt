"""Shared, transaction-bound receipt-only acknowledgement service."""
from __future__ import annotations

import uuid

import sqlalchemy as sa

from uvm.persistence.assessment_schema import assessment_audit_events, assessment_group_state
from uvm.persistence.exception_sla_schema import exception_warning_intents


def acknowledge_warning_receipt(connection, *, intent_id: str, principal_id: str,
                                group_id: str, policy_revision: int,
                                authorization_context, now, origin: str,
                                evidence_ref: str, link_revision: int = 0) -> dict:
    """Record one audited receipt without changing assessment or exception state.

    Callers hold the shared policy lock and the relevant identity/link locks. The
    intent is locked here so browser and Slack receipt paths serialize together.
    """
    intent = connection.execute(sa.select(exception_warning_intents).where(
        exception_warning_intents.c.intent_id == intent_id).with_for_update()
        ).mappings().one_or_none()
    if intent is None or intent["status"] != "sent":
        raise ValueError("only a sent warning can be acknowledged")
    group = connection.execute(sa.select(assessment_group_state).where(
        assessment_group_state.c.group_id == group_id).with_for_update()
        ).mappings().one_or_none()
    if group is None:
        raise ValueError("warning finding group is unavailable")
    if intent["acknowledged_at"] is None:
        connection.execute(exception_warning_intents.update().where(
            exception_warning_intents.c.intent_id == intent_id,
            exception_warning_intents.c.acknowledged_at.is_(None)).values(
                acknowledged_at=now, acknowledged_by=principal_id, updated_at=now,
                acknowledged_policy_revision=policy_revision,
                acknowledged_group_revision=int(group["revision"]),
                acknowledged_link_revision=link_revision))
        sequence = connection.execute(sa.select(sa.func.coalesce(
            sa.func.max(assessment_audit_events.c.event_sequence), 0) + 1)).scalar_one()
        command_id, event_id = str(uuid.uuid4()), str(uuid.uuid4())
        connection.execute(assessment_audit_events.insert().values(
            event_id=event_id, event_sequence=sequence, actor_id=principal_id,
            actor_kind="principal", origin=origin,
            action="exception_warning.acknowledge", target_id=group_id,
            before_value={"acknowledged_at": None}, after_value={
                "intent_id": intent_id, "acknowledged_at": now.isoformat(),
                "effect": "receipt_only"}, membership_ids=[], membership_revision=0,
            rationale="Recipient acknowledged warning receipt", evidence_ref=evidence_ref,
            policy_revision=policy_revision, identity_revision=link_revision,
            occurred_at=now, received_at=now, correlation_id=command_id,
            command_id=command_id,
            authorization_context=(authorization_context.document()
                if authorization_context is not None else None)))
        intent = connection.execute(sa.select(exception_warning_intents).where(
            exception_warning_intents.c.intent_id == intent_id)).mappings().one()
    return {"intent_id": intent_id, "acknowledged_at": intent["acknowledged_at"],
        "acknowledged_by": intent["acknowledged_by"], "effect": "receipt_only"}
