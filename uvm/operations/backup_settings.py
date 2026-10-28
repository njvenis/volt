"""Atomic immutable desired backup settings publication."""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import uuid

import sqlalchemy as sa

from uvm.operations.observer_settings import (
    ObserverSettingsConflict, ObserverSettingsError, ObserverSettingsUnavailable,
    validate_backup_values,
)
from uvm.operations.observer_settings import deployment_audit_id
from uvm.persistence.assessment_schema import (
    assessment_audit_events, assessment_command_receipts, assessment_policy,
)
from uvm.persistence.backup_settings_schema import g7_backup_settings_revisions, g7_backup_state


def canonical_digest(value: object) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"),
        ensure_ascii=False, allow_nan=False).encode("utf-8")).hexdigest()


def commit_backup_settings(connection, *, deployment_id: str, principal: str,
        command_id: str, action: str, body: dict, now: datetime,
        authorization_context: dict | None = None,
        disposable_failpoint: str | None = None) -> tuple[dict, bool]:
    """Commit revision, audit, host intent and receipt in the caller's transaction.

    The current global policy lock is acquired first. The locked assessment
    policy row serializes native authority writers; the deployment state row is
    then locked before the command receipt and revision are published.
    """
    from uvm.assessment.policy_lock import lock_policy
    from uvm.auth.native_authority import native_state
    lock_policy(connection)
    policy_row = connection.execute(sa.select(assessment_policy).where(
        assessment_policy.c.policy_id == 1).with_for_update()).mappings().one_or_none()
    if policy_row is None:
        raise ObserverSettingsError("policy authority is unavailable")
    policy = policy_row["document"]
    authority = int(native_state(policy).get("revision", 0))
    state = connection.execute(sa.select(g7_backup_state).where(
        g7_backup_state.c.deployment_id == deployment_id).with_for_update()).mappings().one_or_none()
    target = deployment_audit_id(deployment_id)
    request_digest = canonical_digest({"principal_id": principal,
        "deployment_id": deployment_id, "body": body})
    prior = connection.execute(sa.select(assessment_command_receipts).where(
        assessment_command_receipts.c.command_id == command_id).with_for_update()).mappings().one_or_none()
    if prior is not None:
        if (prior["principal_id"] == principal and prior["action"] == action
                and prior["target_id"] == target and prior["request_digest"] == request_digest):
            return prior["result"], True
        raise ObserverSettingsConflict("command_id is retained for different content or actor")
    expected = body.get("expected_revisions")
    current_revision = connection.execute(sa.select(sa.func.coalesce(
        sa.func.max(g7_backup_settings_revisions.c.revision), 0)).where(
            g7_backup_settings_revisions.c.deployment_id == deployment_id)).scalar_one()
    host_revision = int(state["host_policy_revision"] or 0) if state else 0
    actual = {"configuration": int(current_revision), "policy": int(policy_row["revision"]),
        "authority": authority, "host_policy": host_revision}
    if not isinstance(expected, dict) or expected != actual:
        raise ObserverSettingsConflict("one or more expected revisions changed")
    if state and state["application_status"] in {"pending", "uncertain"}:
        raise ObserverSettingsConflict("an earlier host application intent is unresolved")
    if not state or not state["host_policy_document"] or not state["host_policy_key_id"]:
        raise ObserverSettingsUnavailable("trusted host policy snapshot is unavailable")
    host_policy = state["host_policy_document"]
    observed = state["host_policy_observed_at"]
    if observed is None:
        raise ObserverSettingsUnavailable("trusted host policy timestamp is unavailable")
    if observed.tzinfo is None:
        observed = observed.replace(tzinfo=timezone.utc)
    max_age = int(host_policy.get("maximum_report_age_seconds", 0))
    age = (now - observed).total_seconds()
    if age < 0 or age > max_age:
        raise ObserverSettingsUnavailable("trusted host policy snapshot is stale or future-dated")
    values = body.get("values")
    if action.endswith("rollback"):
        rollback = body.get("rollback_revision")
        if type(rollback) is not int or rollback < 1 or values is not None:
            raise ObserverSettingsError("rollback must name one retained revision")
        values = connection.execute(sa.select(g7_backup_settings_revisions.c["values"]).where(
            g7_backup_settings_revisions.c.deployment_id == deployment_id,
            g7_backup_settings_revisions.c.revision == rollback)).scalar_one_or_none()
        if values is None:
            raise ObserverSettingsError("rollback revision is not retained")
    else:
        rollback = None
    checked = validate_backup_values(values, host_policy)
    revision = int(current_revision) + 1
    digest = canonical_digest(checked)
    intent_id, event_id, decision_id = str(uuid.uuid4()), str(uuid.uuid4()), str(uuid.uuid4())
    sequence = connection.execute(sa.select(sa.func.coalesce(
        sa.func.max(assessment_audit_events.c.event_sequence), 0) + 1)).scalar_one()
    latest = None
    if current_revision:
        latest = connection.execute(sa.select(g7_backup_settings_revisions).where(
            g7_backup_settings_revisions.c.deployment_id == deployment_id,
            g7_backup_settings_revisions.c.revision == int(current_revision))).mappings().one()
    before = {"deployment_id": deployment_id, "revision": int(current_revision),
        "values": latest["values"] if latest else None, "digest": latest["digest"] if latest else None}
    after = {"deployment_id": deployment_id, "revision": revision, "values": checked,
        "digest": digest, "action": action, "copied_from_revision": rollback}
    connection.execute(g7_backup_settings_revisions.insert().values(
        deployment_id=deployment_id, revision=revision, values=checked, digest=digest,
        command_id=command_id, actor_id=principal, action=action,
        copied_from_revision=rollback, rationale=body["rationale"],
        evidence_ref=body.get("evidence_ref"), policy_revision=actual["policy"],
        authority_revision=authority, host_policy_revision=host_revision, created_at=now))
    if disposable_failpoint == "audit":
        raise ObserverSettingsUnavailable("disposable audit write failure fixture")
    connection.execute(assessment_audit_events.insert().values(
        event_id=event_id, event_sequence=sequence, actor_id=principal,
        actor_kind="principal", origin="backup_settings_api", action=action,
        target_id=target, before_value=before, after_value=after, membership_ids=[],
        membership_revision=authority, rationale=body["rationale"],
        evidence_ref=body.get("evidence_ref") or "backup_settings:no_external_evidence",
        policy_revision=actual["policy"], identity_revision=0, occurred_at=now,
        received_at=now, correlation_id=command_id, command_id=command_id,
        authorization_context=authorization_context))
    if disposable_failpoint == "intent":
        raise ObserverSettingsUnavailable("disposable intent write failure fixture")
    status_values = {"deployment_id": deployment_id, "requested_revision": revision,
        "requested_digest": digest, "application_intent_id": intent_id,
        "application_status": "pending", "latest_failure_code": None,
        "host_policy_revision": host_revision, "updated_at": now}
    if state is None:
        connection.execute(g7_backup_state.insert().values(**status_values))
    else:
        connection.execute(g7_backup_state.update().where(
            g7_backup_state.c.deployment_id == deployment_id).values(**status_values))
    result = {"schema_version": 1, "command_id": command_id,
        "deployment_id": deployment_id, "actor_id": principal, "action": action,
        "request_digest": "sha256:" + request_digest, "settings_digest": "sha256:" + digest,
        "desired_revision": revision,
        "evaluated_revisions": actual,
        "audit_id": event_id, "intent_id": intent_id,
        "committed_at": now.astimezone(timezone.utc).isoformat().replace("+00:00", "Z"),
        "outcome": "desired_committed"}
    if disposable_failpoint == "receipt":
        raise ObserverSettingsUnavailable("disposable receipt write failure fixture")
    connection.execute(assessment_command_receipts.insert().values(
        command_id=command_id, principal_id=principal, action=action,
        target_id=target, request_digest=request_digest, decision_id=decision_id,
        audit_event_id=event_id, intent_id=intent_id, result=result, created_at=now,
        authorization_context=authorization_context))
    return result, False


def intent_quarantined(connection, intent_id: str, connector_id: str | None = None) -> bool:
    """The durable restore hold remains authoritative at dispatch admission."""
    from uvm.persistence.backup_settings_schema import g7_backup_connector_quarantine
    conditions = [g7_backup_connector_quarantine.c.intent_id == intent_id]
    if connector_id is not None:
        from uvm.persistence.connector_schema import connector_intents
        # The signed queue inventory uses a table namespace for connector
        # intents; direct host holds may use the concrete connector UUID.
        # Both require the exact authorized connector/intent membership.
        conditions.extend([
            sa.exists(sa.select(connector_intents.c.intent_id).where(
                connector_intents.c.intent_id == intent_id,
                connector_intents.c.connector_id == connector_id)),
            g7_backup_connector_quarantine.c.connector_id.in_([
                connector_id, connector_intents.name])])
    return connection.execute(sa.select(g7_backup_connector_quarantine.c.intent_id).where(
        *conditions).limit(1)).first() is not None
