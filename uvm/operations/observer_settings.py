"""Pure validation for deployment-scoped observer timing revisions."""
from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime, timedelta, timezone
import hashlib
import uuid


TIMING_FIELDS = (
    "observation_interval_seconds",
    "request_deadline_seconds",
    "heartbeat_freshness_seconds",
    "maximum_future_skew_seconds",
    "anchor_export_lag_seconds",
    "incident_projection_deadline_seconds",
    "scheduler_progress_freshness_seconds",
)


class ObserverSettingsError(ValueError):
    """A desired timing document is malformed or outside host policy."""


class ObserverSettingsConflict(RuntimeError):
    """A revision, command identity or pending application changed."""


class ObserverSettingsUnavailable(RuntimeError):
    """Required trusted host policy or durable dependency is unavailable."""


def validate_timing_values(values: object, bounds: Mapping[str, object]) -> dict[str, int]:
    """Return a canonical complete timing object after independent bound checks.

    Bounds are host-owned. This function deliberately has no cross-field timing
    relationships: each accepted integer remains independently meaningful and
    the checked-in revision-3 local fixture is valid under its own policy.
    """
    if not isinstance(values, dict) or set(values) != set(TIMING_FIELDS):
        raise ObserverSettingsError("timing values must contain exactly the seven v1 fields")
    if not isinstance(bounds, Mapping) or set(bounds) != set(TIMING_FIELDS):
        raise ObserverSettingsError("host timing policy must define bounds for all seven fields")
    checked: dict[str, int] = {}
    for field in TIMING_FIELDS:
        value = values[field]
        if type(value) is not int:
            raise ObserverSettingsError(f"{field} must be an integer")
        limit = bounds[field]
        if not isinstance(limit, Mapping) or set(limit) != {"min", "max"}:
            raise ObserverSettingsError(f"host bounds for {field} are invalid")
        minimum, maximum = limit["min"], limit["max"]
        if (type(minimum) is not int or type(maximum) is not int
                or minimum < 0 or maximum < minimum):
            raise ObserverSettingsError(f"host bounds for {field} are invalid")
        required_minimum = 0 if field == "maximum_future_skew_seconds" else 1
        if minimum < required_minimum:
            raise ObserverSettingsError(f"host minimum for {field} is below the v1 floor")
        if value < minimum or value > maximum:
            raise ObserverSettingsError(f"{field} is outside current host policy bounds")
        checked[field] = value
    return checked


def deployment_grants(policy: dict, principal_id: str, action: str,
                      deployment_id: str, request_context=None) -> list[dict]:
    """Return current native grants for one exact deployment and action.

    Each returned permission independently names the deployment. Source or
    target scope cannot supply this dimension. Explicit denies are evaluated
    after current membership resolution and override every matching grant.
    """
    if action not in {"observer.timing.read", "observer.timing.configure"}:
        return []
    if not isinstance(deployment_id, str) or not deployment_id or len(deployment_id) > 256:
        return []
    from uvm.auth.native_authority import NATIVE_MODE, effective_access, native_state

    state = native_state(policy)
    if state.get("mode") != NATIVE_MODE:
        return []
    principals = policy.get("principals", {})
    if not isinstance(principals, dict) or principals.get(principal_id, {}).get("enabled") is False:
        return []
    access = effective_access(policy, principal_id)
    if access is None:
        return []
    member_groups = set(access[0])
    if (request_context is not None and request_context.principal_id == principal_id
            and request_context.credential_mode in {"oidc_session", "github_link"}):
        member_groups.intersection_update(request_context.access_groups)

    authority_ids = {principal_id, *member_groups}
    for denial in policy.get("denies", []):
        if (isinstance(denial, dict)
                and denial.get("principal_id") in authority_ids | {"*"}
                and ("*" in denial.get("actions", []) or action in denial.get("actions", []))
                and ("*" in denial.get("target_ids", [])
                    or deployment_id in denial.get("target_ids", []))):
            return []

    result = []
    for group_id in sorted(member_groups):
        group = state.get("access_groups", {}).get(group_id)
        if not isinstance(group, dict) or group.get("enabled", True) is not True:
            continue
        allowed_roles = None
        if (request_context is not None and request_context.principal_id == principal_id
                and request_context.credential_mode in {"oidc_session", "github_link"}):
            allowed_roles = set(request_context.roles_for_group(group_id))
        for permission in group.get("permissions", []):
            deployment_scopes = permission.get("deployment_scopes") if isinstance(permission, dict) else None
            if (not isinstance(permission, dict) or permission.get("action") != action
                    or not isinstance(deployment_scopes, list)
                    or any(not isinstance(value, str) for value in deployment_scopes)
                    or deployment_id not in deployment_scopes):
                continue
            if allowed_roles is not None and permission.get("role_id") not in allowed_roles:
                continue
            result.append({"access_group_id": group_id,
                "permission_id": permission.get("permission_id"),
                "role_id": permission.get("role_id"),
                "deployment_id": deployment_id, "action": action})
    return result


def deployment_audit_id(deployment_id: str) -> str:
    """Map an opaque deployment key to the UUID target required by audit schema."""
    return str(uuid.uuid5(uuid.NAMESPACE_URL, "uvm:deployment:" + deployment_id))


def command_digest(principal_id: str, deployment_id: str, body: dict) -> str:
    import json
    raw = json.dumps({"principal_id": principal_id, "deployment_id": deployment_id,
        "body": body}, sort_keys=True, separators=(",", ":"),
        ensure_ascii=True, allow_nan=False).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def commit_desired_revision(connection, *, deployment_id: str, command_id: str,
        actor_id: str, actor_kind: str, action: str, request_digest: str,
        expected_revisions: dict, rationale: str, evidence_ref: str | None,
        values: dict | None, rollback_revision: int | None,
        now: datetime, authorization_context: dict | None = None) -> dict:
    """Atomically append settings, audit, receipt and host-application intent.

    The caller owns authentication/current deployment grants, an open database
    transaction and the global policy lock. The function rechecks every
    revision token and command replay identity within that transaction.
    """
    import sqlalchemy as sa
    from uvm.assessment.policy_lock import lock_policy
    from uvm.auth.native_authority import native_state
    from uvm.persistence.assessment_schema import (
        assessment_audit_events, assessment_command_receipts, assessment_policy,
    )
    from uvm.persistence.observer_settings_schema import (
        g7_observer_application_intents, g7_observer_settings_revisions,
        g7_observer_status,
    )

    if action not in {"observer.timing.publish", "observer.timing.rollback"}:
        raise ObserverSettingsError("unsupported observer timing action")
    if not isinstance(deployment_id, str) or not deployment_id or len(deployment_id) > 256:
        raise ObserverSettingsError("deployment ID is invalid")
    try:
        canonical_command_id = str(uuid.UUID(command_id))
    except (TypeError, ValueError, AttributeError) as exc:
        raise ObserverSettingsError("command_id must be a UUID") from exc
    if canonical_command_id != command_id:
        raise ObserverSettingsError("command_id must be canonical")
    if type(now) is not datetime or now.tzinfo is None or now.utcoffset() != timedelta(0):
        raise ObserverSettingsError("transaction time must be UTC")
    for token in ("configuration", "policy", "authority", "host_policy"):
        if type(expected_revisions.get(token)) is not int or expected_revisions[token] < 0:
            raise ObserverSettingsError(f"expected_revisions.{token} must be a non-negative integer")

    lock_policy(connection)
    policy_row = connection.execute(sa.select(assessment_policy).where(
        assessment_policy.c.policy_id == 1).with_for_update()).mappings().first()
    if policy_row is None:
        raise ObserverSettingsError("assessment policy is not configured")
    policy = policy_row["document"]
    authority_revision = int(native_state(policy).get("revision", 0))
    status_row = connection.execute(sa.select(g7_observer_status).where(
        g7_observer_status.c.deployment_id == deployment_id).with_for_update()).mappings().first()
    host_policy_revision = int(status_row["host_policy_revision"] or 0) if status_row else 0
    if (status_row is None or not status_row["host_policy_revision"]
            or not status_row["host_policy_digest"]
            or status_row["host_policy_bounds"] is None
            or status_row["host_policy_observed_at"] is None
            or not status_row["host_policy_key_id"]):
        raise ObserverSettingsUnavailable("trusted host policy snapshot is unavailable")
    current_revision = connection.execute(sa.select(sa.func.coalesce(
        sa.func.max(g7_observer_settings_revisions.c.revision), 0)).where(
            g7_observer_settings_revisions.c.deployment_id == deployment_id)).scalar_one()
    target_id = deployment_audit_id(deployment_id)

    prior = connection.execute(sa.select(assessment_command_receipts).where(
        assessment_command_receipts.c.command_id == canonical_command_id).with_for_update()).mappings().first()
    if prior is not None:
        if (prior["principal_id"] == actor_id and prior["action"] == action
                and prior["target_id"] == target_id
                and prior["request_digest"] == request_digest):
            return prior["result"]
        raise ObserverSettingsConflict("command_id is retained for different content or actor")

    expected_current = {"configuration": int(current_revision),
        "policy": int(policy_row["revision"]), "authority": authority_revision,
        "host_policy": host_policy_revision}
    if expected_revisions != expected_current:
        raise ObserverSettingsConflict("one or more expected revisions changed")
    unresolved = connection.execute(sa.select(g7_observer_application_intents.c.intent_id).where(
        g7_observer_application_intents.c.deployment_id == deployment_id,
        g7_observer_application_intents.c.status.in_(("pending", "uncertain")))
        .with_for_update()).first()
    if unresolved is not None:
        raise ObserverSettingsConflict("an earlier observer application is unresolved")

    if action == "observer.timing.publish":
        if rollback_revision is not None:
            raise ObserverSettingsError("publish cannot include rollback_revision")
        source_values = values
    else:
        if values is not None or type(rollback_revision) is not int or rollback_revision < 1:
            raise ObserverSettingsError("rollback requires one retained revision")
        historical = connection.execute(sa.select(
            g7_observer_settings_revisions.c["values"]).where(
                g7_observer_settings_revisions.c.deployment_id == deployment_id,
                g7_observer_settings_revisions.c.revision == rollback_revision)).scalar_one_or_none()
        if historical is None:
            raise ObserverSettingsError("rollback revision is not retained")
        source_values = historical

    if not isinstance(source_values, dict) or set(source_values) != set(TIMING_FIELDS):
        raise ObserverSettingsError("complete observer timing values are required")
    checked_values = {}
    for field in TIMING_FIELDS:
        value = source_values[field]
        floor = 0 if field == "maximum_future_skew_seconds" else 1
        if type(value) is not int or value < floor:
            raise ObserverSettingsError(f"{field} must be an integer at or above {floor}")
        checked_values[field] = value

    bounds_fresh = False
    bounds = None
    if status_row and status_row["host_policy_bounds"] is not None:
        policy_observed_at = status_row["host_policy_observed_at"]
        if policy_observed_at is not None and policy_observed_at.tzinfo is None:
            # SQLite drops timezone metadata; persisted contract timestamps are UTC.
            policy_observed_at = policy_observed_at.replace(tzinfo=timezone.utc)
        age = (now - policy_observed_at).total_seconds()
        bounds_fresh = (age >= 0 and age <= int(status_row["host_policy_freshness_seconds"] or 0))
        if bounds_fresh:
            bounds = status_row["host_policy_bounds"]
    if bounds_fresh:
        checked_values = validate_timing_values(checked_values, bounds)

    revision = int(current_revision) + 1
    settings_digest = hashlib.sha256(__import__("json").dumps(
        checked_values, sort_keys=True, separators=(",", ":"),
        ensure_ascii=False, allow_nan=False).encode("utf-8")).hexdigest()
    intent_id = str(uuid.uuid4())
    event_id = str(uuid.uuid4())
    decision_id = str(uuid.uuid4())
    sequence = connection.execute(sa.select(sa.func.coalesce(
        sa.func.max(assessment_audit_events.c.event_sequence), 0) + 1)).scalar_one()
    latest = None
    if current_revision:
        latest = connection.execute(sa.select(g7_observer_settings_revisions).where(
            g7_observer_settings_revisions.c.deployment_id == deployment_id,
            g7_observer_settings_revisions.c.revision == int(current_revision))).mappings().one()
    before = ({"deployment_id": deployment_id, "revision": 0,
        "values": None, "digest": None} if latest is None else {
        "deployment_id": deployment_id, "revision": int(current_revision),
        "values": latest["values"], "digest": latest["digest"]})
    after = {"deployment_id": deployment_id, "revision": revision,
        "values": checked_values, "digest": settings_digest,
        "action": action, "rollback_revision": rollback_revision}
    connection.execute(g7_observer_settings_revisions.insert().values(
        deployment_id=deployment_id, revision=revision, values=checked_values,
        digest=settings_digest, command_id=canonical_command_id, actor_id=actor_id,
        action=action, copied_from_revision=rollback_revision, rationale=rationale,
        evidence_ref=evidence_ref, created_at=now))
    connection.execute(assessment_audit_events.insert().values(
        event_id=event_id, event_sequence=sequence, actor_id=actor_id,
        actor_kind=actor_kind, origin="observer_settings_api", action=action,
        target_id=target_id, before_value=before, after_value=after,
        membership_ids=[], membership_revision=authority_revision,
        rationale=rationale, evidence_ref=evidence_ref or "observer_settings:no_external_evidence",
        policy_revision=int(policy_row["revision"]), identity_revision=0,
        occurred_at=now, received_at=now, correlation_id=canonical_command_id,
        command_id=canonical_command_id, authorization_context=authorization_context))
    connection.execute(g7_observer_application_intents.insert().values(
        intent_id=intent_id, deployment_id=deployment_id, command_id=canonical_command_id,
        revision=revision, digest=settings_digest, status="pending", result=None,
        created_at=now, updated_at=now))
    status_values = {"deployment_id": deployment_id,
        "application_status": "pending", "latest_failure_code": None}
    if status_row is None:
        status_values["latest_report_sequence"] = 0
        connection.execute(g7_observer_status.insert().values(**status_values))
    else:
        connection.execute(g7_observer_status.update().where(
            g7_observer_status.c.deployment_id == deployment_id).values(**status_values))
    receipt = {"schema_version": 1, "command_id": canonical_command_id,
        "deployment_id": deployment_id, "action": action,
        "effect": "desired_committed", "request_digest": "sha256:" + request_digest,
        "configuration_revision": revision,
        "configuration_digest": "sha256:" + settings_digest,
        "evaluated_revisions": {"policy": int(policy_row["revision"]),
            "authority": authority_revision, "host_policy": host_policy_revision},
        "audit_id": event_id, "intent_id": intent_id,
        "committed_at": now.isoformat().replace("+00:00", "Z")}
    connection.execute(assessment_command_receipts.insert().values(
        command_id=canonical_command_id, principal_id=actor_id, action=action,
        target_id=target_id, request_digest=request_digest, decision_id=decision_id,
        audit_event_id=event_id, intent_id=intent_id, result=receipt, created_at=now,
        authorization_context=authorization_context))
    return receipt
