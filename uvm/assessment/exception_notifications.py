"""Durable exception expiry warning intents and bounded dispatch decisions."""
from __future__ import annotations

import uuid
from datetime import timedelta

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import insert as postgres_insert

from uvm.persistence.exception_sla_schema import exception_warning_attempts, exception_warning_intents


def create_intent(connection, *, decision_id: str, expiry_revision: int,
                  offset_seconds: int, channel: str, destination_ref: str, now,
                  due_at=None, max_attempts: int = 5, retry_base_seconds: int = 60,
                  route_revision: int | None = None, recipient_id: str | None = None,
                  route_id: str | None = None, destination_revision: int | None = None,
                  approved_destination: dict | None = None,
                  failure_alert_group_ids: list[str] | None = None):
    if channel not in {"slack", "email"}:
        raise ValueError("notification channel must be slack or email")
    if expiry_revision < 1 or offset_seconds < 0 or not destination_ref:
        raise ValueError("notification identity is incomplete")
    if not 1 <= max_attempts <= 20 or not 1 <= retry_base_seconds <= 3600:
        raise ValueError("notification retry policy is out of bounds")
    values = {"intent_id": str(uuid.uuid4()), "decision_id": decision_id,
        "expiry_revision": expiry_revision, "offset_seconds": offset_seconds,
        "channel": channel, "destination_ref": destination_ref,
        "status": "pending", "suppression_reason": None,
        "due_at": due_at or now,
        "next_attempt_at": None, "max_attempts": max_attempts,
        "retry_base_seconds": retry_base_seconds, "route_revision": route_revision,
        "recipient_id": recipient_id, "route_id": route_id,
        "destination_revision": destination_revision,
        "approved_destination": approved_destination,
        "approved_failure_alert_group_ids": sorted(set(failure_alert_group_ids or [])),
        "created_at": now, "updated_at": now}
    connection.execute(postgres_insert(exception_warning_intents).values(**values)
        .on_conflict_do_nothing(constraint="uq_exception_warning_key"))
    return connection.execute(sa.select(exception_warning_intents).where(
        exception_warning_intents.c.decision_id == decision_id,
        exception_warning_intents.c.expiry_revision == expiry_revision,
        exception_warning_intents.c.offset_seconds == offset_seconds,
        exception_warning_intents.c.channel == channel,
        exception_warning_intents.c.destination_ref == destination_ref
    ).with_for_update()).mappings().one()


def approval_intents(connection, *, acceptance, group_id, policy, now):
    """Commit configured warning obligations with final approval; no transport."""
    from datetime import datetime
    expiry = datetime.fromisoformat(acceptance["expires_at"].replace("Z", "+00:00"))
    for route in policy.get("exception_warning_routes", []):
        if route["group_id"] != group_id:
            continue
        for offset in route["offset_seconds"]:
            intent = create_intent(connection, decision_id=acceptance["acceptance_id"],
                expiry_revision=acceptance["request_revision"], offset_seconds=offset,
                channel=route["channel"], destination_ref=route["destination_ref"], now=now,
                due_at=expiry - timedelta(seconds=offset),
                max_attempts=route.get("max_attempts", 5),
                retry_base_seconds=route.get("retry_base_seconds", 60),
                route_revision=route.get("revision", 1), recipient_id=route["recipient_id"],
                route_id=route.get("route_id"),
                destination_revision=route.get("destination_revision", route.get("revision", 1)),
                approved_destination={"channel": route["channel"],
                    "route_id": route.get("route_id"),
                    "destination_revision": route.get("destination_revision", route.get("revision", 1)),
                    "installation_id": route.get("installation_id"),
                    "workspace_id": route.get("workspace_id"), "channel_id": route.get("channel_id"),
                    "destination_ref": route["destination_ref"],
                    "recipient_id": route["recipient_id"],
                    "usergroup_ids": list(route.get("usergroup_ids", [])),
                    "link": route.get("link"),
                    "email_recipient": route.get("email_recipient"),
                    "expires_at": acceptance["expires_at"]},
                failure_alert_group_ids=route.get("failure_alert_group_ids", []))
            if expiry - timedelta(seconds=offset) < now:
                connection.execute(exception_warning_intents.update().where(
                    exception_warning_intents.c.intent_id == intent["intent_id"]).values(
                        status="missed", suppression_reason="offset_passed_at_approval"))


def dispatch_eligibility(connection, intent, now, *, authority_resolver=None,
                         authority_snapshot=None, require_approved_snapshot=False):
    """Recheck effective lifecycle, exact route, outstanding membership and recipient scope."""
    from datetime import datetime, timedelta
    from uvm.persistence.assessment_schema import assessment_group_state, assessment_policy
    from uvm.persistence.g4_schema import exposure_episode_members
    from uvm.assessment.api import _complete_target_grants
    from uvm.persistence.observation_schema import source_observations
    from uvm.persistence.schema import exposures, occurrences

    policy_row = connection.execute(sa.select(assessment_policy).where(
        assessment_policy.c.policy_id == 1).with_for_update(read=True)).mappings().one_or_none()
    policy = policy_row["document"] if policy_row else None
    if not isinstance(policy, dict):
        return False, "current_policy_unavailable"
    for row in connection.execute(sa.select(assessment_group_state).with_for_update()).mappings():
        decision = next((item for item in row["document"].get("acceptances", [])
            if item["acceptance_id"] == intent["decision_id"]), None)
        if not decision:
            continue
        if decision.get("request_revision") != intent["expiry_revision"]:
            return False, "expiry_revision_changed"
        expiry = datetime.fromisoformat(decision["expires_at"].replace("Z", "+00:00"))
        if decision.get("state") != "active" or now >= expiry:
            return False, "exception_ineffective"
        if now < expiry - timedelta(seconds=intent["offset_seconds"]):
            return False, "not_due"
        outstanding = any(
            connection.execute(sa.select(exposure_episode_members.c.status).where(
                exposure_episode_members.c.episode_id == snapshot["episode_id"],
                exposure_episode_members.c.occurrence_id == snapshot["occurrence_id"]
            ).with_for_update()).scalar_one_or_none() == "outstanding"
            and snapshot["occurrence_id"] not in decision.get("suspended_membership_ids", [])
            for snapshot in decision.get("pause_snapshots", []))
        if not outstanding:
            return False, "no_outstanding_paused_membership"
        routes = [route for route in policy.get("exception_warning_routes", [])
            if route.get("group_id") == row["group_id"]
            and route.get("channel") == intent["channel"]
            and route.get("destination_ref") == intent["destination_ref"]
            and (intent.get("route_revision") is None
                or route.get("revision", 1) == intent.get("route_revision"))
            and (intent.get("route_id") is None
                or route.get("route_id") == intent.get("route_id"))
            and (intent.get("destination_revision") is None
                or route.get("destination_revision", route.get("revision", 1))
                    == intent.get("destination_revision"))
            and (intent.get("recipient_id") is None
                or route.get("recipient_id") == intent.get("recipient_id"))
            and intent["offset_seconds"] in route.get("offset_seconds", [])]
        if not routes:
            return False, "route_unavailable_or_changed"
        route = routes[0]
        if require_approved_snapshot and (not intent.get("route_id")
                or intent.get("destination_revision") is None):
            return False, "approved_route_identity_unavailable"
        approved = intent.get("approved_destination") or {}
        expected = {"channel": intent["channel"], "destination_ref": intent["destination_ref"],
            "route_id": intent.get("route_id"),
            "destination_revision": intent.get("destination_revision"),
            "recipient_id": route.get("recipient_id"), "installation_id": route.get("installation_id"),
            "workspace_id": route.get("workspace_id"), "channel_id": route.get("channel_id"),
            "usergroup_ids": list(route.get("usergroup_ids", [])), "link": route.get("link"),
            "email_recipient": route.get("email_recipient"), "expires_at": decision["expires_at"]}
        if require_approved_snapshot and (not approved
                or any(approved.get(key) != value for key, value in expected.items())):
            return False, "approved_destination_snapshot_mismatch"
        import os
        if os.environ.get("UVM_AUTH_MODE") == "oidc" and authority_resolver is None:
            return False, "current_recipient_authority_unavailable"
        from uvm.auth.schema import AUTHORITY_CONTEXT
        from uvm.auth.service import group_scope_covered
        source_families = set(connection.execute(sa.select(source_observations.c.source_family)
            .select_from(source_observations.join(occurrences,
                source_observations.c.occurrence_id == occurrences.c.occurrence_id).join(
                exposures, occurrences.c.exposure_id == exposures.c.exposure_id))
            .where(exposures.c.group_id == row["group_id"])).scalars())
        if not source_families:
            return False, "recipient_scope_unavailable"
        for route in routes:
            try:
                from uvm.persistence.auth_schema import auth_group_memberships, oidc_subject_links
                connection.execute(sa.select(auth_group_memberships).where(
                    auth_group_memberships.c.principal_id == route["recipient_id"]
                ).with_for_update()).all()
                connection.execute(sa.select(oidc_subject_links).where(
                    oidc_subject_links.c.principal_id == route["recipient_id"]
                ).with_for_update()).all()
                context = authority_resolver(connection, route["recipient_id"]) if authority_resolver else None
            except Exception as exc:
                # A current explicit identity denial is a revoked destination;
                # infrastructure/freshness failures remain unavailable and fail closed.
                if getattr(exc, "status_code", None) in (401, 403):
                    continue
                return False, "current_recipient_authority_unavailable"
            token = AUTHORITY_CONTEXT.set(context)
            try:
                grants_by_source = [_complete_target_grants(connection, policy,
                    route["recipient_id"], "assessment.read", row["group_id"], source_family)
                    for source_family in sorted(source_families)]
                granting_groups = {grant.get("principal_id") for grants in grants_by_source
                    for grant in grants}
                if (all(grants_by_source) and group_scope_covered(connection, context,
                    [row["group_id"]], granting_identity_groups=granting_groups)):
                    if authority_snapshot is not None:
                        authority_snapshot.update({
                            "policy_revision": int(policy_row["revision"]),
                            "group_revision": int(row["revision"]),
                            "route_revision": int(route.get("revision", 1)),
                            "link_revision": (int(context.link_revision)
                                if context is not None and context.link_revision is not None else 0),
                            "recipient_revision": (int(context.group_revision)
                                if context is not None else 0),
                        })
                    return True, None
            finally:
                AUTHORITY_CONTEXT.reset(token)
        return False, "destination_no_longer_authorised"
    return False, "decision_unavailable"


def suppress_intent(connection, intent_id: str, *, reason: str, now):
    if not reason.strip():
        raise ValueError("suppression reason is required")
    row = connection.execute(sa.select(exception_warning_intents).where(
        exception_warning_intents.c.intent_id == intent_id).with_for_update()).mappings().one_or_none()
    if row is None:
        raise ValueError("notification intent does not exist")
    if row["status"] in {"sent", "uncertain"}:
        raise ValueError("delivered or ambiguous notification intent cannot be suppressed")
    connection.execute(exception_warning_intents.update().where(
        exception_warning_intents.c.intent_id == intent_id).values(
            status="suppressed", suppression_reason=reason[:500], updated_at=now))
    return {"intent_id": intent_id, "status": "suppressed", "suppression_reason": reason}


def record_attempt(connection, intent_id: str, *, attempted_at, outcome: str,
                   receipt: str | None = None, error: str | None = None,
                   authority_resolver=None):
    """Compatibility entry point for deterministic adapter/test receipts."""
    if outcome not in {"sent", "failed", "uncertain"}:
        raise ValueError("delivery attempt outcome is invalid")
    intent = connection.execute(sa.select(exception_warning_intents).where(
        exception_warning_intents.c.intent_id == intent_id).with_for_update()).mappings().one_or_none()
    if intent is None:
        raise ValueError("notification intent does not exist")
    if intent["status"] in {"sent", "missed", "suppressed", "uncertain", "sending"}:
        raise ValueError("notification intent is terminal or in flight")
    allowed, reason = dispatch_eligibility(connection, intent, attempted_at, authority_resolver=authority_resolver)
    if not allowed:
        if reason == "not_due":
            raise ValueError("notification is not due")
        return suppress_intent(connection, intent_id, reason=reason, now=attempted_at)
    attempt_number = connection.execute(sa.select(sa.func.coalesce(
        sa.func.max(exception_warning_attempts.c.attempt_number), 0) + 1).where(
        exception_warning_attempts.c.intent_id == intent_id)).scalar_one()
    connection.execute(exception_warning_attempts.insert().values(
        attempt_id=str(uuid.uuid4()), intent_id=intent_id, attempt_number=int(attempt_number),
        attempted_at=attempted_at, finished_at=attempted_at, outcome=outcome,
        receipt=receipt, error=(error or "")[:1000] or None))
    connection.execute(exception_warning_intents.update().where(
        exception_warning_intents.c.intent_id == intent_id).values(
            status=outcome, updated_at=attempted_at,
            next_attempt_at=(attempted_at + timedelta(minutes=1) if outcome == "failed" else None)))
    return {"intent_id": intent_id, "attempt_number": int(attempt_number), "status": outcome}
