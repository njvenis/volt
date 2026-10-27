"""Durable consumer for native administration reconciliation intents."""
from __future__ import annotations

import logging
import threading
from datetime import datetime, timedelta, timezone

import sqlalchemy as sa

from uvm.assessment.policy_lock import lock_policy
from uvm.auth.native_authority import native_state
from uvm.persistence.assessment_schema import assessment_group_state, assessment_policy
from uvm.persistence.g4_schema import github_group_issues, github_projection_intents
from uvm.persistence.native_authority_schema import administration_reconciliation_intents as intents

UTC = timezone.utc
LOG = logging.getLogger(__name__)
ZERO_ID = "00000000-0000-4000-8000-000000000000"


def _team_owned_groups(connection, team_id: str) -> list[tuple[str, dict]]:
    result = []
    rows = connection.execute(sa.select(assessment_group_state.c.group_id,
        assessment_group_state.c.revision,
        assessment_group_state.c.document)).mappings().all()
    for row in rows:
        document = row["document"] or {}
        owners = document.get("owners", [])
        portions = document.get("portions", [])
        assigned = any(isinstance(owner, dict) and owner.get("owner_id") == team_id
            and owner.get("owner_type") == "team" for owner in owners)
        assigned = assigned or any(isinstance(portion, dict)
            and team_id in (portion.get("owner_ids") or []) for portion in portions)
        if assigned:
            result.append((row["group_id"], int(row["revision"]), document))
    return result


def _apply_current_effect(connection, intent: dict, policy: dict, revision: int, now: datetime) -> dict:
    state = native_state(policy)
    ownership = intent["kind"] == "administration.ownership.reconcile"
    current = int(state.get("ownership_revision" if ownership else "revision", 0))
    if current < int(intent["authority_revision"]):
        raise RuntimeError("committed_revision_unavailable")
    target = (state.get("ownership_teams", {}) if ownership
        else state.get("access_groups", {})).get(intent["target_id"])
    if intent["target_id"] != ZERO_ID and target is None:
        raise RuntimeError("administration_target_unavailable")
    if not ownership:
        # Native access is resolved from the policy on every request. Persisting
        # this readback makes the cache/session fence outcome observable.
        return {"effect": "current_authority_readback", "authority_mode": state.get("mode", "legacy"),
            "authority_revision": current, "policy_revision": revision,
            "target_id": intent["target_id"], "target_present": target is not None}

    team_id = intent["target_id"]
    groups = _team_owned_groups(connection, team_id)
    projection_ids = []
    projection_readbacks = []
    from uvm.persistence.github_lifecycle import enqueue_group_projection
    for group_id, assessment_revision, document in groups:
        issue = connection.execute(sa.select(github_group_issues.c.desired_revision).where(
            github_group_issues.c.group_id == group_id).with_for_update()).scalar_one_or_none()
        if issue is None:
            projection_readbacks.append({"group_id": group_id, "github_issue_linked": False})
            continue
        projection_id = enqueue_group_projection(connection, group_id,
            recorded_at=now, assessment_document=document,
            assessment_revision=assessment_revision)
        if projection_id is None:
            raise RuntimeError("github_projection_enqueue_failed")
        projection = connection.execute(sa.select(github_projection_intents).where(
            github_projection_intents.c.projection_id == projection_id)).mappings().first()
        current_issue = connection.execute(sa.select(github_group_issues).where(
            github_group_issues.c.group_id == group_id)).mappings().first()
        if (projection is None or current_issue is None
                or int(current_issue["desired_revision"]) <= int(issue)
                or projection["group_id"] != group_id
                or projection["payload"].get("assessment_revision") != assessment_revision):
            raise RuntimeError("github_projection_readback_failed")
        projection_ids.append(projection_id)
        projection_readbacks.append({"group_id": group_id, "github_issue_linked": True,
            "projection_id": projection_id, "desired_revision": int(current_issue["desired_revision"])})
    # The stored policy is itself the live report input; reread the exact team
    # record before committing the receipt and completion in the same transaction.
    verified_policy = connection.execute(sa.select(assessment_policy.c.document).where(
        assessment_policy.c.policy_id == 1)).scalar_one_or_none() or {}
    verified_team = native_state(verified_policy).get("ownership_teams", {}).get(team_id)
    if verified_team != target:
        raise RuntimeError("ownership_policy_readback_failed")
    return {"effect": "ownership_projection_refresh", "ownership_revision": current,
        "policy_revision": revision, "team_id": team_id,
        "team_revision": int(target.get("revision", 0)),
        "display_name": target.get("display_name"),
        "reporting_input_readback": True,
        "current_group_ids": [group_id for group_id, _, _ in groups],
        "github_projection_ids": projection_ids,
        "github_projection_readbacks": projection_readbacks}


def consume_one(engine, *, now=None, fail_completion=False):
    """Claim one due intent and atomically apply/read back its durable local effect."""
    now = (now or datetime.now(UTC)).astimezone(UTC)
    with engine.begin() as connection:
        lock_policy(connection)
        connection.execute(intents.update().where(intents.c.status == "running",
            intents.c.claimed_at < now - timedelta(seconds=30)).values(
            status="failed", last_error="worker_interrupted",
            next_attempt_at=now + timedelta(seconds=2), updated_at=now))
        query = sa.select(intents).where(sa.or_(
            intents.c.status == "pending",
            sa.and_(intents.c.status == "failed",
                sa.or_(intents.c.next_attempt_at.is_(None), intents.c.next_attempt_at <= now))))\
            .order_by(intents.c.created_at, intents.c.intent_id).limit(1).with_for_update(skip_locked=True)
        intent = connection.execute(query).mappings().first()
        if intent is None:
            return False
        attempt = int(intent["attempts"]) + 1
        connection.execute(intents.update().where(intents.c.intent_id == intent["intent_id"]).values(
            status="running", attempts=attempt, claimed_at=now, updated_at=now,
            next_attempt_at=None))
        intent = dict(intent)
        intent["attempts"] = attempt

    failure = None
    try:
        with engine.begin() as connection:
            lock_policy(connection)
            current_intent = connection.execute(sa.select(intents).where(
                intents.c.intent_id == intent["intent_id"], intents.c.status == "running"
                ).with_for_update()).mappings().first()
            if current_intent is None:
                return True
            policy_row = connection.execute(sa.select(assessment_policy.c.revision,
                assessment_policy.c.document).where(assessment_policy.c.policy_id == 1)
                .with_for_update()).mappings().first()
            if policy_row is None:
                raise RuntimeError("policy_unavailable")
            effect = _apply_current_effect(connection, dict(current_intent),
                policy_row["document"], int(policy_row["revision"]), now)
            if fail_completion:
                raise RuntimeError("completion_persistence_failed")
            connection.execute(intents.update().where(intents.c.intent_id == intent["intent_id"],
                intents.c.status == "running").values(status="complete", result=effect,
                completed_at=now, claimed_at=None, next_attempt_at=None,
                last_error=None, updated_at=now))
    except Exception as exc:
        failure = str(exc) if str(exc) in {"policy_unavailable", "committed_revision_unavailable",
            "administration_target_unavailable", "github_projection_enqueue_failed",
            "github_projection_readback_failed", "ownership_policy_readback_failed"} \
            else "completion_persistence_failed"
    if failure is not None:
        with engine.begin() as connection:
            lock_policy(connection)
            delay = min(3600, 2 ** min(intent["attempts"], 10))
            connection.execute(intents.update().where(intents.c.intent_id == intent["intent_id"],
                intents.c.status == "running").values(status="failed", completed_at=None,
                result=None, last_error=failure,
                next_attempt_at=datetime.now(UTC) + timedelta(seconds=delay),
                claimed_at=None, updated_at=datetime.now(UTC)))
    return True


def run(engine, stop: threading.Event, poll_seconds=1.0):
    while not stop.wait(poll_seconds):
        try:
            while consume_one(engine):
                if stop.is_set():
                    return
        except Exception:
            LOG.exception("native_administration_reconciliation_failed")
