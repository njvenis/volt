"""Persistent per-exposure remediation episodes and continuity coverage."""

from __future__ import annotations

import uuid
import os
from datetime import datetime, timedelta, timezone

import sqlalchemy as sa

from uvm.persistence.assessment_schema import (assessment_audit_events,
    assessment_command_receipts, assessment_group_state)
from uvm.persistence.g4_schema import (exposure_episode_events,
    exposure_episode_members, exposure_episodes)
from uvm.persistence.observation_schema import source_observations
from uvm.persistence.lineage_schema import identity_resolutions
from uvm.persistence.schema import exposures, occurrences

UTC = timezone.utc
_FUTURE_CLOCK_TOLERANCE_ENV = "UVM_G4_FUTURE_CLOCK_TOLERANCE_SECONDS"


def future_clock_policy() -> dict:
    """Return the reproducible local scanner future-clock policy."""
    raw = os.environ.get(_FUTURE_CLOCK_TOLERANCE_ENV)
    if raw is None:
        return {"tolerance_seconds": 300, "source": "default",
            "configuration": _FUTURE_CLOCK_TOLERANCE_ENV}
    try:
        tolerance = int(raw, 10)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{_FUTURE_CLOCK_TOLERANCE_ENV} must be a non-negative integer") from exc
    if tolerance < 0 or str(tolerance) != raw.strip():
        raise ValueError(f"{_FUTURE_CLOCK_TOLERANCE_ENV} must be a non-negative integer")
    return {"tolerance_seconds": tolerance, "source": "environment",
        "configuration": _FUTURE_CLOCK_TOLERANCE_ENV}


def _clock_evidence(evaluation_at: datetime, observed_at: datetime,
                    policy: dict) -> dict:
    return {"evaluation_clock_utc": evaluation_at.astimezone(UTC).isoformat().replace("+00:00", "Z"),
        "observed_at_utc": observed_at.astimezone(UTC).isoformat().replace("+00:00", "Z"),
        "future_clock_tolerance_seconds": policy["tolerance_seconds"],
        "future_clock_tolerance_source": policy["source"],
        "future_clock_tolerance_configuration": policy["configuration"]}


def observation_is_beyond_future_tolerance(observed_at: datetime | None,
        evaluation_at: datetime, policy: dict) -> bool:
    """Do not adjust source time; compare the retained instant to this evaluation."""
    return (observed_at is not None and observed_at.tzinfo is not None and
        observed_at.astimezone(UTC) > evaluation_at.astimezone(UTC) +
        timedelta(seconds=policy["tolerance_seconds"]))


def _id() -> str:
    return str(uuid.uuid4())


def _confirmed_history(connection, group_id: str) -> dict[str, tuple[str, datetime]]:
    """Return only exact G3 membership confirmations recoverable from audit."""
    query = (sa.select(assessment_audit_events, assessment_command_receipts.c.decision_id)
        .select_from(assessment_audit_events.outerjoin(assessment_command_receipts,
            assessment_command_receipts.c.audit_event_id == assessment_audit_events.c.event_id))
        .where(assessment_audit_events.c.target_id == group_id)
        .order_by(assessment_audit_events.c.event_sequence))
    result: dict[str, tuple[str, datetime]] = {}
    for row in connection.execute(query).mappings():
        before = set((row["before_value"] or {}).get("completed_ids", []))
        after = set((row["after_value"] or {}).get("completed_ids", []))
        decision_id = row["decision_id"]
        if not decision_id:
            continue
        for occurrence_id in after - before:
            if occurrence_id in row["membership_ids"]:
                result[occurrence_id] = (decision_id, row["occurred_at"])
    return result


def _current_members(connection, exposure_id: str) -> list[str]:
    return list(connection.execute(sa.select(occurrences.c.occurrence_id)
        .where(occurrences.c.exposure_id == exposure_id)
        .order_by(occurrences.c.occurrence_id)).scalars())


def _reliable_positive_observations(connection, group_id: str, exposure_id: str):
    latest = (sa.select(identity_resolutions.c.observation_id,
        sa.func.max(identity_resolutions.c.revision).label("revision"))
        .group_by(identity_resolutions.c.observation_id).subquery())
    rows = connection.execute(sa.select(source_observations.c.observation_id,
        source_observations.c.occurrence_id, source_observations.c.observed_at,
        identity_resolutions.c.outcome).select_from(source_observations.join(
            latest, latest.c.observation_id == source_observations.c.observation_id)
            .join(identity_resolutions, sa.and_(
                identity_resolutions.c.observation_id == latest.c.observation_id,
                identity_resolutions.c.revision == latest.c.revision)))
        .where(identity_resolutions.c.group_id == group_id,
            identity_resolutions.c.exposure_id == exposure_id,
            identity_resolutions.c.occurrence_id.is_not(None),
            identity_resolutions.c.outcome.in_(["matched", "new"]),
            source_observations.c.collection_status != "failed",
            source_observations.c.observed_at.is_not(None))
        .order_by(source_observations.c.observed_at,
            source_observations.c.observation_id)).mappings().all()
    return [dict(row) for row in rows
        if row["observed_at"].tzinfo is not None]


def _state(member_statuses: list[str]) -> str:
    if not member_statuses or "review" in member_statuses:
        return "review"
    outstanding = sum(value == "outstanding" for value in member_statuses)
    if outstanding == len(member_statuses):
        return "open"
    if outstanding:
        return "partially_remediated"
    return "remediated"


def _append_event(connection, *, episode_id: str, revision: int,
                  event_type: str, actor_id: str, origin: str,
                  decision_id: str | None, occurrence_ids: list[str],
                  source_observation_id: str | None, observed_at: datetime | None,
                  recorded_at: datetime, reason_codes: list[str], details: dict) -> None:
    connection.execute(exposure_episode_events.insert().values(
        event_id=_id(), episode_id=episode_id, state_revision=revision,
        event_type=event_type, actor_id=actor_id, origin=origin,
        decision_id=decision_id, occurrence_ids=sorted(set(occurrence_ids)),
        source_observation_id=source_observation_id, observed_at=observed_at,
        recorded_at=recorded_at, reason_codes=reason_codes, details=details))


def ensure_current_episodes(connection, group_id: str, *, now: datetime,
                            actor_id: str = "g4-system",
                            origin: str = "g4_episode_materialization") -> list[dict]:
    """Materialise a labelled baseline and append newly arrived members.

    The caller must have checked current read/write permission and hold the
    same group/exposure/occurrence locks used by assessment and reconciliation.
    Existing history is never deleted or silently rebased.
    """
    history = _confirmed_history(connection, group_id)
    group_document = connection.execute(sa.select(
        assessment_group_state.c.document).where(
            assessment_group_state.c.group_id == group_id)).scalar_one_or_none() or {}
    legacy_completed = set(group_document.get("completed_ids", []))
    rows = connection.execute(sa.select(exposures).where(
        exposures.c.group_id == group_id).order_by(exposures.c.exposure_id)).mappings().all()
    result = []
    newly_adopted = []
    for exposure in rows:
        exposure_id = exposure["exposure_id"]
        current = connection.execute(sa.select(exposure_episodes).where(
            exposure_episodes.c.exposure_id == exposure_id,
            exposure_episodes.c.is_current.is_(True)).with_for_update()).mappings().first()
        members = _current_members(connection, exposure_id)
        if current is None:
            newly_adopted.append(exposure_id)
            number = int(connection.execute(sa.select(sa.func.coalesce(
                sa.func.max(exposure_episodes.c.episode_number), 0)).where(
                    exposure_episodes.c.exposure_id == exposure_id)).scalar_one()) + 1
            episode_id = str(uuid.uuid5(uuid.NAMESPACE_URL,
                f"uvm-exposure-episode:{exposure_id}:{number}"))
            completed = {member for member in members if member in history}
            statuses = ["confirmed" if member in completed else
                "review" if member in legacy_completed else "outstanding"
                for member in members]
            state = _state(statuses)
            confirmed_times = [history[member][1] for member in completed]
            closed_at = max(confirmed_times) if state == "remediated" and confirmed_times else None
            connection.execute(exposure_episodes.insert().values(
                episode_id=episode_id, exposure_id=exposure_id, group_id=group_id,
                episode_number=number, state_revision=1, state=state, is_current=True,
                opened_at=min(confirmed_times) if confirmed_times else now,
                closed_at=closed_at, created_at=now, updated_at=now))
            for member in members:
                confirmation = history.get(member)
                connection.execute(exposure_episode_members.insert().values(
                    episode_id=episode_id, occurrence_id=member,
                    status="confirmed" if confirmation else
                        "review" if member in legacy_completed else "outstanding",
                    coverage_reason="direct_confirmation" if confirmation else
                        "review" if member in legacy_completed else "outstanding",
                    original_decision_id=confirmation[0] if confirmation else None,
                    original_confirmed_at=confirmation[1] if confirmation else None,
                    confirmation_decision_id=confirmation[0] if confirmation else None,
                    confirmed_at=confirmation[1] if confirmation else None,
                    updated_at=now))
            _append_event(connection, episode_id=episode_id, revision=1,
                event_type="g3_baseline_materialized", actor_id=actor_id,
                origin=origin, decision_id=None, occurrence_ids=members,
                source_observation_id=None, observed_at=None, recorded_at=now,
                reason_codes=["historical_confirmation_missing"] if
                    bool((set(members) & legacy_completed) - completed) else [],
                details={"baseline_source": "g3_audit_receipts",
                    "confirmed_member_count": len(completed),
                    "member_count": len(members)})
            current = connection.execute(sa.select(exposure_episodes).where(
                exposure_episodes.c.episode_id == episode_id)).mappings().one()
        else:
            existing = set(connection.execute(sa.select(
                exposure_episode_members.c.occurrence_id).where(
                    exposure_episode_members.c.episode_id == current["episode_id"])).scalars())
            added = sorted(set(members) - existing)
            if added:
                if current["state"] == "remediated":
                    previous_episode = dict(current)
                    previous_members = connection.execute(sa.select(
                        exposure_episode_members).where(
                            exposure_episode_members.c.episode_id == current["episode_id"])
                        .order_by(exposure_episode_members.c.occurrence_id)).mappings().all()
                    number = int(connection.execute(sa.select(sa.func.max(
                        exposure_episodes.c.episode_number)).where(
                            exposure_episodes.c.exposure_id == exposure_id)).scalar_one()) + 1
                    successor_id = _id()
                    connection.execute(exposure_episodes.update().where(
                        exposure_episodes.c.episode_id == current["episode_id"]).values(
                            is_current=False, updated_at=now))
                    connection.execute(exposure_episodes.insert().values(
                        episode_id=successor_id, exposure_id=exposure_id,
                        group_id=group_id, episode_number=number,
                        state_revision=1, state="open", is_current=True,
                        opened_at=now, closed_at=None, created_at=now, updated_at=now))
                    for previous_member in previous_members:
                        original_time = (previous_member["confirmed_at"]
                            or previous_member["original_confirmed_at"])
                        has_contradiction = bool(original_time and connection.execute(
                            sa.select(source_observations.c.observation_id).where(
                                source_observations.c.occurrence_id == previous_member["occurrence_id"],
                                source_observations.c.collection_status != "failed",
                                source_observations.c.observed_at > original_time).limit(1)
                            ).first())
                        covered = (previous_member["status"] in {"confirmed", "continuity_covered"}
                            and original_time is not None and not has_contradiction)
                        connection.execute(exposure_episode_members.insert().values(
                            episode_id=successor_id,
                            occurrence_id=previous_member["occurrence_id"],
                            status="continuity_covered" if covered else "outstanding",
                            coverage_reason="verified_continuity" if covered else "continuity_not_proven",
                            original_decision_id=previous_member["original_decision_id"],
                            original_confirmed_at=previous_member["original_confirmed_at"],
                            confirmation_decision_id=(previous_member["confirmation_decision_id"]
                                or previous_member["original_decision_id"]) if covered else None,
                            confirmed_at=original_time if covered else None, updated_at=now))
                    for member in added:
                        connection.execute(exposure_episode_members.insert().values(
                            episode_id=successor_id, occurrence_id=member,
                            status="outstanding", coverage_reason="outstanding",
                            original_decision_id=None, original_confirmed_at=None,
                            confirmation_decision_id=None, confirmed_at=None,
                            updated_at=now))
                    _append_event(connection, episode_id=successor_id, revision=1,
                        event_type="membership_added", actor_id=actor_id,
                        origin=origin, decision_id=None, occurrence_ids=added,
                        source_observation_id=None, observed_at=None,
                        recorded_at=now, reason_codes=["new_membership_outstanding"],
                        details={"predecessor_episode_id": previous_episode["episode_id"],
                            "recurrence": False})
                    current = connection.execute(sa.select(exposure_episodes).where(
                        exposure_episodes.c.episode_id == successor_id)).mappings().one()
                    member_rows = connection.execute(sa.select(
                        exposure_episode_members).where(
                            exposure_episode_members.c.episode_id == successor_id,
                            exposure_episode_members.c.occurrence_id.in_(members)).order_by(
                                exposure_episode_members.c.occurrence_id)).mappings().all()
                    episode_ids = list(connection.execute(sa.select(
                        exposure_episodes.c.episode_id).where(
                            exposure_episodes.c.exposure_id == exposure_id)).scalars())
                    event_rows = connection.execute(sa.select(
                        exposure_episode_events).where(
                            exposure_episode_events.c.episode_id.in_(episode_ids)).order_by(
                                exposure_episode_events.c.recorded_at)).mappings().all()
                    recurrence_events = [item for item in event_rows
                        if item["event_type"] == "recurrence_opened"]
                    review_reasons = sorted({reason for item in event_rows
                        if item["event_type"] == "observation_requires_review"
                        for reason in item["reason_codes"]})
                    result.append({"episode": dict(current),
                        "members": [dict(item) for item in member_rows],
                        "recurrence_count": len(recurrence_events),
                        "last_recurrence_at": recurrence_events[-1]["recorded_at"]
                            if recurrence_events else None,
                        "recurrence_reason_codes": sorted({reason
                            for item in recurrence_events for reason in item["reason_codes"]}),
                        "review_reasons": review_reasons})
                    continue
                for member in added:
                    connection.execute(exposure_episode_members.insert().values(
                        episode_id=current["episode_id"], occurrence_id=member,
                        status="outstanding", coverage_reason="outstanding",
                        original_decision_id=None, original_confirmed_at=None,
                        confirmation_decision_id=None, confirmed_at=None,
                        updated_at=now))
                member_statuses = list(connection.execute(sa.select(
                    exposure_episode_members.c.status).where(
                        exposure_episode_members.c.episode_id == current["episode_id"]
                        ).where(exposure_episode_members.c.occurrence_id.in_(members))).scalars())
                revision = int(current["state_revision"]) + 1
                state = _state(member_statuses)
                connection.execute(exposure_episodes.update().where(
                    exposure_episodes.c.episode_id == current["episode_id"]).values(
                        state=state, state_revision=revision, closed_at=None,
                        updated_at=now))
                _append_event(connection, episode_id=current["episode_id"],
                    revision=revision, event_type="membership_added",
                    actor_id=actor_id, origin=origin, decision_id=None,
                    occurrence_ids=added, source_observation_id=None,
                    observed_at=None, recorded_at=now,
                    reason_codes=["new_membership_outstanding"], details={})
                current = connection.execute(sa.select(exposure_episodes).where(
                    exposure_episodes.c.episode_id == current["episode_id"])).mappings().one()
        member_rows = connection.execute(sa.select(exposure_episode_members).where(
            exposure_episode_members.c.episode_id == current["episode_id"],
            exposure_episode_members.c.occurrence_id.in_(members)).order_by(
                exposure_episode_members.c.occurrence_id)).mappings().all() if members else []
        episode_ids = list(connection.execute(sa.select(
            exposure_episodes.c.episode_id).where(
                exposure_episodes.c.exposure_id == exposure_id)).scalars())
        event_rows = connection.execute(sa.select(exposure_episode_events).where(
            exposure_episode_events.c.episode_id.in_(episode_ids)).order_by(
                exposure_episode_events.c.recorded_at)).mappings().all() if episode_ids else []
        recurrence_events = [row for row in event_rows
            if row["event_type"] == "recurrence_opened"]
        review_reasons = sorted({reason for row in event_rows
            if row["event_type"] == "observation_requires_review"
            for reason in row["reason_codes"]})
        result.append({"episode": dict(current), "members": [dict(member) for member in member_rows],
            "recurrence_count": len(recurrence_events),
            "last_recurrence_at": recurrence_events[-1]["recorded_at"] if recurrence_events else None,
            "recurrence_reason_codes": sorted({reason for row in recurrence_events
                for reason in row["reason_codes"]}), "review_reasons": review_reasons})
    if newly_adopted:
        for exposure_id in newly_adopted:
            for observation in _reliable_positive_observations(
                    connection, group_id, exposure_id):
                record_positive_observation(connection, group_id=group_id,
                    exposure_id=exposure_id,
                    occurrence_id=observation["occurrence_id"],
                    observation_id=observation["observation_id"],
                    observed_at=observation["observed_at"],
                    collection_status="success", resolution_reliable=True,
                    now=now)
        return ensure_current_episodes(connection, group_id, now=now,
            actor_id=actor_id, origin=origin)
    return result


def read_current_episodes(connection, group_id: str) -> list[dict]:
    """Read current coverage without adopting history or advancing episode state.

    For a legacy exposure not yet adopted by a writer, return the deterministic
    revision-one baseline that the next controlled writer will persist. No
    event, decision, time, or prior history is synthesized.
    """
    history = _confirmed_history(connection, group_id)
    document = connection.execute(sa.select(assessment_group_state.c.document).where(
        assessment_group_state.c.group_id == group_id)).scalar_one_or_none() or {}
    legacy_completed = set(document.get("completed_ids", []))
    result = []
    for exposure in connection.execute(sa.select(exposures).where(
            exposures.c.group_id == group_id).order_by(exposures.c.exposure_id)).mappings():
        members = _current_members(connection, exposure["exposure_id"])
        episode = connection.execute(sa.select(exposure_episodes).where(
            exposure_episodes.c.exposure_id == exposure["exposure_id"],
            exposure_episodes.c.is_current.is_(True))).mappings().first()
        if episode is None:
            episode_id = str(uuid.uuid5(uuid.NAMESPACE_URL,
                f"uvm-exposure-episode:{exposure['exposure_id']}:1"))
            member_rows = []
            reliable_rows = _reliable_positive_observations(connection, group_id,
                exposure["exposure_id"])
            for member_id in members:
                confirmed = history.get(member_id)
                contradicted = confirmed is not None and any(row["occurrence_id"] == member_id
                    and row["observed_at"] > confirmed[1] for row in reliable_rows)
                status = "outstanding" if contradicted else "confirmed" if confirmed else (
                    "review" if member_id in legacy_completed else "outstanding")
                member_rows.append({"occurrence_id": member_id, "status": status,
                    "coverage_reason": "legacy_positive_pending_adoption" if contradicted else
                        "direct_confirmation" if confirmed else
                        "review" if status == "review" else "outstanding",
                    "original_decision_id": confirmed[0] if confirmed else None,
                    "original_confirmed_at": confirmed[1] if confirmed else None,
                    "confirmation_decision_id": confirmed[0] if confirmed else None,
                    "confirmed_at": confirmed[1] if confirmed else None})
            result.append({"episode": {"episode_id": episode_id,
                "exposure_id": exposure["exposure_id"], "episode_number": 1,
                "state_revision": 1, "state": "review"},
                "members": member_rows, "recurrence_count": 0,
                "last_recurrence_at": None, "recurrence_reason_codes": [],
                "review_reasons": sorted((
                    {"historical_confirmation_missing"} if any(
                        row["status"] == "review" for row in member_rows) else set()) |
                    {"legacy_adoption_required"}), "adoption_required": True})
            continue
        member_rows = connection.execute(sa.select(exposure_episode_members).where(
            exposure_episode_members.c.episode_id == episode["episode_id"])
            .order_by(exposure_episode_members.c.occurrence_id)).mappings().all()
        episode_ids = list(connection.execute(sa.select(exposure_episodes.c.episode_id).where(
            exposure_episodes.c.exposure_id == exposure["exposure_id"])).scalars())
        event_rows = connection.execute(sa.select(exposure_episode_events).where(
            exposure_episode_events.c.episode_id.in_(episode_ids)).order_by(
                exposure_episode_events.c.recorded_at)).mappings().all() if episode_ids else []
        recurrences = [row for row in event_rows if row["event_type"] == "recurrence_opened"]
        result.append({"episode": dict(episode), "members": [dict(row) for row in member_rows],
            "recurrence_count": len(recurrences),
            "last_recurrence_at": recurrences[-1]["recorded_at"] if recurrences else None,
            "recurrence_reason_codes": sorted({reason for row in recurrences
                for reason in row["reason_codes"]}),
            "review_reasons": sorted({reason for row in event_rows
                if row["event_type"] == "observation_requires_review"
                for reason in row["reason_codes"]})})
    return result


def confirm_members(connection, group_id: str, occurrence_ids: list[str], *,
                    decision_id: str, actor_id: str, origin: str,
                    now: datetime) -> list[str]:
    """Commit direct coverage only for members in the command's exact scope."""
    wanted = set(occurrence_ids)
    updated = []
    for record in ensure_current_episodes(connection, group_id, now=now):
        episode = record["episode"]
        covered = wanted.intersection(member["occurrence_id"] for member in record["members"])
        if not covered:
            continue
        for member in record["members"]:
            if member["occurrence_id"] not in covered:
                continue
            existing_member = connection.execute(sa.select(
                exposure_episode_members.c.original_decision_id,
                exposure_episode_members.c.original_confirmed_at).where(
                    exposure_episode_members.c.episode_id == episode["episode_id"],
                    exposure_episode_members.c.occurrence_id == member["occurrence_id"])
                .with_for_update()).mappings().one()
            connection.execute(exposure_episode_members.update().where(
                exposure_episode_members.c.episode_id == episode["episode_id"],
                exposure_episode_members.c.occurrence_id == member["occurrence_id"]).values(
                    status="confirmed", coverage_reason="direct_confirmation",
                    original_decision_id=(existing_member["original_decision_id"] or decision_id),
                    original_confirmed_at=(existing_member["original_confirmed_at"] or now),
                    confirmation_decision_id=decision_id, confirmed_at=now,
                    updated_at=now))
        statuses = list(connection.execute(sa.select(
            exposure_episode_members.c.status).where(
                exposure_episode_members.c.episode_id == episode["episode_id"])).scalars())
        new_state = _state(statuses)
        revision = int(episode["state_revision"]) + 1
        connection.execute(exposure_episodes.update().where(
            exposure_episodes.c.episode_id == episode["episode_id"]).values(
                state=new_state, state_revision=revision,
                closed_at=now if new_state == "remediated" else None, updated_at=now))
        _append_event(connection, episode_id=episode["episode_id"],
            revision=revision, event_type="remediation_confirmed", actor_id=actor_id,
            origin=origin, decision_id=decision_id, occurrence_ids=sorted(covered),
            source_observation_id=None, observed_at=None, recorded_at=now,
            reason_codes=[], details={"group_id": group_id})
        updated.append(episode["episode_id"])
    if wanted and not updated:
        raise ValueError("confirmation membership does not resolve to a current exposure episode")
    return updated


def record_positive_observation(connection, *, group_id: str,
        exposure_id: str, occurrence_id: str, observation_id: str,
        observed_at: datetime | None, collection_status: str,
        resolution_reliable: bool, now: datetime) -> dict:
    """Reconcile a newly linked scanner row under the exposure serialization lock."""
    exposure = connection.execute(sa.select(exposures).where(
        exposures.c.exposure_id == exposure_id,
        exposures.c.group_id == group_id).with_for_update()).mappings().first()
    if exposure is None:
        return {"status": "unresolved", "reason": "exposure_not_current"}
    previous = connection.execute(sa.select(exposure_episodes.c.episode_id,
        exposure_episodes.c.state_revision).where(
            exposure_episodes.c.exposure_id == exposure_id,
            exposure_episodes.c.is_current.is_(True))).first()
    previous_signature = ((previous[0], int(previous[1])) if previous else None)
    records = ensure_current_episodes(connection, group_id, now=now,
        actor_id="g4-identity-reconciler", origin="identity_observation")
    record = next((item for item in records
        if item["episode"]["exposure_id"] == exposure_id), None)
    if record is None:
        return {"status": "unresolved", "reason": "episode_not_materialized"}
    episode = record["episode"]
    member = next((item for item in record["members"]
        if item["occurrence_id"] == occurrence_id), None)
    if member is None:
        return {"status": "review", "reason": "membership_not_in_episode"}
    clock_policy = future_clock_policy()
    evaluation_at = now.astimezone(UTC)

    def queue_if_changed():
        latest = connection.execute(sa.select(exposure_episodes.c.episode_id,
            exposure_episodes.c.state_revision).where(
                exposure_episodes.c.exposure_id == exposure_id,
                exposure_episodes.c.is_current.is_(True))).first()
        signature = (latest[0], int(latest[1])) if latest else None
        if signature != previous_signature:
            from uvm.persistence.github_lifecycle import enqueue_group_projection
            enqueue_group_projection(connection, group_id, recorded_at=now)

    reliable = (resolution_reliable and collection_status != "failed"
                and observed_at is not None and observed_at.tzinfo is not None)
    beyond_future_tolerance = (reliable and observation_is_beyond_future_tolerance(
        observed_at, evaluation_at, clock_policy))
    if not reliable or beyond_future_tolerance:
        reason = "observation_time_unknown" if observed_at is None else (
            "identity_resolution_unreliable" if not resolution_reliable else
            "collection_failed" if collection_status == "failed" else
            "observation_time_beyond_future_tolerance" if beyond_future_tolerance else
            "observation_time_invalid")
        revision = int(episode["state_revision"]) + 1
        connection.execute(exposure_episode_members.update().where(
            exposure_episode_members.c.episode_id == episode["episode_id"],
            exposure_episode_members.c.occurrence_id == occurrence_id).values(
                status="review", coverage_reason="review", updated_at=now))
        statuses = list(connection.execute(sa.select(
            exposure_episode_members.c.status).where(
            exposure_episode_members.c.episode_id == episode["episode_id"])).scalars())
        state = _state(statuses)
        connection.execute(exposure_episodes.update().where(
            exposure_episodes.c.episode_id == episode["episode_id"]).values(
                state=state, state_revision=revision, closed_at=None, updated_at=now))
        details = (_clock_evidence(evaluation_at, observed_at, clock_policy)
            if observed_at is not None and observed_at.tzinfo is not None else {})
        _append_event(connection, episode_id=episode["episode_id"],
            revision=revision, event_type="observation_requires_review",
            actor_id="g4-identity-reconciler", origin="identity_observation",
            decision_id=None, occurrence_ids=[occurrence_id],
            source_observation_id=observation_id, observed_at=observed_at,
            recorded_at=now, reason_codes=[reason], details=details)
        queue_if_changed()
        return {"status": "review", "reason": reason,
            "clock_policy": clock_policy, "evaluation_clock_utc":
                evaluation_at.isoformat().replace("+00:00", "Z")}

    confirmation_time = member.get("confirmed_at") or member.get("original_confirmed_at")
    if confirmation_time is None or observed_at <= confirmation_time:
        queue_if_changed()
        return {"status": "ignored_old_or_unconfirmed"}

    # A fully remediated exposure starts a successor episode exactly once.
    # A repeated fresh positive while that successor is open merely keeps its
    # affected member outstanding.
    if episode["state"] == "remediated":
        all_exposures = connection.execute(sa.select(exposure_episodes).where(
            exposure_episodes.c.exposure_id == exposure_id).order_by(
                exposure_episodes.c.episode_number.desc())).mappings().all()
        successor_id = _id()
        number = int(episode["episode_number"]) + 1
        all_member_rows = connection.execute(sa.select(exposure_episode_members).where(
            exposure_episode_members.c.episode_id == episode["episode_id"]).order_by(
                exposure_episode_members.c.occurrence_id)).mappings().all()
        current_members = set(_current_members(connection, exposure_id))
        connection.execute(exposure_episodes.update().where(
            exposure_episodes.c.episode_id == episode["episode_id"]).values(
                is_current=False, updated_at=now))
        connection.execute(exposure_episodes.insert().values(
            episode_id=successor_id, exposure_id=exposure_id, group_id=group_id,
            episode_number=number, state_revision=1, state="open", is_current=True,
            opened_at=observed_at, closed_at=None, created_at=now, updated_at=now))
        copied = []
        copied_statuses = []
        for previous in all_member_rows:
            old_member_id = previous["occurrence_id"]
            if old_member_id not in current_members:
                continue
            if old_member_id == occurrence_id:
                status, reason = "outstanding", "new_positive_observation"
                current_decision = current_time = None
            else:
                original_time = (previous["confirmed_at"]
                    or previous["original_confirmed_at"])
                contradicted = False
                if original_time is not None:
                    contradicted = connection.execute(sa.select(
                        source_observations.c.observation_id).where(
                            source_observations.c.occurrence_id == old_member_id,
                            source_observations.c.collection_status != "failed",
                            source_observations.c.observed_at > original_time).limit(1)
                        ).first() is not None
                if (previous["status"] in {"confirmed", "continuity_covered"}
                        and original_time is not None and not contradicted):
                    status, reason = "continuity_covered", "verified_continuity"
                    current_decision = previous["confirmation_decision_id"] or previous["original_decision_id"]
                    current_time = original_time
                else:
                    status, reason = "outstanding", "continuity_not_proven"
                    current_decision = current_time = None
            connection.execute(exposure_episode_members.insert().values(
                episode_id=successor_id, occurrence_id=old_member_id, status=status,
                coverage_reason=reason,
                original_decision_id=previous["original_decision_id"],
                original_confirmed_at=previous["original_confirmed_at"],
                confirmation_decision_id=current_decision, confirmed_at=current_time,
                updated_at=now))
            copied.append(old_member_id)
            copied_statuses.append(status)
        successor_state = _state(copied_statuses)
        connection.execute(exposure_episodes.update().where(
            exposure_episodes.c.episode_id == successor_id).values(state=successor_state))
        # The direct recurrence event is appended after the successor and all
        # continuity references have been written in the same transaction.
        _append_event(connection, episode_id=successor_id, revision=1,
            event_type="recurrence_opened", actor_id="g4-identity-reconciler",
            origin="identity_observation", decision_id=None,
            occurrence_ids=copied, source_observation_id=observation_id,
            observed_at=observed_at, recorded_at=now,
            reason_codes=["newer_positive_after_remediation"],
            details={"predecessor_episode_id": episode["episode_id"],
                "trigger_occurrence_id": occurrence_id,
                **_clock_evidence(evaluation_at, observed_at, clock_policy)})
        queue_if_changed()
        return {"status": "recurrence_opened", "episode_id": successor_id,
            "episode_number": number, "prior_episode_id": episode["episode_id"]}

    # Partial coverage is invalidated only for the affected occurrence; other
    # direct or verified-continuity coverage remains traceable.
    if member["status"] in {"confirmed", "continuity_covered"}:
        revision = int(episode["state_revision"]) + 1
        connection.execute(exposure_episode_members.update().where(
            exposure_episode_members.c.episode_id == episode["episode_id"],
            exposure_episode_members.c.occurrence_id == occurrence_id).values(
                status="outstanding", coverage_reason="new_positive_observation",
                confirmation_decision_id=None, confirmed_at=None, updated_at=now))
        statuses = list(connection.execute(sa.select(
            exposure_episode_members.c.status).where(
                exposure_episode_members.c.episode_id == episode["episode_id"])).scalars())
        connection.execute(exposure_episodes.update().where(
            exposure_episodes.c.episode_id == episode["episode_id"]).values(
                state=_state(statuses), state_revision=revision, closed_at=None,
                updated_at=now))
        _append_event(connection, episode_id=episode["episode_id"],
            revision=revision, event_type="coverage_reopened",
            actor_id="g4-identity-reconciler", origin="identity_observation",
            decision_id=None, occurrence_ids=[occurrence_id],
            source_observation_id=observation_id, observed_at=observed_at,
            recorded_at=now, reason_codes=["newer_positive_after_confirmation"],
            details=_clock_evidence(evaluation_at, observed_at, clock_policy))
        queue_if_changed()
        return {"status": "coverage_reopened", "episode_id": episode["episode_id"],
            "state_revision": revision}
    queue_if_changed()
    return {"status": "outstanding_or_duplicate", "episode_id": episode["episode_id"]}


def public_episode_view(records: list[dict]) -> list[dict]:
    return [{"exposure_id": record["episode"]["exposure_id"],
        "episode_id": record["episode"]["episode_id"],
        "episode_number": record["episode"]["episode_number"],
        "state_revision": record["episode"]["state_revision"],
        "state": record["episode"]["state"],
        "members": [{"membership_id": row["occurrence_id"],
            "status": "review" if record.get("adoption_required") else row["status"],
            "coverage_reason": "legacy_adoption_required" if record.get("adoption_required")
                else row["coverage_reason"],
            "original_confirmation_decision_id": row["original_decision_id"],
            "original_confirmation_at": row["original_confirmed_at"].isoformat().replace("+00:00", "Z")
                if row["original_confirmed_at"] else None,
            "confirmed_by_decision_id": row["confirmation_decision_id"],
            "confirmed_at": row["confirmed_at"].isoformat().replace("+00:00", "Z")
                if row["confirmed_at"] else None} for row in record["members"]],
        "recurrence": {"count": record["recurrence_count"],
            "last_event_at": record["last_recurrence_at"].isoformat().replace("+00:00", "Z")
                if record["last_recurrence_at"] else None,
            "reason_codes": record["recurrence_reason_codes"]},
        "adoption_required": bool(record.get("adoption_required", False)),
        "review_reasons": record["review_reasons"] or ([]
            if record["episode"]["state"] != "review" else ["episode_requires_review"])}
        for record in records]
