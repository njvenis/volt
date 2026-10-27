"""Transactional G7 clock projection and evaluation helpers.

All G7 readers use this projection so an expired pause resolves at its
contractual expiry even when the expiry worker runs late.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import uuid

import sqlalchemy as sa

from uvm.persistence.exception_sla_schema import (sla_clock_events,
    sla_episode_contracts, sla_ingest_receipts, source_observation_receipts)
from uvm.persistence.metrics_schema import (g7_sla_evaluations,
    sla_policy_versions)
from uvm.persistence.observation_schema import source_observations


EARLIER_RECEIPT_GAP = "earlier_proven_ingest_receipt_requires_authorised_correction"


def _time(value):
    return datetime.fromisoformat(value.replace("Z", "+00:00")) if isinstance(value, str) else value


def project_clock(events, at: datetime, evaluations=()) -> dict:
    """Reconcile effective events and evaluation revisions; completion is terminal."""
    if at.tzinfo is None or at.utcoffset() is None:
        raise ValueError("projection instant must be timezone-aware")
    state = {"state": "gap", "target_at": None, "frozen_sla_seconds": None,
             "prior_breach": False, "remaining_seconds": None}
    # An event consumes its captured evaluation revision. At an unchanged
    # clock instant it follows that revision and precedes a subsequent revision.
    # Event sequence retains transaction order within the same evaluation head.
    timeline = [(row["effective_at"], int(row["revision"]), 0, 0, "evaluation", dict(row))
                for row in evaluations if row["effective_at"] <= at]
    timeline += [(row["effective_at"], int(row.get("evaluation_revision", 0)), 1, int(row["sequence"]), "event", dict(row))
                 for row in events if row["effective_at"] <= at]
    for effective, _, _, _, kind, row in sorted(timeline, key=lambda item: item[:4]):
        if state["state"] in {"completed", "completed_during_exception"}:
            break
        # Resolve implicit expiry before a subsequent command/evaluation.
        if state["state"] == "paused" and effective >= state["target_at"]:
            state.update(state="running", target_at=state["target_at"] + timedelta(
                seconds=state["frozen_sla_seconds"]), frozen_sla_seconds=None)
        # Preserve breach already incurred before replacing a running target.
        state["prior_breach"] |= bool(state["state"] == "running"
            and state["target_at"] and effective > state["target_at"])
        if kind == "evaluation":
            if state["state"] != "paused":
                target = row["current_deadline_at"]
                state.update(state="running" if target else "gap", target_at=target,
                             frozen_sla_seconds=None, evaluation_revision=row["revision"])
            continue
        data = row.get("data") or {}
        event_type = row["event_type"]
        state["event_id"] = row["event_id"]
        state["prior_breach"] |= bool(data.get("previously_breached"))
        if event_type == "started" and data.get("gap_reason") == EARLIER_RECEIPT_GAP:
            state.update(state="gap", target_at=None, frozen_sla_seconds=None,
                         requires_authorised_correction=True, gap_reasons=[EARLIER_RECEIPT_GAP],
                         evaluation_revision=row["evaluation_revision"])
        elif event_type == "paused":
            target = _time(data.get("expires_at"))
            state.update(state=data.get("status", "paused"),
                target_at=target if data.get("remaining_seconds") is not None else None,
                frozen_sla_seconds=data.get("remaining_seconds"))
        elif event_type == "completed":
            state.update(state=("completed_during_exception" if state["state"] == "paused"
                else "completed"), target_at=None, frozen_sla_seconds=None,
                completed_at=effective)
        elif event_type in {"resumed", "revoked", "suspended"}:
            if int(row.get("evaluation_revision", 0)) < int(state.get("evaluation_revision", 0)):
                continue
            target = _time(data.get("resumed_deadline_at"))
            state.update(state="running" if target else "gap", target_at=target,
                         frozen_sla_seconds=None)
    if state["state"] == "paused" and at >= state["target_at"]:
        state.update(state="running", target_at=state["target_at"] + timedelta(
            seconds=state["frozen_sla_seconds"]), frozen_sla_seconds=None)
    target = state["target_at"]
    state["remaining_seconds"] = max(0, (target-at).total_seconds()) if target else None
    state["currently_breached"] = bool(state["state"] == "running" and target and at > target)
    state["prior_breach"] |= state["currently_breached"]
    return state


def read_clock(connection, episode_id: str, occurrence_id: str, at: datetime,
               *, known_at=None) -> dict:
    known_at = known_at or at
    rows = connection.execute(sa.select(sla_clock_events).where(
        sla_clock_events.c.episode_id == episode_id,
        sla_clock_events.c.occurrence_id == occurrence_id,
        sla_clock_events.c.recorded_at <= known_at).order_by(
        sla_clock_events.c.sequence)).mappings().all()
    evaluations = connection.execute(sa.select(g7_sla_evaluations).where(
        g7_sla_evaluations.c.episode_id == episode_id,
        g7_sla_evaluations.c.occurrence_id == occurrence_id,
        g7_sla_evaluations.c.known_at <= known_at)).mappings().all()
    return project_clock(rows, at, evaluations)


def evaluation_head(connection, episode_id: str, occurrence_id: str, *, for_update=False):
    query = sa.select(g7_sla_evaluations).where(
        g7_sla_evaluations.c.episode_id == episode_id,
        g7_sla_evaluations.c.occurrence_id == occurrence_id,
        g7_sla_evaluations.c.is_authoritative.is_(True)).order_by(
        g7_sla_evaluations.c.revision.desc()).limit(1)
    if for_update:
        query = query.with_for_update()
    return connection.execute(query).mappings().first()


def process_expired_pauses(engine, now: datetime) -> int:
    """Append idempotent expiry transitions effective at selected expiry."""
    from datetime import timedelta
    if now.tzinfo is None or now.utcoffset() is None:
        raise ValueError("worker instant must be timezone-aware")
    now = now.astimezone(timezone.utc)
    changed = 0
    with engine.begin() as connection:
        pauses = connection.execute(sa.select(sla_clock_events).where(
            sla_clock_events.c.event_type == "paused",
            sla_clock_events.c.effective_at <= now).order_by(
                sla_clock_events.c.recorded_at).with_for_update(skip_locked=True)).mappings().all()
        for pause in pauses:
            exists = connection.execute(sa.select(sla_clock_events.c.event_id).where(
                sla_clock_events.c.episode_id == pause["episode_id"],
                sla_clock_events.c.occurrence_id == pause["occurrence_id"],
                sla_clock_events.c.predecessor_event_id == pause["event_id"])).first()
            if exists:
                continue
            data = dict(pause["data"] or {})
            expiry = data.get("expires_at")
            if isinstance(expiry, str):
                expiry = datetime.fromisoformat(expiry.replace("Z", "+00:00"))
            if expiry is None or expiry.astimezone(timezone.utc) > now:
                continue
            remaining = data.get("remaining_seconds")
            deadline = expiry.astimezone(timezone.utc) + timedelta(seconds=float(remaining)) if remaining is not None else None
            seq = connection.execute(sa.select(sa.func.coalesce(
                sa.func.max(sla_clock_events.c.sequence), 0) + 1).where(
                sla_clock_events.c.episode_id == pause["episode_id"],
                sla_clock_events.c.occurrence_id == pause["occurrence_id"])).scalar_one()
            data.update({"resumed_at": expiry.isoformat().replace("+00:00", "Z"),
                "resumed_deadline_at": deadline.isoformat().replace("+00:00", "Z") if deadline else None,
                "accepted_risk": True})
            connection.execute(sla_clock_events.insert().values(
                event_id=str(uuid.uuid4()), episode_id=pause["episode_id"],
                occurrence_id=pause["occurrence_id"], sequence=int(seq),
                event_type="resumed", effective_at=expiry, recorded_at=now,
                ingest_receipt_id=pause["ingest_receipt_id"], decision_id=pause["decision_id"],
                membership_ids=pause["membership_ids"], policy_id=pause["policy_id"],
                policy_version=pause["policy_version"],
                evaluation_revision=pause["evaluation_revision"],
                predecessor_event_id=pause["event_id"], data=data))
            changed += 1
    return changed


def record_earlier_proven_receipt_gap(connection, *, episode_id, occurrence_id,
        original_receipt, earlier_receipt, resolution_id, authorisation_decision_id, known_at):
    """Append uncertainty/provenance without rewriting receipts or frozen decisions.

    The caller has resolved both retained positives to the exact occurrence under
    the identity transaction lock. Locators alone never establish this proof.
    """
    events = connection.execute(sa.select(sla_clock_events).where(
        sla_clock_events.c.episode_id == episode_id,
        sla_clock_events.c.occurrence_id == occurrence_id).order_by(
        sla_clock_events.c.sequence).with_for_update()).mappings().all()
    if any((row["data"] or {}).get("earlier_retention_receipt_id") == earlier_receipt["receipt_id"]
           for row in events):
        return
    head = evaluation_head(connection, episode_id, occurrence_id, for_update=True)
    if head is None:
        head = ensure_current_evaluation(connection, episode_id=episode_id,
            occurrence_id=occurrence_id, known_at=known_at)
    event_id = str(uuid.uuid4())
    revision = connection.execute(sa.select(sa.func.coalesce(
        sa.func.max(g7_sla_evaluations.c.revision), 0)+1).where(
        g7_sla_evaluations.c.episode_id == episode_id,
        g7_sla_evaluations.c.occurrence_id == occurrence_id)).scalar_one()
    evaluation = dict(head)
    evaluation.update(evaluation_id=str(uuid.uuid4()), revision=int(revision),
        predecessor_evaluation_id=head["evaluation_id"], started_at=None,
        original_deadline_at=None, current_deadline_at=None, deadline_basis="unknown",
        gap_reasons=sorted(set(head["gap_reasons"]) | {EARLIER_RECEIPT_GAP}),
        reference_binding_id=None, clock_reset_event_id=event_id,
        clock_reset_absorbed=False, effective_at=known_at, known_at=known_at,
        derivation_kind="writer", is_authoritative=True)
    connection.execute(g7_sla_evaluations.insert().values(**evaluation))
    def provenance(row):
        return {key: value.isoformat() if isinstance(value, datetime) else value
                for key, value in dict(row).items()}
    connection.execute(sla_clock_events.insert().values(
        event_id=event_id, episode_id=episode_id, occurrence_id=occurrence_id,
        sequence=max((int(row["sequence"]) for row in events), default=0)+1,
        event_type="started", effective_at=known_at, recorded_at=known_at,
        ingest_receipt_id=original_receipt["receipt_id"], decision_id=None,
        membership_ids=[occurrence_id], policy_id=head["policy_id"],
        policy_version=head["policy_version"], evaluation_revision=int(revision),
        predecessor_event_id=events[-1]["event_id"] if events else None,
        data={"gap_reason": EARLIER_RECEIPT_GAP,
            "original_ingest_receipt": provenance(original_receipt),
            "earlier_retention_receipt_id": earlier_receipt["receipt_id"],
            "earlier_retention_receipt": provenance(earlier_receipt),
            "identity_resolution_id": resolution_id,
            "authorisation_decision_id": authorisation_decision_id,
            "predecessor_evaluation_id": head["evaluation_id"],
            "evaluation_id": evaluation["evaluation_id"]}))


def classification_source_ratings(connection, occurrence_id: str, known_at: datetime):
    """Canonical retained, successfully retrieved source heads at the knowledge boundary."""
    observations = connection.execute(sa.select(source_observations).join(
        source_observation_receipts, source_observation_receipts.c.source_observation_id == source_observations.c.observation_id).where(
        source_observation_receipts.c.retained_at <= known_at,
        source_observations.c.occurrence_id == occurrence_id,
        source_observations.c.collected_at <= known_at,
        source_observations.c.collection_status != "failed",
        sa.or_(source_observations.c.observed_at.is_(None),
               source_observations.c.observed_at <= known_at)).order_by(
        source_observations.c.observed_at.desc().nullslast(),
        source_observations.c.retention_order.desc())).mappings().all()
    latest_sources = {}
    for observation in observations:
        latest_sources.setdefault((observation["source_family"], observation["source_account_id"]),
                                  observation["source_rating"])
    return tuple(latest_sources.values())


def ensure_current_evaluation(connection, *, episode_id: str, occurrence_id: str,
                              known_at: datetime, assessed_severity: str | None = None):
    """Create the G7 head from its pinned contract, without requiring a report."""
    from uvm.assessment.sla_classification import elapsed_deadline, evaluation_revision_head
    contract = connection.execute(sa.select(sla_episode_contracts).where(
        sla_episode_contracts.c.episode_id == episode_id).with_for_update()).mappings().first()
    receipt = connection.execute(sa.select(sla_ingest_receipts).where(
        sla_ingest_receipts.c.episode_id == episode_id,
        sla_ingest_receipts.c.occurrence_id == occurrence_id).with_for_update()).mappings().first()
    history = [dict(row) for row in connection.execute(sa.select(g7_sla_evaluations).where(
        g7_sla_evaluations.c.episode_id == episode_id,
        g7_sla_evaluations.c.occurrence_id == occurrence_id).order_by(
        g7_sla_evaluations.c.revision).with_for_update()).mappings().all()]
    head = evaluation_revision_head(history)
    if head and (head["known_at"] > known_at or EARLIER_RECEIPT_GAP in head["gap_reasons"]):
        return head
    if not contract or contract["contract_version"] != 7 or not receipt:
        if head:
            return head
        gaps = ["g7_contract_not_pinned"] if not contract or contract["contract_version"] != 7 else ["missing_durable_ingest_receipt"]
        row = {"evaluation_id": str(uuid.uuid4()), "episode_id": episode_id,
            "occurrence_id": occurrence_id, "revision": 1, "policy_id": None,
            "policy_version": None, "reference_binding_id": None, "started_at": None,
            "original_deadline_at": None, "current_deadline_at": None,
            "deadline_basis": "unknown", "gap_reasons": gaps,
            "predecessor_evaluation_id": None, "head_decision_id": None,
            "is_authoritative": True, "derivation_kind": "writer",
            "clock_reset_event_id": None, "clock_reset_absorbed": True,
            "effective_at": known_at, "known_at": known_at}
        connection.execute(g7_sla_evaluations.insert().values(**row))
        return row
    policy = connection.execute(sa.select(sla_policy_versions).where(
        sla_policy_versions.c.policy_id == contract["policy_id"],
        sla_policy_versions.c.version == contract["policy_version"]).with_for_update()).mappings().first()
    if policy is None or policy["document"].get("start_source") != "uvm_ingest_commit_v1":
        return None
    start = receipt["ingested_at"]
    from uvm.assessment.sla_classification import resolve_classification
    from uvm.assessment.sla_references import resolve_policy_reference
    ratings = classification_source_ratings(connection, occurrence_id, known_at)
    document = policy["document"]
    severity, reasons = resolve_classification(ratings,
        document.get("classification", {}).get("source_rating_map", {}), override=assessed_severity)
    gaps = list(reasons)
    eligible = document.get("eligibility", {}).get("included_severities", [])
    if severity is not None and eligible and severity not in eligible:
        gaps.append("severity_not_eligible")
    duration = document.get("duration_seconds_by_severity", {}).get(severity) if severity else None
    if type(duration) is not int or duration <= 0:
        gaps.append("missing_sla_duration")
    deadline = elapsed_deadline(start, duration) if not gaps else None
    basis = "policy_calculation" if deadline else "unknown"
    binding_id = None
    reference = resolve_policy_reference(connection, document,
        policy_id=contract["policy_id"], policy_version=contract["policy_version"],
        episode_id=episode_id, occurrence_id=occurrence_id, started_at=start,
        as_of=known_at, known_at=known_at)
    if reference:
        binding_id = reference["reference_binding_id"]
        gaps.extend(("warning:" + reason if reference["status"] == "incomplete" else reason)
                    for reason in reference["gap_reasons"])
        if reference["status"] == "complete":
            deadline = _time(reference["deadline_at"])
            basis = "supplied_reference"
        elif reference["status"] == "conflict":
            deadline, basis = None, "unknown"
    gaps = sorted(set(gaps))
    if head:
        clock = read_clock(connection, episode_id, occurrence_id, known_at)
        if clock["state"] in {"paused", "completed", "completed_during_exception"}:
            return head
        if head.get("head_decision_id"):
            deadline = head["current_deadline_at"]
            basis = head["deadline_basis"]
        elif clock.get("event_id"):
            if head["gap_reasons"] == gaps and head["reference_binding_id"] == binding_id:
                return head
            deadline = clock.get("target_at")
            basis = head["deadline_basis"]
        if (head["gap_reasons"] == gaps and head["current_deadline_at"] == deadline
                and head["reference_binding_id"] == binding_id):
            return head
    revision = max((int(item["revision"]) for item in history), default=0) + 1
    row = {"evaluation_id": str(uuid.uuid4()), "episode_id": episode_id,
        "occurrence_id": occurrence_id, "revision": revision,
        "policy_id": contract["policy_id"], "policy_version": contract["policy_version"],
        "reference_binding_id": binding_id, "started_at": start,
        "original_deadline_at": head["original_deadline_at"] if head else deadline, "current_deadline_at": deadline,
        "deadline_basis": basis,
        "gap_reasons": gaps, "predecessor_evaluation_id": history[-1]["evaluation_id"] if history else None,
        "head_decision_id": head["head_decision_id"] if head else None, "is_authoritative": True, "derivation_kind": "writer",
        "clock_reset_event_id": None, "clock_reset_absorbed": True,
        "effective_at": known_at, "known_at": known_at}
    connection.execute(g7_sla_evaluations.insert().values(**row))
    return row
