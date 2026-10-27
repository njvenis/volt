"""Canonical classification of the sources selected for one report context.

Callers select effective/known latest evidence per authoritative source first.
An exact-member assessment override can supply classification; otherwise every
selected source must resolve, and all resolved classes must agree.
"""
from __future__ import annotations
from datetime import datetime, timezone


def resolve_classification(source_values, mapping, *, override=None):
    """Return (canonical value or None, immutable gap reasons)."""
    labels = {str(label).strip().casefold(): str(value).strip().casefold()
        for label, value in mapping.items()}
    if override is not None:
        canonical_override = str(override).strip().casefold()
        return ((canonical_override, ()) if canonical_override in {
            "critical", "high", "medium", "low", "informational"}
            else (None, ("missing_classification",)))
    values = list(source_values)
    canonical = set()
    unresolved = not values
    for value in values:
        raw = str(value).strip().casefold() if value is not None else ""
        resolved = labels.get(raw) if labels else (
            raw if raw in {"critical", "high", "medium", "low", "informational"} else None)
        if resolved is None:
            unresolved = True
        else:
            canonical.add(resolved)
    gaps = []
    if unresolved:
        gaps.append("missing_classification")
    if len(canonical) > 1:
        gaps.append("source_classification_conflict")
    return (next(iter(canonical)) if len(canonical) == 1 and not gaps else None,
        tuple(gaps))


def trustworthy_causal_start(events, occurrence_id, observations):
    """Use reliable retained positives, never review timestamps or receipt time.

    Callers bound events/observations by effective and knowledge context.
    observations are dictionaries including observation_id, observed_at,
    collected_at and collection_status. Review events disqualify their row.
    """
    return trustworthy_causal_transition(events, occurrence_id, observations)["started_at"]


def trustworthy_causal_transition(events, occurrence_id, observations):
    """Resolve a member's causal start and exact reset event as one value.

    `events` and `observations` must already be bounded by the caller's
    effective and knowledge clocks. Carrying the event identity with its
    timestamp prevents a later reset from accidentally reusing an older
    evaluation's marker.
    """
    rejected = {event.get("source_observation_id") for event in events
        if event.get("event_type") == "observation_requires_review"
        and occurrence_id in (event.get("occurrence_ids") or [])}
    qualifying = [row["observed_at"] for row in observations
        if row.get("observed_at") is not None
        and row.get("collection_status") != "failed"
        and row.get("observation_id") not in rejected
        and row.get("collected_at") is not None]
    for event in reversed(events):
        applies = occurrence_id in (event.get("occurrence_ids") or [])
        if event.get("event_type") == "recurrence_opened":
            applies = event.get("details", {}).get("trigger_occurrence_id") == occurrence_id
        if applies and event.get("event_type") in {"coverage_reopened", "recurrence_opened"}:
            start = event.get("observed_at") or event.get("recorded_at")
            if start is not None:
                return {"started_at": start, "event_id": event.get("event_id"),
                    "event": event, "source": "episode_transition"}
    return {"started_at": min(qualifying, default=None), "event_id": None,
        "event": None, "source": "retained_observation" if qualifying else "unknown"}


def evaluation_revision_head(history):
    """Return the current authorised evaluation head, excluding report branches."""
    authoritative = [row for row in history if row.get("is_authoritative", True)]
    candidates = authoritative or list(history)
    return max(candidates, key=lambda row: int(row["revision"]), default=None)


def evaluation_for_context(history, as_of, known_at):
    """Select the newest applicable row across authoritative and derived history.

    A report-only derivation is reusable when its effective and knowledge
    clocks fit this context.  The separate authoritative-head selector governs
    writer lineage, so selecting a historical branch here never promotes it
    over a newer accepted writer head.
    """
    visible = [row for row in history
        if row["effective_at"] <= as_of and row["known_at"] <= known_at]
    if not visible:
        return None
    # Supersession requires applicability on BOTH clocks. Crossed boundaries
    # are separate branches, not a total order of effective timestamps.
    candidates = [row for row in visible if not any(
        other["effective_at"] >= row["effective_at"]
        and other["known_at"] >= row["known_at"]
        and (other["effective_at"] > row["effective_at"]
            or other["known_at"] > row["known_at"])
        for other in visible)]
    by_id = {row.get("evaluation_id"): row for row in history if row.get("evaluation_id")}

    def descends_from(row, ancestor_id):
        seen = set()
        predecessor_id = row.get("predecessor_evaluation_id")
        while predecessor_id and predecessor_id not in seen:
            if predecessor_id == ancestor_id:
                return True
            seen.add(predecessor_id)
            predecessor = by_id.get(predecessor_id)
            predecessor_id = predecessor.get("predecessor_evaluation_id") if predecessor else None
        return False

    # At an identical pair of context clocks use explicit lineage, then the
    # recorded derivation origin. Revision is only an identifier/order guard,
    # never a substitute for knowledge or supersession.
    maximal = [row for row in candidates if not any(
        other is not row and descends_from(other, row.get("evaluation_id"))
        for other in candidates)]
    if len(maximal) == 1:
        return maximal[0]
    # A historical calculation cannot supersede an applicable accepted head
    # across an unrelated, incomparable knowledge branch. Keep the retained
    # authoritative lineage; never manufacture a winner by revision/UUID.
    accepted = evaluation_revision_head([row for row in maximal
        if row.get("is_authoritative", True)]) if any(
            row.get("is_authoritative", True) for row in maximal) else None
    if accepted is not None and all(
        row is accepted or row.get("known_at") < accepted["known_at"]
        for row in maximal):
        return accepted
    writers = [row for row in maximal if row.get("derivation_kind") == "writer"]
    if len(writers) == 1:
        return writers[0]
    semantic_keys = {
        tuple(row.get(key) for key in (
            "policy_id", "policy_version", "reference_binding_id", "started_at",
            "original_deadline_at", "current_deadline_at", "deadline_basis",
            "head_decision_id", "clock_reset_event_id", "clock_reset_absorbed"))
        + (tuple(row.get("gap_reasons") or ()),)
        for row in maximal
    }
    if len(semantic_keys) == 1 and accepted is not None:
        return accepted
    return None


def evaluation_is_authoritative_in_context(history, as_of, known_at):
    """A report derivation is a head only when no newer head is out of context."""
    head = evaluation_revision_head(history)
    return head is None or (head["effective_at"] <= as_of and head["known_at"] <= known_at)


def next_evaluation_revision(history):
    """Allocate a unique per-member revision across authoritative/history branches."""
    return max((int(row["revision"]) for row in history), default=0) + 1


def has_unabsorbed_causal_reset(history, head, causal_start, *,
        causal_event_id=None, causal_known_at=None):
    """Whether this head is the first clock row after a causal reset.

    A report may materialise the reset before a later classification writer.
    The predecessor link preserves that lineage so writer order cannot change
    the original baseline. The first subsequent writer absorbs the reset once;
    later writers see a same-clock predecessor and preserve its decisions.
    """
    if head is None or causal_start is None or head.get("started_at") != causal_start:
        return False
    reset_event_id = head.get("clock_reset_event_id")
    if reset_event_id is not None:
        if causal_event_id is not None and causal_event_id != reset_event_id:
            return True
        return not bool(head.get("clock_reset_absorbed", False))
    if (causal_event_id is not None and causal_known_at is not None
            and causal_known_at > head["known_at"]):
        return True
    by_id = {row.get("evaluation_id"): row for row in history if row.get("evaluation_id")}
    chain = []
    seen = set()
    cursor = head
    while cursor is not None and cursor.get("evaluation_id") not in seen:
        seen.add(cursor.get("evaluation_id"))
        chain.append(cursor)
        predecessor_id = cursor.get("predecessor_evaluation_id")
        cursor = by_id.get(predecessor_id) if predecessor_id else None
    reset_index = next((index for index, row in enumerate(chain)
        if row.get("started_at") == causal_start and any(
            ancestor.get("started_at") != causal_start for ancestor in chain[index + 1:])), None)
    if reset_index is None:
        return False
    # A command writer on this reset clock absorbs the event. Report
    # derivations carry the lineage marker forward without consuming it.
    return not any((row.get("derivation_kind") == "writer"
        # Before 0031, an accepted deadline decision is durable writer
        # provenance even though the row origin field is necessarily legacy.
        # Treat that decision as absorbing the reset instead of rediscovering
        # the reset from its missing origin marker on every later writer.
        or row.get("head_decision_id") is not None)
        and row.get("started_at") == causal_start
        for row in chain[:reset_index + 1])


def select_reset_policy(policy_rows, group_id, stable_attrs, clock_at, *,
        policy_scope_matches):
    """Select the policy for a new causal clock using shared reset rules.

    Backfill authorises exact targets at publication time. It is never a
    reusable scope-wide policy for a later reset; changed clocks require an
    applicable prospective policy. Callers pass rows already bounded by
    `known_at` and the same environment/service predicate used by evaluation.
    """
    candidates = []
    for row in policy_rows:
        # A policy published after the causal anchor cannot retroactively
        # authorise that clock, even if its interval is backdated.
        if row.get("created_at") is not None and row["created_at"] > clock_at:
            continue
        document = row["document"]
        scope = document.get("scope", {})
        if group_id not in scope.get("group_ids", []):
            continue
        if not policy_scope_matches(document, stable_attrs):
            continue
        if document.get("backfill", {}).get("mode") != "prospective":
            continue
        try:
            starts = datetime.fromisoformat(document["effective_from"].replace("Z", "+00:00"))
            ends = (datetime.fromisoformat(document["effective_until"].replace("Z", "+00:00"))
                if document.get("effective_until") else None)
        except (KeyError, TypeError, ValueError):
            continue
        if starts <= clock_at and (ends is None or clock_at < ends):
            candidates.append(row)
    if len(candidates) == 1:
        return candidates[0], None
    return None, "conflicting_sla_policies" if candidates else "no_applicable_sla_policy"



def elapsed_deadline(started_at, duration_seconds):
    """Add elapsed policy seconds in UTC, independently of display/session zone."""
    from datetime import timedelta
    return started_at.astimezone(timezone.utc) + timedelta(seconds=duration_seconds)

def guard_pending_anchor(started_at, as_of, original_deadline, current_deadline,
        deadline_basis, gap_reasons):
    """Apply anchor applicability after all deadline precedence decisions.

    Retain bindings, decisions and warnings as provenance, but no source of
    deadline authority can make a committed future clock applicable early.
    """
    reasons = list(gap_reasons)
    if started_at is not None and started_at > as_of:
        if "awaiting_source_time" not in reasons:
            reasons.append("awaiting_source_time")
        return None, None, "unknown", reasons
    return original_deadline, current_deadline, deadline_basis, reasons


def reset_original_baseline(connection, policy, *, group_id, episode_id,
        occurrence_id, started_at, known_at, source_watermark=None, event_watermark=None, as_of=None):
    """Recover the computable causal baseline, independently of first read time.

    Later scanner classifications and later overrides change the current
    deadline, not the original classification at the retained reset anchor.
    Bound both evidence clocks and any frozen report watermarks. An unknown
    causal classification stays unknown; callers may record a later first
    computable deadline without pretending it was known at the reset.
    """
    if policy is None or started_at is None or started_at > (as_of or known_at):
        return None
    import sqlalchemy as sa
    from uvm.persistence.observation_schema import source_observations
    from uvm.persistence.assessment_schema import assessment_audit_events
    from uvm.assessment.sla_references import resolve_policy_reference
    query = sa.select(source_observations).where(
        source_observations.c.occurrence_id == occurrence_id,
        source_observations.c.observed_at <= started_at,
        source_observations.c.collected_at <= known_at,
        source_observations.c.collection_status != "failed")
    if source_watermark is not None:
        query = query.where(source_observations.c.retention_order <= source_watermark)
    sources = {}
    for row in connection.execute(query.order_by(
            source_observations.c.observed_at.desc(),
            source_observations.c.retention_order.desc())).mappings():
        sources.setdefault((row["source_family"], row["source_account_id"]), row)
    query = sa.select(assessment_audit_events).where(
        assessment_audit_events.c.target_id == group_id,
        assessment_audit_events.c.action == "severity.override",
        assessment_audit_events.c.occurred_at <= started_at,
        assessment_audit_events.c.received_at <= known_at)
    if event_watermark is not None:
        query = query.where(assessment_audit_events.c.event_sequence <= event_watermark)
    override = None
    for event in connection.execute(query.order_by(
            assessment_audit_events.c.event_sequence)).mappings():
        if occurrence_id in (event["membership_ids"] or []):
            override = ((event["after_value"] or {}).get("assessed_severity") or {}).get("value")
    document = policy["document"]
    severity, gaps = resolve_classification([row["source_rating"] for row in sources.values()],
        document.get("classification", {}).get("source_rating_map", {}), override=override)
    duration = document.get("duration_seconds_by_severity", {}).get(severity)
    baseline = (elapsed_deadline(started_at, duration)
        if not gaps and type(duration) is int and duration > 0 else None)
    reference = resolve_policy_reference(connection, document,
        policy_id=policy["policy_id"], policy_version=int(policy["version"]),
        episode_id=episode_id, occurrence_id=occurrence_id,
        started_at=started_at, as_of=started_at, known_at=known_at)
    if reference and reference["status"] == "complete":
        return datetime.fromisoformat(reference["deadline_at"].replace("Z", "+00:00"))
    if reference and reference["status"] == "conflict":
        return None
    return baseline
