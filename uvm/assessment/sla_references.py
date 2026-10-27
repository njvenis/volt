"""Resolve immutable G5 policy bindings to retained G3 deadline references."""
from datetime import timezone

import sqlalchemy as sa

from uvm.persistence.deadline_reference_store import DeadlineReferenceStore
from uvm.persistence.deadline_reference_schema import identity_deadline_references

UTC = timezone.utc


def _instant(value):
    if value is None:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=UTC)
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def resolve_policy_reference(connection, policy_document, *, policy_id, policy_version,
        episode_id, occurrence_id, started_at, as_of, known_at,
        reference_history_cache=None, reference_recorded_at_cache=None):
    """Return a recognized complete exact binding, a fail-closed gap, or None.

    Binding records live inside immutable published policy versions. A rule is
    applicable only to its exact episode, occurrence, policy version, start,
    and retained reference ID. Unbound supplied history does not suppress a
    separately complete policy calculation.
    """
    rules = policy_document.get("deadline_reference_rules", {})
    bindings = rules.get("bindings", []) if isinstance(rules, dict) else []
    candidates = [item for item in bindings if item.get("episode_id") == episode_id
        and item.get("occurrence_id") == occurrence_id
        and item.get("policy_id") == policy_id
        and item.get("policy_version") == policy_version]
    if not candidates:
        return None
    applicable = []
    for binding in candidates:
        reference_id = binding.get("reference_id")
        history = (reference_history_cache.get(occurrence_id)
            if reference_history_cache is not None else None)
        if history is None:
            history = DeadlineReferenceStore.read_history_on_connection(connection, occurrence_id)
            if reference_history_cache is not None:
                reference_history_cache[occurrence_id] = history
        matching = next((row for row in history if row["reference"]["reference_id"] == reference_id), None)
        if matching is None:
            continue
        if reference_recorded_at_cache is not None and reference_id in reference_recorded_at_cache:
            recorded_at = reference_recorded_at_cache[reference_id]
        else:
            recorded_at = connection.execute(sa.select(identity_deadline_references.c.recorded_at).where(
                identity_deadline_references.c.reference_id == reference_id)).scalar_one_or_none()
            if reference_recorded_at_cache is not None:
                reference_recorded_at_cache[reference_id] = recorded_at
        if recorded_at is None or recorded_at > as_of or recorded_at > known_at:
            continue
        applicable.append((binding, matching["reference"], recorded_at))
    if not applicable:
        return None
    evidence_known_at = max(item[2] for item in applicable)
    if len(applicable) != 1:
        return {"known_at": evidence_known_at, "status": "conflict", "deadline_at": None, "reference_binding_id": None,
            "gap_reasons": ["conflicting_deadline_references"]}
    binding, reference, _ = applicable[0]
    if binding.get("started_at") != _instant(started_at):
        return {"known_at": evidence_known_at, "status": "incomplete", "deadline_at": None,
            "reference_binding_id": binding.get("binding_id"),
            "gap_reasons": ["deadline_reference_start_mismatch"]}
    if not reference.get("deadline_at") or not reference.get("policy_ref"):
        return {"known_at": evidence_known_at, "status": "incomplete", "deadline_at": None,
            "reference_binding_id": binding.get("binding_id"),
            "gap_reasons": ["incomplete_deadline_reference"]}
    return {"known_at": evidence_known_at, "status": "complete", "deadline_at": reference["deadline_at"],
        "reference_binding_id": binding["binding_id"], "gap_reasons": []}
