"""Pure versioned G7 SLA clock arithmetic and durable intent keys.

G5 keeps its own scanner-observation contract. Callers opt into this module
only for an explicitly selected ``uvm_ingest_commit_v1`` policy.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from hashlib import sha256
import json

START_SOURCE = "uvm_ingest_commit_v1"
DEFINITION = "g7-exception-sla-v1"
LEGACY_START_SOURCE = "source_observation_v1"
SUPPORTED_CLOCK_BASES = {"elapsed_utc_seconds", "calendar_days_utc"}


def _utc(value: datetime, label: str) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{label} must be timezone-aware")
    return value.astimezone(timezone.utc)


def elapsed_duration(started_at: datetime, deadline_at: datetime) -> timedelta:
    """Return a nonnegative UTC duration, preserving zero for an overdue atom."""
    return max(timedelta(0), _utc(deadline_at, "deadline_at") - _utc(started_at, "started_at"))


def pause_snapshot(*, started_at: datetime, original_deadline_at: datetime | None,
                   current_deadline_at: datetime | None, approved_at: datetime,
                   expires_at: datetime, previously_breached: bool,
                   clock_basis: str = "elapsed_utc_seconds") -> dict:
    """Freeze one known atom; an unknown deadline remains an explicit gap."""
    if clock_basis not in SUPPORTED_CLOCK_BASES:
        raise ValueError("unsupported SLA clock basis")
    approved = _utc(approved_at, "approved_at")
    expiry = _utc(expires_at, "expires_at")
    if expiry <= approved:
        raise ValueError("expiry must be after approval")
    started = _utc(started_at, "started_at")
    if original_deadline_at is None or current_deadline_at is None:
        return {"status": "gap", "started_at": started, "original_deadline_at": None,
                "pre_pause_deadline_at": None, "remaining_seconds": None,
                "previously_breached": bool(previously_breached), "approved_at": approved,
                "expires_at": expiry, "clock_basis": clock_basis}
    original = _utc(original_deadline_at, "original_deadline_at")
    current = _utc(current_deadline_at, "current_deadline_at")
    return {"status": "paused", "started_at": started, "original_deadline_at": original,
            "pre_pause_deadline_at": current,
            "remaining_seconds": max(0, (current - approved).total_seconds()),
            "previously_breached": bool(previously_breached or approved > current),
            "approved_at": approved, "expires_at": expiry, "clock_basis": clock_basis}


def resumed_deadline(snapshot: dict, effective_end: datetime, *, allow_early: bool = False) -> datetime | None:
    """Calculate from the committed end instant, never a late worker's now."""
    if snapshot.get("status") != "paused":
        return None
    end = _utc(effective_end, "effective_end")
    expiry = _utc(snapshot["expires_at"], "expires_at")
    if end < expiry and not allow_early:
        raise ValueError("pause cannot end before its selected expiry unless explicitly revoked/suspended")
    return end + timedelta(seconds=float(snapshot["remaining_seconds"]))


def state_at(snapshot: dict, instant: datetime, *, terminal_confirmation_at: datetime | None = None) -> dict:
    """Read one pause interval with equality resolved as expiry being effective."""
    at = _utc(instant, "instant")
    expiry = _utc(snapshot["expires_at"], "expires_at")
    if terminal_confirmation_at is not None and _utc(terminal_confirmation_at, "terminal_confirmation_at") <= at:
        return {"state": "completed_during_exception" if _utc(terminal_confirmation_at, "terminal_confirmation_at") < expiry else "completed",
                "target_at": None, "remaining_seconds": 0,
                "prior_breach": bool(snapshot.get("previously_breached"))}
    if at < expiry:
        return {"state": snapshot["status"], "target_at": expiry,
                "remaining_seconds": max(0, (expiry - at).total_seconds()),
                "frozen_sla_seconds": snapshot.get("remaining_seconds"),
                "prior_breach": bool(snapshot.get("previously_breached"))}
    deadline = resumed_deadline(snapshot, expiry)
    return {"state": "running" if deadline is not None else "gap",
            "target_at": deadline, "remaining_seconds": max(0, (deadline - at).total_seconds()) if deadline else None,
            "prior_breach": bool(snapshot.get("previously_breached")),
            "currently_breached": bool(deadline and at > deadline)}


def warning_intent_key(*, decision_id: str, expiry_revision: int, offset_seconds: int,
                       channel: str, destination_ref: str) -> str:
    """Stable idempotency key; channel/destination retries remain independent."""
    if channel not in {"slack", "email"} or type(expiry_revision) is not int or expiry_revision < 1:
        raise ValueError("invalid warning intent identity")
    if type(offset_seconds) is not int or offset_seconds < 0 or not destination_ref:
        raise ValueError("invalid warning offset or destination")
    value = [decision_id, expiry_revision, offset_seconds, channel, destination_ref]
    return sha256(json.dumps(value, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()
