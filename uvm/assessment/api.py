"""Authenticated G3 HTTP routes, kept separate from the G2 read surfaces."""

from __future__ import annotations

from contextlib import contextmanager, nullcontext
from concurrent.futures import ThreadPoolExecutor
import hashlib
import hmac
import json
import math
import base64
import copy
import contextvars
import os
import re
import threading
import logging
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

import sqlalchemy as sa
from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request
from uvm.assessment.policy_lock import lock_policy
from uvm.auth.schema import AUTHORITY_CONTEXT
from uvm.auth.native_authority import (NATIVE_ACTIONS, NATIVE_MODE, apply_command as apply_native_command,
    effective_access, effective_team_members, native_state)
from uvm.assessment.sla_references import resolve_policy_reference
from uvm.assessment.sla_classification import (evaluation_revision_head,
    has_unabsorbed_causal_reset, next_evaluation_revision, resolve_classification,
    trustworthy_causal_transition, reset_original_baseline, elapsed_deadline,
    guard_pending_anchor)
from uvm.assessment.read_diagnostics import stage as read_stage
from uvm.assessment.report_authority import report_scope_read
from uvm.assessment.episodes import (confirm_members, ensure_current_episodes,
                                    public_episode_view, read_current_episodes)
from uvm.persistence.github_lifecycle import enqueue_group_projection

from uvm.persistence.assessment_schema import (
    assessment_audit_events, assessment_command_receipts,
    assessment_export_acknowledgements, assessment_group_state,
    assessment_policy, assessment_projection_intents,
)
from uvm.persistence.auth_schema import auth_principals, oidc_sessions
from uvm.persistence.native_authority_schema import administration_reconciliation_intents
from uvm.persistence.metrics_schema import metrics_report_atoms, report_requests
from uvm.persistence.metrics_schema import (reporting_projection_intents,
    inventory_policy_heads, inventory_policy_versions, g7_sla_evaluations,
    g7_sla_deadline_decisions, sla_deadline_decisions, sla_evaluations,
    sla_policy_heads, sla_policy_versions)
from uvm.persistence.exception_sla_schema import (sla_ingest_receipts,
    sla_clock_events, sla_episode_contracts, exception_warning_intents,
    exception_warning_attempts, exception_warning_callback_inbox,
    exception_warning_failure_alerts, exception_warning_routes,
    exception_warning_actor_links)
from uvm.persistence.incident_schema import (g7_incident_routes,
    g7_incident_service_bindings,
    g7_incident_streams, g7_incident_transitions,
    g7_incident_projection_receipts, g7_incident_notification_intents,
    g7_incident_notification_attempts)
from uvm.persistence.ingestion_schema import collection_runs, collection_schedules
from uvm.persistence.observation_schema import source_observations
from uvm.persistence.schema import exposures, group_cve_refs, groups, occurrences, workloads
from uvm.persistence.identity_resolution_store import (
    IdentityResolutionReadError, IdentityResolutionStore,
)
from uvm.persistence.deadline_reference_store import DeadlineReferenceStore
from uvm.persistence.g4_schema import (github_command_previews,
    github_group_issues, github_identity_links, github_repositories)
from uvm.persistence.g4_schema import (exposure_episodes, exposure_episode_events,
    exposure_episode_members)
from uvm.identity.deadline_reference import DeadlineReferenceError
from uvm.auth.native_authority import effective_access, native_state

_ZERO_ID = "00000000-0000-4000-8000-000000000000"
_UTC = timezone.utc
_FINDINGS_PROJECTION_LOCK = threading.Lock()


def _parse_cursor_utc(value: str) -> datetime:
    """Parse a signed cursor UTC instant without lexical precision assumptions."""
    if not isinstance(value, str):
        raise ValueError("cursor time must be a string")
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None or parsed.utcoffset() != timedelta(0):
        raise ValueError("cursor time must have a UTC offset")
    return parsed.astimezone(_UTC)


def _findings_cursor_deadline(now: datetime, previous: str | None,
        temporal_boundaries: list[datetime]) -> datetime | None:
    """Keep a cursor chain's original expiry and shorten it at live boundaries."""
    deadline = (_parse_cursor_utc(previous) if previous is not None
        else now.astimezone(_UTC) + timedelta(minutes=10))
    if deadline <= now:
        return None
    for boundary in temporal_boundaries:
        instant = boundary.astimezone(_UTC)
        if instant < deadline:
            deadline = instant
    return deadline if deadline > now else None


def _findings_worker_limit(pool, group_count: int) -> int:
    """Bound parallel readers, reserve exporter and one ordinary pool slot."""
    if group_count < 2:
        return 0
    size_method = getattr(pool, "size", None)
    checked_method = getattr(pool, "checkedout", None)
    size = size_method() if callable(size_method) else 0
    if size <= 1 or not callable(checked_method):
        return 0
    overflow = getattr(pool, "_max_overflow", 0)
    if not isinstance(overflow, int) or overflow < 0:
        return 0
    capacity = size + overflow
    checked_out = checked_method()
    # The parent exporter is already checked out. Leave another pool slot for
    # ordinary API work; pool-size-one configurations use the serial path.
    available_workers = max(0, capacity - checked_out - 1)
    return min(8, group_count, available_workers)


@contextmanager
def _reserve_findings_workers(engine, count: int):
    """Acquire all worker connections before exporting a snapshot.

    A pool timeout falls back to the caller's existing connection. Any partial
    reservation is closed before fallback, and every successful reservation is
    returned even if snapshot import or DTO materialization raises.
    """
    acquired = []
    configured_connections = []
    fallback = False
    try:
        for _ in range(count):
            try:
                connection = engine.connect()
            except sa.exc.TimeoutError:
                fallback = True
                break
            # Record ownership immediately. Isolation setup can itself fail,
            # and all earlier successful acquisitions must still be closed.
            acquired.append(connection)
            configured_connections.append(connection.execution_options(
                isolation_level="REPEATABLE READ"))
        if fallback:
            for connection in acquired:
                connection.close()
            acquired.clear()
            yield []
        else:
            yield configured_connections
    finally:
        for connection in acquired:
            connection.close()


@contextmanager
def _findings_read_connection(engine):
    """Serialize PostgreSQL Findings snapshots before borrowing pool slots."""
    serialized = engine.dialect.name == "postgresql"
    if serialized:
        _FINDINGS_PROJECTION_LOCK.acquire()
    connection = None
    try:
        connection = engine.connect()
        configured = connection.execution_options(isolation_level=(
            "REPEATABLE READ" if serialized else "SERIALIZABLE"))
        yield configured
    finally:
        if connection is not None:
            connection.close()
        if serialized:
            _FINDINGS_PROJECTION_LOCK.release()


def _membership_causal_transition(connection, episode_id, occurrence, *, as_of, known_at):
    """Return the member clock and matching reset identity in one context.

    Writers pass their trusted transaction clock for both bounds. This avoids
    selecting a future-effective or not-yet-recorded transition, and ensures a
    reset marker always names the event that supplied this exact start.
    """
    event_rows = connection.execute(sa.select(exposure_episode_events).where(
        exposure_episode_events.c.episode_id == episode_id).order_by(
        exposure_episode_events.c.state_revision)).mappings().all()
    events = []
    for row in event_rows:
        event = dict(row)
        # Membership transitions become visible when the supported writer
        # commits them. Their scanner observation time remains the causal SLA
        # clock, even when it is later than this report's as_of boundary.
        if (event.get("recorded_at") is not None
                and event["recorded_at"] <= known_at
                and event["recorded_at"] <= as_of):
            events.append(event)
    observation_rows = connection.execute(sa.select(source_observations).where(
        source_observations.c.occurrence_id == occurrence["occurrence_id"])).mappings().all()
    observations = []
    for row in observation_rows:
        observation = dict(row)
        if (observation.get("collected_at") is not None
                and observation["collected_at"] <= known_at
                and observation.get("collection_status") != "failed"
                and (observation.get("observed_at") is None
                    or observation["observed_at"] <= as_of)):
            observations.append(observation)
    from uvm.assessment.sla_classification import trustworthy_causal_transition
    return trustworthy_causal_transition(events, occurrence["occurrence_id"], observations)


def _membership_causal_start(connection, episode_id, occurrence, *, as_of, known_at):
    return _membership_causal_transition(connection, episode_id, occurrence,
        as_of=as_of, known_at=known_at)["started_at"]


def _record_g7_exception_pause(connection, *, acceptance, episode_records,
                               command_id, now):
    """Append approval-time snapshots and receipt rows in the command transaction."""
    from uvm.assessment.exception_sla import pause_snapshot

    expiry = datetime.fromisoformat(acceptance["expires_at"].replace("Z", "+00:00"))
    snapshots = []
    for occurrence_id in acceptance["membership_ids"]:
        record = next((item for item in episode_records if any(
            member["occurrence_id"] == occurrence_id for member in item["members"])), None)
        if record is None:
            _error(409, "revision_conflict", "Exception membership no longer maps to a current episode")
        episode_id = record["episode"]["episode_id"]
        occurrence = connection.execute(sa.select(occurrences).where(
            occurrences.c.occurrence_id == occurrence_id).with_for_update()).mappings().first()
        if occurrence is None:
            _error(409, "revision_conflict", "Exception occurrence is unavailable")
        receipt = connection.execute(sa.select(sla_ingest_receipts).where(
            sla_ingest_receipts.c.episode_id == episode_id,
            sla_ingest_receipts.c.occurrence_id == occurrence_id).with_for_update()).mappings().first()
        receipt_at = receipt["ingested_at"] if receipt else None
        from uvm.assessment.g7_clock import ensure_current_evaluation, evaluation_head
        guarded_head = evaluation_head(connection, episode_id, occurrence_id, for_update=True)
        ensure_current_evaluation(connection, episode_id=episode_id,
            occurrence_id=occurrence_id, known_at=now,
            assessed_severity=_membership_assessed_severity(connection,
                connection.execute(sa.select(exposures.c.group_id).select_from(
                    occurrences.join(exposures, occurrences.c.exposure_id == exposures.c.exposure_id))
                    .where(occurrences.c.occurrence_id == occurrence_id)).scalar_one(), occurrence_id))
        evaluation = evaluation_head(connection, episode_id, occurrence_id, for_update=True)
        evaluation = dict(evaluation) if evaluation else None
        if guarded_head and evaluation and evaluation["evaluation_id"] != guarded_head["evaluation_id"]:
            _error(409, "revision_conflict", "Exception evaluation requires refresh before approval")
        start = evaluation["started_at"] if evaluation else None
        deadline = evaluation["current_deadline_at"] if evaluation else None
        policy = None
        if evaluation and evaluation.get("policy_id") and evaluation.get("policy_version"):
            policy = connection.execute(sa.select(sla_policy_versions).where(
                sla_policy_versions.c.policy_id == evaluation["policy_id"],
                sla_policy_versions.c.version == evaluation["policy_version"])).mappings().first()
        ingestion_clock = (receipt is not None and start == receipt_at and policy is not None
            and policy["document"].get("start_source") == "uvm_ingest_commit_v1")
        if not ingestion_clock or receipt is None:
            _error(409, "sla_clock_gap", "A durable retained-source receipt and pinned G7 evaluation are required")
        from uvm.assessment.g7_clock import read_clock
        clock = read_clock(connection, episode_id, occurrence_id, now)
        if clock["state"] in {"completed", "completed_during_exception"}:
            _error(409, "revision_conflict", "Completed membership cannot be paused")
        deadline = clock.get("target_at") if clock["state"] == "running" else deadline
        snapshot = pause_snapshot(started_at=start,
            original_deadline_at=evaluation["original_deadline_at"] if ingestion_clock else None,
            current_deadline_at=deadline if ingestion_clock else None,
            approved_at=now, expires_at=expiry,
            previously_breached=bool(clock.get("prior_breach") or (deadline and now > deadline)),
            clock_basis=(policy["document"].get("clock_basis", "elapsed_utc_seconds")
                if ingestion_clock else "elapsed_utc_seconds"))
        event_id = str(uuid.uuid4())
        sequence = int(connection.execute(sa.select(sa.func.coalesce(
            sa.func.max(sla_clock_events.c.sequence), 0) + 1).where(
                sla_clock_events.c.episode_id == episode_id,
                sla_clock_events.c.occurrence_id == occurrence_id)).scalar_one())
        predecessor = connection.execute(sa.select(sla_clock_events.c.event_id).where(
            sla_clock_events.c.episode_id == episode_id,
            sla_clock_events.c.occurrence_id == occurrence_id).order_by(
                sla_clock_events.c.sequence.desc()).limit(1).with_for_update()).scalar_one_or_none()
        data = {key: (_utc_z(value) if isinstance(value, datetime) else value)
            for key, value in snapshot.items()}
        data.update({"acceptance_id": acceptance["acceptance_id"],
            "accepted_risk": True, "receipt_id": receipt["receipt_id"] if receipt else None,
            "evaluation_id": evaluation["evaluation_id"] if evaluation else None,
            "start_source": "uvm_ingest_commit_v1",
            "policy_id": evaluation["policy_id"] if ingestion_clock else None,
            "policy_version": evaluation["policy_version"] if ingestion_clock else None,
            "evaluation_revision": int(evaluation["revision"]) if evaluation else 0})
        connection.execute(sla_clock_events.insert().values(
            event_id=event_id, episode_id=episode_id, occurrence_id=occurrence_id,
            sequence=sequence, event_type="paused", effective_at=now,
            recorded_at=now, ingest_receipt_id=receipt["receipt_id"] if receipt else None,
            decision_id=acceptance["acceptance_id"],
            membership_ids=acceptance["membership_ids"],
            policy_id=evaluation["policy_id"] if ingestion_clock else None,
            policy_version=evaluation["policy_version"] if ingestion_clock else None,
            evaluation_revision=int(evaluation["revision"]) if evaluation else 0,
            predecessor_event_id=predecessor, data=data))
        snapshots.append({"episode_id": episode_id, "occurrence_id": occurrence_id,
            "event_id": event_id, **data})
    acceptance["pause_snapshots"] = snapshots


def _record_g7_exception_resume(connection, *, acceptance, event_type, now):
    """Close each retained pause at its contractual effective instant."""
    from uvm.assessment.exception_sla import resumed_deadline

    for snapshot in acceptance.get("pause_snapshots", []):
        if (event_type == "suspended" and acceptance.get("suspended_membership_ids")
                and snapshot["occurrence_id"] not in acceptance["suspended_membership_ids"]):
            continue
        from uvm.assessment.g7_clock import read_clock
        clock = read_clock(connection, snapshot["episode_id"], snapshot["occurrence_id"], now)
        latest = connection.execute(sa.select(sla_clock_events).where(
            sla_clock_events.c.episode_id == snapshot["episode_id"],
            sla_clock_events.c.occurrence_id == snapshot["occurrence_id"])
            .order_by(sla_clock_events.c.sequence.desc()).limit(1)).mappings().first()
        if (clock["state"] != "paused" or not latest
                or latest["decision_id"] != acceptance["acceptance_id"]):
            continue
        selected_expiry = datetime.fromisoformat(acceptance["expires_at"].replace("Z", "+00:00"))
        effective_end = (selected_expiry if event_type == "resumed" or now >= selected_expiry else now)
        pure_snapshot = {**snapshot,
            "started_at": datetime.fromisoformat(snapshot["started_at"].replace("Z", "+00:00"))
                if isinstance(snapshot.get("started_at"), str) else snapshot.get("started_at"),
            "original_deadline_at": datetime.fromisoformat(snapshot["original_deadline_at"].replace("Z", "+00:00"))
                if isinstance(snapshot.get("original_deadline_at"), str) else snapshot.get("original_deadline_at"),
            "pre_pause_deadline_at": datetime.fromisoformat(snapshot["pre_pause_deadline_at"].replace("Z", "+00:00"))
                if isinstance(snapshot.get("pre_pause_deadline_at"), str) else snapshot.get("pre_pause_deadline_at"),
            "approved_at": datetime.fromisoformat(snapshot["approved_at"].replace("Z", "+00:00"))
                if isinstance(snapshot.get("approved_at"), str) else snapshot.get("approved_at"),
            "expires_at": datetime.fromisoformat(snapshot["expires_at"].replace("Z", "+00:00"))
                if isinstance(snapshot.get("expires_at"), str) else snapshot.get("expires_at")}
        deadline = resumed_deadline(pure_snapshot, effective_end,
            allow_early=event_type in {"revoked", "suspended", "completed"})
        sequence = int(connection.execute(sa.select(sa.func.coalesce(
            sa.func.max(sla_clock_events.c.sequence), 0) + 1).where(
                sla_clock_events.c.episode_id == snapshot["episode_id"],
                sla_clock_events.c.occurrence_id == snapshot["occurrence_id"])).scalar_one())
        predecessor = connection.execute(sa.select(sla_clock_events.c.event_id).where(
            sla_clock_events.c.episode_id == snapshot["episode_id"],
            sla_clock_events.c.occurrence_id == snapshot["occurrence_id"]).order_by(
                sla_clock_events.c.sequence.desc()).limit(1).with_for_update()).scalar_one_or_none()
        data = {**snapshot, "resumed_at": _utc_z(effective_end),
            "resumed_deadline_at": _utc_z(deadline), "accepted_risk": True}
        connection.execute(sla_clock_events.insert().values(
            event_id=str(uuid.uuid4()), episode_id=snapshot["episode_id"],
            occurrence_id=snapshot["occurrence_id"], sequence=sequence,
            event_type=event_type, effective_at=effective_end, recorded_at=now,
            ingest_receipt_id=snapshot.get("receipt_id"),
            decision_id=acceptance["acceptance_id"],
            membership_ids=acceptance["membership_ids"], policy_id=snapshot.get("policy_id"),
            policy_version=snapshot.get("policy_version"),
            evaluation_revision=snapshot.get("evaluation_revision", 0),
            predecessor_event_id=predecessor, data=data))


def _sla_evaluation_table(connection, episode_id):
    contract = connection.execute(sa.select(sla_episode_contracts).where(
        sla_episode_contracts.c.episode_id == episode_id)).mappings().first()
    return (g7_sla_evaluations if contract and contract["contract_version"] == 7
        else sla_evaluations)


def _sla_evaluation_history(connection, episode_id, occurrence_id, *, for_update=False):
    table = _sla_evaluation_table(connection, episode_id)
    query = sa.select(table).where(
        table.c.episode_id == episode_id,
        table.c.occurrence_id == occurrence_id).order_by(table.c.revision)
    if for_update:
        query = query.with_for_update()
    rows = [dict(row) for row in connection.execute(query).mappings().all()]
    return rows, evaluation_revision_head(rows)


def _sla_policy_for_clock(connection, group_id, stable_attrs, clock_at, known_at):
    """Resolve the unique policy applicable at a changed member clock.

    Existing same-clock evaluations remain pinned. This resolver is used only
    when a trusted causal reset moves the clock and applies current knowledge,
    exact group/environment/service scope and half-open policy validity.
    """
    from uvm.assessment.sla_classification import select_reset_policy
    rows = connection.execute(sa.select(sla_policy_versions).where(
        sla_policy_versions.c.created_at <= known_at).order_by(
        sla_policy_versions.c.revision)).mappings().all()
    return select_reset_policy(rows, group_id, stable_attrs, clock_at,
        policy_scope_matches=_sla_policy_scope_matches_member)


def _membership_assessed_severity(connection, group_id, occurrence_id):
    """Resolve the last authorized exact-member override from its audit history."""
    events = connection.execute(sa.select(assessment_audit_events).where(
        assessment_audit_events.c.target_id == group_id,
        assessment_audit_events.c.action == "severity.override").order_by(
            assessment_audit_events.c.event_sequence.desc())).mappings().all()
    for event in events:
        if occurrence_id not in (event["membership_ids"] or []):
            continue
        value = (event["after_value"] or {}).get("assessed_severity") or {}
        if isinstance(value, dict) and value.get("value"):
            return str(value["value"]).casefold()
    return None
_LIMIT_DEFAULTS = {"maximum_acceptance_days": None, "maximum_severity": None,
    "whole_group_confirmation": False, "allowed_environments": [], "allowed_service_ids": [],
    "allowed_sla_clock_bases": [], "allowed_sla_severities": [],
    "allowed_sla_start_sources": [],
    "maximum_sla_duration_seconds": None, "allow_sla_backfill": False,
    "maximum_deadline_extension_seconds": None, "allowed_identity_scalar_fields": {}}
_DUTY_DEFAULTS = {"approval_requires_distinct_actor": True,
    "prohibit_requester_approval": True, "required_approver_count": 1,
    "prohibited_action_pairs": []}
_EMPTY_SCOPE = {"group_ids": [], "source_families": [], "environments": [],
    "service_ids": [], "membership_mode": "explicit"}
_SEVERITIES = {"critical", "high", "medium", "low", "informational"}
_ACTIONS = (
    "assessment.read", "audit.read", "owners.directory.read", "owners.assign",
    "portion.define", "portion.transfer", "portion.split", "routing.override",
    "routing.expire", "severity.override", "acceptance.submit", "acceptance.approve",
    "acceptance.expire", "acceptance.reconcile",
    "acceptance.reject", "acceptance.revoke", "remediation.confirm_portion",
    "remediation.confirm_group", "policy.role.create", "policy.role.assign",
    "policy.role.update", "principal.update", "audit.export",
    "github.identity.link", "github.repository.configure",
    "connector.read", "connector.configure", "connector.secret.manage",
    "github.commands.preview", "github.issue.sync", "github.poll",
    "report.create", "report.read", "report.export", "policy.read",
    "policy.sla.publish", "sla.deadline.revise", "access_group.read",
    "ownership.team.read", "ownership.team.manage",
    "warning.route.manage", "warning.actor_link.manage",
    "integration.health.read",
    "observer.timing.read", "observer.timing.configure",
    "backup.settings.read", "backup.settings.configure",
)
_LOG = logging.getLogger("uvm.assessment.api")
_TRUSTED_COMMAND_ORIGIN: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "uvm_trusted_command_origin", default=None)
_ACTIVE_COMMAND_CONNECTION: contextvars.ContextVar[Any] = contextvars.ContextVar(
    "uvm_active_command_connection", default=None)
_TRUSTED_GITHUB_CONTEXT: contextvars.ContextVar[dict[str, Any] | None] = contextvars.ContextVar(
    "uvm_trusted_github_context", default=None)


def _error(status: int, code: str, message: str, details: dict[str, Any] | None = None):
    raise HTTPException(status, {"code": code, "message": message,
                                "details": details or {}})


def _uuid(value: Any, field: str) -> str:
    try:
        parsed = uuid.UUID(value)
    except (ValueError, TypeError, AttributeError):
        _error(422, "invalid_command", f"{field} must be a canonical UUID")
    if str(parsed) != value:
        _error(422, "invalid_command", f"{field} must be a canonical UUID")
    return value


def _sla_policy_scope_matches_member(document: dict, stable_attrs: dict) -> bool:
    scope = document.get("scope", {})
    return (all(not scope.get(selector) or stable_attrs.get(attribute) in scope[selector]
        for selector, attribute in (("environments", "environment"),
            ("service_ids", "service_id"))))


def _utc_z(value: datetime | None) -> str | None:
    if value is None:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=_UTC)
    return value.astimezone(_UTC).isoformat().replace("+00:00", "Z")


def _public_reconciliation_record(record: dict) -> dict:
    """Expose required unknowns without rewriting retained decision history."""
    public = {key: value for key, value in record.items() if not key.startswith("_")}
    public.setdefault("workload_id", None)
    public.setdefault("component_locator", None)
    return public


def _complete_policy_scope(value: Any) -> dict[str, Any]:
    scope = dict(value) if isinstance(value, dict) else {}
    return {**_EMPTY_SCOPE, **scope}


def _complete_policy_limits(value: Any) -> dict[str, Any]:
    limits = dict(value) if isinstance(value, dict) else {}
    return {**_LIMIT_DEFAULTS, **limits}


def _complete_policy_duties(value: Any) -> dict[str, Any]:
    duties = dict(value) if isinstance(value, dict) else {}
    return {**_DUTY_DEFAULTS, **duties}


def _digest(principal: str, body: dict) -> str:
    raw = json.dumps({"principal_id": principal, **body}, sort_keys=True,
                     separators=(",", ":"), ensure_ascii=True).encode()
    return hashlib.sha256(raw).hexdigest()


def _scoped_grants(policy: dict, principal: str, action: str, target_id: str,
                   source_family: str | None = None, *, environment: str | None = None,
                   service_id: str | None = None, include_unresolved: bool = False) -> list[dict]:
    result = []
    for grant in _matching_grants(policy, principal, action, target_id):
        scope = grant.get("target_scope", {})
        sources = scope.get("source_families", [])
        if (source_family is not None and sources and "*" not in sources
                and source_family not in sources):
            continue
        limits = grant.get("limits", {})
        constraints = ((environment, scope.get("environments", []), limits.get("allowed_environments", [])),
            (service_id, scope.get("service_ids", []), limits.get("allowed_service_ids", [])))
        for value, scoped, limited in constraints:
            selectors = [item for item in (scoped, limited) if item]
            if value is None:
                if (selectors and not include_unresolved
                        and any("*" not in item for item in selectors)):
                    break
            elif any("*" not in item and value not in item for item in selectors):
                break
        else:
            result.append(grant)
    return result


def _matches(policy: dict, principal: str, action: str, target_id: str,
             source_family: str | None = None) -> bool:
    return bool(_scoped_grants(policy, principal, action, target_id, source_family))


def _native_access_group_grants(policy: dict, access_group_id: str, action: str,
                                target_id: str, source_family: str,
                                principal_id: str | None = None) -> list[dict]:
    """Resolve complete current native access-group grants for routed incident disclosure."""
    group = native_state(policy).get("access_groups", {}).get(access_group_id)
    if not group or not group.get("enabled", True):
        return []
    deny_principals = {access_group_id, "*"}
    if principal_id:
        deny_principals.add(principal_id)
        current_groups = effective_access(policy, principal_id)[0] or ()
        deny_principals.update(current_groups)
    for denial in policy.get("denies", []):
        if (isinstance(denial, dict) and denial.get("principal_id") in deny_principals
                and ("*" in denial.get("actions", []) or action in denial.get("actions", []))
                and ("*" in denial.get("target_ids", []) or target_id in denial.get("target_ids", []))):
            return []
    grants = []
    for permission in group.get("permissions", []):
        if not isinstance(permission, dict) or permission.get("action") != action:
            continue
        scope = permission.get("target_scope", {})
        targets = scope.get("group_ids", [])
        sources = scope.get("source_families", [])
        limits = permission.get("limits", {})
        if (target_id not in targets and "*" not in targets
                or sources and "*" not in sources and source_family not in sources
                or scope.get("environments") or scope.get("service_ids")
                or limits.get("allowed_environments") or limits.get("allowed_service_ids")):
            continue
        grants.append({"principal_id": access_group_id,
            "role_id": permission.get("role_id"),
            "target_scope": scope, "limits": limits})
    return grants


def _github_sync_conflict_matches(github: dict) -> bool:
    """Only the persisted conflict state selects this queue."""
    return isinstance(github, dict) and github.get("state") == "conflict"


def _findings_severity_matches(actual: Any, requested: str, *, unknown: bool = False) -> bool:
    """Match the UI's canonical severity category while preserving null as unknown."""
    value = actual.get("value") if isinstance(actual, dict) else actual
    if unknown:
        return value is None
    return isinstance(value, str) and value.casefold() == requested.casefold()


def _validate_routing_rules(policy: dict) -> None:
    rules = policy.get("routing_rules", [])
    raw_directory = policy.get("owner_directory", [])
    if (not isinstance(raw_directory, list) or any(not isinstance(item, dict)
            or not isinstance(item.get("owner_id"), str) or not item["owner_id"].strip()
            or type(item.get("enabled", True)) is not bool for item in raw_directory)):
        _error(422, "invalid_command", "Routing directory must have stable IDs and boolean availability")
    directory = {item["owner_id"]: item for item in raw_directory}
    if len(directory) != len(raw_directory):
        _error(422, "invalid_command", "Routing directory IDs must be unique")
    if not isinstance(rules, list):
        _error(422, "invalid_command", "routing_rules must be an array")
    principal_records = policy.get("principals", {})
    if not isinstance(principal_records, dict):
        _error(422, "invalid_command", "Routing principals must be an object")
    seen = set()
    for rule in rules:
        if (not isinstance(rule, dict) or set(rule) != {"rule_id", "match", "owner_ids"}
                or not isinstance(rule["rule_id"], str) or not rule["rule_id"].strip()
                or rule["rule_id"] in seen or not isinstance(rule["match"], dict)
                or set(rule["match"]) != {"source_family"}
                or not isinstance(rule["match"]["source_family"], str)
                or not rule["match"]["source_family"].strip()
                or not isinstance(rule["owner_ids"], list) or not rule["owner_ids"]
                or any(not isinstance(owner, str) for owner in rule["owner_ids"])
                or len(set(rule["owner_ids"])) != len(rule["owner_ids"])
                or any(owner not in directory for owner in rule["owner_ids"])):
            _error(422, "invalid_command", "Routing rule must bind a unique stable ID, exact source and enabled owner set")
        for owner in rule["owner_ids"]:
            entry = directory[owner]
            principal = principal_records.get(owner, {})
            owner_type = entry.get("owner_type")
            if (not isinstance(owner_type, str) or owner_type not in {"person", "team"}
                    or not isinstance(principal, dict)
                    or type(principal.get("enabled", True)) is not bool
                    or not entry.get("enabled", True) or not principal.get("enabled", True)):
                _error(422, "invalid_command", "Routing owner metadata must be typed and available")
        seen.add(rule["rule_id"])


def _evaluate_routing(policy: dict, source_family: str, policy_revision: int) -> dict:
    directory = {item.get("owner_id"): item for item in policy.get("owner_directory", [])}
    entries = []
    for rule in sorted(policy.get("routing_rules", []), key=lambda item: item["rule_id"]):
        matched = rule["match"]["source_family"] == source_family
        owners = sorted(rule["owner_ids"])
        available = all(owner in directory and directory[owner].get("enabled", True)
            and policy.get("principals", {}).get(owner, {}).get("enabled") is not False for owner in owners)
        entries.append({"rule_id": rule["rule_id"], "match": dict(rule["match"]),
            "matched": matched, "owner_ids": owners,
            "outcome": "unmatched" if not matched else "matched" if available else "owner_unavailable"})
    matches = [entry for entry in entries if entry["matched"]]
    sets = {tuple(entry["owner_ids"]) for entry in matches}
    conflict = len(sets) > 1
    if conflict:
        for entry in matches:
            if entry["outcome"] == "matched":
                entry["outcome"] = "conflicting"
    resolved = bool(matches) and not conflict and all(entry["outcome"] == "matched" for entry in matches)
    return {"status": "assigned" if resolved else "unresolved",
        "owner_ids": list(next(iter(sets))) if resolved else [], "override": None,
        "evaluated_policy_revision": policy_revision, "evidence": entries}


def _reference_context(connection, membership_ids: list[str]) -> list[dict]:
    try:
        current = DeadlineReferenceStore.current_on_connection(connection, membership_ids)
    except DeadlineReferenceError:
        _error(503, "persistence_unavailable", "Supplied reference history is unavailable")
    return [{"occurrence_id": member,
        "deadline_reference_revision": current[member]["revision"] if current[member] else 0,
        "deadline_reference": current[member]["reference"] if current[member] else None}
        for member in sorted(membership_ids)]


def _require_authority(policy: dict, principal: str, action: str, target_id: str,
                       source_family: str | None = None, *, origin: str = "local_api",
                       correlation_id: str, connection=None) -> list[dict]:
    """Shared admission/final evaluator; denial is operational, not a decision."""
    grants = (_complete_target_grants(connection, policy, principal, action, target_id,
        source_family) if connection is not None else
        _scoped_grants(policy, principal, action, target_id, source_family))
    if not grants:
        _LOG.warning("ASSESSMENT_AUTHORITY_DENIED %s", json.dumps({
            "event": "assessment_authority_denied", "event_id": str(uuid.uuid4()),
            "principal_id": principal, "action": action, "origin": origin,
            "correlation_id": correlation_id, "occurred_at": _utc_z(datetime.now(_UTC)),
        }, sort_keys=True))
        _error(403, "forbidden", "Current complete authority is unavailable")
    return grants


def _authority_groups_for_scope(policy: dict, principal: str, action: str,
                                target_id: str, source_family: str | None = None) -> set[str]:
    """Identity groups whose own role grant can act on this exact target."""
    context = AUTHORITY_CONTEXT.get()
    if context is None or context.credential_mode not in {"oidc_session", "github_link"}:
        return set()
    return {grant.get("principal_id") for grant in _scoped_grants(
        policy, principal, action, target_id, source_family)
        if grant.get("principal_id") in context.access_groups}


def _source_covered_grants(connection, grants: list[dict], group_id: str) -> list[dict]:
    """Keep each OIDC access-group grant paired with its own exact source ceiling."""
    grants = _target_scoped_grants(connection, grants, group_id)
    context = AUTHORITY_CONTEXT.get()
    rows = connection.execute(sa.select(source_observations.c.source_family,
        source_observations.c.source_account_id, collection_runs.c.scope_key)
        .select_from(source_observations.join(occurrences,
            source_observations.c.occurrence_id == occurrences.c.occurrence_id).join(
            exposures, occurrences.c.exposure_id == exposures.c.exposure_id).join(
            collection_runs, sa.and_(sa.cast(collection_runs.c.run_id, sa.String) == source_observations.c.run_id,
                collection_runs.c.source_family == source_observations.c.source_family,
                collection_runs.c.source_account_id == source_observations.c.source_account_id)))
        .where(exposures.c.group_id == group_id)).all()
    observed = {(row.source_family, row.source_account_id, row.scope_key) for row in rows}

    def grant_has_complete_source(grant):
        permitted = grant.get("source_scopes")
        if permitted is None:
            return True  # Legacy grants predate native source-scope ceilings.
        allowed = {tuple(item.get(key) for key in
            ("source_family", "source_account_id", "scope_key"))
            for item in permitted if isinstance(item, dict)}
        return bool(observed) and observed <= allowed

    if context is None or context.credential_mode not in {"oidc_session", "github_link"}:
        return [grant for grant in grants if grant_has_complete_source(grant)]
    from uvm.auth.service import group_scope_covered
    def complete(grant):
        if not group_scope_covered(connection, context, [group_id],
                granting_identity_groups=[grant.get("principal_id")]):
            return False
        return grant_has_complete_source(grant)
    return [grant for grant in grants if complete(grant)]


def _target_scoped_grants(connection, grants: list[dict], target_id: str) -> list[dict]:
    attrs = [row[0] for row in connection.execute(sa.select(workloads.c.stable_attrs)
        .select_from(workloads.join(exposures, exposures.c.workload_id == workloads.c.workload_id))
        .where(exposures.c.group_id == target_id)).all()]
    def allowed(grant):
        scope, limits = grant.get("target_scope", {}), grant.get("limits", {})
        dimensions = ((scope.get("environments", []), limits.get("allowed_environments", []), "environment"),
            (scope.get("service_ids", []), limits.get("allowed_service_ids", []), "service_id"))
        if not any(selectors for scoped, limited, _ in dimensions for selectors in (scoped, limited)):
            return True
        if not attrs:
            return all(not selectors or "*" in selectors
                for scoped, limited, _ in dimensions for selectors in (scoped, limited))
        return all(isinstance(item, dict) and all(not selectors or "*" in selectors
            or item.get(key) in selectors for scoped, limited, key in dimensions
            for selectors in (scoped, limited)) for item in attrs)
    return [grant for grant in grants if allowed(grant)]


def _complete_target_grants(connection, policy: dict, principal: str, action: str,
                            target_id: str, source_family: str | None = None) -> list[dict]:
    grants = _scoped_grants(policy, principal, action, target_id, source_family,
        include_unresolved=True)
    if source_family is not None:
        return _source_covered_grants(connection, grants, target_id)
    return _target_scoped_grants(connection, grants, target_id)


def _sla_publication_grant_ids(policy: dict, principal: str, requested_scope: dict,
                               source_families: dict[str, str]) -> set[str]:
    """Return complete grants that cover every selected group and scope selector."""
    def dimension_covers(requested: list[str], scoped: list[str], limited: list[str]) -> bool:
        requested_set, scoped_set, limited_set = set(requested), set(scoped), set(limited)
        if not requested_set:
            return not scoped_set and "*" not in scoped_set and not limited_set and "*" not in limited_set
        return ("*" in scoped_set or requested_set <= scoped_set) and (
            "*" in limited_set or requested_set <= limited_set)

    complete: set[str] | None = None
    for group_id in requested_scope.get("group_ids", []):
        viable = set()
        for grant in _matching_grants(policy, principal, "policy.sla.publish", group_id):
            scope, limits = grant.get("target_scope", {}), grant.get("limits", {})
            group_scope = scope.get("group_ids", []) or grant.get("target_ids", [])
            if ("*" not in group_scope and group_id not in group_scope
                    or scope.get("source_families") and "*" not in scope["source_families"]
                        and source_families.get(group_id) not in scope["source_families"]
                    or not dimension_covers(requested_scope.get("environments", []),
                        scope.get("environments", []), limits.get("allowed_environments", []))
                    or not dimension_covers(requested_scope.get("service_ids", []),
                        scope.get("service_ids", []), limits.get("allowed_service_ids", []))):
                continue
            viable.add(grant.get("grant_id"))
        complete = viable if complete is None else complete & viable
    return complete or set()


def _sla_publication_grant_groups(policy: dict, principal: str, requested_scope: dict,
                                  source_families: dict[str, str]) -> dict[str, set[str]]:
    """Pair each target's exact source scope with its complete SLA grant."""
    complete_grants = _sla_publication_grant_ids(policy, principal,
        requested_scope, source_families)
    return {group_id: {grant.get("principal_id") for grant in
        _matching_grants(policy, principal, "policy.sla.publish", group_id)
        if grant.get("grant_id") in complete_grants}
        for group_id in requested_scope.get("group_ids", [])}


def _sla_publication_complete_grants(connection, context, policy: dict, principal: str,
                                     requested_scope: dict,
                                     source_families: dict[str, str]) -> list[dict]:
    """Return individual complete grants whose own identity group covers every target."""
    group_ids = requested_scope.get("group_ids", [])
    if not group_ids:
        return []
    complete_ids = _sla_publication_grant_ids(policy, principal,
        requested_scope, source_families)
    if not complete_ids:
        return []
    from uvm.auth.service import group_scope_covered
    candidates = [grant for grant in _matching_grants(policy, principal,
        "policy.sla.publish", group_ids[0]) if grant.get("grant_id") in complete_ids]
    return [grant for grant in candidates if all(group_scope_covered(connection,
        context, [group_id], granting_identity_groups=[grant.get("principal_id")])
        for group_id in group_ids)]


def _sla_publication_grants_with_limits(grants: list[dict], requested: dict) -> list[dict]:
    """Keep a single grant's limits paired with the complete scope it authorises."""
    duration_limits = requested.get("duration_seconds_by_severity", {})
    used_severities = (set(duration_limits)
        | set(requested.get("eligibility", {}).get("included_severities", []))
        | set(requested.get("eligibility", {}).get("excluded_classifications", [])))
    backfill_mode = requested.get("backfill", {}).get("mode")
    start_source = requested.get("start_source", "source_observation_v1")
    def covers(grant):
        limits = grant.get("limits", {})
        return (requested.get("clock_basis") in limits.get("allowed_sla_clock_bases", [])
            and (start_source != "uvm_ingest_commit_v1"
                or start_source in limits.get("allowed_sla_start_sources", []))
            and used_severities <= set(limits.get("allowed_sla_severities", []))
            and all(type(seconds) is int and seconds > 0
                and limits.get("maximum_sla_duration_seconds") is not None
                and seconds <= limits["maximum_sla_duration_seconds"]
                for seconds in duration_limits.values())
            and (backfill_mode != "backfill_existing" or limits.get("allow_sla_backfill", False)))
    return [grant for grant in grants if covers(grant)]


def _effective_acceptance_members(acceptance: dict, connection, engine,
                                  now: datetime, *, lock: bool = False) -> set[str]:
    if datetime.fromisoformat(acceptance["expires_at"].replace("Z", "+00:00")) <= now:
        return set()
    members = set(acceptance.get("membership_ids", []))
    # Suspended derived membership remains reserved for linked replacement,
    # although read effectiveness is deliberately active-only.
    if acceptance.get("state") in {"active", "suspended"}:
        members.update(item.get("successor_occurrence_id") for item in
            acceptance.get("successor_coverage", []) if item.get("accepted") is True
            and item.get("permitted") is True
            and _coverage_binding_is_current(connection, engine, item, lock=lock))
    if acceptance.get("exception_contract_version") == 1 and acceptance.get("state") != "pending":
        snapshots = {(item["occurrence_id"], item["episode_id"])
            for item in acceptance.get("pause_snapshots", [])}
        current = connection.execute(sa.select(occurrences.c.occurrence_id, exposure_episodes.c.episode_id)
            .join(exposure_episodes, occurrences.c.exposure_id == exposure_episodes.c.exposure_id).where(
                occurrences.c.occurrence_id.in_(members), exposure_episodes.c.is_current.is_(True))).all()
        members = {occurrence_id for occurrence_id, episode_id in current
            if (occurrence_id, episode_id) in snapshots}
    return members


def _coverage_heads_are_current(connection, engine, binding, *, lock: bool = False) -> bool:
    """A necessary validity condition, never a substitute for retained proof."""
    if not isinstance(binding, dict):
        return False
    try:
        heads = binding.get("correspondence_heads")
        if not isinstance(heads, list) or not heads:
            return False
        exposure_ids = sorted({item["exposure_id"] for item in heads})
        occurrence_ids = sorted({item["occurrence_id"] for item in heads})
        exposure_query = sa.select(exposures).where(
            exposures.c.exposure_id.in_(exposure_ids)).order_by(exposures.c.exposure_id)
        occurrence_query = sa.select(occurrences).where(
            occurrences.c.occurrence_id.in_(occurrence_ids)).order_by(occurrences.c.occurrence_id)
        if lock and engine.dialect.name == "postgresql":
            exposure_query = exposure_query.with_for_update()
            occurrence_query = occurrence_query.with_for_update()
        exposure_rows = {row["exposure_id"]: row for row in
            connection.execute(exposure_query).mappings()}
        occurrence_rows = {row["occurrence_id"]: row for row in
            connection.execute(occurrence_query).mappings()}
        for head in heads:
            occurrence = occurrence_rows.get(head["occurrence_id"])
            exposure = exposure_rows.get(head["exposure_id"])
            if occurrence is None or exposure is None:
                return False
            if (occurrence["exposure_id"] != head["exposure_id"]
                    or occurrence["revision"] != head["occurrence_revision"]
                    or exposure["revision"] != head["exposure_revision"]
                    or exposure["group_id"] != head["group_id"]
                    or occurrence["workload_id"] != head["workload_id"]
                    or occurrence["component_locator"] != head["component_locator"]):
                return False
        return True
    except (KeyError, TypeError, ValueError):
        return False


def _coverage_binding_is_current(connection, engine, coverage: dict, *, lock: bool = False) -> bool:
    binding = coverage.get("_identity_binding")
    if not isinstance(binding, dict):
        return False
    try:
        if lock and engine.dialect.name == "postgresql":
            connection.execute(sa.select(source_observations.c.observation_id).where(
                source_observations.c.observation_id == binding["observation_id"]
            ).with_for_update()).first()
        store = IdentityResolutionStore(engine)
        result = store.read_status_on_connection(connection, binding["resolution_id"])
        resolution = result.resolution
        if result.status != "verified" or resolution.outcome not in {"matched", "new"}:
            return False
        history = store.read_observation_history(connection, [binding["observation_id"]])
        rows, _, _ = history[binding["observation_id"]]
        if not rows or rows[-1].resolution_id != binding["resolution_id"]:
            return False
        if (resolution.observation_id != binding["observation_id"]
                or resolution.occurrence_id != binding["successor_occurrence_id"]):
            return False
        return _coverage_heads_are_current(connection, engine, binding, lock=lock)
    except (IdentityResolutionReadError, KeyError, TypeError, ValueError):
        return False


def _policy_authority_ids(policy: dict, principal: str) -> set[str]:
    """Return a principal and its currently configured, enabled teams."""
    record = policy.get("principals", {}).get(principal, {})
    if record.get("enabled") is False:
        return set()
    directory = {entry.get("owner_id"): entry for entry in policy.get("owner_directory", [])
        if isinstance(entry, dict)}
    identities = {principal}
    request_context = AUTHORITY_CONTEXT.get()
    if request_context is not None and request_context.principal_id == principal:
        identities.update(request_context.access_groups)
    native = native_state(policy)
    if native.get("mode") == NATIVE_MODE:
        access = effective_access(policy, principal)
        return {principal, *access[0]} if access else {principal}
    for team_id in record.get("team_ids", []):
        team = directory.get(team_id)
        if team and team.get("owner_type") == "team" and team.get("enabled", True):
            identities.add(team_id)
    return identities


def _matching_grants(policy: dict, principal: str, action: str, target_id: str) -> list[dict]:
    principal_record = policy.get("principals", {}).get(principal, {})
    if principal_record.get("enabled") is False:
        return []
    now = datetime.now(_UTC)

    def effective(rule):
        start, end = rule.get("effective_from"), rule.get("effective_until")
        try:
            return ((not start or datetime.fromisoformat(start.replace("Z", "+00:00")) <= now)
                    and (not end or datetime.fromisoformat(end.replace("Z", "+00:00")) > now))
        except (ValueError, AttributeError, TypeError):
            return False

    if not effective(principal_record):
        return []
    authority_ids = _policy_authority_ids(policy, principal)
    for rule in policy.get("denies", []):
        actions, targets = rule.get("actions", []), rule.get("target_ids", [])
        if (rule.get("principal_id") in authority_ids | {"*"}
                and ("*" in actions or action in actions)
                and ("*" in targets or target_id in targets)):
            return []
    roles = policy.get("roles", {})
    native = native_state(policy)
    resolved_grants = []
    # Native mode is an explicit authority boundary. Legacy role projections
    # remain retained for rollback/audit, but cannot preserve stale grants.
    if native.get("mode") != NATIVE_MODE:
        for grant in policy.get("grants", []):
            if grant.get("role_id") in roles:
                role = roles[grant["role_id"]]
                scope = role.get("target_scope", {})
                resolved_grants.append({**role, **grant,
                    "actions": role.get("actions", []),
                    "target_ids": (scope.get("group_ids", [])
                        or (["*"] if scope.get("membership_mode") == "all_current" else []))})
            else:
                resolved_grants.append(grant)
    if native.get("mode") == NATIVE_MODE:
        group_ids = set(effective_access(policy, principal)[0])
        for group_id in group_ids:
            group = native.get("access_groups", {}).get(group_id, {})
            for permission in group.get("permissions", []):
                if permission.get("action") != action:
                    continue
                scope = permission.get("target_scope", {})
                targets = scope.get("group_ids", []) or (
                    ["*"] if scope.get("membership_mode") == "all_current" else [])
                resolved_grants.append({**permission, "principal_id": group_id,
                    "grant_id": f"native:{group_id}:{permission['permission_id']}",
                    "actions": [action], "target_ids": targets,
                    "source_scopes": group.get("source_scopes", [])})
    request_context = AUTHORITY_CONTEXT.get()
    mapped_groups = set()
    oidc_session = (request_context is not None
        and request_context.principal_id == principal
        and request_context.credential_mode in {"oidc_session", "github_link"})
    if request_context is not None and request_context.principal_id == principal:
        mapped_groups = set(request_context.access_groups)
    matching = [rule for rule in resolved_grants if (
        (rule.get("principal_id") in authority_ids | {"*"}
            and (not oidc_session or rule.get("principal_id") in mapped_groups)
            and (rule.get("principal_id") not in mapped_groups
                 or rule.get("role_id") in (request_context.roles_for_group(
                     rule.get("principal_id")) if request_context else ()))
            and (not request_context or request_context.principal_id != principal
                or request_context.credential_mode != "service_bearer"
                or rule.get("role_id") in request_context.role_ids))
        and effective(rule)
        and ("*" in (rule.get("actions") or []) or action in (rule.get("actions") or []))
        and ("*" in (rule.get("target_ids") or []) or target_id in (rule.get("target_ids") or []))
    )]
    return matching


def _membership(connection, group_id: str) -> tuple[list[str], int]:
    rows = connection.execute(sa.select(occurrences.c.occurrence_id,
                                        occurrences.c.revision)
        .select_from(occurrences.join(exposures, occurrences.c.exposure_id == exposures.c.exposure_id))
        .where(exposures.c.group_id == group_id)
        .order_by(occurrences.c.occurrence_id)).all()
    identifiers = [row.occurrence_id for row in rows]
    material = json.dumps([(row.occurrence_id, int(row.revision)) for row in rows],
                          separators=(",", ":")).encode()
    revision = (int.from_bytes(hashlib.sha256(material).digest()[:4], "big") & 0x7fffffff) or 1
    return identifiers, revision


def _lock_group_membership(connection, group_id: str) -> None:
    """Serialize existing-member corrections and arrivals before taking the revision.

    The caller holds the group row: its FK also serializes new exposures.
    Occurrence writers lock an existing exposure before adding its membership.
    """
    parent_ids = connection.execute(sa.select(exposures.c.exposure_id).where(
        exposures.c.group_id == group_id).order_by(exposures.c.exposure_id)
        .with_for_update()).scalars().all()
    if parent_ids:
        connection.execute(sa.select(occurrences.c.occurrence_id).where(
            occurrences.c.exposure_id.in_(parent_ids)).order_by(occurrences.c.occurrence_id)
            .with_for_update()).all()


def _successor_reconciliation_evidence(connection, engine, group: dict,
                                       resolution_id: str,
                                       predecessor_occurrence_id: str,
                                       original_membership_ids: list[str]) -> dict:
    """Validate retained identity evidence for one assessment reconciliation.

    This reads the strict identity-resolution history on the caller's open
    assessment transaction. It never writes or repairs identity state.
    """
    try:
        store = IdentityResolutionStore(engine)
        result = store.read_status_on_connection(connection, resolution_id)
        resolution = result.resolution
        observation_id = resolution.observation_id
        observation_query = sa.select(source_observations).where(
            source_observations.c.observation_id == observation_id)
        if engine.dialect.name == "postgresql":
            observation_query = observation_query.with_for_update()
        observation = connection.execute(observation_query).mappings().first()
        if observation is None:
            _error(409, "revision_conflict", "Identity observation is unavailable")
        # IdentityRepository takes this observation lock before appending a
        # new resolution head. Re-read strict history only after acquiring it.
        result = store.read_status_on_connection(connection, resolution_id)
        resolution = result.resolution
        histories = store.read_observation_history(connection, [observation_id])
        history, _, _ = histories[observation_id]
        if not history or history[-1].resolution_id != resolution_id:
            _error(409, "revision_conflict", "Identity resolution is no longer current")
        selected_occurrence_id = resolution.occurrence_id
        # Strictly read, valid ambiguous/unresolved resolutions have no
        # selected occurrence by design. Preserve them as blocked history;
        # only a selected mapping needs the successor locks and anchors below.
        if not selected_occurrence_id:
            if (result.status != "not_applicable"
                    or resolution.outcome not in {"ambiguous", "unresolved"}):
                _error(409, "revision_conflict", "Identity resolution has no valid selected outcome")
            if (resolution.workload_id is not None or resolution.incarnation_id is not None
                    or resolution.exposure_id is not None):
                _error(409, "revision_conflict", "Unselected identity resolution has corrupt anchors")
            native_key = (observation["source_family"], observation["native_id_scheme"],
                observation["native_id_authority"], observation["native_id_value"])
            group_key = (group["source_family"], group["native_id_scheme"],
                group["native_id_authority"], group["native_id_value"])
            if native_key != group_key:
                _error(409, "revision_conflict", "Identity observation belongs to another finding group")
            if resolution.group_id not in (None, group["group_id"]):
                _error(409, "revision_conflict", "Identity resolution crosses finding groups")
            return {"resolution_id": resolution_id, "observation_id": observation_id,
                "predecessor_occurrence_id": predecessor_occurrence_id,
                "successor_occurrence_id": None, "resolution_status": result.status,
                "resolution_outcome": resolution.outcome,
                "proof_reference": result.proof_reference, "permitted": False,
                "reason": "identity_" + resolution.outcome}
        lock_ids = sorted(set(original_membership_ids) | {predecessor_occurrence_id, selected_occurrence_id})
        occurrence_heads = connection.execute(sa.select(
            occurrences.c.occurrence_id, occurrences.c.exposure_id).where(
                occurrences.c.occurrence_id.in_(lock_ids))).mappings().all()
        if {row["occurrence_id"] for row in occurrence_heads} != set(lock_ids):
            _error(409, "revision_conflict", "Identity correspondence changed during reconciliation")
        exposure_ids = sorted({row["exposure_id"] for row in occurrence_heads})
        exposure_query = sa.select(exposures).where(exposures.c.exposure_id.in_(exposure_ids)).order_by(
            exposures.c.exposure_id)
        if engine.dialect.name == "postgresql":
            exposure_query = exposure_query.with_for_update()
        locked_exposures = connection.execute(exposure_query).mappings().all()
        occurrence_query = sa.select(occurrences).where(
            occurrences.c.occurrence_id.in_(lock_ids)).order_by(occurrences.c.occurrence_id)
        if engine.dialect.name == "postgresql":
            occurrence_query = occurrence_query.with_for_update()
        locked_occurrences = connection.execute(occurrence_query).mappings().all()
        if (len(locked_exposures) != len(exposure_ids)
                or len(locked_occurrences) != len(lock_ids)):
            _error(409, "revision_conflict", "Identity correspondence changed during reconciliation")
        if any(row["exposure_id"] not in exposure_ids for row in locked_occurrences):
            _error(409, "revision_conflict", "Identity parent mapping changed during reconciliation")
        selected_head = next(row for row in locked_occurrences
            if row["occurrence_id"] == selected_occurrence_id)
        selected_exposure = next(row for row in locked_exposures
            if row["exposure_id"] == selected_head["exposure_id"])
        selected_exposure_revision = getattr(resolution, "selected_exposure_revision", 1)
        selected_occurrence_revision = getattr(resolution, "selected_occurrence_revision", 1)
        if (selected_exposure["revision"] != selected_exposure_revision
                or selected_head["revision"] != selected_occurrence_revision):
            _error(409, "revision_conflict", "Identity selection is stale; resolve current correspondence")
        native_key = (observation["source_family"], observation["native_id_scheme"],
            observation["native_id_authority"], observation["native_id_value"])
        group_key = (group["source_family"], group["native_id_scheme"],
            group["native_id_authority"], group["native_id_value"])
        if native_key != group_key:
            _error(409, "revision_conflict", "Identity observation belongs to another finding group")
        if resolution.group_id not in (None, group["group_id"]):
            _error(409, "revision_conflict", "Identity resolution crosses finding groups")
    except IdentityResolutionReadError:
        _error(409, "revision_conflict", "Identity resolution is not verifiable")

    record = {"resolution_id": resolution_id, "observation_id": observation_id,
        "predecessor_occurrence_id": predecessor_occurrence_id,
        "successor_occurrence_id": resolution.occurrence_id,
        "resolution_status": result.status, "resolution_outcome": resolution.outcome,
        "proof_reference": result.proof_reference, "permitted": False, "reason": None}
    if (result.status != "verified" or resolution.outcome not in {"matched", "new"}
            or not resolution.occurrence_id or not resolution.workload_id):
        record["reason"] = ("identity_" + resolution.outcome if resolution.outcome in
            {"ambiguous", "unresolved"} else "identity_unverified")
        return record

    selected = connection.execute(sa.select(
        occurrences.c.occurrence_id, occurrences.c.workload_id,
        occurrences.c.component_locator, exposures.c.group_id)
        .select_from(occurrences.join(exposures,
            occurrences.c.exposure_id == exposures.c.exposure_id))
        .where(occurrences.c.occurrence_id == resolution.occurrence_id)).mappings().first()
    if (selected is None or selected["group_id"] != group["group_id"]
            or selected["workload_id"] != resolution.workload_id
            or selected["component_locator"] is None):
        record["reason"] = "selected_identity_mismatch"
        return record
    record.update(workload_id=selected["workload_id"],
        component_locator=selected["component_locator"])
    record["_identity_binding"] = {
        "resolution_id": resolution_id,
        "observation_id": observation_id,
        "successor_occurrence_id": resolution.occurrence_id,
        "selected_exposure_revision": selected_exposure["revision"],
        "selected_occurrence_revision": selected_head["revision"],
        "correspondence_heads": [{
            "occurrence_id": row["occurrence_id"], "exposure_id": row["exposure_id"],
            "occurrence_revision": row["revision"],
            "exposure_revision": next(parent["revision"] for parent in locked_exposures
                if parent["exposure_id"] == row["exposure_id"]),
            "group_id": next(parent["group_id"] for parent in locked_exposures
                if parent["exposure_id"] == row["exposure_id"]),
            "workload_id": row["workload_id"], "component_locator": row["component_locator"],
        } for row in locked_occurrences],
    }
    predecessors = connection.execute(sa.select(
        occurrences.c.occurrence_id, occurrences.c.workload_id,
        occurrences.c.component_locator)
        .select_from(occurrences.join(exposures,
            occurrences.c.exposure_id == exposures.c.exposure_id))
        .where(exposures.c.group_id == group["group_id"],
            occurrences.c.occurrence_id.in_(original_membership_ids))).mappings().all()
    if not any(row["occurrence_id"] == predecessor_occurrence_id for row in predecessors):
        _error(409, "revision_conflict", "Acceptance predecessor is not in its current group")
    matching_predecessors = [row for row in predecessors
        if row["workload_id"] == selected["workload_id"]
        and row["component_locator"] is not None
        and row["component_locator"] == selected["component_locator"]
        and row["occurrence_id"] != resolution.occurrence_id]
    record["permitted"] = (len(matching_predecessors) == 1
        and matching_predecessors[0]["occurrence_id"] == predecessor_occurrence_id)
    if not record["permitted"]:
        record["reason"] = ("predecessor_ambiguous" if len(matching_predecessors) > 1
            else "workload_or_component_mismatch")
    return record


def _payload_rationale(action: str, payload: dict) -> tuple[str, str]:
    shapes = {
        "connector.configuration.stage": ({"connector_id", "source_id", "rationale", "evidence_ref", "settings"}, set()),
        "connector.configuration.validate": ({"connector_id", "source_id", "rationale", "evidence_ref", "configuration_revision"}, set()),
        "connector.configuration.activate": ({"connector_id", "source_id", "rationale", "evidence_ref", "configuration_revision", "validation_intent_id"}, set()),
        "connector.configuration.disable": ({"connector_id", "source_id", "rationale", "evidence_ref"}, set()),
        "connector.configuration.rollback": ({"connector_id", "source_id", "rationale", "evidence_ref", "configuration_revision", "validation_intent_id"}, set()),
        "connector.secret.version.revoke": ({"connector_id", "source_id", "rationale", "evidence_ref", "secret_id", "version_id"}, set()),
        "connector.secret.submission.reconcile": ({"connector_id", "source_id", "rationale", "evidence_ref", "submission_id", "secret_id", "version_id"}, set()),
        "owners.assign": ({"owners"}, {"routing_override", "rationale"}),
        "portion.define": ({"portion_id", "owner_ids", "membership_ids"}, {"rationale"}),
        "portion.transfer": ({"portion_id", "owner_ids", "membership_ids", "rationale"}, set()),
        "portion.split": ({"portion_id", "portions", "rationale"}, set()),
        "routing.override": ({"owner_ids", "rationale"}, {"expires_at", "evidence_ref"}),
        "routing.expire": ({"override_id", "rationale"}, set()),
        "severity.override": ({"assessed_severity", "rationale"}, {"evidence_ref"}),
        "acceptance.submit": ({"accountable_owner_id", "rationale", "expires_at", "continuity_allowed"}, {"predecessor_id", "exception_contract_version", "context", "compensating_controls"}),
        "acceptance.approve": ({"acceptance_id", "rationale"}, {"selected_expires_at", "expected_request_revision"}),
        "acceptance.expire": ({"acceptance_id", "rationale"}, set()),
        "acceptance.reconcile": ({"acceptance_id", "resolution_id",
            "predecessor_occurrence_id", "rationale"}, set()),
        "acceptance.reject": ({"acceptance_id", "rationale"}, set()),
        "acceptance.revoke": ({"acceptance_id", "rationale"}, set()),
        "remediation.confirm_portion": ({"portion_id", "membership_ids", "rationale", "evidence_ref"}, set()),
        "remediation.confirm_group": ({"membership_ids", "rationale", "evidence_ref"}, set()),
        "policy.role.create": ({"role_id", "actions", "target_scope", "limits", "separation_of_duties"}, {"description"}),
        "policy.role.assign": ({"role_id", "principal_id", "effective_from"}, {"effective_until"}),
        "policy.role.update": ({"role_id", "actions", "target_scope", "limits", "separation_of_duties"}, {"description"}),
        "policy.sla.publish": ({"policy"}, {"rationale", "evidence_ref", "inventory_configuration"}),
        "sla.deadline.revise": ({"revisions", "rationale", "evidence_ref"}, set()),
        "native.authority.activate": ({"mapping_revision", "rationale", "evidence_ref"}, set()),
        "native.authority.rollback": ({"rationale", "evidence_ref"}, set()),
        "access_group.create": ({"access_group_id", "display_name", "source_scopes", "permissions", "rationale", "evidence_ref"}, {"description", "enabled"}),
        "access_group.update": ({"access_group_id", "display_name", "source_scopes", "permissions", "rationale", "evidence_ref"}, {"description", "enabled"}),
        "access_group.membership.set": ({"access_group_id", "principal_id", "effective_from", "enabled", "rationale", "evidence_ref"}, {"effective_until"}),
        "ownership.team.create": ({"team_id", "display_name", "rationale", "evidence_ref"}, {"enabled"}),
        "ownership.team.update": ({"team_id", "display_name", "rationale", "evidence_ref"}, {"enabled"}),
        "ownership.team.membership.set": ({"team_id", "principal_id", "effective_from", "enabled", "rationale", "evidence_ref"}, {"effective_until"}),
    }
    if action == "principal.update":
        # One existing audited administration action has two explicit variants:
        # update a configured principal's effective membership, or rename an
        # existing stable team identity while retaining its label history.
        variants = (
            ({"principal_id", "enabled"}, {"team_ids", "effective_from", "effective_until", "rationale"}),
            ({"team_id", "display_name"}, {"rationale"}),
        )
        if not any(required <= payload.keys() and not payload.keys() - required - optional
                   for required, optional in variants):
            _error(422, "invalid_command", "principal.update payload fields are invalid")
        rationale = payload.get("rationale", "")
        if rationale and (not isinstance(rationale, str) or not rationale.strip()):
            _error(422, "invalid_command", "Rationale must be non-empty")
        return rationale, ""
    shapes["principal.update"] = ({"principal_id", "enabled"},
        {"team_ids", "effective_from", "effective_until"})
    shape = shapes.get(action)
    if shape is None:
        _error(422, "invalid_command", "Action is not implemented")
    required, optional = shape
    if not required <= payload.keys() or payload.keys() - required - optional:
        _error(422, "invalid_command", "Action payload fields are invalid")
    rationale = payload.get("rationale", "")
    if rationale and (not isinstance(rationale, str) or not rationale.strip()):
        _error(422, "invalid_command", "Rationale must be non-empty")
    evidence = payload.get("evidence_ref", "")
    if evidence and not isinstance(evidence, str):
        _error(422, "invalid_command", "Evidence reference must be text")
    return rationale, evidence


def _owner_list(value, allowed_ids: set[str] | None = None) -> list[dict]:
    if not isinstance(value, list) or not value:
        _error(422, "invalid_command", "At least one owner is required")
    result = []
    seen = set()
    for item in value:
        if not isinstance(item, dict) or set(item) != {"owner_id", "owner_type"}:
            _error(422, "invalid_command", "Owner entries require owner_id and owner_type")
        owner_id, owner_type = item["owner_id"], item["owner_type"]
        if not isinstance(owner_id, str) or not owner_id or owner_type not in {"person", "team"}:
            _error(422, "invalid_command", "Owner identity is invalid")
        if allowed_ids is not None and owner_id not in allowed_ids:
            _error(422, "invalid_command", "Owner identity is not in the configured directory")
        if (owner_id, owner_type) in seen:
            _error(422, "invalid_command", "Owner entries must be unique")
        seen.add((owner_id, owner_type))
        result.append({"owner_id": owner_id, "owner_type": owner_type})
    return result


def _apply_group_action(document: dict, action: str, payload: dict, membership_ids: list[str],
                        current_membership: list[str], principal: str, policy: dict,
                        target_id: str, now: datetime, native_severity: str | None = None,
                        successor_evidence: dict | None = None,
                        scoped_grants: list[dict] | None = None,
                        effective_members: dict[str, set[str]] | None = None,
                        routing_evaluation: dict | None = None) -> dict:
    after = copy.deepcopy(document)
    effective_members = effective_members or {}
    rationale, evidence = _payload_rationale(action, payload)
    owner_revision = int(after.get("owner_revision", 1))
    portions = after.get("portions", [])
    acceptances = after.get("acceptances", [])
    if action == "severity.override":
        severity = payload["assessed_severity"]
        if severity not in _SEVERITIES:
            _error(422, "invalid_command", "Assessed severity is invalid")
        old_value = (after.get("assessed_severity") or {}).get("value") or native_severity
        after["assessed_severity"] = {"value": severity, "rationale": rationale,
            "actor_id": principal, "updated_at": now.isoformat().replace("+00:00", "Z"),
            "evidence_ref": evidence}
        rank = {"informational": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
        g7_exception_active = any(item.get("exception_contract_version") == 1
            and item.get("state") == "active" for item in acceptances)
        material_g7_severity_change = (g7_exception_active
            and policy.get("acceptance_material_changes", {}).get("severity_increase", True)
            and old_value in rank and severity in rank and rank[severity] > rank[old_value])
        if "__material_severity_members__" in effective_members:
            material_g7_severity_change = bool(effective_members["__material_severity_members__"])
        if material_g7_severity_change or (not g7_exception_active and old_value in rank and severity in rank
                and rank[severity] > rank[old_value]):
            for acceptance in acceptances:
                if acceptance["state"] == "active" and (not membership_ids or set(acceptance["membership_ids"]) & set(membership_ids)):
                    affected = set(acceptance["membership_ids"]) & set(
                        effective_members.get("__material_severity_members__", membership_ids or current_membership)
                        if acceptance.get("exception_contract_version") == 1 else (membership_ids or current_membership))
                    if not affected:
                        continue
                    suspended = set(acceptance.get("suspended_membership_ids", [])) | affected
                    acceptance["suspended_membership_ids"] = sorted(suspended)
                    acceptance["state"] = ("suspended" if acceptance.get("exception_contract_version") != 1
                        or suspended >= set(acceptance["membership_ids"]) else "active")
                    acceptance.setdefault("history", []).append({"state": "suspended", "actor_id": "system:material-change", "at": now.isoformat(), "reason": "severity_increased", "membership_ids": sorted(affected)})
    elif action == "owners.assign":
        previous_owners = {(item.get("owner_id"), item.get("owner_type"))
            for item in after.get("owners", [])}
        directory = {entry["owner_id"] for entry in policy.get("owner_directory", [])
                     if entry.get("enabled", True)}
        owners = _owner_list(payload["owners"], directory if directory else None)
        after["owners"] = owners
        after["owner_revision"] = owner_revision + 1
        new_ids = {owner["owner_id"] for owner in owners}
        g7_owner_change = previous_owners != {(item["owner_id"], item["owner_type"])
            for item in owners}
        for acceptance in acceptances:
            if (acceptance["state"] == "active"
                    and acceptance.get("accountable_owner_id") not in new_ids
                    and (acceptance.get("exception_contract_version") != 1
                        or policy.get("acceptance_material_changes", {}).get("accountable_owner_removed", True))):
                acceptance["state"] = "suspended"
                acceptance.setdefault("history", []).append({"state": "suspended", "actor_id": "system:material-change", "at": now.isoformat(), "reason": "accountable_owner_changed"})
    elif action == "portion.define":
        portion_id = _uuid(payload["portion_id"], "portion_id")
        members = payload["membership_ids"]
        if not isinstance(members, list) or not members or any(member not in current_membership for member in members):
            _error(422, "invalid_command", "Portion membership must be a non-empty subset of current membership")
        if any(set(members) & set(item["membership_ids"]) for item in portions if item.get("active", True)):
            _error(409, "revision_conflict", "Portions cannot overlap")
        owners = payload["owner_ids"]
        if not isinstance(owners, list) or not owners or len(set(owners)) != len(owners):
            _error(422, "invalid_command", "Portion owner_ids must be a non-empty unique list")
        portions.append({"portion_id": portion_id, "revision": 1, "owner_ids": owners,
            "membership_ids": members, "completed_membership_ids": [], "active": True,
            "created_at": now.isoformat().replace("+00:00", "Z")})
        after["portions"] = portions
        after["owner_revision"] = owner_revision + 1
    elif action == "portion.transfer":
        portion_id = payload["portion_id"]
        portion = next((item for item in portions if item["portion_id"] == portion_id and item.get("active", True)), None)
        if portion is None or payload["membership_ids"] != portion["membership_ids"] or membership_ids != portion["membership_ids"]:
            _error(409, "revision_conflict", "Portion membership changed")
        owners = payload["owner_ids"]
        if not isinstance(owners, list) or not owners or len(set(owners)) != len(owners):
            _error(422, "invalid_command", "Portion owner_ids must be a non-empty unique list")
        portion["owner_ids"] = owners
        portion["revision"] += 1
        portion["updated_at"] = now.isoformat().replace("+00:00", "Z")
        after["portions"] = portions
        after["owner_revision"] = owner_revision + 1
    elif action == "portion.split":
        old_id = payload["portion_id"]
        old = next((item for item in portions if item["portion_id"] == old_id and item.get("active", True)), None)
        children = payload["portions"]
        if old is None or not isinstance(children, list) or len(children) < 2:
            _error(422, "invalid_command", "An active portion and at least two new portions are required")
        assigned = []
        for child in children:
            if set(child) != {"portion_id", "owner_ids", "membership_ids"}:
                _error(422, "invalid_command", "Split portion shape is invalid")
            _uuid(child["portion_id"], "portion_id")
            if child["portion_id"] == old_id or not child["owner_ids"] or not child["membership_ids"]:
                _error(422, "invalid_command", "Split portion fields are invalid")
            assigned.extend(child["membership_ids"])
        if sorted(assigned) != sorted(old["membership_ids"]) or len(set(assigned)) != len(assigned):
            _error(422, "invalid_command", "Split must partition the original membership exactly")
        completed = set(old.get("completed_membership_ids", []))
        old["active"] = False
        old["revision"] += 1
        for child in children:
            portions.append({"portion_id": child["portion_id"], "revision": 1,
                "owner_ids": child["owner_ids"], "membership_ids": child["membership_ids"],
                "completed_membership_ids": [m for m in child["membership_ids"] if m in completed],
                "active": True, "created_at": now.isoformat().replace("+00:00", "Z")})
        after["portions"] = portions
        after["owner_revision"] = owner_revision + 1
    elif action == "routing.override":
        owners = payload["owner_ids"]
        if not isinstance(owners, list) or not owners:
            _error(422, "invalid_command", "routing owner_ids must be non-empty")
        until = payload.get("expires_at")
        if until:
            try:
                expiry = datetime.fromisoformat(until.replace("Z", "+00:00"))
            except (ValueError, AttributeError):
                _error(422, "invalid_command", "expires_at must be UTC RFC 3339")
            if expiry.tzinfo is None or expiry <= now:
                _error(422, "invalid_command", "expires_at must be a future UTC instant")
        override = {"override_id": str(uuid.uuid4()), "owner_ids": owners,
            "rationale": rationale, "evidence_ref": evidence, "expires_at": until,
            "actor_id": principal, "created_at": now.isoformat().replace("+00:00", "Z"),
            "status": "active"}
        evaluation = copy.deepcopy(routing_evaluation or {
            "status": "unresolved", "owner_ids": [], "override": None,
            "evaluated_policy_revision": int(policy.get("revision", 1)), "evidence": []})
        history = copy.deepcopy(after.get("routing", {}).get("history", []))
        history.append({"event": "evaluated", "actor_id": principal,
            "at": _utc_z(now), "evaluation": copy.deepcopy(evaluation)})
        after["routing"] = {**evaluation, "status": "assigned", "owner_ids": owners,
            "override": override, "history": history}
    elif action == "routing.expire":
        routing = dict(after.get("routing", {}))
        override = routing.get("override")
        if not override or override.get("override_id") != payload["override_id"]:
            _error(409, "revision_conflict", "Routing override changed")
        if override.get("expires_at") and datetime.fromisoformat(
                override["expires_at"].replace("Z", "+00:00")) > now:
            _error(409, "revision_conflict", "Routing override has not expired")
        override = dict(override, status="expired")
        evaluation = copy.deepcopy(routing_evaluation or {
            "status": "unresolved", "owner_ids": [], "override": None,
            "evaluated_policy_revision": int(policy.get("revision", 1)), "evidence": []})
        history = routing.get("history", [])
        history.append({"event": "evaluated", "actor_id": principal,
            "at": _utc_z(now), "evaluation": copy.deepcopy(evaluation)})
        history.append({"event": "expired", "rationale": rationale,
            "actor_id": principal, "at": now.isoformat().replace("+00:00", "Z")})
        after["routing"] = {**evaluation, "override": override, "history": history}
    elif action == "acceptance.submit":
        members = list(membership_ids)
        if not members or any(member not in current_membership for member in members):
            _error(422, "invalid_command", "Acceptance membership must be non-empty current membership")
        owner_id, expires = payload["accountable_owner_id"], payload["expires_at"]
        if not isinstance(owner_id, str) or not owner_id:
            _error(422, "invalid_command", "Accountable owner is required")
        try:
            expiry = datetime.fromisoformat(expires.replace("Z", "+00:00"))
        except (ValueError, AttributeError):
            _error(422, "invalid_command", "expires_at must be UTC RFC 3339")
        if expiry.tzinfo is None or expiry <= now:
            _error(422, "invalid_command", "Acceptance expiry must be in the future")
        exception_contract = payload.get("exception_contract_version")
        if exception_contract is not None:
            if exception_contract != 1:
                _error(422, "invalid_command", "Unsupported exception request contract version")
            if (not isinstance(payload.get("compensating_controls"), str)
                    or not payload["compensating_controls"].strip()):
                _error(422, "invalid_command", "Compensating controls are required for a G7 exception")
            if not isinstance(payload.get("context", {}), dict):
                _error(422, "invalid_command", "Exception context must be an object")
        predecessor_id = payload.get("predecessor_id")
        predecessor = next((item for item in acceptances if item["acceptance_id"] == predecessor_id), None) if predecessor_id else None
        if predecessor_id and (predecessor is None or predecessor["state"] not in {"pending", "active", "suspended"}):
            _error(409, "revision_conflict", "Replacement predecessor is unavailable")
        if predecessor and datetime.fromisoformat(predecessor["expires_at"].replace("Z", "+00:00")) <= now:
            _error(409, "revision_conflict", "Expired predecessor cannot be replaced")
        for existing in acceptances:
            if existing["state"] in {"pending", "active", "suspended"} and effective_members.get(existing["acceptance_id"], set()) & set(members):
                if existing is not predecessor:
                    _error(409, "revision_conflict", "Acceptance membership overlaps an existing decision")
        acceptance_id = str(uuid.uuid4())
        acceptance = {"acceptance_id": acceptance_id, "state": "pending",
            "membership_ids": members, "accountable_owner_id": owner_id, "requester_id": principal,
            "rationale": rationale, "submitted_at": now.isoformat().replace("+00:00", "Z"), "expires_at": expires,
            "continuity_allowed": bool(payload["continuity_allowed"]),
            "predecessor_id": predecessor_id, "history": [{"state": "pending", "actor_id": principal,
                "at": now.isoformat().replace("+00:00", "Z"), "rationale": rationale}]}
        if exception_contract == 1:
            acceptance.update(exception_contract_version=1, request_revision=1, proposed_expires_at=expires,
                context={"group_id": target_id, "membership_ids": list(members),
                    "submitted_context": copy.deepcopy(payload.get("context", {}))},
                compensating_controls=payload["compensating_controls"])
        acceptances.append(acceptance)
        if predecessor is not None and predecessor["state"] == "pending":
            predecessor["state"] = "rejected"
            predecessor.setdefault("history", []).append({"state": "rejected",
                "actor_id": principal, "at": now.isoformat().replace("+00:00", "Z"),
                "rationale": rationale, "reason": "superseded_pending_proposal",
                "successor_id": acceptance_id})
        after["acceptances"] = acceptances
    elif action in {"acceptance.approve", "acceptance.reject", "acceptance.revoke", "acceptance.expire"}:
        acceptance = next((item for item in acceptances if item["acceptance_id"] == payload["acceptance_id"]), None)
        if acceptance is None:
            _error(409, "revision_conflict", "Acceptance decision is unavailable")
        expected_states = {"acceptance.approve": {"pending"}, "acceptance.reject": {"pending"},
                           "acceptance.revoke": {"active", "suspended"},
                           "acceptance.expire": {"pending", "active", "suspended"}}[action]
        if acceptance["state"] not in expected_states:
            _error(409, "revision_conflict", "Acceptance transition is not allowed from its current state")
        if action == "acceptance.approve":
            grants = scoped_grants or []
            if any(grant.get("separation_of_duties", {}).get("prohibit_requester_approval", True)
                   and acceptance["requester_id"] == principal for grant in grants):
                _error(403, "forbidden", "Requester cannot approve their own acceptance")
            exception_v1 = acceptance.get("exception_contract_version") == 1
            if exception_v1:
                if payload.get("expected_request_revision") != acceptance.get("request_revision", 1):
                    _error(409, "revision_conflict", "Exception request revision changed")
                selected_expiry = payload.get("selected_expires_at")
                if not isinstance(selected_expiry, str):
                    _error(422, "invalid_command", "Approver-selected expiry is required")
                try:
                    expiry = datetime.fromisoformat(selected_expiry.replace("Z", "+00:00"))
                except ValueError:
                    _error(422, "invalid_command", "selected_expires_at must be RFC 3339")
                if expiry.tzinfo is None or expiry.utcoffset() != _UTC.utcoffset(expiry) or expiry <= now:
                    _error(422, "invalid_command", "Approver-selected expiry must be a future UTC instant")
                accepted_expiry = _utc_z(expiry)
                if any(item.get("expiry") != accepted_expiry or
                       item.get("request_revision") != acceptance.get("request_revision", 1)
                       for item in acceptance.get("approvals", [])):
                    _error(409, "revision_conflict", "Approvals must sign the same expiry and request revision")
                acceptance["expires_at"] = accepted_expiry
            else:
                expiry = datetime.fromisoformat(acceptance["expires_at"].replace("Z", "+00:00"))
            if expiry <= now:
                _error(409, "revision_conflict", "Expired acceptance cannot be approved")
            candidate_members = effective_members.get(acceptance["acceptance_id"], set())
            linked_predecessor = None
            if acceptance.get("predecessor_id"):
                linked_predecessor = next((item for item in acceptances
                    if item.get("acceptance_id") == acceptance["predecessor_id"]), None)
                superseded_pending = (linked_predecessor is not None
                    and linked_predecessor.get("state") == "rejected"
                    and any(item.get("reason") == "superseded_pending_proposal"
                        and item.get("successor_id") == acceptance["acceptance_id"]
                        for item in linked_predecessor.get("history", [])))
                if not superseded_pending and (linked_predecessor is None
                        or linked_predecessor.get("state") not in {"active", "suspended"}
                        or datetime.fromisoformat(linked_predecessor["expires_at"].replace("Z", "+00:00")) <= now):
                    _error(409, "revision_conflict", "Replacement predecessor is no longer active")
            for existing in acceptances:
                if (existing is acceptance or existing is linked_predecessor
                        or existing.get("state") not in {"active", "suspended"}):
                    continue
                if effective_members.get(existing["acceptance_id"], set()) & candidate_members:
                    _error(409, "revision_conflict",
                        "Acceptance overlaps effective membership already covered")
            submitted = datetime.fromisoformat(acceptance["submitted_at"].replace("Z", "+00:00"))
            duration_days = max(1, math.ceil((expiry - submitted).total_seconds() / 86400))
            current_severity = ((after.get("assessed_severity") or {}).get("value")
                or native_severity)
            rank = {"informational": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
            def grant_covers_severity(grant):
                maximum = grant.get("limits", {}).get("maximum_severity")
                # A null maximum is an explicit unbounded setting. A bounded
                # grant needs a known current rating to compare against; two
                # unknown values must not silently satisfy that bound.
                if maximum is None:
                    return True
                return (current_severity in rank and maximum in rank
                    and rank[current_severity] <= rank[maximum])

            eligible = [grant for grant in grants
                if grant.get("limits", {}).get("maximum_acceptance_days") is not None
                and duration_days <= grant["limits"]["maximum_acceptance_days"]
                and grant_covers_severity(grant)]
            if not eligible:
                _error(403, "forbidden", "No complete approval grant covers duration and severity")
            approvals = acceptance.setdefault("approvals", [])
            if any(item.get("actor_id") == principal for item in approvals):
                _error(409, "revision_conflict", "Approver has already recorded this decision")
            approvals.append({"actor_id": principal, "at": now.isoformat().replace("+00:00", "Z"),
                "rationale": rationale, **({"expiry": accepted_expiry,
                    "request_revision": acceptance.get("request_revision", 1),
                    "grant_ids": sorted(grant["grant_id"] for grant in eligible if grant.get("grant_id")),
                    "required_approver_count": max(grant.get("separation_of_duties", {}).get("required_approver_count", 1)
                        for grant in eligible)} if exception_v1 else {})})
            needed = max(grant.get("separation_of_duties", {}).get("required_approver_count", 1)
                         for grant in eligible)
            if exception_v1:
                needed = max([needed] + [item.get("required_approver_count", 1) for item in approvals])
            if len(approvals) >= needed:
                acceptance["state"] = "active"
            if (acceptance["state"] == "active" and acceptance.get("predecessor_id")
                    and linked_predecessor.get("state") in {"active", "suspended"}):
                predecessor = next(item for item in acceptances if item["acceptance_id"] == acceptance["predecessor_id"])
                predecessor["state"] = "revoked"
                predecessor.setdefault("history", []).append({"state": "revoked", "actor_id": principal,
                    "at": now.isoformat().replace("+00:00", "Z"), "reason": "replaced"})
        elif action == "acceptance.reject":
            acceptance["state"] = "rejected"
        elif action == "acceptance.revoke":
            acceptance["state"] = "revoked"
        else:
            expiry = datetime.fromisoformat(acceptance["expires_at"].replace("Z", "+00:00"))
            if expiry > now:
                _error(409, "revision_conflict", "Acceptance has not expired")
            acceptance["state"] = "expired"
        acceptance.setdefault("history", []).append({"state": acceptance["state"],
            "actor_id": principal, "at": now.isoformat().replace("+00:00", "Z"), "rationale": rationale})
        after["acceptances"] = acceptances
    elif action == "acceptance.reconcile":
        acceptance = next((item for item in acceptances
            if item["acceptance_id"] == payload["acceptance_id"]), None)
        if acceptance is None or acceptance["state"] not in {"active", "suspended"}:
            _error(409, "revision_conflict", "Acceptance is unavailable for reconciliation")
        if payload["predecessor_occurrence_id"] not in acceptance["membership_ids"]:
            _error(409, "revision_conflict", "Reconciliation predecessor is outside immutable acceptance membership")
        if successor_evidence is None:
            _error(409, "revision_conflict", "Identity evidence is unavailable")
        covered = acceptance.setdefault("successor_coverage", [])
        history = acceptance.setdefault("reconciliation_history", [])
        reason = successor_evidence.get("reason")
        permitted = (acceptance["state"] == "active"
            and acceptance.get("continuity_allowed") is True
            and datetime.fromisoformat(acceptance["expires_at"].replace("Z", "+00:00")) > now
            and successor_evidence.get("permitted") is True
            and successor_evidence.get("successor_occurrence_id") not in acceptance["membership_ids"]
            and successor_evidence.get("successor_occurrence_id") not in
                effective_members.get(acceptance["acceptance_id"], set()))
        if acceptance["state"] != "active":
            reason = "acceptance_not_active"
        elif datetime.fromisoformat(acceptance["expires_at"].replace("Z", "+00:00")) <= now:
            reason = "acceptance_expired"
        elif acceptance.get("continuity_allowed") is not True:
            reason = "continuity_not_allowed"
        elif not successor_evidence.get("permitted"):
            reason = reason or "identity_not_permitted"
        elif successor_evidence.get("successor_occurrence_id") in effective_members.get(
                acceptance["acceptance_id"], set()):
            reason = "successor_already_covered"
        entry = {**successor_evidence, "accepted": permitted,
            "actor_id": principal, "at": now.isoformat().replace("+00:00", "Z"),
            "rationale": rationale}
        if not permitted:
            entry["reason"] = reason or "continuity_not_permitted"
        history.append(entry)
        if permitted:
            overlap = any(item is not acceptance
                and item.get("state") in {"active", "suspended"}
                and successor_evidence["successor_occurrence_id"] in effective_members.get(item["acceptance_id"], set())
                for item in acceptances)
            if overlap:
                _error(409, "revision_conflict", "Successor is already covered by another effective acceptance")
            else:
                # Historical decisions remain append-only in reconciliation_history.
                # Replace only obsolete current coverage for this successor.
                covered[:] = [item for item in covered if item.get("successor_occurrence_id")
                    != successor_evidence["successor_occurrence_id"]]
                covered.append(copy.deepcopy(entry))
        after["acceptances"] = acceptances
    elif action in {"remediation.confirm_portion", "remediation.confirm_group"}:
        requested = payload["membership_ids"]
        if not isinstance(requested, list) or requested != membership_ids:
            _error(422, "invalid_command", "Confirmation payload and command membership must match")
        outstanding = list((effective_members or {}).get("__episode_outstanding__",
            [item for item in current_membership if item not in set(after.get("completed_ids", []))]))
        if action == "remediation.confirm_group":
            grants = scoped_grants or []
            if not any(grant.get("limits", {}).get("whole_group_confirmation") is True for grant in grants):
                _error(403, "forbidden", "Whole-group confirmation requires its configured authority")
            if sorted(requested) != sorted(outstanding):
                _error(409, "revision_conflict", "Whole-group confirmation requires exact outstanding membership")
            after["completed_ids"] = sorted(set(after.get("completed_ids", [])) | set(requested))
        else:
            portion = next((item for item in portions if item["portion_id"] == payload["portion_id"] and item.get("active", True)), None)
            if portion is None or sorted(requested) != sorted(portion["membership_ids"]):
                _error(409, "revision_conflict", "Confirmation must match the exact current portion")
            portion["completed_membership_ids"] = sorted(set(portion.get("completed_membership_ids", [])) | set(requested))
            after["portions"] = portions
            after["completed_ids"] = sorted(set(after.get("completed_ids", [])) | set(requested))
        after["outstanding_ids"] = [item for item in current_membership if item not in set(after["completed_ids"])]
        after.setdefault("confirmations", []).append({"actor_id": principal, "action": action,
            "membership_ids": requested, "rationale": rationale, "evidence_ref": evidence,
            "at": now.isoformat().replace("+00:00", "Z")})
    else:
        _error(422, "invalid_command", "Policy action is not valid for a group target")
    after["acceptances"] = acceptances
    after.setdefault("owner_revision", owner_revision)
    return after


_CONNECTOR_COMMAND_ACTIONS = {"connector.configuration.stage", "connector.configuration.validate",
    "connector.configuration.activate", "connector.configuration.disable",
    "connector.configuration.rollback", "connector.secret.version.revoke",
    "connector.secret.submission.reconcile"}
_POLICY_ACTIONS = {"policy.role.create", "policy.role.assign", "policy.role.update", "principal.update", "policy.sla.publish"} | NATIVE_ACTIONS | _CONNECTOR_COMMAND_ACTIONS
_NO_INTENT_POLICY_ACTIONS = {"policy.role.create", "policy.role.assign", "policy.role.update", "principal.update"}
_SCOPE_KEYS = {"group_ids", "source_families", "environments", "service_ids", "membership_mode"}
_LIMIT_KEYS = {"maximum_acceptance_days", "maximum_severity", "whole_group_confirmation",
               "allowed_environments", "allowed_service_ids", "allowed_sla_clock_bases",
               "allowed_sla_severities", "allowed_sla_start_sources", "maximum_sla_duration_seconds", "allow_sla_backfill",
               "maximum_deadline_extension_seconds", "allowed_identity_scalar_fields"}
_LEGACY_LIMIT_KEYS = _LIMIT_KEYS - {"allowed_sla_clock_bases", "allowed_sla_severities",
    "allowed_sla_start_sources",
    "maximum_sla_duration_seconds", "allow_sla_backfill", "maximum_deadline_extension_seconds",
    "allowed_identity_scalar_fields"}
_SOD_KEYS = {"approval_requires_distinct_actor", "prohibit_requester_approval",
             "required_approver_count", "prohibited_action_pairs"}


def _validate_role_document(payload: dict) -> dict:
    scope, limits, sod = payload["target_scope"], payload["limits"], payload["separation_of_duties"]
    if not isinstance(scope, dict) or set(scope) != _SCOPE_KEYS:
        _error(422, "invalid_command", "target_scope shape is invalid")
    if any(not isinstance(scope[key], list) or any(not isinstance(value, str) for value in scope[key])
           for key in ("group_ids", "source_families", "environments", "service_ids")):
        _error(422, "invalid_command", "target_scope selectors must be string arrays")
    if scope["membership_mode"] not in {"explicit", "all_current"}:
        _error(422, "invalid_command", "membership_mode is invalid")
    if not isinstance(limits, dict) or not _LEGACY_LIMIT_KEYS <= set(limits) or not set(limits) <= _LIMIT_KEYS:
        _error(422, "invalid_command", "limits shape is invalid")
    limits = {**_LIMIT_DEFAULTS, **limits}
    days, severity = limits["maximum_acceptance_days"], limits["maximum_severity"]
    if days is not None and (type(days) is not int or days < 1):
        _error(422, "invalid_command", "maximum_acceptance_days must be positive or null")
    if severity is not None and severity not in _SEVERITIES:
        _error(422, "invalid_command", "maximum_severity is invalid")
    if type(limits["whole_group_confirmation"]) is not bool:
        _error(422, "invalid_command", "whole_group_confirmation must be boolean")
    if any(not isinstance(limits[key], list) or any(not isinstance(x, str) for x in limits[key])
           for key in ("allowed_environments", "allowed_service_ids")):
        _error(422, "invalid_command", "allowed environment/service lists are invalid")
    if (any(not isinstance(limits[key], list) or any(not isinstance(x, str) for x in limits[key])
            for key in ("allowed_sla_clock_bases", "allowed_sla_severities", "allowed_sla_start_sources"))
            or any(value not in {"elapsed_utc_seconds", "calendar_days_utc"} for value in limits["allowed_sla_clock_bases"])
            or any(value not in {"source_observation_v1", "uvm_ingest_commit_v1"} for value in limits["allowed_sla_start_sources"])
            or any(value not in _SEVERITIES for value in limits["allowed_sla_severities"])
            or type(limits["allow_sla_backfill"]) is not bool
            or any(limits[key] is not None and (type(limits[key]) is not int or limits[key] < 0)
                   for key in ("maximum_sla_duration_seconds", "maximum_deadline_extension_seconds"))):
        _error(422, "invalid_command", "SLA authority limits are invalid")
    if not isinstance(sod, dict) or set(sod) != _SOD_KEYS:
        _error(422, "invalid_command", "separation_of_duties shape is invalid")
    if (type(sod["approval_requires_distinct_actor"]) is not bool
            or type(sod["prohibit_requester_approval"]) is not bool
            or type(sod["required_approver_count"]) is not int or sod["required_approver_count"] < 1
            or not isinstance(sod["prohibited_action_pairs"], list)):
        _error(422, "invalid_command", "separation_of_duties values are invalid")
    fields = limits["allowed_identity_scalar_fields"]
    scalar_actions = {"identity.workload_field_correct", "identity.incarnation_locator_correct"}
    if (not isinstance(fields, dict) or not set(fields) <= scalar_actions
            or any(not isinstance(values, list)
                or any(type(value) is not str or not value or value == "*" for value in values)
                or len(values) != len(set(values))
                for values in fields.values())
            or any(value != "host_locator" for value in fields.get("identity.incarnation_locator_correct", []))):
        _error(422, "invalid_command", "Scalar field authority limits are invalid")
    actions = payload["actions"]
    if not isinstance(actions, list) or not actions or len(set(actions)) != len(actions) or any(action not in set(_ACTIONS) | scalar_actions for action in actions):
        _error(422, "invalid_command", "role actions must be unique known actions")
    role = {"actions": actions, "target_scope": scope, "limits": limits,
            "separation_of_duties": sod, "description": payload.get("description", "")}
    if role["description"] and not isinstance(role["description"], str):
        _error(422, "invalid_command", "description must be text")
    return role


def _envelope_allows(envelope: dict, role: dict) -> bool:
    allowed_actions = set(envelope.get("actions", []))
    if "*" not in allowed_actions and not set(role["actions"]) <= allowed_actions:
        return False
    outer, inner = envelope.get("target_scope", {}), role.get("target_scope", {})
    for key in ("group_ids", "source_families", "environments", "service_ids"):
        allowed = set(outer.get(key, []))
        requested = set(inner.get(key, []))
        if "*" not in allowed and (not requested or not requested <= allowed):
            return False
    if inner.get("membership_mode") == "all_current" and outer.get("membership_mode") != "all_current":
        return False
    observer_actions = {"observer.timing.read", "observer.timing.configure"}
    if observer_actions.intersection(role.get("actions", [])):
        allowed_deployments = envelope.get("deployment_scopes", [])
        requested_deployments = role.get("deployment_scopes", [])
        if (not isinstance(allowed_deployments, list)
                or not isinstance(requested_deployments, list)
                or not requested_deployments
                or any(not isinstance(value, str) or not value
                    for value in [*allowed_deployments, *requested_deployments])
                or not set(requested_deployments) <= set(allowed_deployments)):
            return False
    outer_limits, inner_limits = envelope.get("limits", {}), role.get("limits", {})
    max_days = outer_limits.get("maximum_acceptance_days")
    requested_days = inner_limits.get("maximum_acceptance_days")
    if max_days is None and requested_days is not None or max_days is not None and requested_days is not None and requested_days > max_days:
        return False
    rank = {"informational": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    max_sev, requested_sev = outer_limits.get("maximum_severity"), inner_limits.get("maximum_severity")
    if max_sev is None and requested_sev is not None or max_sev is not None and requested_sev is not None and rank[requested_sev] > rank[max_sev]:
        return False
    if inner_limits.get("whole_group_confirmation") and not outer_limits.get("whole_group_confirmation", False):
        return False
    for key in ("allowed_sla_clock_bases", "allowed_sla_severities", "allowed_sla_start_sources"):
        allowed = set(outer_limits.get(key, []))
        requested = set(inner_limits.get(key, []))
        # Empty capability lists are intentionally useful for read-only roles.
        if "*" not in allowed and not requested <= allowed:
            return False
    for key in ("allowed_environments", "allowed_service_ids"):
        allowed, requested = set(outer_limits.get(key, [])), set(inner_limits.get(key, []))
        if "*" not in allowed and (not requested or not requested <= allowed):
            return False
    for key in ("maximum_sla_duration_seconds", "maximum_deadline_extension_seconds"):
        outer_value, inner_value = outer_limits.get(key), inner_limits.get(key)
        if inner_value is not None and (outer_value is None or inner_value > outer_value):
            return False
    if inner_limits.get("allow_sla_backfill") and not outer_limits.get("allow_sla_backfill", False):
        return False
    outer_fields = outer_limits.get("allowed_identity_scalar_fields") or {}
    inner_fields = inner_limits.get("allowed_identity_scalar_fields") or {}
    if any(not set(fields) <= set(outer_fields.get(action, [])) for action, fields in inner_fields.items()):
        return False
    outer_sod, inner_sod = envelope.get("separation_of_duties", {}), role.get("separation_of_duties", {})
    for key in ("approval_requires_distinct_actor", "prohibit_requester_approval"):
        if outer_sod.get(key, True) and not inner_sod.get(key, False):
            return False
    if inner_sod.get("required_approver_count", 1) < outer_sod.get("required_approver_count", 1):
        return False
    if not set(map(tuple, outer_sod.get("prohibited_action_pairs", []))) <= set(map(tuple, inner_sod.get("prohibited_action_pairs", []))):
        return False
    return True


def _apply_policy_action(document: dict, principal: str, action: str, payload: dict,
                        now: datetime, configured_principals: dict,
                        expected_revisions: dict | None = None) -> dict:
    after = json.loads(json.dumps(document))
    envelope = after.get("delegation_envelopes", {}).get(principal, {})
    if action in NATIVE_ACTIONS:
        state = native_state(after)
        if action in {"access_group.create", "access_group.update", "access_group.membership.set",
                      "native.authority.activate", "native.authority.rollback"} and principal not in set(state.get("bootstrap_admins", [])):
            _error(403, "forbidden", "Protected bootstrap administration is required")
        if action in {"ownership.team.create", "ownership.team.update", "ownership.team.membership.set"}:
            if state.get("mode") != NATIVE_MODE or not _matches(after, principal,
                    "ownership.team.manage", payload.get("team_id", _ZERO_ID), None):
                _error(403, "forbidden", "Current ownership-team administration authority is required")
        grantable = state.get("grantable_envelope", {})
        source_ceiling = {tuple((item.get("source_family"), item.get("source_account_id"), item.get("scope_key")))
            for item in grantable.get("source_scopes", []) if isinstance(item, dict)}
        def validate_permission(role_input):
            if role_input["actions"][0] not in _ACTIONS:
                _error(422, "invalid_command", "Access-group action is not selectable")
            return _validate_role_document(role_input)
        def envelope_allows_native(current_envelope, role, scopes, actor):
            scope_allowed = (bool(source_ceiling) and all(tuple((item["source_family"],
                item["source_account_id"], item["scope_key"])) in source_ceiling for item in scopes))
            return scope_allowed and _envelope_allows(current_envelope, role)
        try:
            after, _kind, _target = apply_native_command(after, action, payload, principal, now,
                configured_principals, validate_permission=validate_permission,
                envelope_allows=envelope_allows_native, expected_revisions=expected_revisions)
        except PermissionError as exc:
            _error(403, "forbidden", str(exc))
        except (FileExistsError, LookupError, RuntimeError) as exc:
            _error(409, "revision_conflict", str(exc))
        except (ValueError, TypeError, AttributeError, KeyError) as exc:
            _error(422, "invalid_command", str(exc))
    elif action in {"policy.role.create", "policy.role.update"}:
        if native_state(after).get("mode") == NATIVE_MODE:
            _error(403, "forbidden", "Legacy role administration is disabled in native mode")
        role_id = payload["role_id"]
        if not isinstance(role_id, str) or not role_id:
            _error(422, "invalid_command", "role_id is required")
        role = _validate_role_document(payload)
        if not _envelope_allows(envelope, role):
            _error(403, "forbidden", "Role exceeds the administrator delegation envelope")
        roles = after.setdefault("roles", {})
        current = roles.get(role_id)
        if action == "policy.role.create" and current is not None:
            _error(409, "revision_conflict", "Role already exists")
        if action == "policy.role.update" and current is None:
            _error(409, "revision_conflict", "Role does not exist")
        role.update(role_id=role_id, revision=int(current.get("revision", 0) + 1) if current else 1)
        roles[role_id] = role
    elif action == "policy.role.assign":
        if native_state(after).get("mode") == NATIVE_MODE:
            _error(403, "forbidden", "Legacy role assignment is disabled in native mode")
        role_id, principal_id = payload["role_id"], payload["principal_id"]
        role = after.get("roles", {}).get(role_id)
        if role is None or not isinstance(principal_id, str) or not principal_id:
            _error(422, "invalid_command", "Role assignment target is invalid")
        if not _envelope_allows(envelope, role):
            _error(403, "forbidden", "Role exceeds the administrator delegation envelope")
        assigned_principal = after.get("principals", {}).get(principal_id)
        configured_person = principal_id in configured_principals
        team_target = next((entry for entry in after.get("owner_directory", [])
            if entry.get("owner_id") == principal_id and entry.get("owner_type") == "team"
            and entry.get("enabled", True)), None)
        if assigned_principal is None and not configured_person and team_target is None:
            _error(422, "invalid_command", "Role assignment target is not a configured principal or enabled team")
        if assigned_principal is not None and assigned_principal.get("enabled") is False:
            _error(409, "revision_conflict", "Disabled principal cannot receive a role")
        start, end = payload["effective_from"], payload.get("effective_until")
        for instant in (start, end):
            if instant is not None:
                try:
                    parsed = datetime.fromisoformat(instant.replace("Z", "+00:00"))
                except (ValueError, AttributeError):
                    _error(422, "invalid_command", "Role assignment timestamps must be UTC RFC 3339")
                if parsed.tzinfo is None:
                    _error(422, "invalid_command", "Role assignment timestamps must include timezone")
        if start and end and datetime.fromisoformat(end.replace("Z", "+00:00")) <= datetime.fromisoformat(start.replace("Z", "+00:00")):
            _error(422, "invalid_command", "Role assignment effective_until must follow effective_from")
        grants = after.setdefault("grants", [])
        grants.append({"grant_id": str(uuid.uuid4()), "role_id": role_id,
            "principal_id": principal_id, "effective_from": start,
            "effective_until": end})
    elif action == "principal.update":
        if native_state(after).get("mode") == NATIVE_MODE:
            native = native_state(after)
            if principal not in set(native.get("bootstrap_admins", [])):
                _error(403, "forbidden", "Protected bootstrap administration is required for account disable")
            expected_authority = (expected_revisions or {}).get("authority")
            if type(expected_authority) is not int or expected_authority != int(native.get("revision", 0)):
                _error(409, "revision_conflict", "Native authority revision changed")
            if "team_id" in payload or set(payload) - {"principal_id", "enabled", "rationale"}:
                _error(403, "forbidden", "Legacy principal updates cannot change native team or group membership")
            principal_id = payload.get("principal_id")
            if not isinstance(principal_id, str) or principal_id not in configured_principals:
                _error(422, "invalid_command", "principal_id is not configured")
            if type(payload.get("enabled")) is not bool:
                _error(422, "invalid_command", "enabled must be boolean")
            after.setdefault("principals", {}).setdefault(principal_id, {})["enabled"] = payload["enabled"]
            native["revision"] = int(native.get("revision", 0)) + 1
            native.setdefault("revocations", []).append({"principal_id": principal_id,
                "effective_at": now.isoformat().replace("+00:00", "Z"),
                "kind": "account_disabled" if payload["enabled"] is False else "account_enabled",
                "authority_revision": native["revision"]})
            return after
        if "team_id" in payload:
            team_id, display_name = payload["team_id"], payload["display_name"]
            if not isinstance(team_id, str) or not team_id:
                _error(422, "invalid_command", "team_id is required")
            if not isinstance(display_name, str) or not display_name.strip():
                _error(422, "invalid_command", "display_name must be non-empty text")
            directory = after.setdefault("owner_directory", [])
            team = next((entry for entry in directory if entry.get("owner_id") == team_id
                and entry.get("owner_type") == "team"), None)
            if team is None:
                _error(422, "invalid_command", "team_id is not a configured stable team identity")
            old_name = team.get("display_name", team_id)
            if old_name != display_name.strip():
                team.setdefault("label_history", []).append({
                    "previous_display_name": old_name,
                    "display_name": display_name.strip(),
                    "changed_at": now.isoformat().replace("+00:00", "Z"),
                    "changed_by": principal,
                })
                team["display_name"] = display_name.strip()
            return after
        principal_id = payload["principal_id"]
        if not isinstance(principal_id, str) or principal_id not in configured_principals:
            _error(422, "invalid_command", "principal_id is not configured")
        record = dict(after.setdefault("principals", {}).get(principal_id, {}))
        if type(payload["enabled"]) is not bool:
            _error(422, "invalid_command", "enabled must be boolean")
        teams = payload.get("team_ids", record.get("team_ids", []))
        if not isinstance(teams, list) or any(not isinstance(team, str) for team in teams):
            _error(422, "invalid_command", "team_ids must be a string array")
        if len(set(teams)) != len(teams):
            _error(422, "invalid_command", "team_ids must be unique")
        configured_teams = {entry.get("owner_id") for entry in after.get("owner_directory", [])
            if entry.get("owner_type") == "team" and entry.get("enabled", True)}
        if not set(teams) <= configured_teams:
            _error(422, "invalid_command", "team_ids must reference enabled configured teams")
        effective_from = payload.get("effective_from", record.get("effective_from"))
        effective_until = payload.get("effective_until", record.get("effective_until"))
        parsed = []
        for instant in (effective_from, effective_until):
            if instant is None:
                parsed.append(None)
                continue
            if not isinstance(instant, str):
                _error(422, "invalid_command", "Principal effective dates must be UTC RFC 3339")
            try:
                value = datetime.fromisoformat(instant.replace("Z", "+00:00"))
            except ValueError:
                _error(422, "invalid_command", "Principal effective dates must be UTC RFC 3339")
            if value.tzinfo is None or value.utcoffset() != _UTC.utcoffset(value):
                _error(422, "invalid_command", "Principal effective dates must be explicit UTC instants")
            parsed.append(value.astimezone(_UTC))
        if parsed[0] is not None and parsed[1] is not None and parsed[1] <= parsed[0]:
            _error(422, "invalid_command", "Principal effective_until must follow effective_from")
        previous_teams = list(record.get("team_ids", []))
        record.update(enabled=payload["enabled"], team_ids=teams,
            effective_from=effective_from, effective_until=effective_until)
        if previous_teams != teams:
            record.setdefault("team_membership_history", []).append({
                "previous_team_ids": previous_teams,
                "team_ids": list(teams),
                "effective_at": now.isoformat().replace("+00:00", "Z"),
                "changed_by": principal,
            })
        after["principals"][principal_id] = record
    return after


def install_assessment_routes(app: FastAPI) -> None:
    engine = app.state.engine
    principals = app.state.principals
    now_utc = app.state.utc_now

    @app.post("/api/v1/assessment/exception-warning-callback")
    async def receive_exception_warning_callback(request: Request):
        """Verify Slack's untouched body and durably queue the interaction before 200."""
        from pathlib import Path
        from uvm.assessment.exception_warning_callbacks import (
            InvalidSlackCallback, receive_signed_slack_callback,
        )
        timestamp_values = request.headers.getlist("x-slack-request-timestamp")
        signature_values = request.headers.getlist("x-slack-signature")
        if len(timestamp_values) != 1 or len(signature_values) != 1:
            _error(400, "invalid_callback", "Signed callback headers are invalid")
        content_length = request.headers.get("content-length")
        if content_length and (not content_length.isdigit() or int(content_length) > 256 * 1024):
            _error(413, "invalid_callback", "Signed callback body is too large")
        body_buffer = bytearray()
        async for chunk in request.stream():
            if len(body_buffer) + len(chunk) > 256 * 1024:
                _error(413, "invalid_callback", "Signed callback body is too large")
            body_buffer.extend(chunk)
        raw_body = bytes(body_buffer)
        secret_path = os.environ.get("UVM_EXCEPTION_WARNING_SIGNING_SECRET_FILE",
            "/run/uvm-g7-secrets/exception-warning/slack-signing-secret")
        installation_id = os.environ.get("UVM_EXCEPTION_WARNING_INSTALLATION_ID")
        try:
            secret = Path(secret_path).read_text(encoding="utf-8").strip()
        except OSError:
            _error(503, "callback_configuration_unavailable", "Callback signing configuration is unavailable")
        if not installation_id or not secret:
            _error(503, "callback_configuration_unavailable", "Callback installation is unavailable")
        try:
            with engine.begin() as connection:
                from uvm.assessment.policy_lock import lock_policy
                lock_policy(connection)
                result = receive_signed_slack_callback(connection, raw_body=raw_body,
                    timestamp=timestamp_values[0], signature=signature_values[0],
                    signing_secret=secret, installation_id=installation_id, now=now_utc())
        except InvalidSlackCallback:
            _error(401, "invalid_callback", "Signed callback could not be verified")
        except Exception as exc:
            _LOG.exception("warning callback inbox write failed: %s", type(exc).__name__)
            _error(503, "callback_inbox_unavailable", "Callback could not be durably queued")
        return {"schema_version": 1, "received": True, "inbox_id": result["inbox_id"],
            "duplicate": result["duplicate"], "state": result["state"]}

    def authenticate(request: Request, authorization: str | None = Header(default=None)):
        read_stage("authentication_start")
        auth_service = getattr(app.state, "oidc_auth", None)
        if auth_service is not None:
            context = auth_service.resolve_request(request)
            read_stage("authentication_complete")
            return context.principal_id
        if not authorization or not authorization.startswith("Bearer "):
            _error(401, "authentication_required", "Authentication required")
        supplied = authorization[7:]
        for name, principal in principals.items():
            token = principal.get("token", "")
            if supplied.isascii() and len(supplied) <= 512 and hmac.compare_digest(supplied, token):
                read_stage("authentication_complete")
                return name
        _error(401, "authentication_required", "Authentication required")

    def _warning_admin_grants(connection, policy, principal, action, group_ids,
                               request, correlation_id):
        if not group_ids or len(set(group_ids)) != len(group_ids):
            _error(422, "invalid_command", "At least one unique affected group is required")
        auth_service = getattr(app.state, "oidc_auth", None)
        context = auth_service.final_context(connection, request) if auth_service else None
        result = []
        authority_token = AUTHORITY_CONTEXT.set(context) if context is not None else None
        from uvm.auth.service import group_scope_covered
        try:
            for group_id in group_ids:
                group = connection.execute(sa.select(groups).where(
                    groups.c.group_id == group_id)).mappings().one_or_none()
                if group is None:
                    _error(404, "invalid_command", "Target not found")
                grants = _complete_target_grants(connection, policy, principal, action,
                    group_id, group["source_family"])
                if not grants or (context is not None and not group_scope_covered(connection,
                        context, [group_id], granting_identity_groups=[
                            grant.get("principal_id") for grant in grants])):
                    _error(403, "source_scope_forbidden", "Current complete target authority is required")
                result.extend(grants)
        finally:
            if authority_token is not None:
                AUTHORITY_CONTEXT.reset(authority_token)
        return context, result

    def _warning_route_scope_allowed(policy, binding):
        """Bound routing administration by the active bootstrap grant ceiling."""
        native = native_state(policy)
        if native.get("mode") != NATIVE_MODE:
            return True
        scope = native.get("grantable_envelope", {}).get("warning_route_scope")
        if not isinstance(scope, dict):
            return False
        dimensions = {
            "installation_id": "installation_ids", "workspace_id": "workspace_ids",
            "channel_id": "channel_ids", "destination_ref": "destination_refs",
            "recipient_id": "recipient_ids", "channel": "channels",
        }
        for field, allowed_field in dimensions.items():
            allowed = scope.get(allowed_field)
            if not isinstance(allowed, list) or binding.get(field) not in allowed:
                return False
        allowed_groups = scope.get("access_group_ids")
        if (not isinstance(allowed_groups, list)
                or not set(binding.get("access_group_ids", [])) <= set(allowed_groups)):
            return False
        allowed_alert_groups = scope.get("failure_alert_group_ids")
        if (not isinstance(allowed_alert_groups, list)
                or not set(binding.get("failure_alert_group_ids", [])) <= set(allowed_alert_groups)):
            return False
        allowed_findings = scope.get("finding_group_ids")
        if allowed_findings is not None and (not isinstance(allowed_findings, list)
                or not set(binding.get("finding_group_ids", [])) <= set(allowed_findings)):
            return False
        return True

    def _warning_admin_audit(connection, *, principal, actor_kind, action, object_id,
                             before, after, policy_revision, context, now):
        command_id = str(uuid.uuid4())
        sequence = connection.execute(sa.select(sa.func.coalesce(
            sa.func.max(assessment_audit_events.c.event_sequence), 0) + 1)).scalar_one()
        event_id = str(uuid.uuid4())
        connection.execute(assessment_audit_events.insert().values(
            event_id=event_id, event_sequence=sequence, actor_id=principal,
            actor_kind=actor_kind, origin="authenticated_warning_administration",
            action=action, target_id=object_id, before_value=before, after_value=after,
            membership_ids=[], membership_revision=0, rationale="Versioned warning configuration",
            evidence_ref="local_audit:warning_configuration", policy_revision=policy_revision,
            identity_revision=0, occurred_at=now, received_at=now,
            correlation_id=command_id, command_id=command_id,
            authorization_context=context.document() if context else None))
        return event_id, command_id

    @app.post("/api/v1/assessment/exception-warning-routes")
    def administer_exception_warning_route(body: dict, request: Request,
                                           principal: str = Depends(authenticate)):
        """Create, revise or revoke a bounded warning route under native authority."""
        now = now_utc()
        try:
            route_id = str(uuid.UUID(body.get("route_id", "")))
            recipient_group_ids = [str(uuid.UUID(value)) for value in body.get("access_group_ids", [])]
            target_group_ids = [str(uuid.UUID(value)) for value in body.get(
                "finding_group_ids", body.get("access_group_ids", []))]
        except (ValueError, TypeError, AttributeError):
            _error(422, "invalid_command", "Warning route identifiers are invalid")
        if (body.get("channel") not in {"slack", "email"}
                or not all(isinstance(body.get(key), str) and body[key] for key in
                    ("installation_id", "workspace_id", "channel_id", "recipient_id", "destination_ref"))
                or not isinstance(body.get("offset_seconds"), list)
                or not body["offset_seconds"] or any(type(value) is not int or not 60 <= value <= 2592000
                    for value in body["offset_seconds"])
                or type(body.get("enabled")) is not bool
                or type(body.get("expected_policy_revision")) is not int
                or body.get("expected_route_revision") is not None
                    and type(body.get("expected_route_revision")) is not int):
            _error(422, "invalid_command", "Warning route configuration is invalid")
        alert_groups = body.get("failure_alert_group_ids", recipient_group_ids)
        try:
            alert_groups = [str(uuid.UUID(value)) for value in alert_groups]
        except (ValueError, TypeError, AttributeError):
            _error(422, "invalid_command", "Warning alert groups are invalid")
        usergroups = body.get("usergroup_ids", [])
        if not isinstance(usergroups, list) or any(not isinstance(value, str)
                or not re.fullmatch(r"S[A-Z0-9]{2,30}", value) for value in usergroups):
            _error(422, "invalid_command", "Slack mention groups are invalid")
        uvm_link = body.get("link")
        email_recipient = body.get("email_recipient")
        if uvm_link is not None and (not isinstance(uvm_link, str) or len(uvm_link) > 2048
                or not re.fullmatch(r"https://[^\s<>\"']+", uvm_link)):
            _error(422, "invalid_command", "Warning link must be an approved HTTPS URL")
        if email_recipient is not None and (not isinstance(email_recipient, str)
                or len(email_recipient) > 320 or not re.fullmatch(r"[^\s@]+@[^\s@]+", email_recipient)):
            _error(422, "invalid_command", "Warning email recipient is invalid")
        with engine.begin() as connection:
            lock_policy(connection)
            policy_row = connection.execute(sa.select(assessment_policy).where(
                assessment_policy.c.policy_id == 1).with_for_update()).mappings().one_or_none()
            if policy_row is None:
                _error(503, "persistence_unavailable", "Assessment policy is unavailable")
            if int(policy_row["revision"]) != body["expected_policy_revision"]:
                _error(409, "stale_revision", "Policy revision changed")
            policy = policy_row["document"]
            if native_state(policy).get("mode") == NATIVE_MODE and not body.get("finding_group_ids"):
                _error(422, "invalid_command", "Native warning routes require explicit finding groups")
            if native_state(policy).get("mode") == NATIVE_MODE:
                known_groups = native_state(policy).get("access_groups", {})
                if any(group_id not in known_groups for group_id in alert_groups):
                    _error(422, "invalid_command", "Failure alert groups must be current native access groups")
            context, grants = _warning_admin_grants(connection, policy, principal,
                "warning.route.manage", target_group_ids, request, str(uuid.uuid4()))
            latest = connection.execute(sa.select(sa.func.max(exception_warning_routes.c.revision)).where(
                exception_warning_routes.c.route_id == route_id)).scalar_one_or_none() or 0
            if body.get("expected_route_revision") != (latest or None):
                _error(409, "stale_revision", "Warning route revision changed")
            proposed_scope = {"channel": body["channel"],
                "installation_id": body["installation_id"], "workspace_id": body["workspace_id"],
                "channel_id": body["channel_id"], "destination_ref": body["destination_ref"],
                "recipient_id": body["recipient_id"], "access_group_ids": recipient_group_ids,
                "failure_alert_group_ids": alert_groups,
                "finding_group_ids": target_group_ids}
            if not _warning_route_scope_allowed(policy, proposed_scope):
                _error(403, "source_scope_forbidden", "Route is outside the current warning administration envelope")
            if latest:
                retained_route = connection.execute(sa.select(exception_warning_routes).where(
                    exception_warning_routes.c.route_id == route_id,
                    exception_warning_routes.c.revision == latest).with_for_update()).mappings().one()
                prior_config = retained_route["configuration"]
                prior_scope = {"channel": prior_config.get("channel"),
                    "installation_id": retained_route["installation_id"],
                    "workspace_id": retained_route["workspace_id"],
                    "channel_id": retained_route["channel_id"],
                    "destination_ref": retained_route["destination_ref"],
                    "recipient_id": retained_route["recipient_id"],
                    "access_group_ids": retained_route["access_group_ids"],
                    "failure_alert_group_ids": prior_config.get("failure_alert_group_ids", []),
                    "finding_group_ids": sorted(set(prior_config.get("finding_group_ids", []))
                        | {item.get("group_id") for item in
                            policy.get("exception_warning_routes", [])
                            if item.get("route_id") == route_id and item.get("group_id")})}
                if not _warning_route_scope_allowed(policy, prior_scope):
                    _error(403, "source_scope_forbidden", "Existing route is outside the current warning administration envelope")
                old_targets = prior_scope["finding_group_ids"]
                if native_state(policy).get("mode") == NATIVE_MODE:
                    if not old_targets:
                        _error(403, "source_scope_forbidden", "Existing route finding scope is unavailable")
                    _warning_admin_grants(connection, policy, principal,
                        "warning.route.manage", old_targets, request, str(uuid.uuid4()))
            revision = int(latest) + 1
            config = {"offset_seconds": sorted(set(body["offset_seconds"])),
                "failure_alert_group_ids": sorted(set(alert_groups)),
                "finding_group_ids": sorted(set(target_group_ids)),
                "usergroup_ids": usergroups, "channel": body["channel"],
                "link": uvm_link, "email_recipient": email_recipient}
            connection.execute(exception_warning_routes.insert().values(
                route_id=route_id, revision=revision,
                installation_id=body["installation_id"], workspace_id=body["workspace_id"],
                channel_id=body["channel_id"], recipient_id=body["recipient_id"],
                destination_ref=body["destination_ref"], access_group_ids=recipient_group_ids,
                configuration=config, enabled=body["enabled"], created_at=now, updated_at=now))
            routes = [item for item in policy.get("exception_warning_routes", [])
                if item.get("route_id") != route_id]
            if body["enabled"]:
                for group_id in target_group_ids:
                    routes.append({"route_id": route_id, "revision": revision,
                        "destination_revision": revision,
                        "group_id": group_id, "channel": body["channel"],
                        "destination_ref": body["destination_ref"],
                        "recipient_id": body["recipient_id"],
                        "offset_seconds": config["offset_seconds"],
                        "installation_id": body["installation_id"],
                        "workspace_id": body["workspace_id"], "channel_id": body["channel_id"],
                        "usergroup_ids": usergroups, "link": uvm_link,
                        "email_recipient": email_recipient, "failure_alert_group_ids": config[
                            "failure_alert_group_ids"]})
            updated_policy = {**policy, "exception_warning_routes": routes,
                "revision": int(policy.get("revision", policy_row["revision"])) + 1}
            next_policy_revision = int(policy_row["revision"]) + 1
            connection.execute(assessment_policy.update().where(
                assessment_policy.c.policy_id == 1).values(
                    revision=next_policy_revision, document=updated_policy, updated_at=now))
            event_id, command_id = _warning_admin_audit(connection, principal=principal,
                actor_kind=principals.get(principal, {}).get("actor_kind", "principal"),
                action="warning.route.manage", object_id=route_id,
                before={"revision": latest or None}, after={"revision": revision,
                    "enabled": body["enabled"], "access_group_ids": recipient_group_ids,
                    "finding_group_ids": target_group_ids},
                policy_revision=next_policy_revision, context=context, now=now)
            result = {"schema_version": 1, "route_id": route_id, "revision": revision,
                "policy_revision": next_policy_revision, "audit": "committed"}
            connection.execute(assessment_command_receipts.insert().values(
                command_id=command_id, principal_id=principal, action="warning.route.manage",
                target_id=route_id, request_digest=hashlib.sha256(json.dumps(body,
                    sort_keys=True, separators=(",", ":")).encode()).hexdigest(),
                decision_id=str(uuid.uuid4()), audit_event_id=event_id, intent_id=None,
                result=result, created_at=now,
                authorization_context=context.document() if context else None))
        return result

    @app.post("/api/v1/assessment/exception-warning-actor-links")
    def administer_exception_warning_actor_link(body: dict, request: Request,
                                                 principal: str = Depends(authenticate)):
        """Version an explicit Slack user to UVM principal binding."""
        now = now_utc()
        try:
            group_ids = [str(uuid.UUID(value)) for value in body.get("access_group_ids", [])]
            target_group_ids = [str(uuid.UUID(value)) for value in body.get(
                "finding_group_ids", body.get("access_group_ids", []))]
        except (ValueError, TypeError, AttributeError):
            _error(422, "invalid_command", "Warning actor-link groups are invalid")
        if (not all(isinstance(body.get(key), str) and body[key] for key in
                ("installation_id", "workspace_id", "slack_user_id", "principal_id"))
                or type(body.get("expected_policy_revision")) is not int
                or type(body.get("expected_link_revision")) is not int
                or type(body.get("enabled")) is not bool):
            _error(422, "invalid_command", "Warning actor link is invalid")
        with engine.begin() as connection:
            lock_policy(connection)
            policy_row = connection.execute(sa.select(assessment_policy).where(
                assessment_policy.c.policy_id == 1).with_for_update()).mappings().one_or_none()
            if policy_row is None or int(policy_row["revision"]) != body["expected_policy_revision"]:
                _error(409, "stale_revision", "Policy revision changed")
            policy = policy_row["document"]
            if native_state(policy).get("mode") == NATIVE_MODE and not body.get("finding_group_ids"):
                _error(422, "invalid_command", "Native warning actor links require explicit finding groups")
            context, _grants = _warning_admin_grants(connection, policy, principal,
                "warning.actor_link.manage", target_group_ids, request, str(uuid.uuid4()))
            latest = connection.execute(sa.select(sa.func.max(exception_warning_actor_links.c.revision)).where(
                exception_warning_actor_links.c.installation_id == body["installation_id"],
                exception_warning_actor_links.c.workspace_id == body["workspace_id"],
                exception_warning_actor_links.c.slack_user_id == body["slack_user_id"])).scalar_one_or_none() or 0
            if int(latest) != body["expected_link_revision"]:
                _error(409, "stale_revision", "Warning actor-link revision changed")
            native = native_state(policy)
            if native.get("mode") == NATIVE_MODE:
                scope = native.get("grantable_envelope", {}).get("warning_route_scope", {})
                allowed_installations = scope.get("installation_ids", [])
                allowed_workspaces = scope.get("workspace_ids", [])
                allowed_principals = scope.get("recipient_ids", [])
                allowed_groups = scope.get("access_group_ids", [])
                if (body["installation_id"] not in allowed_installations
                        or body["workspace_id"] not in allowed_workspaces
                        or body["principal_id"] not in allowed_principals
                        or not set(group_ids) <= set(allowed_groups)):
                    _error(403, "source_scope_forbidden", "Actor link is outside the current warning administration envelope")
                if latest:
                    old_link = connection.execute(sa.select(exception_warning_actor_links).where(
                        exception_warning_actor_links.c.installation_id == body["installation_id"],
                        exception_warning_actor_links.c.workspace_id == body["workspace_id"],
                        exception_warning_actor_links.c.slack_user_id == body["slack_user_id"],
                        exception_warning_actor_links.c.revision == latest).with_for_update()).mappings().one()
                    if old_link["principal_id"] not in allowed_principals:
                        _error(403, "source_scope_forbidden", "Rebinding is outside the current warning administration envelope")
            identity = policy.get("principals", {}).get(body["principal_id"])
            if body["enabled"] and (not isinstance(identity, dict)
                    or identity.get("actor_kind") != "principal" or identity.get("enabled") is False):
                _error(422, "invalid_command", "Slack links require a configured human UVM principal")
            revision, link_id = int(latest) + 1, str(uuid.uuid4())
            connection.execute(exception_warning_actor_links.insert().values(
                link_id=link_id, installation_id=body["installation_id"],
                workspace_id=body["workspace_id"], slack_user_id=body["slack_user_id"],
                principal_id=body["principal_id"], revision=revision,
                enabled=body["enabled"], created_at=now, updated_at=now))
            next_policy_revision = int(policy_row["revision"]) + 1
            connection.execute(assessment_policy.update().where(
                assessment_policy.c.policy_id == 1).values(
                    revision=next_policy_revision,
                    document={**policy, "revision": int(policy.get("revision", policy_row["revision"])) + 1},
                    updated_at=now))
            event_id, command_id = _warning_admin_audit(connection, principal=principal,
                actor_kind=principals.get(principal, {}).get("actor_kind", "principal"),
                action="warning.actor_link.manage", object_id=link_id,
                before={"revision": latest or None}, after={"revision": revision,
                    "installation_id": body["installation_id"],
                    "workspace_id": body["workspace_id"], "slack_user_id": body["slack_user_id"],
                    "principal_id": body["principal_id"], "enabled": body["enabled"]},
                policy_revision=next_policy_revision, context=context, now=now)
            result = {"schema_version": 1, "link_id": link_id, "revision": revision,
                "policy_revision": next_policy_revision, "audit": "committed"}
            connection.execute(assessment_command_receipts.insert().values(
                command_id=command_id, principal_id=principal, action="warning.actor_link.manage",
                target_id=link_id, request_digest=hashlib.sha256(json.dumps(body,
                    sort_keys=True, separators=(",", ":")).encode()).hexdigest(),
                decision_id=str(uuid.uuid4()), audit_event_id=event_id, intent_id=None,
                result=result, created_at=now,
                authorization_context=context.document() if context else None))
        return result

    @app.post("/api/v1/assessment/bootstrap-policy")
    def bootstrap_policy(body: dict, principal: str = Depends(authenticate)):
        """Install first fixture policy only through its explicitly configured bootstrap identity."""
        if principal != app.state.assessment_bootstrap_principal:
            _error(403, "forbidden", "Access forbidden")
        document = body.get("policy")
        if not isinstance(document, dict) or not isinstance(document.get("grants"), list) or not isinstance(document.get("denies", []), list):
            _error(422, "invalid_command", "Policy document is invalid")
        material = document.get("acceptance_material_changes", {})
        routes = document.get("exception_warning_routes", [])
        if (not isinstance(material, dict) or set(material) - {"severity_increase", "accountable_owner_removed"}
                or any(type(value) is not bool for value in material.values())
                or not isinstance(routes, list)):
            _error(422, "invalid_command", "Exception material-change and warning configuration is invalid")
        for route in routes:
            route_required = {"group_id", "channel", "destination_ref", "recipient_id", "offset_seconds"}
            route_optional = {"max_attempts", "retry_base_seconds", "failure_alert_group_ids"}
            if (not isinstance(route, dict) or not route_required <= set(route)
                    or set(route) - route_required - route_optional
                    or route["channel"] not in {"slack", "email"}
                    or any(not isinstance(route[key], str) or not route[key] for key in ("group_id", "destination_ref", "recipient_id"))
                    or not isinstance(route["offset_seconds"], list) or not route["offset_seconds"]
                    or any(type(offset) is not int or offset < 0 for offset in route["offset_seconds"])
                    or ("max_attempts" in route and (type(route["max_attempts"]) is not int
                        or not 1 <= route["max_attempts"] <= 20))
                    or ("retry_base_seconds" in route and (type(route["retry_base_seconds"]) is not int
                        or not 1 <= route["retry_base_seconds"] <= 3600))
                    or ("failure_alert_group_ids" in route and (
                        not isinstance(route["failure_alert_group_ids"], list)
                        or len(route["failure_alert_group_ids"]) > 20
                        or any(not isinstance(value, str) or not value for value in
                            route["failure_alert_group_ids"])) )):
                _error(422, "invalid_command", "Exception warning route is invalid")
        for denial in document.get("denies", []):
            if (not isinstance(denial, dict) or not isinstance(denial.get("deny_id"), str)
                    or not denial["deny_id"].strip()
                    or not isinstance(denial.get("principal_id"), str)
                    or not isinstance(denial.get("actions"), list)
                    or not isinstance(denial.get("target_ids"), list)):
                _error(422, "invalid_command", "Policy denial must include its stable deny_id and scope")
        document = json.loads(json.dumps(document))
        _validate_routing_rules(document)
        document.setdefault("routing_rules", [])
        roles = document.setdefault("roles", {})
        canonical_grants = []
        limit_defaults = {"maximum_acceptance_days": None, "maximum_severity": None,
            "whole_group_confirmation": False, "allowed_environments": [], "allowed_service_ids": [],
            "allowed_sla_clock_bases": [], "allowed_sla_severities": [],
            "allowed_sla_start_sources": [],
            "maximum_sla_duration_seconds": None, "allow_sla_backfill": False,
            "maximum_deadline_extension_seconds": None}
        duty_defaults = {"approval_requires_distinct_actor": True,
            "prohibit_requester_approval": True, "required_approver_count": 1,
            "prohibited_action_pairs": []}
        for grant in document["grants"]:
            if not all(isinstance(grant.get(key), list) for key in ("actions", "target_ids")) or not isinstance(grant.get("principal_id"), str):
                _error(422, "invalid_command", "Policy grant is invalid")
            # Bootstrap accepts the original inline grant fixture for migration
            # compatibility, then persists it as an explicit role assignment.
            # Consumers always receive stable IDs and complete evaluated policy.
            grant_id = grant.get("grant_id")
            role_id = grant.get("role_id")
            if not isinstance(grant_id, str) or not grant_id:
                grant_id = f"bootstrap-grant-{uuid.uuid4()}"
            if not isinstance(role_id, str) or not role_id:
                role_id = f"bootstrap-role-{uuid.uuid4()}"
                supplied_scope = grant.get("target_scope")
                scope = supplied_scope if isinstance(supplied_scope, dict) else {
                    "group_ids": list(grant["target_ids"]), "source_families": [],
                    "environments": [], "service_ids": [], "membership_mode": "explicit"}
                if set(scope) != _SCOPE_KEYS:
                    _error(422, "invalid_command", "Policy grant target scope is invalid")
                limits = dict(limit_defaults)
                if isinstance(grant.get("limits"), dict):
                    limits.update(grant["limits"])
                duties = dict(duty_defaults)
                if isinstance(grant.get("separation_of_duties"), dict):
                    duties.update(grant["separation_of_duties"])
                roles[role_id] = {"role_id": role_id, "revision": 1,
                    "actions": list(grant["actions"]), "target_scope": scope,
                    "limits": limits, "separation_of_duties": duties,
                    "description": grant.get("description", "")}
            elif role_id not in roles:
                _error(422, "invalid_command", "Policy grant references an unknown role")
            canonical_grants.append({"grant_id": grant_id, "role_id": role_id,
                "principal_id": grant["principal_id"],
                "effective_from": grant.get("effective_from"),
                "effective_until": grant.get("effective_until")})
        document["grants"] = canonical_grants
        configured_bootstrap_admins = sorted({item.strip() for item in
            os.getenv("UVM_NATIVE_BOOTSTRAP_PRINCIPALS", "").split(",") if item.strip()})
        try:
            grantable_envelope = json.loads(os.getenv("UVM_NATIVE_GRANTABLE_ENVELOPE", "{}") or "{}")
        except json.JSONDecodeError:
            _error(503, "configuration_invalid", "Native grantable envelope configuration is invalid")
        if not isinstance(grantable_envelope, dict):
            _error(503, "configuration_invalid", "Native grantable envelope configuration is invalid")
        document["native_authority"] = {"mode": "legacy", "revision": 0,
            "ownership_revision": 0, "mapping_revision": 0,
            "bootstrap_admins": configured_bootstrap_admins,
            "grantable_envelope": grantable_envelope, "access_groups": {},
            "ownership_teams": {}, "revocations": []}
        now = now_utc()
        with engine.begin() as connection:
            lock_policy(connection)
            row = connection.execute(sa.select(assessment_policy).where(
                assessment_policy.c.policy_id == 1).with_for_update()).mappings().first()
            if row is not None:
                _error(409, "revision_conflict", "Initial policy already exists")
            connection.execute(assessment_policy.insert().values(policy_id=1, revision=1,
                document=document, updated_at=now, updated_by=principal))
        return {"schema_version": 1, "policy_revision": 1, "status": "installed"}

    def administration_history(connection, object_kind: str, object_id: str):
        rows = connection.execute(sa.select(assessment_audit_events).where(
            assessment_audit_events.c.action.in_(NATIVE_ACTIONS)
            ).order_by(assessment_audit_events.c.event_sequence)).mappings().all()
        history = []
        key = "access_groups" if object_kind == "access_group" else "ownership_teams"
        id_key = "access_group_id" if object_kind == "access_group" else "team_id"
        for row in rows:
            before = (row["before_value"] or {}).get("native_authority", {})
            after = (row["after_value"] or {}).get("native_authority", {})
            old_item = before.get(key, {}).get(object_id)
            new_item = after.get(key, {}).get(object_id)
            if old_item == new_item:
                continue
            history.append({"event_id": row["event_id"], "action": row["action"],
                "actor_id": row["actor_id"], "occurred_at": row["occurred_at"].isoformat().replace("+00:00", "Z"),
                "rationale": row["rationale"], "before_value": copy.deepcopy(old_item),
                "after_value": copy.deepcopy(new_item)})
        return history

    @app.get("/api/v1/assessment/administration/catalogue")
    def administration_catalogue(principal: str = Depends(authenticate)):
        with engine.connect() as connection:
            row = connection.execute(sa.select(assessment_policy).where(
                assessment_policy.c.policy_id == 1)).mappings().first()
            if row is None:
                _error(503, "persistence_unavailable", "Assessment policy is not configured")
            policy = row["document"]
            state = native_state(policy)
            bootstrap = principal in set(state.get("bootstrap_admins", []))
            group_admin = bootstrap or _matches(policy, principal, "access_group.read", _ZERO_ID, None)
            team_admin = bootstrap or (state.get("mode") == NATIVE_MODE and any(
                _matches(policy, principal, "ownership.team.manage", team_id, None)
                for team_id in state.get("ownership_teams", {})))
            envelope = state.get("grantable_envelope", {}) if bootstrap else {}
            allowed_actions = set(envelope.get("actions", []))
            selectable = []
            for action in _ACTIONS:
                if action in {"policy.role.create", "policy.role.assign", "policy.role.update",
                        "principal.update"}:
                    continue
                if "*" not in allowed_actions and action not in allowed_actions:
                    continue
                item = {"action": action,
                    "target_scope": copy.deepcopy(envelope.get("target_scope", _EMPTY_SCOPE)),
                    "limits": copy.deepcopy(envelope.get("limits", _LIMIT_DEFAULTS))}
                if action in {"observer.timing.read", "observer.timing.configure"}:
                    item["deployment_scopes"] = copy.deepcopy(envelope.get("deployment_scopes", []))
                selectable.append(item)
            return {"schema_version": 1, "authority_mode": state.get("mode", "legacy"),
                "policy_revision": row["revision"], "authority_revision": state.get("revision", 0),
                "ownership_revision": state.get("ownership_revision", 0),
                "selectable_actions": selectable,
                "caller": {"principal_id": principal, "can_manage_access_groups": group_admin,
                    "can_manage_ownership_teams": team_admin, "grantable": envelope}}

    @app.get("/api/v1/assessment/access-groups")
    def read_access_groups(principal: str = Depends(authenticate)):
        with engine.connect() as connection:
            row = connection.execute(sa.select(assessment_policy).where(
                assessment_policy.c.policy_id == 1)).mappings().first()
            if row is None:
                _error(503, "persistence_unavailable", "Assessment policy is not configured")
            policy, state = row["document"], native_state(row["document"])
            bootstrap = principal in set(state.get("bootstrap_admins", []))
            context = AUTHORITY_CONTEXT.get()
            items = []
            for group_id, group in sorted(state.get("access_groups", {}).items()):
                scoped = bootstrap or _matches(policy, principal, "access_group.read", group_id, None)
                if not scoped:
                    continue
                items.append({"access_group_id": group_id, "display_name": group["display_name"],
                    "description": group.get("description", ""), "enabled": group.get("enabled", True),
                    "revision": group["revision"], "source_scopes": copy.deepcopy(group.get("source_scopes", [])),
                    "permissions": copy.deepcopy(group.get("permissions", [])),
                    "memberships": copy.deepcopy(group.get("memberships", [])),
                    "history": administration_history(connection, "access_group", group_id)})
            if not bootstrap and not items and not any(_matches(policy, principal,
                    "ownership.team.manage", team_id, None)
                    for team_id in state.get("ownership_teams", {})):
                _error(403, "forbidden", "Current access-group read scope is required")
            configured = [{"principal_id": item["principal_id"],
                "display_name": item["display_label"], "enabled": item["enabled"],
                "actor_kind": "principal", "membership_eligibility": {
                    "access_group": item["enabled"], "ownership_team": item["enabled"],
                    "reason": None if item["enabled"] else "principal_disabled"}}
                for item in connection.execute(
                    sa.select(auth_principals.c.principal_id, auth_principals.c.display_label,
                        auth_principals.c.enabled).order_by(auth_principals.c.principal_id)
                ).mappings().all()]
            return {"schema_version": 1, "authority_mode": state.get("mode", "legacy"),
                "policy_revision": row["revision"], "authority_revision": state.get("revision", 0),
                "principals": configured, "items": items}

    @app.get("/api/v1/assessment/access-groups/{access_group_id}/deletion-impact")
    def access_group_deletion_impact(access_group_id: str, principal: str = Depends(authenticate)):
        access_group_id = _uuid(access_group_id, "access_group_id")
        with engine.connect() as connection:
            row = connection.execute(sa.select(assessment_policy).where(
                assessment_policy.c.policy_id == 1)).mappings().first()
            if row is None:
                _error(503, "persistence_unavailable", "Assessment policy is not configured")
            policy, state = row["document"], native_state(row["document"])
            group = state.get("access_groups", {}).get(access_group_id)
            if group is None:
                _error(404, "not_found", "Access group does not exist")
            context = AUTHORITY_CONTEXT.get()
            readable = (principal in set(state.get("bootstrap_admins", [])) or
                _matches(policy, principal, "access_group.read", access_group_id, None))
            if not readable:
                _error(403, "forbidden", "Current access-group read scope is required")
            from uvm.auth.native_authority import effective_access
            now = now_utc()
            principals_now = sorted({item.get("principal_id") for item in
                group.get("memberships", []) if isinstance(item, dict) and item.get("principal_id")})
            active, remaining = [], {}
            for member in principals_now:
                resolved = effective_access(policy, member, now)
                groups_now = list(resolved[0] if resolved is not None else ())
                if access_group_id not in groups_now:
                    continue
                membership = next((item for item in reversed(group.get("memberships", []))
                    if item.get("principal_id") == member and item.get("enabled") is True
                    and item.get("effective_from") and datetime.fromisoformat(
                        item["effective_from"].replace("Z", "+00:00")) <= now
                    and (not item.get("effective_until") or datetime.fromisoformat(
                        item["effective_until"].replace("Z", "+00:00")) > now)), None)
                if membership is None:
                    continue
                active.append({"principal_id": member,
                    "effective_from": membership["effective_from"],
                    "effective_until": membership.get("effective_until")})
                remaining[member] = [value for value in groups_now if value != access_group_id]
            withdrawn = sorted({item.get("action") for item in group.get("permissions", [])
                if isinstance(item, dict) and isinstance(item.get("action"), str)})
            return {"schema_version": 1, "access_group_id": access_group_id,
                "group_revision": group["revision"], "policy_revision": row["revision"],
                "authority_revision": state.get("revision", 0), "enabled": group.get("enabled", True),
                "active_memberships": active, "permission_count": len(group.get("permissions", [])),
                "affected_principals": [item["principal_id"] for item in active],
                "remaining_access_groups_by_principal": remaining,
                "withdrawn_actions": withdrawn,
                "expected_intent": {"kind": "administration.authority.reconcile", "status": "pending"}}

    @app.get("/api/v1/assessment/administration/intents/{intent_id}")
    def read_administration_intent(intent_id: str, principal: str = Depends(authenticate)):
        intent_id = _uuid(intent_id, "intent_id")
        with engine.connect() as connection:
            row = connection.execute(sa.select(administration_reconciliation_intents).where(
                administration_reconciliation_intents.c.intent_id == intent_id)).mappings().first()
            if row is None:
                _error(404, "not_found", "Administration intent does not exist")
            policy_row = connection.execute(sa.select(assessment_policy).where(
                assessment_policy.c.policy_id == 1)).mappings().first()
            if policy_row is None:
                _error(503, "persistence_unavailable", "Assessment policy is not configured")
            policy, state = policy_row["document"], native_state(policy_row["document"])
            bootstrap = principal in set(state.get("bootstrap_admins", []))
            if row["kind"] == "administration.authority.reconcile":
                permitted = bootstrap or (row["target_id"] != _ZERO_ID and _matches(
                    policy, principal, "access_group.read", row["target_id"], None))
            else:
                permitted = bootstrap or _matches(policy, principal, "ownership.team.read",
                    row["target_id"], None) or _matches(policy, principal,
                        "ownership.team.manage", row["target_id"], None)
            if not permitted:
                _error(403, "forbidden", "Current administration intent read scope is required")
            return {"schema_version": 1, "intent_id": row["intent_id"], "kind": row["kind"],
                "target_id": row["target_id"], "authority_revision": row["authority_revision"],
                "status": row["status"], "attempts": row["attempts"],
                "last_error": "reconciliation_failed" if row["last_error"] else None,
                "next_attempt_at": row["next_attempt_at"].astimezone(_UTC).isoformat().replace("+00:00", "Z")
                    if row["next_attempt_at"] else None,
                "completed_at": row["completed_at"].astimezone(_UTC).isoformat().replace("+00:00", "Z")
                    if row["completed_at"] else None,
                "result": row["result"],
                "created_at": row["created_at"].astimezone(_UTC).isoformat().replace("+00:00", "Z"),
                "updated_at": row["updated_at"].astimezone(_UTC).isoformat().replace("+00:00", "Z")}

    @app.get("/api/v1/assessment/ownership-teams")
    def read_ownership_teams(principal: str = Depends(authenticate)):
        with engine.connect() as connection:
            row = connection.execute(sa.select(assessment_policy).where(
                assessment_policy.c.policy_id == 1)).mappings().first()
            if row is None:
                _error(503, "persistence_unavailable", "Assessment policy is not configured")
            policy, state = row["document"], native_state(row["document"])
            bootstrap = principal in set(state.get("bootstrap_admins", []))
            items = []
            for team_id, team in sorted(state.get("ownership_teams", {}).items()):
                if not bootstrap and not (_matches(policy, principal, "ownership.team.read", team_id, None)
                        or _matches(policy, principal, "ownership.team.manage", team_id, None)):
                    continue
                items.append({"team_id": team_id, "display_name": team["display_name"],
                    "enabled": team.get("enabled", True), "revision": team["revision"],
                    "memberships": copy.deepcopy(team.get("memberships", [])),
                    "history": administration_history(connection, "ownership_team", team_id)})
            if not bootstrap and not items:
                _error(403, "forbidden", "Current ownership-team read scope is required")
            return {"schema_version": 1, "policy_revision": row["revision"],
                "ownership_revision": state.get("ownership_revision", 0), "items": items}

    @app.get("/api/v1/assessment/ownership-teams/{team_id}/principals")
    def read_ownership_team_principals(team_id: str, principal: str = Depends(authenticate)):
        team_id = _uuid(team_id, "team_id")
        with engine.connect() as connection:
            row = connection.execute(sa.select(assessment_policy).where(
                assessment_policy.c.policy_id == 1)).mappings().first()
            if row is None:
                _error(503, "persistence_unavailable", "Assessment policy is not configured")
            policy, state = row["document"], native_state(row["document"])
            team = state.get("ownership_teams", {}).get(team_id)
            if team is None:
                _error(404, "not_found", "Ownership team does not exist")
            bootstrap = principal in set(state.get("bootstrap_admins", []))
            if not bootstrap and not (_matches(policy, principal, "ownership.team.manage", team_id, None)
                    or _matches(policy, principal, "ownership.team.read", team_id, None)):
                _error(403, "forbidden", "Current ownership-team membership read scope is required")
            principals = [{"principal_id": item["principal_id"],
                "display_name": item["display_label"], "enabled": item["enabled"],
                "membership_eligibility": {"ownership_team": item["enabled"],
                    "reason": None if item["enabled"] else "principal_disabled"}}
                for item in connection.execute(sa.select(auth_principals.c.principal_id,
                    auth_principals.c.display_label, auth_principals.c.enabled).order_by(
                        auth_principals.c.principal_id)).mappings().all()]
            return {"schema_version": 1, "team_id": team_id,
                "policy_revision": row["revision"],
                "ownership_revision": state.get("ownership_revision", 0),
                "principals": principals}

    @app.post("/api/v1/assessment/commands")
    def submit_command(body: dict, request: Request, principal: str = Depends(authenticate)):
        command_id = _uuid(body.get("command_id"), "command_id")
        target_id = _uuid(body.get("target_id"), "target_id")
        action = body.get("action")
        membership_ids = body.get("membership_ids")
        expected = body.get("expected_revisions")
        payload = body.get("payload")
        if (not isinstance(action, str) or not isinstance(membership_ids, list)
                or len(set(membership_ids)) != len(membership_ids)
                or not isinstance(expected, dict) or not isinstance(payload, dict)):
            _error(422, "invalid_command", "Command envelope is invalid")
        for membership_id in membership_ids:
            _uuid(membership_id, "membership_ids item")
        if action in _CONNECTOR_COMMAND_ACTIONS:
            from uvm.connectors.api import execute_connector_command
            try:
                return execute_connector_command(app, body, request, principal)
            except sa.exc.DBAPIError as exc:
                sqlstate = getattr(getattr(exc, "orig", None), "sqlstate", None)
                if exc.connection_invalidated or not sqlstate:
                    outcome = "unknown"
                    code = "outcome_unknown"
                    message = "Connector command commit outcome could not be confirmed"
                else:
                    # The connector writer uses one transaction for state,
                    # audit, receipt and intent. A server-reported statement
                    # error means that transaction rolled back atomically.
                    outcome = "not_committed"
                    code = "dependency_unavailable"
                    message = "Connector command was rolled back"
                raise HTTPException(status_code=503, detail={"code":code,
                    "message":message,"details":{"outcome":outcome,
                        "expected_revisions":None,"current_revisions":None,
                        "lookup_url":None}}) from None
        rationale, evidence_ref = _payload_rationale(action, payload)
        policy_command = action in _POLICY_ACTIONS
        if policy_command and (target_id != _ZERO_ID or membership_ids):
            _error(422, "invalid_command", "Policy commands use the global policy target and empty membership")
        if not policy_command and target_id == _ZERO_ID:
            _error(422, "invalid_command", "Group commands require a group target")
        digest = _digest(principal, body)
        now = now_utc()
        try:
            active_connection = _ACTIVE_COMMAND_CONNECTION.get()
            transaction = engine.begin() if active_connection is None else nullcontext(active_connection)
            with transaction as connection:
                if policy_command:
                    lock_policy(connection)
                policy_row = connection.execute(sa.select(assessment_policy).where(
                    assessment_policy.c.policy_id == 1).with_for_update()).mappings().first()
                if policy_row is None:
                    _error(503, "persistence_unavailable", "Assessment policy is not configured")
                policy = policy_row["document"]
                auth_service = getattr(app.state, "oidc_auth", None)
                auth_context = (auth_service.final_context(connection, request)
                    if auth_service is not None else None)
                if auth_context is not None and auth_context.principal_id != principal:
                    _error(403, "authority_changed", "Current identity authority changed")
                source_family = None
                if not policy_command:
                    source_family = connection.execute(sa.select(groups.c.source_family).where(
                        groups.c.group_id == target_id)).scalar_one_or_none()
                    if source_family is None:
                        _error(404, "invalid_command", "Target not found")
                    from uvm.auth.service import group_scope_covered
                    if auth_context is not None:
                        action_grants = _scoped_grants(policy, principal, action, target_id, source_family)
                        if not group_scope_covered(connection, auth_context, [target_id],
                                granting_identity_groups=[g.get("principal_id") for g in action_grants]):
                            _error(403, "source_scope_forbidden", "Current exact source scope is required")
                origin = (_TRUSTED_COMMAND_ORIGIN.get()
                    or principals.get(principal, {}).get("origin", "local_api"))
                # SLA publication is authorised against every explicit policy
                # group inside its transaction below. Its envelope target is a
                # reserved global ID and cannot itself be matched to a scoped
                # grant. Receipt replay performs the same scoped recheck.
                native_action = action in NATIVE_ACTIONS or (action == "principal.update"
                    and native_state(policy).get("mode") == NATIVE_MODE)
                protected_native = action in {"native.authority.activate", "native.authority.rollback",
                    "access_group.create", "access_group.update", "access_group.membership.set"} or (
                    action == "principal.update" and native_state(policy).get("mode") == NATIVE_MODE)
                if action != "policy.sla.publish" and not protected_native:
                    required_action = ("ownership.team.manage" if action.startswith("ownership.team.") else action)
                    required_target = payload.get("team_id", target_id) if action.startswith("ownership.team.") else target_id
                    _require_authority(policy, principal, required_action, required_target, source_family,
                        origin=origin, correlation_id=command_id, connection=connection)
                trusted_github = _TRUSTED_GITHUB_CONTEXT.get()
                if trusted_github is not None:
                    # The poller supplies captured transport context, but this
                    # transaction is authoritative for both link revocation and
                    # acknowledgement. Lock these records through assessment,
                    # audit, receipt and projection-intent commit.
                    link = connection.execute(sa.select(github_identity_links).where(
                        github_identity_links.c.link_id == trusted_github["link_id"])
                        .with_for_update()).mappings().first()
                    preview = connection.execute(sa.select(github_command_previews).where(
                        github_command_previews.c.preview_id == trusted_github["preview_id"])
                        .with_for_update()).mappings().first()
                    if (link is None or not link["enabled"]
                            or link["revision"] != trusted_github["link_revision"]
                            or link["account_id"] != trusted_github["account_id"]
                            or link["principal_id"] != principal):
                        _error(403, "github_actor_unlinked", "GitHub actor link changed")
                    if (preview is None or preview["state"] not in {"acknowledged", "executed"}
                            or preview["principal_id"] != principal
                            or preview["link_id"] != link["link_id"]
                            or preview["repository_id"] != trusted_github["repository_id"]
                            or preview["issue_number"] != trusted_github["issue_number"]
                            or preview["canonical_digest"] != trusted_github["command_digest"]
                            or preview["signature"] != trusted_github["signature"]):
                        _error(409, "command_needs_resubmission",
                            "Acknowledged GitHub command context changed")
                    if (trusted_github.get("submission_at") is None
                            or trusted_github["submission_at"] > preview["expires_at"]):
                        _error(409, "command_needs_resubmission",
                            "GitHub submission was created after preview expiry")
                    repository = connection.execute(sa.select(github_repositories).where(
                        github_repositories.c.repository_id == trusted_github["repository_id"])
                        .with_for_update()).mappings().first()
                    if repository is None:
                        _error(409, "github_audience_unknown", "Repository approval is unavailable")
                    from uvm.github.api import _assert_group_audience_binding
                    _assert_group_audience_binding(connection, dict(repository), target_id)
                prior = connection.execute(sa.select(assessment_command_receipts).where(
                    assessment_command_receipts.c.command_id == command_id).with_for_update()).mappings().first()
                if protected_native and principal not in set(native_state(policy).get("bootstrap_admins", [])):
                    _error(403, "forbidden", "Protected bootstrap administration is required")
                if prior is not None:
                    if prior["request_digest"] != digest:
                        _error(409, "command_id_reused", "Command ID is bound to different content")
                    if action == "policy.sla.publish":
                        requested_scope = payload.get("policy", {}).get("scope", {})
                        target_groups = requested_scope.get("group_ids", []) if isinstance(requested_scope, dict) else []
                        if (not target_groups or any(not isinstance(requested_scope.get(key, []), list)
                                for key in ("environments", "service_ids"))):
                            _error(403, "forbidden", "Current SLA publication authority is required")
                        source_families = {}
                        for scoped_group_id in target_groups:
                            scoped_group = connection.execute(sa.select(groups).where(
                                groups.c.group_id == scoped_group_id)).mappings().first()
                            if scoped_group is None:
                                _error(403, "forbidden", "Current SLA publication authority is required")
                            source_families[scoped_group_id] = scoped_group["source_family"]
                        scoped_authorities = _sla_publication_complete_grants(connection,
                            auth_context, policy, principal, requested_scope, source_families)
                        replay_policy = payload.get("policy", {})
                        scoped_authorities = _sla_publication_grants_with_limits(
                            scoped_authorities, replay_policy)
                        if not scoped_authorities:
                            _error(403, "forbidden", "Current complete SLA publication authority is unavailable")
                        inventory_config = payload.get("inventory_configuration")
                        if inventory_config is not None:
                            inventory_group_ids = {item.get("group_id") for item in
                                inventory_config.get("targets", []) if isinstance(item, dict)}
                            if not inventory_group_ids or not inventory_group_ids <= set(target_groups):
                                _error(403, "forbidden", "Current SLA publication authority does not cover the retained inventory scope")
                    elif action == "sla.deadline.revise":
                        _require_authority(policy, principal, action, target_id, source_family,
                            origin=origin, correlation_id=command_id)
                    elif (not policy_command and not _matches(policy, principal,
                            "assessment.read", target_id, source_family)):
                        _error(403, "forbidden",
                            "Current assessment-read authority is required to replay a receipt")
                    return dict(prior["result"])
                confirmation_command = action in {
                    "remediation.confirm_portion", "remediation.confirm_group"}
                g7_exception_command = (action == "acceptance.submit" and payload.get("exception_contract_version") == 1
                    or action == "acceptance.approve" and ("selected_expires_at" in payload or "expected_request_revision" in payload))
                guarded_episode_command = confirmation_command or action == "sla.deadline.revise" or g7_exception_command
                expected_exposures = body.get("expected_exposures")
                if guarded_episode_command and not isinstance(expected_exposures, list):
                    _error(422, "invalid_command",
                        "New remediation and SLA commands require expected_exposures")
                if guarded_episode_command:
                    parsed_expected = []
                    for item in expected_exposures:
                        if (not isinstance(item, dict)
                                or set(item) != {"exposure_id", "episode_id", "state_revision"}
                                or type(item.get("state_revision")) is not int
                                or item["state_revision"] < 1):
                            _error(422, "invalid_command", "expected_exposures item is invalid")
                        parsed_expected.append((_uuid(item["exposure_id"], "exposure_id"),
                            _uuid(item["episode_id"], "episode_id"), item["state_revision"]))
                    if len({row[0] for row in parsed_expected}) != len(parsed_expected):
                        _error(422, "invalid_command", "expected_exposures must be unique by exposure")
                decision_id = str(uuid.uuid4())
                audit_event_id = str(uuid.uuid4())
                sla_write_evidence = []
                severity_sla_revisions = []
                current_policy_revision = int(policy_row["revision"])
                if policy_command:
                    if (expected.get("target") != current_policy_revision
                            or expected.get("policy") != current_policy_revision
                            or expected.get("identity_membership") != 0
                            or expected.get("owners") != 0):
                        _error(409, "revision_conflict", "Policy revision changed")
                    old_document = copy.deepcopy(policy)
                    now = now_utc()
                    if action == "native.authority.activate":
                        auth_service = getattr(app.state, "oidc_auth", None)
                        configured_mapping_revision = (auth_service.config.get("mapping_revision")
                            if auth_service is not None else None)
                        if (configured_mapping_revision is None or payload.get("mapping_revision")
                                != configured_mapping_revision):
                            _error(409, "revision_conflict",
                                "Native activation must pin the current explicit OIDC mapping revision")
                    if action != "policy.sla.publish" and not protected_native:
                        required_action = ("ownership.team.manage" if action.startswith("ownership.team.") else action)
                        required_target = payload.get("team_id", target_id) if action.startswith("ownership.team.") else target_id
                        _require_authority(policy, principal, required_action, required_target,
                            origin=origin, correlation_id=command_id)
                    if action == "policy.sla.publish":
                        requested = payload.get("policy")
                        required = {"policy_id", "version", "effective_from", "effective_until", "scope",
                            "eligibility", "classification", "duration_seconds_by_severity", "clock_basis",
                            "deadline_reference_rules", "backfill"}
                        if (not isinstance(requested, dict)
                                or frozenset(requested) not in {frozenset(required), frozenset(required | {"start_source"})}):
                            _error(422, "invalid_command", "SLA policy document shape is invalid")
                        start_source = requested.get("start_source", "source_observation_v1")
                        if start_source not in {"source_observation_v1", "uvm_ingest_commit_v1"}:
                            _error(422, "invalid_command", "Unsupported SLA start source")
                        reference_rules = requested.get("deadline_reference_rules")
                        reference_bindings = (reference_rules.get("bindings", [])
                            if isinstance(reference_rules, dict) else None)
                        if (reference_bindings is None or set(reference_rules) - {"bindings"}
                                or not isinstance(reference_bindings, list)):
                            _error(422, "invalid_command", "Deadline reference rules must contain an optional bindings list")
                        seen_binding_ids, seen_binding_members = set(), set()
                        binding_fields = {"binding_id", "reference_id", "occurrence_id",
                            "episode_id", "policy_id", "policy_version", "started_at"}
                        for binding in reference_bindings:
                            if not isinstance(binding, dict) or set(binding) != binding_fields:
                                _error(422, "invalid_command", "Deadline reference binding shape is invalid")
                            for name in ("binding_id", "reference_id", "occurrence_id", "episode_id"):
                                _uuid(binding[name], "deadline_reference_rules.bindings." + name)
                            member_key = (binding["episode_id"], binding["occurrence_id"], binding["reference_id"])
                            if (binding["binding_id"] in seen_binding_ids or member_key in seen_binding_members
                                    or binding["policy_id"] != requested["policy_id"]
                                    or type(binding["policy_version"]) is not int
                                    or binding["policy_version"] != requested["version"]
                                    or not isinstance(binding["started_at"], str)):
                                _error(422, "invalid_command", "Deadline reference binding is duplicate or policy-mismatched")
                            seen_binding_ids.add(binding["binding_id"])
                            seen_binding_members.add(member_key)
                        head = connection.execute(sa.select(sla_policy_heads).where(
                            sla_policy_heads.c.head_id == 1).with_for_update()).mappings().first()
                        if head is None or expected.get("sla_policy") != int(head["revision"]):
                            _error(409, "revision_conflict", "SLA publication head changed")
                        if (not isinstance(requested["policy_id"], str) or not requested["policy_id"].strip()
                                or type(requested["version"]) is not int or requested["version"] < 1
                                or not isinstance(requested["scope"], dict)
                                or not isinstance(requested["scope"].get("group_ids"), list)
                                or not requested["scope"]["group_ids"]):
                            _error(422, "invalid_command", "SLA policy identity and explicit group scope are required")
                        action_scope = requested["scope"]
                        requested_environments = action_scope.get("environments", [])
                        requested_services = action_scope.get("service_ids", [])
                        if (not isinstance(requested_environments, list) or any(not isinstance(x, str) for x in requested_environments)
                                or not isinstance(requested_services, list) or any(not isinstance(x, str) for x in requested_services)):
                            _error(422, "invalid_command", "SLA environment/service scope must be string arrays")
                        source_families = {}
                        for group_id in requested["scope"]["group_ids"]:
                            _uuid(group_id, "policy scope group_id")
                            group_row = connection.execute(sa.select(groups).where(
                                groups.c.group_id == group_id)).mappings().first()
                            if group_row is None:
                                _error(404, "invalid_command", "SLA policy target not found")
                            source_families[group_id] = group_row["source_family"]
                        scoped_scope = {"group_ids": requested["scope"]["group_ids"],
                             "environments": requested_environments,
                             "service_ids": requested_services}
                        scoped_authorities = _sla_publication_complete_grants(connection,
                            auth_context, policy, principal, scoped_scope, source_families)
                        scoped_authorities = _sla_publication_grants_with_limits(
                            scoped_authorities, requested)
                        if not scoped_authorities:
                            _error(403, "forbidden", "One complete source-covered SLA grant must cover the scope and limits")
                        for binding in reference_bindings:
                            episode = connection.execute(sa.select(exposure_episodes).where(
                                exposure_episodes.c.episode_id == binding["episode_id"])).mappings().first()
                            member = connection.execute(sa.select(exposure_episode_members).where(
                                exposure_episode_members.c.episode_id == binding["episode_id"],
                                exposure_episode_members.c.occurrence_id == binding["occurrence_id"])).mappings().first()
                            occurrence = connection.execute(sa.select(occurrences).where(
                                occurrences.c.occurrence_id == binding["occurrence_id"])).mappings().first()
                            exposure = connection.execute(sa.select(exposures).where(
                                exposures.c.exposure_id == occurrence["exposure_id"])).mappings().first() if occurrence else None
                            if (episode is None or member is None or exposure is None
                                    or episode["group_id"] not in requested["scope"]["group_ids"]
                                    or exposure["group_id"] != episode["group_id"]):
                                _error(422, "invalid_command", "Deadline reference binding is outside policy episode scope")
                            _, prior_evaluation = _sla_evaluation_history(
                                connection, binding["episode_id"], binding["occurrence_id"])
                            started_at = (_membership_causal_start(connection, binding["episode_id"], occurrence,
                                as_of=now, known_at=now)
                                or (prior_evaluation["started_at"] if prior_evaluation else None))
                            if (started_at is None or binding["started_at"] !=
                                    started_at.astimezone(_UTC).isoformat().replace("+00:00", "Z")):
                                _error(422, "invalid_command", "Deadline reference binding must pin the retained first detection")
                            try:
                                reference_history = DeadlineReferenceStore.read_history_on_connection(
                                    connection, binding["occurrence_id"])
                            except DeadlineReferenceError:
                                _error(409, "reference_conflict", "Retained deadline reference history is invalid")
                            if not any(row["reference"]["reference_id"] == binding["reference_id"]
                                    for row in reference_history):
                                _error(409, "reference_conflict", "Binding must name an exact trusted retained reference")
                        limits = scoped_authorities[0].get("limits", {})
                        inventory_document = None
                        inventory_revision = None
                        inventory_config = payload.get("inventory_configuration")
                        if inventory_config is not None:
                            required_inventory = {"effective_from", "effective_until", "freshness_horizon_seconds",
                                "expected_schedule_seconds", "targets"}
                            if not isinstance(inventory_config, dict) or set(inventory_config) != required_inventory:
                                _error(422, "invalid_command", "Inventory configuration fields are invalid")
                            inventory_starts = datetime.fromisoformat(inventory_config["effective_from"].replace("Z", "+00:00")) if isinstance(inventory_config["effective_from"], str) else None
                            inventory_ends = (datetime.fromisoformat(inventory_config["effective_until"].replace("Z", "+00:00"))
                                if isinstance(inventory_config["effective_until"], str) else None)
                            freshness = inventory_config["freshness_horizon_seconds"]
                            schedule_interval = inventory_config["expected_schedule_seconds"]
                            if (inventory_starts is None or inventory_starts.tzinfo is None
                                    or inventory_starts.utcoffset() != _UTC.utcoffset(inventory_starts)
                                    or inventory_starts < now
                                    or inventory_ends is not None and (inventory_ends.tzinfo is None
                                        or inventory_ends.utcoffset() != _UTC.utcoffset(inventory_ends)
                                        or inventory_ends <= inventory_starts)
                                    or type(freshness) is not int or freshness <= 0
                                    or type(schedule_interval) is not int or schedule_interval <= 0):
                                _error(422, "invalid_command", "Inventory effective interval and freshness bounds are invalid")
                            target_ids, inventory_group_ids = set(), set()
                            targets = inventory_config["targets"]
                            if not isinstance(targets, list) or not targets:
                                _error(422, "invalid_command", "Inventory requires explicit expected targets")
                            for target in targets:
                                if not isinstance(target, dict) or set(target) != {"target_id", "group_id", "required_sources"}:
                                    _error(422, "invalid_command", "Inventory target fields are invalid")
                                if not isinstance(target["target_id"], str) or not target["target_id"].strip() or target["target_id"] in target_ids:
                                    _error(422, "invalid_command", "Inventory target IDs must be unique stable strings")
                                target_ids.add(target["target_id"])
                                target["group_id"] = _uuid(target["group_id"], "inventory.target.group_id")
                                inventory_group_ids.add(target["group_id"])
                                sources = target["required_sources"]
                                if not isinstance(sources, list) or not sources:
                                    _error(422, "invalid_command", "Each inventory target requires a source")
                                source_keys = set()
                                for source in sources:
                                    required_source = {"source_family", "source_account_id", "scope_key", "schedule_id", "schedule_revision", "target_match"}
                                    if not isinstance(source, dict) or set(source) != required_source:
                                        _error(422, "invalid_command", "Inventory source binding fields are invalid")
                                    if any(not isinstance(source[key], str) or not source[key].strip()
                                            for key in ("source_family", "source_account_id", "scope_key", "schedule_id")):
                                        _error(422, "invalid_command", "Inventory source identity is invalid")
                                    if type(source["schedule_revision"]) is not int or source["schedule_revision"] < 1:
                                        _error(422, "invalid_command", "Inventory source schedule revision is invalid")
                                    match = source["target_match"]
                                    allowed_match_shapes = ({"field", "value"}, {"field", "scheme", "authority", "value"})
                                    if (not isinstance(match, dict) or set(match) not in allowed_match_shapes
                                            or match.get("field") not in {"asset_locator", "native_id"}
                                            or not isinstance(match.get("value"), str) or not match["value"].strip()
                                            or match["field"] == "native_id" and (not match.get("scheme") or not match.get("authority"))
                                            or match["field"] == "asset_locator" and set(match) != {"field", "value"}):
                                        _error(422, "invalid_command", "Inventory target match must name an exact retained identity")
                                    key = (source["source_family"], source["source_account_id"], source["scope_key"])
                                    if key in source_keys:
                                        _error(422, "invalid_command", "Inventory target source bindings must be unique")
                                    source_keys.add(key)
                                    schedule_row = connection.execute(sa.select(collection_schedules).where(
                                        collection_schedules.c.schedule_id == source["schedule_id"],
                                        collection_schedules.c.revision == source["schedule_revision"])).mappings().first()
                                    if (schedule_row is None or not schedule_row["enabled"]
                                            or (schedule_row["source_family"], schedule_row["source_account_id"], schedule_row["scope_key"])
                                            != (source["source_family"], source["source_account_id"], source["scope_key"])):
                                        _error(422, "invalid_command", "Inventory source must bind its exact enabled collection schedule")
                            if not inventory_group_ids <= set(requested["scope"]["group_ids"]):
                                _error(403, "forbidden", "Inventory groups must be inside the complete SLA publication scope")
                            inventory_head = connection.execute(sa.select(inventory_policy_heads).where(
                                inventory_policy_heads.c.head_id == 1).with_for_update()).mappings().first()
                            if inventory_head is None or type(expected.get("inventory")) is not int or expected["inventory"] != int(inventory_head["revision"]):
                                _error(409, "revision_conflict", "Expected inventory revision changed")
                            inventory_revision = int(inventory_head["revision"]) + 1
                            inventory_document = {**inventory_config, "scope_group_ids": sorted(inventory_group_ids)}
                        duration_limits = requested.get("duration_seconds_by_severity", {})
                        eligibility_severities = requested.get("eligibility", {}).get("included_severities", [])
                        excluded_classifications = requested.get("eligibility", {}).get("excluded_classifications", [])
                        if (not isinstance(duration_limits, dict) or not isinstance(eligibility_severities, list)
                                or not isinstance(excluded_classifications, list)
                                or any(not isinstance(item, str) or not item for item in excluded_classifications)
                                or len(set(excluded_classifications)) != len(excluded_classifications)
                                or not isinstance(requested.get("backfill"), dict)):
                            _error(422, "invalid_command", "SLA policy eligibility, durations and backfill are invalid")
                        canonical_classes = _SEVERITIES
                        if (not set(excluded_classifications) <= canonical_classes
                                or excluded_classifications and requested.get("backfill", {}).get("mode") != "backfill_existing"
                                or excluded_classifications and not requested.get("backfill", {}).get("targets")):
                            _error(422, "invalid_command", "Classification exclusion requires canonical classes and exact backfill targets")
                        if excluded_classifications and not rationale.strip():
                            _error(422, "invalid_command", "Classification exclusion requires a publication rationale")
                        used_severities = (set(duration_limits) | set(eligibility_severities)
                            | set(excluded_classifications))
                        if (requested["clock_basis"] not in limits.get("allowed_sla_clock_bases", [])
                                or not used_severities <= set(limits.get("allowed_sla_severities", []))
                                or any(type(seconds) is not int or seconds <= 0
                                    or limits.get("maximum_sla_duration_seconds") is None
                                    or seconds > limits["maximum_sla_duration_seconds"]
                                    for seconds in duration_limits.values())
                                or requested["backfill"].get("mode") == "backfill_existing" and not limits.get("allow_sla_backfill", False)):
                            _error(403, "forbidden", "SLA policy exceeds its complete grant limits")
                        starts = datetime.fromisoformat(requested["effective_from"].replace("Z", "+00:00")) if isinstance(requested["effective_from"], str) else None
                        ends = datetime.fromisoformat(requested["effective_until"].replace("Z", "+00:00")) if isinstance(requested["effective_until"], str) else None
                        if starts is None or starts.tzinfo is None or starts.utcoffset() != _UTC.utcoffset(starts) or starts < now:
                            _error(422, "invalid_command", "SLA policy activation must be an explicit UTC instant no earlier than commit")
                        if ends is not None and (ends.tzinfo is None or ends.utcoffset() != _UTC.utcoffset(ends) or ends <= starts):
                            _error(422, "invalid_command", "SLA policy effective_until must be a later UTC instant")
                        if requested["clock_basis"] not in {"elapsed_utc_seconds", "calendar_days_utc"}:
                            _error(422, "invalid_command", "SLA policy clock basis is unsupported")
                        backfill = requested["backfill"]
                        if not isinstance(backfill, dict) or backfill.get("mode") not in {"prospective", "backfill_existing"}:
                            _error(422, "invalid_command", "SLA policy backfill mode is invalid")
                        if (requested.get("start_source") == "uvm_ingest_commit_v1"
                                and backfill["mode"] != "prospective"):
                            _error(422, "invalid_command", "G7 activation is prospective; migration is outside this contract")
                        backfill_targets = []
                        if backfill["mode"] == "prospective":
                            if set(backfill) != {"mode"}:
                                _error(422, "invalid_command", "Prospective policy cannot name backfill targets")
                        else:
                            if set(backfill) != {"mode", "targets"} or not isinstance(backfill.get("targets"), list) or not backfill["targets"]:
                                _error(422, "invalid_command", "Backfill requires a non-empty exact target list")
                            target_ids = set()
                            for target in backfill["targets"]:
                                required_target = {"episode_id", "occurrence_id", "expected_episode_state_revision",
                                    "expected_evaluation_revision", "predecessor_evaluation_id"}
                                if not isinstance(target, dict) or set(target) != required_target:
                                    _error(422, "invalid_command", "Backfill target guard shape is invalid")
                                _uuid(target["episode_id"], "backfill episode_id")
                                _uuid(target["occurrence_id"], "backfill occurrence_id")
                                if target["predecessor_evaluation_id"] is not None:
                                    _uuid(target["predecessor_evaluation_id"], "backfill predecessor_evaluation_id")
                                if (type(target["expected_episode_state_revision"]) is not int
                                        or target["expected_episode_state_revision"] < 1
                                        or type(target["expected_evaluation_revision"]) is not int
                                        or target["expected_evaluation_revision"] < 0):
                                    _error(422, "invalid_command", "Backfill revision guards are invalid")
                                if target["occurrence_id"] in target_ids:
                                    _error(422, "invalid_command", "Backfill targets must be unique by occurrence")
                                target_ids.add(target["occurrence_id"])
                                backfill_targets.append(target)
                        if rationale:
                            requested = {**requested, "publication_rationale": rationale}
                        if evidence_ref:
                            requested = {**requested, "publication_evidence_ref": evidence_ref}
                        policy_id, version = requested["policy_id"], requested["version"]
                        exists = connection.execute(sa.select(sla_policy_versions.c.revision).where(
                            sla_policy_versions.c.policy_id == policy_id,
                            sla_policy_versions.c.version == version)).scalar_one_or_none()
                        if exists is not None:
                            _error(409, "revision_conflict", "SLA policy version is immutable and already exists")
                        after = old_document
                        policy_revision = int(head["revision"]) + 1
                        connection.execute(sla_policy_versions.insert().values(policy_id=policy_id,
                            version=version, revision=policy_revision, document=requested,
                            created_at=now, created_by=principal))
                        connection.execute(sla_policy_heads.update().where(
                            sla_policy_heads.c.head_id == 1).values(revision=policy_revision, updated_at=now))
                        if inventory_document is not None:
                            connection.execute(inventory_policy_versions.insert().values(
                                revision=inventory_revision, command_id=command_id,
                                document=inventory_document, created_at=now,
                                created_by=principal, audit_event_id=audit_event_id))
                            connection.execute(inventory_policy_heads.update().where(
                                inventory_policy_heads.c.head_id == 1).values(
                                    revision=inventory_revision, updated_at=now))
                        if backfill_targets:
                            scoped_group_ids = set(requested["scope"]["group_ids"])
                            for target in backfill_targets:
                                episode = connection.execute(sa.select(exposure_episodes).where(
                                    exposure_episodes.c.episode_id == target["episode_id"],
                                    exposure_episodes.c.is_current.is_(True)).with_for_update()).mappings().first()
                                member = connection.execute(sa.select(exposure_episode_members).where(
                                    exposure_episode_members.c.episode_id == target["episode_id"],
                                    exposure_episode_members.c.occurrence_id == target["occurrence_id"]
                                ).with_for_update()).mappings().first()
                                occurrence = connection.execute(sa.select(occurrences).where(
                                    occurrences.c.occurrence_id == target["occurrence_id"])).mappings().first()
                                exposure = (connection.execute(sa.select(exposures).where(
                                    exposures.c.exposure_id == occurrence["exposure_id"])).mappings().first()
                                    if occurrence else None)
                                member_context = (connection.execute(sa.select(workloads.c.stable_attrs).where(
                                    workloads.c.workload_id == occurrence["workload_id"])).scalar_one_or_none()
                                    if occurrence else None) or {}
                                if (episode is None or member is None or occurrence is None or exposure is None
                                        or exposure["group_id"] not in scoped_group_ids
                                        or episode["group_id"] != exposure["group_id"]
                                        or int(episode["state_revision"]) != target["expected_episode_state_revision"]
                                        or member["status"] not in {"outstanding", "review"}):
                                    _error(409, "revision_conflict", "Backfill episode membership or scope changed")
                                if not _sla_policy_scope_matches_member(requested, member_context):
                                    _error(403, "forbidden", "Backfill member is outside the policy environment/service applicability")
                                if _sla_evaluation_table(connection, target["episode_id"]) is g7_sla_evaluations:
                                    _error(409, "revision_conflict", "G5 backfill cannot change a pinned G7 episode")
                                prior_history, prior = _sla_evaluation_history(
                                    connection, target["episode_id"], target["occurrence_id"], for_update=True)
                                prior_revision = int(prior["revision"]) if prior else 0
                                prior_id = prior["evaluation_id"] if prior else None
                                if (prior_revision != target["expected_evaluation_revision"]
                                        or prior_id != target["predecessor_evaluation_id"]):
                                    _error(409, "revision_conflict", "Backfill evaluation predecessor changed")
                                source_rows = connection.execute(sa.select(
                                    source_observations.c.source_rating,
                                    source_observations.c.source_family,
                                    source_observations.c.source_account_id)
                                    .where(source_observations.c.occurrence_id == target["occurrence_id"],
                                        source_observations.c.collected_at <= now,
                                        sa.or_(source_observations.c.observed_at.is_(None),
                                            source_observations.c.observed_at <= now))
                                    .order_by(source_observations.c.observed_at.desc().nullslast(),
                                        source_observations.c.retention_order.desc())).all()
                                latest_sources = {}
                                for source_row in source_rows:
                                    latest_sources.setdefault((source_row[1], source_row[2]), source_row[0])
                                override = _membership_assessed_severity(
                                    connection, episode["group_id"], target["occurrence_id"])
                                mapping = requested.get("classification", {}).get("source_rating_map", {})
                                severity, classification_gaps = resolve_classification(
                                    latest_sources.values(), mapping, override=override)
                                excluded_classes = requested.get("eligibility", {}).get("excluded_classifications", [])
                                if excluded_classes and severity not in excluded_classes:
                                    _error(422, "invalid_command", "Every exclusion target must resolve to an explicitly excluded canonical classification")
                                gap_reasons = list(classification_gaps)
                                included = requested.get("eligibility", {}).get("included_severities", [])
                                if included and severity not in included:
                                    gap_reasons.append("severity_not_eligible")
                                causal_transition = _membership_causal_transition(connection,
                                    target["episode_id"], occurrence, as_of=now, known_at=now)
                                causal_start = causal_transition["started_at"]
                                start_at = causal_start or (prior["started_at"] if prior else None)
                                clock_reset = bool(prior and causal_start is not None and (
                                    prior["started_at"] != causal_start or
                                    has_unabsorbed_causal_reset(prior_history, prior, causal_start,
                                        causal_event_id=causal_transition["event_id"],
                                        causal_known_at=causal_transition["event"]["recorded_at"]
                                            if causal_transition["event"] else None)))
                                reset_event_id = (causal_transition["event_id"] if clock_reset
                                    else prior.get("clock_reset_event_id") if prior else None)
                                duration = requested.get("duration_seconds_by_severity", {}).get(severity) if severity else None
                                if type(duration) is not int or duration <= 0:
                                    gap_reasons.append("missing_sla_duration")
                                    deadline = None
                                elif start_at is not None and start_at > now:
                                    gap_reasons.append("awaiting_source_time")
                                    deadline = None
                                elif start_at is None:
                                    gap_reasons.append("unknown_start")
                                    deadline = None
                                else:
                                    deadline = elapsed_deadline(start_at, duration)
                                reference_binding_id = None
                                deadline_basis = "authorised_backfill" if deadline else "unknown"
                                reference_result = resolve_policy_reference(connection, requested,
                                    policy_id=policy_id, policy_version=version,
                                    episode_id=target["episode_id"],
                                    occurrence_id=target["occurrence_id"], started_at=start_at,
                                    as_of=starts.astimezone(_UTC), known_at=now)
                                if reference_result is not None:
                                    if reference_result["status"] == "incomplete":
                                        gap_reasons.extend("warning:" + reason
                                            for reason in reference_result["gap_reasons"])
                                    else:
                                        gap_reasons.extend(reference_result["gap_reasons"])
                                    reference_binding_id = reference_result["reference_binding_id"]
                                    if reference_result["status"] == "complete":
                                        deadline = datetime.fromisoformat(
                                            reference_result["deadline_at"].replace("Z", "+00:00"))
                                        deadline_basis = "supplied_reference"
                                    elif reference_result["status"] == "conflict":
                                        deadline = None
                                        deadline_basis = "unknown"
                                preserve_existing_clock = bool(prior and not clock_reset and (
                                    prior["head_decision_id"] is not None or
                                    severity in excluded_classes or
                                    (prior["policy_id"] and prior["policy_version"] and
                                     (prior_policy := connection.execute(sa.select(sla_policy_versions.c.document).where(
                                         sla_policy_versions.c.policy_id == prior["policy_id"],
                                         sla_policy_versions.c.version == prior["policy_version"])).scalar_one_or_none()) and
                                     severity in prior_policy.get("eligibility", {}).get("excluded_classifications", []) and
                                     any(item.get("episode_id") == target["episode_id"] and
                                         item.get("occurrence_id") == target["occurrence_id"]
                                         for item in prior_policy.get("backfill", {}).get("targets", []) if isinstance(item, dict)))))
                                if preserve_existing_clock:
                                    deadline = prior["current_deadline_at"]
                                    deadline_basis = prior["deadline_basis"]
                                    reference_binding_id = prior["reference_binding_id"]
                                head_decision_id = prior["head_decision_id"] if preserve_existing_clock else None
                                evaluation_id = str(uuid.uuid4())
                                original_deadline = (prior["original_deadline_at"] if prior
                                    and prior["started_at"] == start_at else None)
                                if original_deadline is None and clock_reset:
                                    reset_policy, _ = _sla_policy_for_clock(connection,
                                        exposure["group_id"], member_context, start_at, now)
                                    original_deadline = reset_original_baseline(connection, reset_policy,
                                        group_id=exposure["group_id"], episode_id=target["episode_id"],
                                        occurrence_id=target["occurrence_id"], started_at=start_at, known_at=now)
                                original_deadline = original_deadline or deadline
                                original_deadline, deadline, deadline_basis, gap_reasons = guard_pending_anchor(
                                    start_at, now, original_deadline, deadline, deadline_basis, gap_reasons)
                                connection.execute(sla_evaluations.insert().values(
                                    evaluation_id=evaluation_id, episode_id=target["episode_id"],
                                    occurrence_id=target["occurrence_id"], revision=next_evaluation_revision(prior_history),
                                    policy_id=policy_id, policy_version=version, started_at=start_at,
                                    reference_binding_id=reference_binding_id,
                                    original_deadline_at=original_deadline,
                                    current_deadline_at=deadline, deadline_basis=deadline_basis,
                                    gap_reasons=sorted(set(gap_reasons)), predecessor_evaluation_id=prior_id,
                                    derivation_kind="writer",
                                    clock_reset_event_id=(reset_event_id if clock_reset else
                                        prior.get("clock_reset_event_id") if prior else None),
                                    clock_reset_absorbed=(True if clock_reset else
                                        prior.get("clock_reset_absorbed", True) if prior else True),
                                    head_decision_id=head_decision_id,
                                    effective_at=max(now, starts.astimezone(_UTC)), known_at=now))
                    else:
                        current_principals = dict(principals)
                        current_principals.update({row["principal_id"]: {
                            "enabled": row["enabled"], "display_name": row["display_label"],
                            "actor_kind": "principal"} for row in connection.execute(
                                sa.select(auth_principals).with_for_update()
                                ).mappings().all()})
                        after = _apply_policy_action(old_document, principal, action, payload, now,
                            current_principals, expected)
                        if action == "principal.update" and native_state(policy).get("mode") == NATIVE_MODE:
                            identity_id = payload.get("principal_id")
                            identity_row = connection.execute(sa.select(auth_principals).where(
                                auth_principals.c.principal_id == identity_id).with_for_update()).mappings().first()
                            if identity_row is None:
                                _error(422, "invalid_command", "principal_id is not a persisted human identity")
                            connection.execute(auth_principals.update().where(
                                auth_principals.c.principal_id == identity_id).values(
                                    enabled=payload["enabled"], revision=identity_row["revision"] + 1))
                            if payload["enabled"] is False:
                                connection.execute(oidc_sessions.update().where(
                                    oidc_sessions.c.principal_id == identity_id,
                                    oidc_sessions.c.revoked_at.is_(None)).values(
                                        revoked_at=now, revision=oidc_sessions.c.revision + 1))
                    revision = current_policy_revision + 1
                    connection.execute(assessment_policy.update().where(
                        assessment_policy.c.policy_id == 1).values(
                            revision=revision, document=after, updated_at=now, updated_by=principal))
                    identity_revision = 0
                else:
                    group = connection.execute(sa.select(groups).where(
                        groups.c.group_id == target_id).with_for_update()).mappings().first()
                    if group is None:
                        _error(404, "invalid_command", "Target not found")
                    source_family = group["source_family"]
                    _lock_group_membership(connection, target_id)
                    current_membership, identity_revision = _membership(connection, target_id)
                    if (expected.get("identity_membership") != identity_revision
                            or any(item not in current_membership for item in membership_ids)):
                        _error(409, "revision_conflict", "Membership changed; refresh and confirm again")
                    old = connection.execute(sa.select(assessment_group_state).where(
                        assessment_group_state.c.group_id == target_id).with_for_update()).mappings().first()
                    old_document = copy.deepcopy(old["document"]) if old else {}
                    old_revision = int(old["revision"]) if old else 1
                    if (expected.get("target") != old_revision
                            or expected.get("policy") != current_policy_revision
                            or expected.get("owners", 1) != int(old_document.get("owner_revision", 1))):
                        _error(409, "revision_conflict", "Assessment revisions changed")
                    episode_records = ensure_current_episodes(connection, target_id, now=now)
                    if guarded_episode_command:
                        selected_exposures = set(connection.execute(sa.select(
                            exposures.c.exposure_id).select_from(occurrences.join(exposures,
                                occurrences.c.exposure_id == exposures.c.exposure_id))
                            .where(exposures.c.group_id == target_id,
                                occurrences.c.occurrence_id.in_(membership_ids))).scalars())
                        current_guards = {record["episode"]["exposure_id"]: {
                            "episode_id": record["episode"]["episode_id"],
                            "state_revision": int(record["episode"]["state_revision"])}
                            for record in episode_records}
                        if {row[0] for row in parsed_expected} != selected_exposures:
                            _error(422, "invalid_command",
                                "expected_exposures must exactly cover captured membership")
                        stale = [{"exposure_id": exposure_id,
                            "expected_episode_id": episode_id,
                            "expected_state_revision": state_revision,
                            "current_episode_id": current_guards.get(exposure_id, {}).get("episode_id"),
                            "current_state_revision": current_guards.get(exposure_id, {}).get("state_revision")}
                            for exposure_id, episode_id, state_revision in parsed_expected
                            if (current_guards.get(exposure_id, {}).get("episode_id") != episode_id
                                or current_guards.get(exposure_id, {}).get("state_revision") != state_revision)]
                        if stale:
                            _error(409, "revision_conflict",
                                "Exposure episode changed; refresh and confirm again",
                                {"stale_exposures": stale})
                    exception_guards = None
                    selected_request = next((item for item in old_document.get("acceptances", [])
                        if item.get("acceptance_id") == payload.get("acceptance_id")), None)
                    if (action == "acceptance.approve" and selected_request
                            and selected_request.get("exception_contract_version") == 1
                            and not g7_exception_command):
                        _error(422, "invalid_command", "Versioned exception approval requires episode/evaluation guards")
                    if g7_exception_command:
                        requested_heads = body.get("expected_evaluations")
                        if not isinstance(requested_heads, list):
                            _error(422, "invalid_command", "Exception requires exact expected_evaluations")
                        actual_heads = []
                        for record in episode_records:
                            for member in record["members"]:
                                if member["occurrence_id"] not in membership_ids:
                                    continue
                                if member["status"] != "outstanding":
                                    _error(409, "revision_conflict", "Exception requires outstanding exact membership")
                                episode_id = record["episode"]["episode_id"]
                                if _sla_evaluation_table(connection, episode_id) is not g7_sla_evaluations:
                                    _error(409, "revision_conflict", "Exception requires a pinned G7 episode")
                                _, head = _sla_evaluation_history(connection, episode_id,
                                    member["occurrence_id"], for_update=True)
                                if head is None:
                                    _error(409, "sla_clock_gap", "Exception evaluation is unavailable")
                                actual_heads.append({"episode_id": episode_id,
                                    "occurrence_id": member["occurrence_id"],
                                    "evaluation_id": head["evaluation_id"], "revision": int(head["revision"])})
                        order = lambda item: item["occurrence_id"]
                        if (any(not isinstance(item, dict) or set(item) != {
                                "episode_id", "occurrence_id", "evaluation_id", "revision"}
                                for item in requested_heads)
                                or len(actual_heads) != len(membership_ids)
                                or sorted(requested_heads, key=order) != sorted(actual_heads, key=order)):
                            _error(409, "revision_conflict", "Exception evaluation head changed")
                        exception_guards = {"episodes": sorted(body["expected_exposures"],
                            key=lambda item: item["exposure_id"]),
                            "evaluations": sorted(actual_heads, key=order)}
                        if (action == "acceptance.approve" and selected_request.get("submitted_guards") != exception_guards):
                            _error(409, "revision_conflict", "Exception submitted episode/evaluation context changed; submit a replacement request")
                        if action == "acceptance.approve" and any(
                                approval.get("policy_revision") != current_policy_revision
                                for approval in selected_request.get("approvals", [])):
                            _error(409, "revision_conflict", "Earlier approval authority changed; fresh approvals are required")
                    if g7_exception_command and action == "acceptance.approve":
                        service = getattr(app.state, "oidc_auth", None)
                        from uvm.auth.service import group_scope_covered
                        for previous_approval in selected_request.get("approvals", []):
                            prior_context = None
                            recorded_context = previous_approval.get("authority_context")
                            if recorded_context and service:
                                try:
                                    mode = recorded_context["credential_mode"]
                                    if mode == "oidc_session":
                                        prior_context = service.resolve_session_id(connection, recorded_context["session_id"])
                                    elif mode == "github_link":
                                        prior_context = service.linked_actor_context(connection, previous_approval["actor_id"])
                                    else:
                                        prior_context = service.service_context_for_principal(previous_approval["actor_id"])
                                except HTTPException:
                                    _error(409, "revision_conflict", "Previous approver no longer has current identity authority")
                                if prior_context is None:
                                    _error(409, "revision_conflict", "Previous approver authority is unavailable")
                            token = AUTHORITY_CONTEXT.set(prior_context)
                            try:
                                grants = _scoped_grants(policy, previous_approval["actor_id"], "acceptance.approve", target_id, source_family)
                                grants = [grant for grant in grants if grant.get("grant_id") in previous_approval.get("grant_ids", [])
                                    and group_scope_covered(connection, prior_context, [target_id],
                                        granting_identity_groups=[grant.get("principal_id")])]
                                if not grants:
                                    _error(409, "revision_conflict", "Previous approver no longer has the signed approval grant")
                            finally:
                                AUTHORITY_CONTEXT.reset(token)
                    native_severity = None
                    successor_evidence = None
                    if action == "acceptance.reconcile":
                        _uuid(payload["resolution_id"], "resolution_id")
                        predecessor_id = _uuid(payload["predecessor_occurrence_id"],
                            "predecessor_occurrence_id")
                        if predecessor_id not in membership_ids:
                            _error(422, "invalid_command",
                                "Reconciliation command membership must name its predecessor")
                        acceptance_for_reconciliation = next((item for item in
                            old_document.get("acceptances", []) if item.get("acceptance_id") ==
                            payload["acceptance_id"]), None)
                        successor_evidence = _successor_reconciliation_evidence(
                            connection, engine, dict(group), payload["resolution_id"],
                            predecessor_id, list(acceptance_for_reconciliation.get(
                                "membership_ids", [])) if acceptance_for_reconciliation else [])
                        expected_reconciliation_members = {predecessor_id}
                        selected_successor = successor_evidence.get("successor_occurrence_id")
                        if selected_successor in current_membership:
                            expected_reconciliation_members.add(selected_successor)
                        if set(membership_ids) != expected_reconciliation_members:
                            _error(422, "invalid_command",
                                "Reconciliation command membership must name the predecessor and selected current successor")
                    if action in {"acceptance.approve", "severity.override"} and not (old_document.get("assessed_severity") or {}).get("value"):
                        native_severity = connection.execute(sa.select(source_observations.c.source_rating)
                            .select_from(source_observations.join(occurrences,
                                source_observations.c.occurrence_id == occurrences.c.occurrence_id)
                                .join(exposures, occurrences.c.exposure_id == exposures.c.exposure_id))
                            .where(exposures.c.group_id == target_id)
                            .order_by(source_observations.c.observed_at.desc().nulls_last(),
                                source_observations.c.retention_order.desc()).limit(1)).scalar_one_or_none()
                    effective_members = {item["acceptance_id"]:
                        _effective_acceptance_members(item, connection, engine,
                            now_utc(), lock=True)
                        for item in old_document.get("acceptances", [])}
                    final_membership, final_identity_revision = _membership(connection, target_id)
                    if (final_membership != current_membership
                            or final_identity_revision != identity_revision):
                        _error(409, "revision_conflict", "Membership changed during validation; refresh and confirm again")
                    final_membership, final_identity_revision = _membership(connection, target_id)
                    if (final_membership != current_membership
                            or final_identity_revision != identity_revision):
                        _error(409, "revision_conflict", "Membership changed during validation; refresh and confirm again")
                    now = now_utc()
                    # Proof and lock acquisition may cross the immutable deadline.
                    for item in old_document.get("acceptances", []):
                        if datetime.fromisoformat(item["expires_at"].replace("Z", "+00:00")) <= now:
                            effective_members[item["acceptance_id"]] = set()
                    scoped_grants = _require_authority(policy, principal, action, target_id,
                        source_family, origin=origin, correlation_id=command_id,
                        connection=connection)
                    # A role's limits and separation-of-duties rules are part of
                    # its grant. Filter by that grant's access-group source ceiling
                    # before any acceptance decision aggregates those rules.
                    if not scoped_grants:
                        _error(403, "source_scope_forbidden", "Current exact source scope is required")
                    if action == "sla.deadline.revise":
                        self_revisions = payload.get("revisions")
                        if not isinstance(self_revisions, list) or len(self_revisions) != len(membership_ids):
                            _error(422, "invalid_command", "One revision is required per exact membership")
                        by_member = {}
                        for item in self_revisions:
                            if not isinstance(item, dict) or set(item) != {"episode_id", "occurrence_id", "evaluation_id", "expected_evaluation_revision", "predecessor_deadline_decision_id", "revised_deadline_at"}:
                                _error(422, "invalid_command", "SLA revision item shape is invalid")
                            occurrence_id = _uuid(item["occurrence_id"], "occurrence_id")
                            _uuid(item["episode_id"], "episode_id")
                            _uuid(item["evaluation_id"], "evaluation_id")
                            if occurrence_id in by_member or occurrence_id not in membership_ids:
                                _error(422, "invalid_command", "SLA revisions must exactly match command membership")
                            by_member[occurrence_id] = item
                        if set(by_member) != set(membership_ids):
                            _error(422, "invalid_command", "SLA revisions must exactly match command membership")
                        current_heads = {}
                        evaluation_tables = {}
                        for record in episode_records:
                            episode = record["episode"]
                            for member in record["members"]:
                                if member["occurrence_id"] in membership_ids:
                                    item = by_member[member["occurrence_id"]]
                                    if item["episode_id"] != episode["episode_id"]:
                                        _error(409, "revision_conflict", "SLA episode head changed")
                                    evaluation_history, head = _sla_evaluation_history(
                                        connection, episode["episode_id"], member["occurrence_id"], for_update=True)
                                    evaluation_table = _sla_evaluation_table(connection, episode["episode_id"])
                                    if evaluation_table is g7_sla_evaluations:
                                        from uvm.assessment.g7_clock import read_clock
                                        clock = read_clock(connection, episode["episode_id"],
                                            member["occurrence_id"], now)
                                        if clock.get("state") == "paused":
                                            _error(409, "revision_conflict",
                                                "G7 deadline cannot be revised during an effective exception pause")
                                    if (head is None or head["evaluation_id"] != item["evaluation_id"]
                                            or int(head["revision"]) != item["expected_evaluation_revision"]
                                            or head["head_decision_id"] != item["predecessor_deadline_decision_id"]):
                                        _error(409, "revision_conflict", "SLA evaluation head changed")
                                    current_heads[member["occurrence_id"]] = head
                                    evaluation_tables[member["occurrence_id"]] = evaluation_table
                        if set(current_heads) != set(membership_ids):
                            _error(409, "revision_conflict", "SLA episode membership changed")
                        limits = [grant.get("limits", {}) for grant in scoped_grants
                            if grant.get("limits", {}).get("maximum_deadline_extension_seconds") is not None]
                        if not limits:
                            _error(403, "forbidden", "A bounded deadline-revision grant is required")
                        max_extension = min(item["maximum_deadline_extension_seconds"] for item in limits)
                        for occurrence_id, item in by_member.items():
                            head = current_heads[occurrence_id]
                            revision_history, _ = _sla_evaluation_history(
                                connection, head["episode_id"], occurrence_id, for_update=True)
                            next_revision = next_evaluation_revision(revision_history)
                            baseline = head["original_deadline_at"]
                            revised = item["revised_deadline_at"]
                            try:
                                revised_at = datetime.fromisoformat(revised.replace("Z", "+00:00"))
                            except (ValueError, AttributeError):
                                _error(422, "invalid_command", "Revised deadline must be UTC RFC 3339")
                            if revised_at.tzinfo is None or revised_at.utcoffset() != _UTC.utcoffset(revised_at):
                                _error(422, "invalid_command", "Revised deadline must be an explicit UTC instant")
                            if baseline is None or revised_at <= baseline or (revised_at - baseline).total_seconds() > max_extension:
                                _error(403, "forbidden", "Deadline revision exceeds its cumulative extension limit")
                            revised_eval_id = str(uuid.uuid4())
                            deadline_decision_id = str(uuid.uuid4())
                            evaluation_table = evaluation_tables[occurrence_id]
                            decision_table = (g7_sla_deadline_decisions
                                if evaluation_table is g7_sla_evaluations else sla_deadline_decisions)
                            connection.execute(evaluation_table.insert().values(
                                evaluation_id=revised_eval_id, episode_id=head["episode_id"],
                                occurrence_id=occurrence_id,
                                revision=next_revision,
                                policy_id=head["policy_id"], policy_version=head["policy_version"],
                                reference_binding_id=head["reference_binding_id"],
                                started_at=head["started_at"], original_deadline_at=baseline,
                                current_deadline_at=revised_at.astimezone(_UTC),
                                deadline_basis="authorised_revision", gap_reasons=head["gap_reasons"],
                                predecessor_evaluation_id=head["evaluation_id"],
                                derivation_kind="writer",
                                clock_reset_event_id=head.get("clock_reset_event_id"),
                                clock_reset_absorbed=True,
                                head_decision_id=deadline_decision_id, is_authoritative=True,
                                effective_at=now, known_at=now))
                            connection.execute(decision_table.insert().values(
                                decision_id=deadline_decision_id, episode_id=head["episode_id"],
                                occurrence_id=occurrence_id, evaluation_id=revised_eval_id,
                                predecessor_decision_id=head["head_decision_id"],
                                original_deadline_at=baseline, revised_deadline_at=revised_at.astimezone(_UTC),
                                actor_id=principal, rationale=rationale, evidence_ref=evidence_ref,
                                audit_event_id=audit_event_id, created_at=now))
                            sla_write_evidence.append({"episode_id": head["episode_id"],
                                "occurrence_id": occurrence_id, "before_evaluation_id": head["evaluation_id"],
                                "before_revision": int(head["revision"]), "evaluation_id": revised_eval_id,
                                "revision": next_revision,
                                "deadline_decision_id": deadline_decision_id,
                                "original_deadline_at": _utc_z(baseline),
                                "revised_deadline_at": _utc_z(revised_at)})
                        after = old_document
                    else:
                        material_members = []
                        if action == "severity.override":
                            from uvm.assessment.g7_clock import read_clock
                            rank = {"informational": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
                            for record in episode_records:
                                for member in record["members"]:
                                    occurrence_id = member["occurrence_id"]
                                    if occurrence_id not in membership_ids:
                                        continue
                                    episode_id = record["episode"]["episode_id"]
                                    if _sla_evaluation_table(connection, episode_id) is not g7_sla_evaluations:
                                        continue
                                    _, head = _sla_evaluation_history(connection, episode_id, occurrence_id, for_update=True)
                                    selected = connection.execute(sa.select(sla_policy_versions.c.document).where(
                                        sla_policy_versions.c.policy_id == head["policy_id"],
                                        sla_policy_versions.c.version == head["policy_version"])).scalar_one() if head else {}
                                    from uvm.assessment.g7_clock import classification_source_ratings
                                    previous, _ = resolve_classification(
                                        classification_source_ratings(connection, occurrence_id, now),
                                        selected.get("classification", {}).get("source_rating_map", {}),
                                        override=_membership_assessed_severity(connection, target_id, occurrence_id))
                                    requested_severity = payload["assessed_severity"]
                                    material = (previous in rank and rank[requested_severity] > rank[previous]
                                        and policy.get("acceptance_material_changes", {}).get("severity_increase", True))
                                    if material:
                                        material_members.append(occurrence_id)
                                    elif previous != requested_severity and read_clock(connection, episode_id, occurrence_id, now)["state"] == "paused":
                                        _error(409, "revision_conflict", "End the effective pause before a nonmaterial classification revision")
                        after = _apply_group_action(old_document, action, payload, membership_ids,
                            current_membership, principal, policy, target_id, now, native_severity,
                            successor_evidence, scoped_grants,
                            {**effective_members, "__material_severity_members__": material_members, "__episode_outstanding__": sorted({
                                member["occurrence_id"] for record in episode_records
                                for member in record["members"]
                                if member["status"] == "outstanding"})},
                            routing_evaluation=_evaluate_routing(policy, source_family, current_policy_revision))
                        if g7_exception_command:
                            if action == "acceptance.submit":
                                after["acceptances"][-1]["submitted_guards"] = exception_guards
                            else:
                                approved_request = next(item for item in after["acceptances"]
                                    if item["acceptance_id"] == payload["acceptance_id"])
                                approved_request["approvals"][-1]["policy_revision"] = current_policy_revision
                                approved_request["approvals"][-1]["authority_context"] = auth_context.document() if auth_context else None
                        prior_acceptances = {item.get("acceptance_id"): item
                            for item in old_document.get("acceptances", [])}
                        for updated in after.get("acceptances", []):
                            prior_acceptance = prior_acceptances.get(updated.get("acceptance_id"))
                            if (prior_acceptance and prior_acceptance.get("exception_contract_version") == 1
                                    and prior_acceptance.get("state") == "active"
                                    and (updated.get("state") in {"suspended", "revoked", "expired"}
                                        or updated.get("suspended_membership_ids") != prior_acceptance.get("suspended_membership_ids"))):
                                terminal_event = ("resumed" if updated["state"] == "expired"
                                    else "suspended" if updated["state"] in {"suspended", "active"} else "revoked")
                                _record_g7_exception_resume(connection, acceptance=updated,
                                    event_type=terminal_event, now=now)
                        if action == "acceptance.approve":
                            selected = next((item for item in after.get("acceptances", [])
                                if item.get("acceptance_id") == payload["acceptance_id"]), None)
                            was_active = any(item.get("acceptance_id") == payload["acceptance_id"]
                                and item.get("state") == "active"
                                for item in old_document.get("acceptances", []))
                            if (selected and selected.get("state") == "active" and not was_active
                                    and selected.get("exception_contract_version") == 1):
                                _record_g7_exception_pause(connection, acceptance=selected,
                                    episode_records=episode_records,
                                    command_id=command_id, now=now)
                                from uvm.assessment.exception_notifications import approval_intents
                                approval_intents(connection, acceptance=selected, group_id=target_id,
                                    policy=policy, now=now)
                    if action == "severity.override":
                        # A classification change after evaluation is an append-only
                        # recalculation in the same authorised/audited transaction.
                        for episode_record in episode_records:
                            episode = episode_record["episode"]
                            for episode_member in episode_record["members"]:
                                occurrence_id = episode_member["occurrence_id"]
                                if occurrence_id not in membership_ids:
                                    continue
                                evaluation_history, head = _sla_evaluation_history(
                                    connection, episode["episode_id"], occurrence_id, for_update=True)
                                if head is None:
                                    continue
                                contract = connection.execute(sa.select(sla_episode_contracts).where(
                                    sla_episode_contracts.c.episode_id == episode["episode_id"])).mappings().first()
                                g7_contract = bool(contract and contract["contract_version"] == 7)
                                evaluation_table = g7_sla_evaluations if g7_contract else sla_evaluations
                                occurrence = connection.execute(sa.select(occurrences).where(
                                    occurrences.c.occurrence_id == occurrence_id)).mappings().first()
                                exposure = connection.execute(sa.select(exposures).where(
                                    exposures.c.exposure_id == occurrence["exposure_id"])).mappings().first() if occurrence else None
                                if occurrence is None or exposure is None:
                                    _error(409, "revision_conflict", "SLA membership source changed during recalculation")
                                member_context = (connection.execute(sa.select(workloads.c.stable_attrs).where(
                                    workloads.c.workload_id == occurrence["workload_id"])).scalar_one_or_none() or {})
                                causal_transition = (_membership_causal_transition(connection,
                                    episode["episode_id"], occurrence, as_of=now, known_at=now)
                                    if not g7_contract else {"started_at": None, "event_id": None, "event": None})
                                causal_start = causal_transition["started_at"]
                                started_at = causal_start or head["started_at"]
                                clock_reset = bool(causal_start is not None and (
                                    causal_start != head["started_at"] or
                                    has_unabsorbed_causal_reset(evaluation_history, head, causal_start,
                                        causal_event_id=causal_transition["event_id"],
                                        causal_known_at=causal_transition["event"]["recorded_at"]
                                            if causal_transition["event"] else None)))
                                if not clock_reset and (not head["policy_id"] or not head["policy_version"]):
                                    continue
                                selected_policy = None
                                reset_event_id = None
                                if clock_reset:
                                    reset_event_id = causal_transition["event_id"]
                                    selected_policy, policy_gap = _sla_policy_for_clock(
                                        connection, exposure["group_id"], member_context or {}, started_at, now)
                                    if selected_policy is None:
                                        policy_doc = {}
                                        policy_id = policy_version_number = None
                                    else:
                                        policy_doc = selected_policy["document"]
                                        policy_id = selected_policy["policy_id"]
                                        policy_version_number = selected_policy["version"]
                                else:
                                    selected_policy = connection.execute(sa.select(sla_policy_versions).where(
                                        sla_policy_versions.c.policy_id == head["policy_id"],
                                        sla_policy_versions.c.version == head["policy_version"])).mappings().first()
                                    if selected_policy is None:
                                        continue
                                    policy_doc = selected_policy["document"]
                                    policy_id = head["policy_id"]
                                    policy_version_number = head["policy_version"]
                                next_revision = next_evaluation_revision(evaluation_history)
                                source_value = payload["assessed_severity"].casefold()
                                rating_map = policy_doc.get("classification", {}).get("source_rating_map", {})
                                mapped_severity, classification_gaps = resolve_classification(
                                    [], rating_map, override=source_value)
                                gaps = list(classification_gaps)
                                eligible = policy_doc.get("eligibility", {}).get("included_severities", [])
                                if mapped_severity is not None and eligible and mapped_severity not in eligible:
                                    gaps.append("severity_not_eligible")
                                durations = policy_doc.get("duration_seconds_by_severity", {})
                                duration = durations.get(mapped_severity) if mapped_severity else None
                                if type(duration) is not int or duration <= 0:
                                    gaps.append("missing_sla_duration")
                                    calculated_deadline = None
                                elif started_at is not None and started_at > now:
                                    gaps.append("awaiting_source_time")
                                    calculated_deadline = None
                                elif started_at is None:
                                    gaps.append("unknown_start")
                                    calculated_deadline = None
                                else:
                                    calculated_deadline = elapsed_deadline(started_at, duration)
                                current_deadline = calculated_deadline
                                deadline_basis = "policy_calculation" if calculated_deadline else "unknown"
                                if clock_reset and selected_policy is None:
                                    gaps.append(policy_gap or "no_applicable_sla_policy")
                                binding_id = (None if clock_reset else head["reference_binding_id"])
                                reference_result = (resolve_policy_reference(connection, policy_doc,
                                    policy_id=policy_id, policy_version=int(policy_version_number),
                                    episode_id=episode["episode_id"], occurrence_id=occurrence_id,
                                    started_at=started_at, as_of=now, known_at=now)
                                    if selected_policy is not None else None)
                                if reference_result is not None:
                                    if reference_result["status"] == "incomplete":
                                        gaps.extend("warning:" + reason
                                            for reason in reference_result["gap_reasons"])
                                    else:
                                        gaps.extend(reference_result["gap_reasons"])
                                    binding_id = reference_result["reference_binding_id"]
                                    if reference_result["status"] == "complete":
                                        current_deadline = datetime.fromisoformat(
                                            reference_result["deadline_at"].replace("Z", "+00:00"))
                                        deadline_basis = "supplied_reference"
                                    elif reference_result["status"] == "conflict":
                                        current_deadline = None
                                        deadline_basis = "unknown"
                                if head["head_decision_id"] and not clock_reset:
                                    current_deadline = head["current_deadline_at"]
                                    deadline_basis = "authorised_revision"
                                evaluation_id = str(uuid.uuid4())
                                original_deadline = (head["original_deadline_at"]
                                    if head["started_at"] == started_at else None)
                                if original_deadline is None and clock_reset:
                                    original_deadline = reset_original_baseline(connection, selected_policy,
                                        group_id=exposure["group_id"], episode_id=episode["episode_id"],
                                        occurrence_id=occurrence_id, started_at=started_at, known_at=now)
                                original_deadline = original_deadline or current_deadline
                                original_deadline, current_deadline, deadline_basis, gaps = guard_pending_anchor(
                                    started_at, now, original_deadline, current_deadline, deadline_basis, gaps)
                                connection.execute(evaluation_table.insert().values(
                                    evaluation_id=evaluation_id, episode_id=episode["episode_id"],
                                    occurrence_id=occurrence_id,
                                    revision=next_revision,
                                    policy_id=policy_id, policy_version=policy_version_number,
                                    reference_binding_id=binding_id, started_at=started_at,
                                    original_deadline_at=original_deadline, current_deadline_at=current_deadline,
                                    deadline_basis=deadline_basis, gap_reasons=sorted(set(gaps)),
                                    predecessor_evaluation_id=head["evaluation_id"],
                                    head_decision_id=(None if clock_reset else head["head_decision_id"]),
                                    derivation_kind="writer",
                                    clock_reset_event_id=(reset_event_id if clock_reset else head.get("clock_reset_event_id")),
                                    clock_reset_absorbed=(True if clock_reset else head.get("clock_reset_absorbed", True)),
                                    is_authoritative=True,
                                    effective_at=now, known_at=now))
                                severity_sla_revisions.append({"episode_id": episode["episode_id"],
                                    "occurrence_id": occurrence_id, "predecessor_evaluation_id": head["evaluation_id"],
                                    "evaluation_id": evaluation_id,
                                    "revision": next_revision,
                                    "original_deadline_at": _utc_z(original_deadline) if original_deadline else None,
                                    "current_deadline_at": _utc_z(current_deadline) if current_deadline else None})
                    if confirmation_command:
                        for record in episode_records:
                            for member in record["members"]:
                                if member["occurrence_id"] not in membership_ids:
                                    continue
                                episode_id = record["episode"]["episode_id"]
                                if _sla_evaluation_table(connection, episode_id) is not g7_sla_evaluations:
                                    continue
                                last = connection.execute(sa.select(sla_clock_events).where(
                                    sla_clock_events.c.episode_id == episode_id,
                                    sla_clock_events.c.occurrence_id == member["occurrence_id"])
                                    .order_by(sla_clock_events.c.sequence.desc()).limit(1)
                                    .with_for_update()).mappings().first()
                                connection.execute(sla_clock_events.insert().values(
                                    event_id=str(uuid.uuid4()), episode_id=episode_id,
                                    occurrence_id=member["occurrence_id"],
                                    sequence=int(last["sequence"]) + 1 if last else 1,
                                    event_type="completed", effective_at=now, recorded_at=now,
                                    ingest_receipt_id=last["ingest_receipt_id"] if last else None,
                                    decision_id=decision_id, membership_ids=membership_ids,
                                    policy_id=last["policy_id"] if last else None,
                                    policy_version=last["policy_version"] if last else None,
                                    evaluation_revision=last["evaluation_revision"] if last else 0,
                                    predecessor_event_id=last["event_id"] if last else None,
                                    data={"confirmation_decision_id": decision_id}))
                        confirm_members(connection, target_id, membership_ids,
                            decision_id=decision_id, actor_id=principal, origin=origin, now=now)
                    if action == "severity.override":
                        after["severity_reference_context"] = {
                            "sla_recalculation": "deferred", "policy_revision": current_policy_revision,
                            "identity_membership_revision": identity_revision,
                            "deadline_references": _reference_context(connection, current_membership)}
                    revision = (max(row["revision"] for row in sla_write_evidence)
                        if action == "sla.deadline.revise" else old_revision + 1)
                    if action != "sla.deadline.revise":
                        if old is None:
                            connection.execute(assessment_group_state.insert().values(
                                group_id=target_id, revision=revision, document=after, updated_at=now))
                        else:
                            connection.execute(assessment_group_state.update().where(
                                assessment_group_state.c.group_id == target_id).values(
                                    revision=revision, document=after, updated_at=now))
                        enqueue_group_projection(connection, target_id, recorded_at=now,
                            assessment_document=after, assessment_revision=revision)
                event_id = audit_event_id
                intent_id = (None if action in _NO_INTENT_POLICY_ACTIONS and not native_action
                    else str(uuid.uuid4()))
                evaluated_identity_context = auth_context.document() if auth_context else None
                if evaluated_identity_context is not None and trusted_github is not None:
                    # Preserve the separately evaluated GitHub account link
                    # alongside the OIDC principal link in the durable record.
                    evaluated_identity_context["github_actor"] = {
                        "link_id": trusted_github["link_id"],
                        "link_revision": trusted_github["link_revision"],
                        "account_id": trusted_github["account_id"],
                        "repository_id": trusted_github["repository_id"],
                        "issue_number": trusted_github["issue_number"],
                        "preview_id": trusted_github["preview_id"],
                        "command_digest": trusted_github["command_digest"],
                    }
                seq = connection.execute(sa.select(sa.func.coalesce(
                    sa.func.max(assessment_audit_events.c.event_sequence), 0) + 1)).scalar_one()
                connection.execute(assessment_audit_events.insert().values(
                    event_id=event_id, event_sequence=seq, actor_id=principal,
                    actor_kind=principals.get(principal, {}).get("actor_kind", "principal"),
                    origin=origin,
                    action=action, target_id=target_id,
                    before_value=old_document,
                    after_value=({"assessment_policy": after,
                        "sla_policy": payload.get("policy"),
                        "sla_policy_head": expected.get("sla_policy", 0) + 1,
                        **({"inventory_configuration": inventory_document,
                            "inventory_policy_head": inventory_revision}
                            if action == "policy.sla.publish" and inventory_document is not None else {})}
                        if action == "policy.sla.publish" else
                        {"deadline_revisions": sla_write_evidence} if action == "sla.deadline.revise" else
                        {**after, "sla_recalculations": severity_sla_revisions}
                            if severity_sla_revisions else after), membership_ids=membership_ids,
                    membership_revision=identity_revision, rationale=rationale,
                    evidence_ref=evidence_ref, policy_revision=current_policy_revision,
                    identity_revision=identity_revision, occurred_at=now, received_at=now,
                    correlation_id=command_id, command_id=command_id,
                    authorization_context=evaluated_identity_context))
                administration_intents = []
                if native_action:
                    state_after = native_state(after)
                    intent_kind = ("administration.ownership.reconcile"
                        if action.startswith("ownership.team.") else "administration.authority.reconcile")
                    intent_target = (payload.get("team_id") if action.startswith("ownership.team.")
                        else payload.get("access_group_id", _ZERO_ID))
                    connection.execute(administration_reconciliation_intents.insert().values(
                        intent_id=intent_id, audit_event_id=event_id, kind=intent_kind,
                        target_id=intent_target, authority_revision=state_after.get(
                            "ownership_revision" if action.startswith("ownership.team.") else "revision", 0),
                        status="pending", attempts=0, last_error=None, created_at=now, updated_at=now))
                    administration_intents.append({"intent_id": intent_id, "kind": intent_kind,
                        "target_id": intent_target, "authority_revision": state_after.get(
                            "ownership_revision" if action.startswith("ownership.team.") else "revision", 0),
                        "status": "pending"})
                elif intent_id is not None and not policy_command and action != "sla.deadline.revise":
                    connection.execute(assessment_projection_intents.insert().values(
                        intent_id=intent_id, event_id=event_id, target_id=target_id,
                        membership_ids=membership_ids, status="pending", created_at=now))
                elif action in {"policy.sla.publish", "sla.deadline.revise"}:
                    connection.execute(reporting_projection_intents.insert().values(
                        intent_id=intent_id, report_id=None, audit_event_id=event_id,
                        kind="reporting.sla.refresh",
                        status="pending", attempts=0, last_error=None,
                        created_at=now, updated_at=now))
                if severity_sla_revisions:
                    refresh_intent_id = str(uuid.uuid4())
                    connection.execute(reporting_projection_intents.insert().values(
                        intent_id=refresh_intent_id, report_id=None, audit_event_id=event_id,
                        kind="reporting.sla.refresh",
                        status="pending", attempts=0, last_error=None,
                        created_at=now, updated_at=now))
                administration_result = None
                if native_action:
                    state_after = native_state(after)
                    if action.startswith("ownership.team."):
                        object_kind = "ownership_team"
                        object_id = payload["team_id"]
                        object_revision = state_after.get("ownership_teams", {}).get(
                            object_id, {}).get("revision")
                    elif action.startswith("access_group."):
                        object_kind = "access_group"
                        object_id = payload["access_group_id"]
                        object_revision = state_after.get("access_groups", {}).get(
                            object_id, {}).get("revision")
                    elif action == "principal.update":
                        object_kind = "principal"
                        object_id = payload["principal_id"]
                        object_revision = None
                    else:
                        object_kind = "authority"
                        object_id = _ZERO_ID
                        object_revision = int(state_after.get("revision", 0))
                    administration_result = {
                        "effect": "native_administration_state_committed",
                        "authority_mode": state_after.get("mode", "legacy"),
                        "policy_revision": revision,
                        "authority_revision": int(state_after.get("revision", 0)),
                        "ownership_revision": int(state_after.get("ownership_revision", 0)),
                        "object_kind": object_kind,
                        "object_id": object_id,
                        "object_revision": object_revision,
                    }
                result = {"schema_version": 1, "command_id": command_id,
                    "decision_id": decision_id, "audit_event_id": event_id,
                    "intent_id": intent_id, "committed_revision": revision,
                    "projection": "none" if action in _NO_INTENT_POLICY_ACTIONS and not native_action else "pending",
                    **({"action": action, "target_id": target_id,
                        "policy_revision": revision, "intents": administration_intents}
                        if native_action else {}),
                    **({"result": administration_result} if native_action else {}),
                    **({"inventory_revision": inventory_revision} if action == "policy.sla.publish"
                        and inventory_revision is not None else {})}
                connection.execute(assessment_command_receipts.insert().values(
                    command_id=command_id, principal_id=principal, action=action,
                    target_id=target_id, request_digest=digest, decision_id=decision_id,
                    audit_event_id=event_id, intent_id=intent_id, result=result, created_at=now,
                    authorization_context=evaluated_identity_context))
            return result
        except HTTPException:
            raise
        except sa.exc.DBAPIError as exc:
            _LOG.exception("Assessment command transaction failed")
            if getattr(exc.orig, "sqlstate", None) in {"40001", "40P01"}:
                _error(409, "revision_conflict", "Concurrent identity or assessment change; refresh and retry")
            if exc.connection_invalidated:
                _error(503, "outcome_unknown",
                    "Database connection was lost during commit; retry the exact command ID")
            raise HTTPException(503, {"code": "persistence_unavailable",
                "message": "Assessment command could not be stored"}) from None
        except sa.exc.SQLAlchemyError:
            _LOG.exception("Assessment command transaction failed")
            raise HTTPException(503, {"code": "persistence_unavailable",
                "message": "Assessment command could not be stored"}) from None

    @app.post("/api/v1/assessment/commands/bulk")
    def submit_bulk(body: dict, request: Request, principal: str = Depends(authenticate)):
        if not isinstance(body, dict) or set(body) != {"commands"}:
            _error(422, "invalid_command", "Bulk request must contain only commands")
        commands = body["commands"]
        if not isinstance(commands, list) or not 1 <= len(commands) <= 100:
            _error(422, "invalid_command", "Bulk commands must contain between 1 and 100 items")
        if any(not isinstance(command, dict) for command in commands):
            _error(422, "invalid_command", "Every bulk command must be an object")
        # Bulk is a transport envelope for independent commands. Each target
        # commits through the same command writer in its own transaction; the
        # exposure guards inside one remediation command remain all-or-none.
        results = []
        for command in commands:
            try:
                receipt = submit_command(command, request, principal)
                results.append({"command_id": command.get("command_id"),
                    "target_id": command.get("target_id"), "status": "committed",
                    "code": "decision_committed", "receipt": receipt, "error": None})
            except HTTPException as exc:
                detail = exc.detail if isinstance(exc.detail, dict) else {
                    "code": "request_error", "message": "Command failed"}
                status = ("denied" if exc.status_code in (401, 403) else
                    "conflict" if exc.status_code == 409 else
                    "invalid" if exc.status_code in (400, 404, 422) else "unavailable")
                results.append({"command_id": command.get("command_id"),
                    "target_id": command.get("target_id"), "status": status,
                    "code": detail.get("code", "request_error"), "receipt": None,
                    "error": {"code": detail.get("code", "request_error"),
                        "message": detail.get("message", "Command failed"),
                        "details": detail.get("details", {}) if status != "denied" else {}}})
        return {"schema_version": 1, "results": results}

    @app.post("/api/v1/assessment/groups/{group_id}/adopt-legacy-episodes")
    def adopt_legacy_episodes(group_id: str, request: Request, principal: str = Depends(authenticate)):
        """Explicitly adopt a read-only G3 baseline before exposing guards."""
        group_id = _uuid(group_id, "group_id")
        now = now_utc()
        with engine.begin() as connection:
            group = connection.execute(sa.select(groups).where(
                groups.c.group_id == group_id).with_for_update()).mappings().first()
            if group is None:
                _error(404, "invalid_command", "Target not found")
            policy = connection.execute(sa.select(assessment_policy).where(
                assessment_policy.c.policy_id == 1).with_for_update()).mappings().first()
            if policy is None:
                _error(503, "persistence_unavailable", "Assessment policy is unavailable")
            auth_service = getattr(app.state, "oidc_auth", None)
            auth_context = auth_service.final_context(connection, request) if auth_service else None
            read_grants = _require_authority(policy["document"], principal, "assessment.read",
                group_id, group["source_family"], origin="local_api",
                correlation_id=str(uuid.uuid4()))
            confirm_grants = _require_authority(policy["document"], principal, "remediation.confirm_group",
                group_id, group["source_family"], origin="local_api",
                correlation_id=str(uuid.uuid4()))
            from uvm.auth.service import group_scope_covered
            granting_groups = ({grant.get("principal_id") for grant in read_grants}
                & {grant.get("principal_id") for grant in confirm_grants})
            if auth_context is not None and not group_scope_covered(connection,
                    auth_context, [group_id], granting_identity_groups=granting_groups):
                _error(403, "source_scope_forbidden", "Current exact source scope is required")
            _lock_group_membership(connection, group_id)
            records = ensure_current_episodes(connection, group_id, now=now,
                actor_id=principal, origin="authorised_legacy_episode_adoption")
        return {"schema_version": 1, "group_id": group_id,
            "adopted": True, "episodes": public_episode_view(records)}

    def _read_group_view(group_id: str, principal: str, *, _connection=None,
            _read_as_of: datetime | None = None, _group_row=None,
            _policy_row=None, _github_link=None):
        read_stage("handler_start")
        group_id = _uuid(group_id, "group_id")
        read_stage("connection_acquisition_start")
        read_context = (engine.connect().execution_options(isolation_level=(
            "REPEATABLE READ" if engine.dialect.name == "postgresql" else "SERIALIZABLE"))
            if _connection is None else nullcontext(_connection))
        with read_context as connection:
            group = (_group_row if _group_row is not None else connection.execute(
                sa.select(groups).where(groups.c.group_id == group_id)).mappings().first())
            if group is None:
                _error(404, "invalid_command", "Target not found")
            policy_row = (_policy_row if _policy_row is not None else connection.execute(
                sa.select(assessment_policy).where(assessment_policy.c.policy_id == 1))
                .mappings().first())
            grants = (_scoped_grants(policy_row["document"], principal,
                "assessment.read", group_id, group["source_family"], include_unresolved=True) if policy_row else [])
            grants = _source_covered_grants(connection, grants, group_id)
            if not grants:
                _error(403, "forbidden", "Access forbidden")
            from uvm.auth.service import group_scope_covered
            if not group_scope_covered(connection, AUTHORITY_CONTEXT.get(), [group_id],
                    granting_identity_groups=[grant.get("principal_id") for grant in grants]):
                _error(403, "source_scope_forbidden", "Current exact source scope is required")
            membership_ids, identity_revision = _membership(connection, group_id)
            episode_records = read_current_episodes(connection, group_id)
            occurrence_rows = connection.execute(sa.select(
                occurrences.c.occurrence_id, occurrences.c.first_observed_at,
                occurrences.c.first_ingested_at)
                .select_from(occurrences.join(exposures,
                    occurrences.c.exposure_id == exposures.c.exposure_id))
                .where(exposures.c.group_id == group_id)
                .order_by(occurrences.c.occurrence_id)).all()
            native_row = connection.execute(sa.select(
                source_observations.c.source_rating,
                source_observations.c.source_family,
                source_observations.c.observed_at)
                .select_from(source_observations.join(occurrences,
                    source_observations.c.occurrence_id == occurrences.c.occurrence_id)
                    .join(exposures, occurrences.c.exposure_id == exposures.c.exposure_id))
                .where(exposures.c.group_id == group_id)
                .order_by(source_observations.c.observed_at.desc().nulls_last(),
                    source_observations.c.retention_order.desc()).limit(1)).mappings().first()
            state = connection.execute(sa.select(assessment_group_state).where(
                assessment_group_state.c.group_id == group_id)).mappings().first()
            github_issue = connection.execute(sa.select(github_group_issues).where(
                github_group_issues.c.group_id == group_id)).mappings().first()
            if _github_link is False:
                github_link = None
            elif _github_link is None:
                github_link = connection.execute(sa.select(github_identity_links).where(
                    github_identity_links.c.principal_id == principal).order_by(
                    github_identity_links.c.updated_at.desc()).limit(1)).mappings().first()
            else:
                github_link = _github_link
            policy_revision = int(policy_row["revision"])
            doc = dict(state["document"]) if state else {}
            owner_revision = int(doc.get("owner_revision", 1))
            owner_names = {entry.get("owner_id"): entry.get("display_name")
                for entry in policy_row["document"].get("owner_directory", [])
                if isinstance(entry, dict) and entry.get("owner_id")}
            owners = [{"owner_id": owner["owner_id"], "owner_type": owner["owner_type"],
                "display_name": owner_names.get(owner["owner_id"]) or owner["owner_id"]}
                for owner in doc.get("owners", [])]
            episode_member_status = {member["occurrence_id"]: (
                "review" if record.get("adoption_required") else member["status"])
                for record in episode_records for member in record["members"]}
            portions = []
            for portion in doc.get("portions", []):
                row = dict(portion)
                if not row.get("active", True):
                    # Retired portions are immutable historical snapshots. Keep
                    # their recorded completion separate from today's episodes.
                    # Materialise the stable DTO pair from that archived
                    # snapshot only; current episode coverage must never
                    # rewrite a predecessor portion's history.
                    historical_members = list(row.get("membership_ids", []))
                    archived_completed = row.get("completed_membership_ids", [])
                    historical_completed = list(archived_completed) if isinstance(
                        archived_completed, list) else []
                    archived_outstanding = row.get("outstanding_membership_ids")
                    row["completed_membership_ids"] = historical_completed
                    row["outstanding_membership_ids"] = (list(archived_outstanding)
                        if isinstance(archived_outstanding, list) else [member for member in
                            historical_members if member not in set(historical_completed)])
                    portions.append(row)
                    continue
                current_portion_members = [member for member in row.get("membership_ids", [])
                    if member in membership_ids]
                row["completed_membership_ids"] = [member for member in current_portion_members
                    if episode_member_status.get(member) in {"confirmed", "continuity_covered"}]
                row["outstanding_membership_ids"] = [member for member in current_portion_members
                    if episode_member_status.get(member) not in {"confirmed", "continuity_covered"}]
                portions.append(row)
            pending = connection.execute(sa.select(assessment_projection_intents).where(
                assessment_projection_intents.c.target_id == group_id,
                assessment_projection_intents.c.status.in_(["pending", "uncertain"])).order_by(
                    assessment_projection_intents.c.created_at)).mappings().all()
            latest = connection.execute(sa.select(assessment_command_receipts).where(
                assessment_command_receipts.c.target_id == group_id,
                assessment_command_receipts.c.action != "report.create").order_by(
                    assessment_command_receipts.c.created_at.desc()).limit(1)).mappings().first()
            current_members = set(membership_ids)
            read_stage("acceptance_coverage_start")
            effective_acceptance_members = set()
            acceptance_views = []
            reconciliation_pending_ids = set()
            for acceptance in doc.get("acceptances", []):
                view = dict(acceptance)
                covered = set(acceptance.get("membership_ids", [])) - set(acceptance.get("suspended_membership_ids", []))
                expires_at = datetime.fromisoformat(
                    acceptance["expires_at"].replace("Z", "+00:00"))
                if (acceptance.get("exception_contract_version") == 1
                        and acceptance.get("state") in {"active", "suspended"}
                        and expires_at <= (_read_as_of or now_utc())):
                    view["recorded_state"] = acceptance["state"]
                    view["state"] = "expired"
                current_coverage = []
                coverage_invalidations = []
                for item in acceptance.get("successor_coverage", []):
                    public_item = _public_reconciliation_record(item)
                    if (item.get("accepted") is True and item.get("permitted") is True
                            # In the PostgreSQL read's repeatable snapshot, a
                            # head mismatch already makes coverage invalid.
                            # Matching heads still require the full proof;
                            # guarded writes retain their original lock/order.
                            and (engine.dialect.name != "postgresql"
                                or _coverage_heads_are_current(connection, engine,
                                    item.get("_identity_binding")))
                            and _coverage_binding_is_current(connection, engine, item)):
                        current_coverage.append(public_item)
                        covered.add(item.get("successor_occurrence_id"))
                    else:
                        coverage_invalidations.append({
                            "resolution_id": item["resolution_id"],
                            "predecessor_occurrence_id": item["predecessor_occurrence_id"],
                            "successor_occurrence_id": item["successor_occurrence_id"],
                            "reason": "identity_correspondence_changed"})
                if acceptance.get("exception_contract_version") == 1 and acceptance.get("state") != "pending":
                    current_bindings = {(member["occurrence_id"], record["episode"]["episode_id"])
                        for record in episode_records for member in record["members"]}
                    covered &= {snapshot["occurrence_id"] for snapshot in acceptance.get("pause_snapshots", [])
                        if (snapshot["occurrence_id"], snapshot["episode_id"]) in current_bindings}
                effective_now = (acceptance.get("state") == "active"
                    and expires_at > (_read_as_of or now_utc()))
                if effective_now:
                    effective = covered & current_members
                    effective_acceptance_members.update(effective)
                    if acceptance.get("continuity_allowed") is True:
                        reconciliation_pending_ids.update(current_members - covered)
                else:
                    effective = set()
                view["successor_coverage"] = current_coverage
                view["coverage_invalidations"] = coverage_invalidations
                view["effective_membership_ids"] = sorted(effective)
                view["reconciliation_history"] = [
                    _public_reconciliation_record(item)
                    for item in acceptance.get("reconciliation_history", [])
                ]
                if acceptance.get("exception_contract_version") == 1:
                    from uvm.assessment.g7_clock import read_clock
                    clock_views = []
                    read_at = _read_as_of or now_utc()
                    for occurrence_id in acceptance.get("membership_ids", []):
                        episode_id = next((snapshot["episode_id"] for snapshot in acceptance.get("pause_snapshots", [])
                            if snapshot["occurrence_id"] == occurrence_id), None)
                        if episode_id is None:
                            continue
                        events = connection.execute(sa.select(sla_clock_events).where(
                            sla_clock_events.c.episode_id == episode_id,
                            sla_clock_events.c.occurrence_id == occurrence_id).order_by(
                                sla_clock_events.c.sequence)).mappings().all()
                        if not events or not any(event["decision_id"] == acceptance["acceptance_id"]
                                for event in events):
                            continue
                        projected = read_clock(connection, episode_id, occurrence_id, read_at)
                        clock_views.append({"occurrence_id": occurrence_id,
                            "event_id": projected.get("event_id"), **projected})
                    view["sla_clock"] = clock_views
                acceptance_views.append(view)
            completed_members = {member for member, status in episode_member_status.items()
                if status in {"confirmed", "continuity_covered"}}
            episode_outstanding_ids = sorted({member["occurrence_id"]
                for record in episode_records if not record.get("adoption_required")
                for member in record["members"] if member["status"] == "outstanding"})
            episode_review_ids = sorted({member["occurrence_id"]
                for record in episode_records for member in record["members"]
                if record.get("adoption_required") or member["status"] == "review"})
            read_stage("acceptance_coverage_complete")
            actionable_ids = sorted(set(episode_outstanding_ids) - effective_acceptance_members)
            reconciliation_pending_ids &= set(actionable_ids)
            routing = _evaluate_routing(policy_row["document"], group["source_family"], policy_revision)
            if "history" in doc.get("routing", {}):
                routing["history"] = doc["routing"]["history"]
            override = doc.get("routing", {}).get("override")
            if override is not None:
                routing["override"] = override
                if override.get("status") == "active":
                    routing.update(status="assigned", owner_ids=override["owner_ids"])
            reference_context = {item["occurrence_id"]: item
                for item in _reference_context(connection, membership_ids)}
            read_stage("reference_repository_complete")
            clocks = []
            for row in occurrence_rows:
                context = reference_context[row.occurrence_id]
                supplied = context["deadline_reference"]
                deadline = supplied["deadline_at"] if supplied else None
                clocks.append({"occurrence_id": row.occurrence_id,
                    "first_observed_at": _utc_z(row.first_observed_at),
                    "first_ingested_at": _utc_z(row.first_ingested_at),
                    "deadline_at": deadline, "deadline_status": "known" if deadline is not None else "unknown",
                    "policy_ref": supplied["policy_ref"] if supplied else None,
                    "deadline_reference_revision": context["deadline_reference_revision"],
                    "deadline_reference": supplied})
        # This initial vertical slice exposes actual identity and persisted severity state;
        # later O1 milestones fill scanner clocks, ownership, portions and acceptance history.
        read_stage("handler_result_serialization_start")
        github_view = ({"state": github_issue["state"],
            "repository_id": github_issue["repository_id"],
            "issue_number": github_issue["issue_number"],
            "issue_url": github_issue["issue_url"],
            "desired_revision": github_issue["desired_revision"],
            "applied_revision": github_issue["applied_revision"],
            "last_reconciled_at": _utc_z(github_issue["last_reconciled_at"]),
            "discrepancy_codes": github_issue["discrepancy_codes"]}
            if github_issue else {"state": "unlinked", "repository_id": None,
                "issue_number": None, "issue_url": None, "desired_revision": 0,
                "applied_revision": 0, "last_reconciled_at": None,
                "discrepancy_codes": []})
        github_identity_view = ({"link_state": "linked" if github_link["enabled"] else "revoked",
            "repository_id": github_issue["repository_id"] if github_issue else None,
            "account_id": github_link["account_id"],
            "principal_id": github_link["principal_id"],
            "link_revision": github_link["revision"]}
            if github_link else {"link_state": "unlinked", "repository_id": None,
                "account_id": None, "principal_id": None, "link_revision": 0})
        return {"schema_version": 1,
            "group": {"group_id": group_id, "source_family": group["source_family"],
                "native_id_scheme": group["native_id_scheme"],
                "native_id_authority": group["native_id_authority"],
                "native_id_value": group["native_id_value"],
                "identity_revision": int(group["revision"])},
            "assessment": {"revision": int(state["revision"]) if state else 1,
                "policy_revision": policy_revision, "owner_revision": owner_revision,
                "native_severity": ({"value": native_row["source_rating"],
                    "source": native_row["source_family"],
                    "observed_at": native_row["observed_at"].isoformat().replace("+00:00", "Z")
                        if native_row["observed_at"] else None}
                    if native_row and native_row["source_rating"] is not None else None),
                "assessed_severity": doc.get("assessed_severity"),
                "owners": owners, "portions": portions,
                "routing": routing,
                "acceptances": acceptance_views,
                "membership": {"revision": identity_revision,
                    "outstanding_ids": episode_outstanding_ids,
                    "review_ids": episode_review_ids,
                    "completed_ids": sorted(completed_members),
                    "reconciliation_pending_ids": sorted(reconciliation_pending_ids),
                    "actionable_ids": actionable_ids},
                "clocks": clocks,
                "latest_receipt": dict(latest["result"]) if latest else None,
                "pending_projection_intents": [{"intent_id": row["intent_id"],
                    "membership_ids": row["membership_ids"], "status": row["status"]} for row in pending]},
            "episodes": public_episode_view(episode_records),
            "github_identity": github_identity_view,
            "github": github_view,
            "audit": {"next_cursor": None}}

    @app.get("/api/v1/assessment/groups/{group_id}")
    def read_group(group_id: str, principal: str = Depends(authenticate)):
        return _read_group_view(group_id, principal)

    def _warning_scope(connection, group_id, principal, request):
        from uvm.persistence.assessment_schema import assessment_policy
        group = connection.execute(sa.select(groups).where(groups.c.group_id == group_id)).mappings().one_or_none()
        state = connection.execute(sa.select(assessment_group_state).where(
            assessment_group_state.c.group_id == group_id)).mappings().one_or_none()
        policy = connection.execute(sa.select(assessment_policy.c.document).where(
            assessment_policy.c.policy_id == 1)).scalar_one_or_none()
        if group is None:
            _error(404, "invalid_command", "Target not found")
        if not isinstance(policy, dict):
            _error(503, "persistence_unavailable", "Assessment policy is unavailable")
        grants = _require_authority(policy, principal, "assessment.read", group_id,
            group["source_family"], correlation_id=str(uuid.uuid4()), connection=connection)
        auth_service = getattr(app.state, "oidc_auth", None)
        auth_context = auth_service.final_context(connection, request) if auth_service else None
        if auth_context is not None:
            from uvm.auth.service import group_scope_covered
            if not group_scope_covered(connection, auth_context, [group_id],
                    granting_identity_groups=[grant.get("principal_id") for grant in grants]):
                _error(403, "source_scope_forbidden", "Current exact source scope is required")
        return group, policy, (state["document"] if state else {})

    @app.get("/api/v1/assessment/groups/{group_id}/exception-warnings")
    def read_exception_warnings(group_id: str, request: Request,
                                principal: str = Depends(authenticate)):
        group_id = _uuid(group_id, "group_id")
        with engine.begin() as connection:
            group, _, document = _warning_scope(connection, group_id, principal, request)
            decisions = [item.get("acceptance_id") for item in
                document.get("acceptances", []) if item.get("acceptance_id")]
            if not decisions:
                return {"schema_version": 1, "group_id": group_id, "items": []}
            intents = connection.execute(sa.select(exception_warning_intents).where(
                exception_warning_intents.c.decision_id.in_(decisions)).order_by(
                    exception_warning_intents.c.created_at,
                    exception_warning_intents.c.intent_id)).mappings().all()
            items = []
            for intent in intents:
                attempts = connection.execute(sa.select(exception_warning_attempts).where(
                    exception_warning_attempts.c.intent_id == intent["intent_id"]).order_by(
                        exception_warning_attempts.c.attempt_number)).mappings().all()
                items.append({"intent_id": intent["intent_id"], "decision_id": intent["decision_id"],
                    "expiry_revision": intent["expiry_revision"], "offset_seconds": intent["offset_seconds"],
                    "channel": intent["channel"], "destination_ref": intent["destination_ref"],
                    "status": intent["status"], "suppression_reason": intent["suppression_reason"],
                    "route_revision": intent["route_revision"],
                    "provider_receipt_basis": intent["provider_receipt_basis"],
                    "due_at": _utc_z(intent["due_at"]),
                    "retry": {"attempts": len(attempts), "max_attempts": intent["max_attempts"],
                        "base_delay_seconds": intent["retry_base_seconds"]},
                    "next_attempt_at": _utc_z(intent["next_attempt_at"]) if intent["next_attempt_at"] else None,
                    "acknowledged_at": _utc_z(intent["acknowledged_at"]) if intent["acknowledged_at"] else None,
                    "acknowledged_by": intent["acknowledged_by"],
                    "attempts": [{"attempt_number": item["attempt_number"],
                        "attempted_at": _utc_z(item["attempted_at"]),
                        "finished_at": _utc_z(item["finished_at"]) if item["finished_at"] else None,
                        "outcome": item["outcome"], "receipt": item["receipt"], "error": item["error"]}
                        for item in attempts]})
        return {"schema_version": 1, "group_id": group_id, "items": items}

    @app.post("/api/v1/assessment/groups/{group_id}/exception-warnings/{intent_id}/acknowledge")
    def acknowledge_exception_warning(group_id: str, intent_id: str, request: Request,
                                      principal: str = Depends(authenticate)):
        group_id, intent_id = _uuid(group_id, "group_id"), _uuid(intent_id, "intent_id")
        now = now_utc()
        with engine.begin() as connection:
            lock_policy(connection)
            group, _, document = _warning_scope(connection, group_id, principal, request)
            decisions = {item.get("acceptance_id") for item in
                document.get("acceptances", [])}
            intent = connection.execute(sa.select(exception_warning_intents).where(
                exception_warning_intents.c.intent_id == intent_id).with_for_update()).mappings().one_or_none()
            if intent is None or intent["decision_id"] not in decisions:
                _error(404, "invalid_command", "Target not found")
            if intent["status"] != "sent":
                _error(409, "invalid_command", "Only a delivered warning receipt can be acknowledged")
            policy_row = connection.execute(sa.select(assessment_policy).where(
                assessment_policy.c.policy_id == 1).with_for_update()).mappings().one()
            auth_service = getattr(app.state, "oidc_auth", None)
            auth_context = auth_service.final_context(connection, request) if auth_service else None
            from uvm.assessment.exception_warning_receipts import acknowledge_warning_receipt
            try:
                receipt = acknowledge_warning_receipt(connection, intent_id=intent_id,
                    principal_id=principal, group_id=group_id,
                    policy_revision=int(policy_row["revision"]),
                    authorization_context=auth_context, now=now,
                    origin="browser_authenticated_receipt",
                    evidence_ref="browser_warning_receipt:" + intent_id)
            except ValueError as exc:
                _error(409, "invalid_command", str(exc))
        return {"schema_version": 1, **receipt,
            "acknowledged_at": _utc_z(receipt["acknowledged_at"])}

    @app.get("/api/v1/assessment/groups/{group_id}/exception-warning-failure-alerts")
    def read_exception_warning_failure_alerts(group_id: str, request: Request,
                                               principal: str = Depends(authenticate)):
        """Read configuration failures only after current complete group authority."""
        group_id = _uuid(group_id, "group_id")
        with engine.begin() as connection:
            _group, policy, _document = _warning_scope(connection, group_id, principal, request)
            auth_service = getattr(app.state, "oidc_auth", None)
            auth_context = auth_service.final_context(connection, request) if auth_service else None
            rows = connection.execute(sa.select(exception_warning_failure_alerts,
                exception_warning_intents.c.channel,
                exception_warning_intents.c.status.label("intent_status"),
                exception_warning_intents.c.approved_failure_alert_group_ids)
                .select_from(exception_warning_failure_alerts.join(exception_warning_intents,
                    exception_warning_intents.c.intent_id == exception_warning_failure_alerts.c.intent_id))
                .where(exception_warning_failure_alerts.c.group_id == group_id)
                .order_by(exception_warning_failure_alerts.c.created_at,
                    exception_warning_failure_alerts.c.alert_id)).mappings().all()
            if native_state(policy).get("mode") == NATIVE_MODE:
                if auth_context is None:
                    _error(403, "source_scope_forbidden", "Current warning alert group membership is required")
                # Resolve recipient-group membership from current native state,
                # rather than trusting a potentially stale token/group claim.
                member_groups = set(effective_access(policy,
                    auth_context.principal_id)[0])
                visible_rows = [row for row in rows if member_groups.intersection(
                    row["approved_failure_alert_group_ids"] or [])]
                if rows and not visible_rows:
                    _error(403, "source_scope_forbidden", "Configured warning alert group membership is required")
                rows = visible_rows
        return {"schema_version": 1, "group_id": group_id,
            "items": [{"alert_id": row["alert_id"], "intent_id": row["intent_id"],
                "attempt_id": row["attempt_id"], "channel": row["channel"],
                "status": row["intent_status"], "reason": row["reason"],
                "created_at": _utc_z(row["created_at"])} for row in rows]}

    @app.get("/api/v1/assessment/groups")
    def read_groups(native_id: str | None = None, source_family: str | None = None,
            cve: str | None = None, native_severity: str | None = None,
            assessed_severity: str | None = None, owner_id: str | None = None,
            queue: str | None = None, report_id: str | None = None,
            sort: str = "native_id_asc", limit: int = Query(25),
            cursor: str | None = None, principal: str = Depends(authenticate)):
        """Current-authorized, cursor-paged native-group Findings projection."""
        if sort != "native_id_asc":
            _error(400, "invalid_sort", "sort must be native_id_asc")
        if limit not in {10, 25, 50}:
            _error(400, "invalid_limit", "limit must be 10, 25 or 50")
        if queue not in {None, "missing_owner", "sync_conflict", "sla_gap"}:
            _error(400, "invalid_queue", "queue must be missing_owner, sync_conflict or sla_gap")
        if assessed_severity is not None and assessed_severity not in {
                "critical", "high", "medium", "low", "informational", "not_assessed"}:
            _error(400, "invalid_filter", "assessed_severity is not a supported value")
        if (queue == "sla_gap") != (report_id is not None):
            _error(400, "invalid_report_scope", "report_id is required only for the sla_gap queue")
        if report_id is not None:
            try:
                parsed_report_id = str(uuid.UUID(report_id))
            except (ValueError, TypeError, AttributeError):
                _error(400, "invalid_report_id", "report_id must be a UUID")
            if parsed_report_id != report_id:
                _error(400, "invalid_report_id", "report_id must be a canonical UUID")
        for name, value in (("native_id", native_id), ("source_family", source_family),
                ("cve", cve), ("native_severity", native_severity),
                ("assessed_severity", assessed_severity), ("owner_id", owner_id)):
            if value == "":
                _error(400, "invalid_filter", f"{name} must be omitted or non-empty")

        filters = {key: value for key, value in {
            "native_id": native_id, "source_family": source_family, "cve": cve,
            "native_severity": native_severity, "assessed_severity": assessed_severity,
            "owner_id": owner_id, "queue": queue, "report_id": report_id}.items()
            if value is not None}
        secret = app.state.cursor_secret
        cursor_payload = None
        if cursor is not None:
            try:
                raw = base64.urlsafe_b64decode(cursor + "=" * (-len(cursor) % 4))
                encoded_body, encoded_signature = raw.split(b".", 1)
                body = base64.urlsafe_b64decode(encoded_body + b"=" * (-len(encoded_body) % 4))
                signature = base64.urlsafe_b64decode(encoded_signature + b"=" * (-len(encoded_signature) % 4))
                expected_signature = hmac.new(secret, encoded_body, hashlib.sha256).digest()
                cursor_payload = json.loads(body)
                expected_keys = {"endpoint", "version", "principal_id", "filters", "sort",
                    "limit", "offset", "projection_sha256", "valid_until", "as_of"}
                if (set(cursor_payload) != expected_keys
                        or not hmac.compare_digest(signature, expected_signature)
                        or cursor_payload.get("endpoint") != "assessment-groups"
                        or cursor_payload.get("version") != 1
                        or cursor_payload.get("principal_id") != principal
                        or cursor_payload.get("filters") != filters
                        or cursor_payload.get("sort") != sort
                        or cursor_payload.get("limit") != limit
                        or type(cursor_payload.get("offset")) is not int
                        or cursor_payload["offset"] < 0
                        or not isinstance(cursor_payload.get("projection_sha256"), str)
                        or not isinstance(cursor_payload.get("valid_until"), str)
                        or not isinstance(cursor_payload.get("as_of"), str)):
                    raise ValueError("cursor claims do not match this request")
                parsed_as_of = datetime.fromisoformat(cursor_payload["as_of"].replace("Z", "+00:00"))
                if _utc_z(parsed_as_of) != cursor_payload["as_of"]:
                    raise ValueError("cursor as_of is not canonical UTC")
                _parse_cursor_utc(cursor_payload["valid_until"])
            except (ValueError, TypeError, KeyError, json.JSONDecodeError, base64.binascii.Error):
                _error(400, "invalid_cursor", "Findings cursor is invalid")

        with _findings_read_connection(engine) as connection:
            # Sample only after the exporter lock and connection admission.
            # A continuation may have waited beyond a signed or authority
            # boundary while queued for this snapshot.
            admission_now = now_utc()
            policy_row = connection.execute(sa.select(assessment_policy).where(
                assessment_policy.c.policy_id == 1)).mappings().first()
            if policy_row is None:
                _error(503, "persistence_unavailable", "Assessment policy is unavailable")
            policy_document = policy_row["document"]
            policy_revision = int(policy_row["revision"])
            all_groups = connection.execute(sa.select(groups).order_by(
                groups.c.native_id_value, groups.c.group_id)).mappings().all()
            from uvm.auth.service import group_scope_covered
            request_context = AUTHORITY_CONTEXT.get()
            authorized_groups = []
            for row in all_groups:
                grants = _source_covered_grants(connection, _scoped_grants(policy_document,
                    principal, "assessment.read", row["group_id"], row["source_family"], include_unresolved=True), row["group_id"])
                if grants and group_scope_covered(connection, request_context, [row["group_id"]],
                        granting_identity_groups=[grant.get("principal_id") for grant in grants]):
                    authorized_groups.append(dict(row))
            authorized_ids = [row["group_id"] for row in authorized_groups]
            authorized_id_set = set(authorized_ids)
            assessment_authority = {row["group_id"]: sorted(_source_covered_grants(connection,
                _scoped_grants(policy_document, principal, "assessment.read", row["group_id"], row["source_family"], include_unresolved=True),
                row["group_id"]),
                key=lambda grant: json.dumps(grant, sort_keys=True, separators=(",", ":"), default=str))
                for row in authorized_groups}
            authorized_group_by_id = {row["group_id"]: row for row in authorized_groups}
            shared_github_link = connection.execute(sa.select(github_identity_links).where(
                github_identity_links.c.principal_id == principal).order_by(
                github_identity_links.c.updated_at.desc()).limit(1)).mappings().first()

            report_snapshot = None
            report_scope = []
            report_authority = {}
            sla_gap_group_ids: set[str] = set()
            def report_group_authorized(connection, policy, actor, action, group_id):
                family = connection.execute(sa.select(groups.c.source_family).where(
                    groups.c.group_id == group_id)).scalar_one_or_none()
                return bool(family is not None and _complete_target_grants(
                    connection, policy, actor, action, group_id, family))
            if queue == "sla_gap":
                report, whole_report_access = report_scope_read(connection, report_id,
                    principal, policy_document, "report.read", report_group_authorized)
                if report is None:
                    _error(404, "not_found", "Report not found")
                report_scope = report["scope"].get("group_ids", [])
                from uvm.auth.service import group_scope_covered
                report_groups = connection.execute(sa.select(groups.c.group_id,
                    groups.c.source_family).where(groups.c.group_id.in_(report_scope))).mappings().all()
                source_family_by_group = {item["group_id"]: item["source_family"]
                    for item in report_groups}
                report_authority = {group_id: sorted(_source_covered_grants(connection, _scoped_grants(
                    policy_document, principal, "report.read", group_id,
                    source_family_by_group.get(group_id), include_unresolved=True), group_id),
                    key=lambda grant: json.dumps(grant, sort_keys=True, separators=(",", ":"), default=str))
                    for group_id in report_scope}
                if (not whole_report_access or set(source_family_by_group) != set(report_scope)
                        or any(not group_scope_covered(connection, AUTHORITY_CONTEXT.get(), [group_id],
                            granting_identity_groups=[grant.get("principal_id")
                                for grant in report_authority[group_id]])
                            for group_id in report_scope)):
                    _error(403, "forbidden", "Current report authority is required for its whole scope")
                if report["status"] != "ready":
                    _error(409, "projection_not_ready", "Report atoms are not available until projection is ready")
                atom_rows = connection.execute(sa.select(metrics_report_atoms.c.group_id,
                    metrics_report_atoms.c.document).where(
                        metrics_report_atoms.c.report_id == report_id).order_by(
                            metrics_report_atoms.c.ordinal)).mappings().all()
                for atom in atom_rows:
                    metric = atom["document"].get("metric_membership", {}).get("sla_gaps", {})
                    if metric.get("numerator") is True:
                        sla_gap_group_ids.add(atom["group_id"])
                report_snapshot = {"report": dict(report), "atoms": [dict(row) for row in atom_rows]}

            cve_rows = connection.execute(sa.select(group_cve_refs.c.group_id,
                group_cve_refs.c.cve_ref).where(group_cve_refs.c.group_id.in_(authorized_ids))
                .order_by(group_cve_refs.c.group_id, group_cve_refs.c.cve_ref)).all() if authorized_ids else []
            cves_by_group: dict[str, list[str]] = {group_id: [] for group_id in authorized_ids}
            for group_id, cve_value in cve_rows:
                cves_by_group[group_id].append(cve_value)
            occurrence_rows = connection.execute(sa.select(exposures.c.group_id,
                occurrences.c.occurrence_id).select_from(occurrences.join(exposures,
                    occurrences.c.exposure_id == exposures.c.exposure_id)).where(
                        exposures.c.group_id.in_(authorized_ids)).order_by(
                            exposures.c.group_id, occurrences.c.occurrence_id)).all() if authorized_ids else []
            occurrence_ids_by_group: dict[str, set[str]] = {group_id: set() for group_id in authorized_ids}
            for group_id, occurrence_id in occurrence_rows:
                occurrence_ids_by_group[group_id].add(occurrence_id)

            items = []
            temporal_boundaries = []
            detail_by_id = {}
            materialization_now = None
            worker_count = (_findings_worker_limit(engine.pool, len(authorized_ids))
                if engine.dialect.name == "postgresql" else 0)
            if worker_count:
                with _reserve_findings_workers(engine, worker_count) as worker_connections:
                    if not worker_connections:
                        worker_count = 0
                    else:
                        materialization_now = now_utc()
                        if cursor_payload is not None:
                            admitted_deadline = _parse_cursor_utc(cursor_payload["valid_until"])
                            if admitted_deadline <= materialization_now:
                                _error(409, "stale_cursor",
                                    "Findings cursor expired while waiting for database capacity")
                        current_authorized_ids = []
                        for current_group in all_groups:
                            current_group = dict(current_group)
                            current_grants = _complete_target_grants(connection, policy_document,
                                principal, "assessment.read", current_group["group_id"],
                                current_group["source_family"])
                            if current_grants and group_scope_covered(connection,
                                    AUTHORITY_CONTEXT.get(), [current_group["group_id"]],
                                    granting_identity_groups=[grant.get("principal_id")
                                        for grant in current_grants]):
                                current_authorized_ids.append(current_group["group_id"])
                        if current_authorized_ids != authorized_ids:
                            _error(409, "stale_cursor",
                                "Findings authority crossed a temporal boundary during admission")
                        if queue == "sla_gap":
                            _current_report, current_report_access = report_scope_read(
                                connection, report_id, principal, policy_document,
                                "report.read", report_group_authorized)
                            if (_current_report is None or not current_report_access
                                    or _current_report.get("status") != "ready"):
                                _error(403, "forbidden",
                                    "Current whole-report authority is required")
                        snapshot = connection.execute(sa.text(
                            "SELECT pg_export_snapshot()")).scalar_one()
                        batches = [authorized_ids[index::len(worker_connections)]
                            for index in range(len(worker_connections))]
                        def materialize_batch(worker, group_ids):
                            details = {}
                            try:
                                if not re.fullmatch(r"[0-9A-Fa-f-]+", snapshot):
                                    raise RuntimeError("PostgreSQL returned an invalid exported snapshot id")
                                worker.exec_driver_sql(f"SET TRANSACTION SNAPSHOT '{snapshot}'")
                                for group_id in group_ids:
                                    details[group_id] = _read_group_view(group_id, principal,
                                        _connection=worker, _read_as_of=materialization_now,
                                        _group_row=authorized_group_by_id[group_id],
                                        _policy_row=policy_row,
                                        _github_link=shared_github_link if shared_github_link is not None else False)
                                return details
                            finally:
                                worker.rollback()
                        with ThreadPoolExecutor(max_workers=len(worker_connections)) as workers:
                            for details in workers.map(materialize_batch,
                                    worker_connections, batches):
                                detail_by_id.update(details)
            if not worker_count:
                materialization_now = now_utc()
                if cursor_payload is not None and _parse_cursor_utc(
                        cursor_payload["valid_until"]) <= materialization_now:
                    _error(409, "stale_cursor",
                        "Findings cursor expired while waiting for database capacity")
                current_authorized_ids = []
                for current_group in all_groups:
                    current_group = dict(current_group)
                    current_grants = _complete_target_grants(connection, policy_document,
                        principal, "assessment.read", current_group["group_id"],
                        current_group["source_family"])
                    if current_grants and group_scope_covered(connection,
                            AUTHORITY_CONTEXT.get(), [current_group["group_id"]],
                            granting_identity_groups=[grant.get("principal_id")
                                for grant in current_grants]):
                        current_authorized_ids.append(current_group["group_id"])
                if current_authorized_ids != authorized_ids:
                    _error(409, "stale_cursor",
                        "Findings authority crossed a temporal boundary during admission")
                detail_by_id = {group_id: _read_group_view(group_id, principal,
                    _connection=connection, _read_as_of=materialization_now,
                    _group_row=authorized_group_by_id[group_id], _policy_row=policy_row,
                    _github_link=shared_github_link if shared_github_link is not None else False)
                    for group_id in authorized_ids}

            for group_id in authorized_ids:
                try:
                    detail = detail_by_id[group_id]
                except HTTPException as error:
                    if cursor is not None and error.status_code in {403, 404}:
                        _error(409, "stale_cursor", "Findings authority or membership changed; refresh the list")
                    raise
                cve_values = cves_by_group[group_id]
                membership = detail["assessment"]["membership"]
                outstanding = set(membership["outstanding_ids"])
                row = {"group": detail, "cves": cve_values,
                    "occurrence_count": len(occurrence_ids_by_group[group_id]),
                    "outstanding_count": len(outstanding)}
                items.append(row)
                for acceptance in detail["assessment"]["acceptances"]:
                    expiry = acceptance.get("expires_at")
                    if expiry:
                        try:
                            boundary = datetime.fromisoformat(expiry.replace("Z", "+00:00"))
                            if boundary > admission_now:
                                temporal_boundaries.append(boundary)
                        except (ValueError, TypeError):
                            pass

            boundary_rows = [policy_document.get("principals", {}).get(principal, {})]
            boundary_rows += list(policy_document.get("grants", []))
            boundary_rows += list(policy_document.get("roles", {}).values())
            for rule in boundary_rows:
                if not isinstance(rule, dict):
                    continue
                for name in ("effective_from", "effective_until"):
                    value = rule.get(name)
                    if value:
                        try:
                            boundary = datetime.fromisoformat(value.replace("Z", "+00:00"))
                            if boundary > admission_now:
                                temporal_boundaries.append(boundary)
                        except (ValueError, TypeError):
                            pass

            by_group = {item["group"]["group"]["group_id"]: item for item in items}
            source_options = sorted({item["group"]["group"]["source_family"] for item in items})
            cve_options = sorted({cve_value for item in items for cve_value in item["cves"]})
            owner_options_map = {}
            for item in items:
                for owner in item["group"]["assessment"]["owners"]:
                    owner_options_map[(owner["owner_id"], owner["owner_type"])] = owner
            owner_options = [owner_options_map[key] for key in sorted(owner_options_map)]

            def matches_filters(item):
                group = item["group"]["group"]
                assessment = item["group"]["assessment"]
                if native_id is not None and native_id.casefold() not in group["native_id_value"].casefold():
                    return False
                if source_family is not None and group["source_family"] != source_family:
                    return False
                if cve is not None and cve not in item["cves"]:
                    return False
                native_value = assessment["native_severity"]
                if native_severity is not None and not _findings_severity_matches(
                        native_value, native_severity, unknown=native_severity == "unknown"):
                    return False
                assessed = assessment["assessed_severity"]
                if assessed_severity is not None and not _findings_severity_matches(
                        assessed, assessed_severity,
                        unknown=assessed_severity == "not_assessed"):
                    return False
                if owner_id is not None and not any(owner["owner_id"] == owner_id for owner in assessment["owners"]):
                    return False
                github = item["group"]["github"]
                if queue == "missing_owner" and assessment["owners"]:
                    return False
                if queue == "sync_conflict" and not _github_sync_conflict_matches(github):
                    return False
                if queue == "sla_gap" and group["group_id"] not in sla_gap_group_ids:
                    return False
                return True

            matched_items = sorted((item for item in items if matches_filters(item)),
                key=lambda item: (item["group"]["group"]["native_id_value"],
                    item["group"]["group"]["group_id"]))
            total_groups = len(matched_items)
            total_occurrences = sum(item["occurrence_count"] for item in matched_items)
            projection = {"policy_revision": policy_revision, "policy_document": policy_document,
                "authorized_group_ids": authorized_ids, "assessment_authority": assessment_authority,
                "report_authority": report_authority, "items": items,
                "filter_options": {"source_families": source_options, "cves": cve_options,
                    "owners": owner_options}, "totals": {"total_groups": total_groups,
                    "total_occurrences": total_occurrences}, "report": report_snapshot}
            projection_sha256 = hashlib.sha256(json.dumps(projection, sort_keys=True,
                separators=(",", ":"), ensure_ascii=True, default=str).encode()).hexdigest()
            valid_until_at = _findings_cursor_deadline(materialization_now,
                cursor_payload.get("valid_until") if cursor_payload else None,
                temporal_boundaries)
            if cursor_payload is not None:
                if (valid_until_at is None
                        or cursor_payload["projection_sha256"] != projection_sha256):
                    _error(409, "stale_cursor", "Findings projection or authority changed; refresh the list")
                offset = cursor_payload["offset"]
                if offset > total_groups:
                    _error(409, "stale_cursor", "Findings list changed; refresh the list")
            else:
                if valid_until_at is None:
                    _error(409, "stale_cursor", "Findings projection changed at a temporal boundary; refresh the list")
                offset = 0
            response_now = now_utc()
            valid_until_at = _findings_cursor_deadline(response_now,
                _utc_z(valid_until_at) if valid_until_at is not None else None,
                temporal_boundaries)
            if valid_until_at is None:
                _error(409, "stale_cursor",
                    "Findings authority or acceptance crossed a temporal boundary during materialization")
            page = matched_items[offset:offset + limit]
            next_cursor = None
            if offset + len(page) < total_groups:
                payload = {"endpoint": "assessment-groups", "version": 1,
                    "principal_id": principal, "filters": filters, "sort": sort,
                    "limit": limit, "offset": offset + len(page),
                    "projection_sha256": projection_sha256,
                    "valid_until": _utc_z(valid_until_at),
                    "as_of": cursor_payload["as_of"] if cursor_payload else _utc_z(materialization_now)}
                body = base64.urlsafe_b64encode(json.dumps(payload, sort_keys=True,
                    separators=(",", ":"), ensure_ascii=True).encode()).rstrip(b"=")
                signature = base64.urlsafe_b64encode(hmac.new(secret, body, hashlib.sha256).digest()).rstrip(b"=")
                signed = body + b"." + signature
                next_cursor = base64.urlsafe_b64encode(signed).decode("ascii").rstrip("=")
        return {"schema_version": 1,
            "as_of": cursor_payload["as_of"] if cursor_payload else _utc_z(materialization_now), "items": page,
            "total_groups": total_groups, "total_occurrences": total_occurrences,
            "next_cursor": next_cursor, "filter_options": {"source_families": source_options,
                "cves": cve_options, "owners": owner_options}}

    @app.get("/api/v1/assessment/permissions")
    def permissions(group_id: str = Query(...), principal: str = Depends(authenticate)):
        group_id = _uuid(group_id, "group_id")
        with engine.connect() as connection:
            source_family = connection.execute(sa.select(groups.c.source_family).where(
                groups.c.group_id == group_id)).scalar_one_or_none()
            policy_row = connection.execute(sa.select(assessment_policy).where(
                assessment_policy.c.policy_id == 1)).mappings().first()
            grants = (_complete_target_grants(connection, policy_row["document"], principal,
                "assessment.read", group_id, source_family) if policy_row and source_family else [])
            from uvm.auth.service import group_scope_covered
            scope_allowed = group_scope_covered(connection, AUTHORITY_CONTEXT.get(), [group_id],
                granting_identity_groups=[grant.get("principal_id") for grant in grants])
        if source_family is None or policy_row is None or not scope_allowed or not grants:
            _error(403, "forbidden", "Access forbidden")
        document = policy_row["document"]
        grants = document.get("grants", [])
        denies = document.get("denies", [])
        authority_ids = _policy_authority_ids(document, principal) | {"*"}
        candidate_actions = {action for grant in grants
            if grant.get("principal_id") in authority_ids
            for action in grant.get("actions", []) if action != "*"}
        for grant in grants:
            if grant.get("principal_id") in authority_ids and grant.get("role_id") in document.get("roles", {}):
                candidate_actions.update(document["roles"][grant["role_id"]].get("actions", []))
        wildcard_grant = any(grant.get("principal_id") in authority_ids
            and "*" in grant.get("actions", []) for grant in grants)
        wildcard_role = any(grant.get("principal_id") in authority_ids
            and grant.get("role_id") in document.get("roles", {})
            and "*" in document["roles"][grant["role_id"]].get("actions", [])
            for grant in grants)
        if wildcard_grant or wildcard_role:
            candidate_actions.update(_ACTIONS)
        candidate_actions.discard("*")
        with engine.connect() as connection:
            actions = sorted(action for action in candidate_actions
                if _complete_target_grants(connection, document, principal, action,
                    group_id, source_family))
            can_read_directory = bool(_complete_target_grants(connection, document,
                principal, "owners.directory.read", group_id, source_family))
            can_read_policy = bool(_complete_target_grants(connection, document,
                principal, "policy.read", group_id, source_family))
        directory = [{key: entry[key] for key in
                      ("owner_id", "owner_type", "display_name", "enabled")}
                     for entry in document.get("owner_directory", [])
                     if isinstance(entry, dict) and entry.get("enabled", True)
                     and can_read_directory
                     and ("visible_to_principals" not in entry
                          or principal in entry["visible_to_principals"]
                          or "*" in entry["visible_to_principals"])]
        visible_grants = []
        roles = document.get("roles", {})
        for grant in grants:
            if not can_read_policy and grant.get("principal_id") not in authority_ids:
                continue
            role = roles.get(grant.get("role_id"), {})
            if role:
                scope = role.get("target_scope", {})
                visible_grants.append({
                    "grant_id": grant.get("grant_id"), "role_id": grant.get("role_id"),
                    "principal_id": grant.get("principal_id"), "actions": role.get("actions", []),
                    "target_scope": _complete_policy_scope(scope),
                    "limits": _complete_policy_limits(role.get("limits")),
                    "separation_of_duties": _complete_policy_duties(role.get("separation_of_duties")),
                    "effective_from": grant.get("effective_from"),
                    "effective_until": grant.get("effective_until")})
            else:
                visible_grants.append({
                    "grant_id": grant.get("grant_id"), "role_id": grant.get("role_id"),
                    "principal_id": grant.get("principal_id"), "actions": grant.get("actions", []),
                    "target_scope": _complete_policy_scope(grant.get("target_scope", {
                        "group_ids": grant.get("target_ids", [])})),
                    "limits": _complete_policy_limits(grant.get("limits")),
                    "separation_of_duties": _complete_policy_duties(grant.get("separation_of_duties")),
                    "effective_from": grant.get("effective_from"),
                    "effective_until": grant.get("effective_until")})
        # Serialize the persisted denial identifier explicitly.  In particular,
        # policy readers and the denied principal must see the same stable ID;
        # consumers use it to identify the actual rule, not a client-side alias.
        visible_denies = [{
            "deny_id": deny["deny_id"],
            "principal_id": deny["principal_id"],
            "actions": deny["actions"],
            "target_ids": deny["target_ids"],
        } for deny in denies
            if can_read_policy or deny.get("principal_id") in authority_ids]
        delegation = document.get("delegation_envelopes", {}).get(principal, {})
        delegation = {"actions": list(delegation.get("actions", [])),
            "target_scope": _complete_policy_scope(delegation.get("target_scope")),
            "limits": _complete_policy_limits(delegation.get("limits")),
            "separation_of_duties": _complete_policy_duties(
                delegation.get("separation_of_duties"))}
        return {"schema_version": 1, "group_id": group_id,
                "policy_revision": int(policy_row["revision"]), "effective_actions": actions,
                "grants": visible_grants, "denies": visible_denies,
                "delegation_envelope": delegation, "owner_directory": directory}

    @app.post("/api/v1/integrations/incidents")
    def ingest_g7_incident(payload: dict, principal: str = Depends(authenticate)):
        configured = principals.get(principal, {})
        if (configured.get("actor_kind") != "service"
                or set(configured.get("role_ids", ())) != {"integration.incident.submit"}):
            _error(403, "incident_ingestion_forbidden",
                   "A dedicated incident submission service is required")
        from uvm.assessment.incidents import (IncidentConflict, IncidentForbidden,
                                              ingest_transition)
        try:
            return ingest_transition(engine, principal, payload, now=now_utc())
        except IncidentForbidden:
            _error(403, "incident_ingestion_forbidden", "Current incident service binding is required")
        except IncidentConflict as exc:
            _error(409, "incident_transition_conflict", str(exc), {"retryable": "stream gap" in str(exc)})
        except Exception as exc:
            _LOG.exception("incident transition transaction failed: %s", type(exc).__name__)
            _error(503, "incident_projection_unavailable", "Incident transition was not committed")

    @app.post("/api/v1/integrations/incidents/{transition_id}/delivery")
    def ingest_g7_incident_delivery(transition_id: str, payload: dict,
                                    principal: str = Depends(authenticate)):
        configured = principals.get(principal, {})
        if (configured.get("actor_kind") != "service"
                or set(configured.get("role_ids", ())) != {"integration.incident.submit"}):
            _error(403, "incident_ingestion_forbidden",
                   "A dedicated incident submission service is required")
        from uvm.assessment.incidents import (IncidentConflict, IncidentForbidden,
                                              ingest_delivery_outcome)
        try:
            return ingest_delivery_outcome(engine, principal, transition_id, payload,
                now=now_utc())
        except IncidentForbidden:
            _error(403, "incident_ingestion_forbidden",
                   "Current incident service binding is required")
        except IncidentConflict as exc:
            _error(409, "incident_transition_conflict", str(exc))
        except Exception as exc:
            _LOG.exception("incident delivery projection failed: %s", type(exc).__name__)
            _error(503, "incident_projection_unavailable",
                   "Incident delivery outcome was not committed")

    @app.get("/api/v1/integrations/incidents")
    def list_g7_incidents(request: Request, limit: int = Query(50), offset: int = Query(0),
                          deployment_id: str | None = None, group_id: str | None = None,
                          principal: str = Depends(authenticate)):
        if type(limit) is not int or not 1 <= limit <= 100 or type(offset) is not int or not 0 <= offset <= 10000:
            _error(422, "invalid_pagination", "Incident pagination is outside the supported bounds")
        if group_id is not None:
            group_id = _uuid(group_id, "group_id")
        if deployment_id is not None and (not deployment_id or len(deployment_id) > 200):
            _error(422, "invalid_filter", "deployment_id is invalid")
        auth_service = getattr(app.state, "oidc_auth", None)
        items = []
        with engine.connect() as connection:
            policy_row = connection.execute(sa.select(assessment_policy).where(
                assessment_policy.c.policy_id == 1)).mappings().first()
            if policy_row is None:
                _error(503, "persistence_unavailable", "Assessment policy is unavailable")
            policy = policy_row["document"]
            context = auth_service.final_context(connection, request) if auth_service else AUTHORITY_CONTEXT.get()
            authority_token = AUTHORITY_CONTEXT.set(context) if context is not None else None
            try:
                memberships = set(effective_access(policy, principal)[0] or ())
                routes = connection.execute(sa.select(g7_incident_routes).where(
                    g7_incident_routes.c.enabled.is_(True))).mappings().all()
                query = (sa.select(g7_incident_transitions,
                    g7_incident_notification_intents.c.state.label("notification_state"))
                    .select_from(g7_incident_transitions.outerjoin(
                        g7_incident_notification_intents,
                        g7_incident_notification_intents.c.transition_id ==
                            g7_incident_transitions.c.transition_id)))
                if deployment_id is not None:
                    query = query.where(g7_incident_transitions.c.deployment_id == deployment_id)
                rows = connection.execute(query.order_by(
                    g7_incident_transitions.c.observed_at,
                    g7_incident_transitions.c.transition_id)).mappings().all()
                attempts_by_transition: dict[str, list[dict]] = {}
                transition_ids = [row["transition_id"] for row in rows]
                if transition_ids:
                    attempts = connection.execute(sa.select(
                        g7_incident_notification_attempts).where(
                            g7_incident_notification_attempts.c.transition_id.in_(transition_ids))
                        .order_by(g7_incident_notification_attempts.c.transition_id,
                            g7_incident_notification_attempts.c.attempted_at,
                            g7_incident_notification_attempts.c.attempt_id)).mappings().all()
                    for attempt in attempts:
                        attempts_by_transition.setdefault(attempt["transition_id"], []).append({
                            "attempt_id": attempt["attempt_id"],
                            "outcome": attempt["outcome"],
                            "attempted_at": _utc_z(attempt["attempted_at"]),
                        })
                authorised = {}
                for row in rows:
                    for route in routes:
                        if (route["deployment_id"] != row["deployment_id"]
                                or (route["subject_id"] is not None and route["subject_id"] != row["subject_id"])
                                or route["recipient_access_group_id"] not in memberships
                                or (group_id is not None and str(route["vulnerability_group_id"] or "") != group_id)):
                            continue
                        recipient = route["recipient_access_group_id"]
                        route_scope = (route["source_family"], route["source_account_id"], route["scope_key"])
                        if route["vulnerability_group_id"] is not None:
                            target_id = str(route["vulnerability_group_id"])
                            group = connection.execute(sa.select(groups).where(
                                groups.c.group_id == target_id)).mappings().first()
                            if group is None or group["source_family"] != route["source_family"]:
                                continue
                            is_audit_event = row["subject_id"].startswith("audit-event:")
                            if is_audit_event:
                                try:
                                    evidence = [json.loads(ref) for ref in row["evidence_refs"]]
                                except (TypeError, ValueError):
                                    evidence = []
                                trusted_targets = {item.get("vulnerability_group_id")
                                    for item in evidence if isinstance(item, dict)}
                                trusted_scopes = {item.get("affected_scope")
                                    for item in evidence if isinstance(item, dict)}
                                if target_id not in trusted_targets or target_id not in trusted_scopes:
                                    continue
                            grants = _native_access_group_grants(policy, recipient,
                                "integration.health.read", target_id, group["source_family"], principal)
                            if not grants:
                                continue
                            from uvm.auth.service import group_scope_covered
                            if is_audit_event:
                                if (context is None or route_scope not in
                                        context.scopes_for_group(recipient) or
                                        not group_scope_covered(connection, context, [target_id],
                                            granting_identity_groups=[recipient])):
                                    continue
                            elif not group_scope_covered(connection, context, [target_id],
                                    granting_identity_groups=[recipient]):
                                continue
                            # The route target must resolve to a current UVM
                            # vulnerability group. Its source tuple must also be
                            # present in the recipient's complete current grant
                            # and exactly match the anchored affected scope.
                            route_is_current = connection.execute(sa.select(sa.literal(True)).where(
                                sa.exists(sa.select(1).select_from(groups).where(
                                    groups.c.group_id == target_id,
                                    groups.c.source_family == route_scope[0])))).scalar_one_or_none()
                            if not route_is_current:
                                continue
                        else:
                            if row["subject_id"].startswith("audit-event:"):
                                continue
                            grants = _native_access_group_grants(policy, recipient,
                                "integration.health.read", _ZERO_ID, route["source_family"], principal)
                            if not grants:
                                continue
                            if context is not None:
                                current_scopes = context.scopes_for_group(recipient)
                            else:
                                current_scopes = {tuple(scope[key] for key in
                                    ("source_family", "source_account_id", "scope_key"))
                                    for scope in native_state(policy).get(
                                        "access_groups", {}).get(recipient, {}).get("source_scopes", ())
                                    if isinstance(scope, dict) and all(scope.get(key) for key in
                                        ("source_family", "source_account_id", "scope_key"))}
                            if route_scope not in current_scopes:
                                continue
                        item = {"transition_id": row["transition_id"],
                            "deployment_id": row["deployment_id"], "subject_id": row["subject_id"],
                            "condition": row["condition"], "transition_sequence": row["transition_sequence"],
                            "predecessor_id": row["predecessor_id"], "episode_id": row["episode_id"],
                            "opening_transition_id": row["opening_transition_id"],
                            "episode_generation": row["episode_generation"],
                            "transition_kind": row["transition_kind"],
                            "configuration_revision": row["configuration_revision"],
                            "first_detected_at": _utc_z(row["first_detected_at"]),
                            "observed_at": _utc_z(row["observed_at"]),
                            "recovered_at": _utc_z(row["recovered_at"]),
                            "evidence_refs": list(row["evidence_refs"]),
                            "notification": {"state": row["notification_state"],
                                "attempts": attempts_by_transition.get(row["transition_id"], [])}}
                        authorised[row["transition_id"]] = item
                        break
                visible = sorted(authorised.values(), key=lambda item:
                    (item["observed_at"], item["transition_id"]))
                return {"schema_version": 1, "items": visible[offset:offset + limit],
                    "next_offset": (offset + limit if offset + limit < len(visible) else None)}
            finally:
                if authority_token is not None:
                    AUTHORITY_CONTEXT.reset(authority_token)

    @app.get("/api/v1/assessment/audit")
    def audit(group_id: str = Query(...), cursor: str | None = None,
              principal: str = Depends(authenticate)):
        group_id = _uuid(group_id, "group_id")
        with engine.connect() as connection:
            source_family = connection.execute(sa.select(groups.c.source_family).where(
                groups.c.group_id == group_id)).scalar_one_or_none()
            policy_row = connection.execute(sa.select(assessment_policy).where(
                assessment_policy.c.policy_id == 1)).mappings().first()
            grants = (_complete_target_grants(connection, policy_row["document"],
                principal, "audit.read", group_id, source_family) if policy_row and source_family else [])
            from uvm.auth.service import group_scope_covered
            scope_allowed = group_scope_covered(connection, AUTHORITY_CONTEXT.get(), [group_id],
                granting_identity_groups=[grant.get("principal_id") for grant in grants])
            if source_family is None or policy_row is None or not scope_allowed or not grants:
                _error(403, "forbidden", "Access forbidden")
            policy_revision = int(policy_row["revision"])
            after = 0
            if cursor:
                try:
                    raw = base64.urlsafe_b64decode(cursor + "=" * (-len(cursor) % 4))
                    body, signature = raw.rsplit(b".", 1)
                    expected_sig = hmac.new(app.state.cursor_secret, body, hashlib.sha256).digest()
                    payload = json.loads(body)
                    if (not hmac.compare_digest(signature, expected_sig)
                            or payload != {"endpoint": "assessment-audit", "group_id": group_id,
                                "principal_id": principal, "policy_revision": policy_revision,
                                "after": payload.get("after")} or type(payload.get("after")) is not int
                            or payload["after"] < 0):
                        raise ValueError
                    after = payload["after"]
                except (ValueError, TypeError, KeyError, json.JSONDecodeError):
                    _error(400, "invalid_cursor", "Audit cursor is invalid")
            rows = connection.execute(sa.select(assessment_audit_events).where(
                assessment_audit_events.c.target_id == group_id,
                assessment_audit_events.c.event_sequence > after)
                .order_by(assessment_audit_events.c.event_sequence).limit(51)).mappings().all()
        more = len(rows) > 50
        page = rows[:50]
        next_cursor = None
        if more and page:
            cursor_body = json.dumps({"endpoint": "assessment-audit", "group_id": group_id,
                "principal_id": principal, "policy_revision": policy_revision,
                "after": int(page[-1]["event_sequence"])}, sort_keys=True,
                separators=(",", ":")).encode()
            signature = hmac.new(app.state.cursor_secret, cursor_body, hashlib.sha256).digest()
            next_cursor = base64.urlsafe_b64encode(cursor_body + b"." + signature).decode().rstrip("=")
        items = []
        for row in page:
            item = {key: value for key, value in row.items() if key != "event_sequence"}
            item["occurred_at"] = _utc_z(item["occurred_at"])
            item["received_at"] = _utc_z(item["received_at"])
            items.append(item)
        return {"schema_version": 1, "group_id": group_id,
                "items": items, "next_cursor": next_cursor}

    def execute_github_assessment_command(body: dict, principal: str,
                                         trusted_context: dict[str, Any] | None = None):
        """Internal adapter seam; origin cannot be selected by HTTP input."""
        from starlette.requests import Request as StarletteRequest
        internal_request = StarletteRequest({"type": "http", "http_version": "1.1",
            "method": "POST", "scheme": "http", "path": "/api/v1/assessment/commands",
            "raw_path": b"/api/v1/assessment/commands", "query_string": b"",
            "headers": [], "client": ("127.0.0.1", 0), "server": ("127.0.0.1", 8000)})
        auth_service = getattr(app.state, "oidc_auth", None)
        authority_token = None
        if auth_service is not None:
            with engine.connect() as connection:
                current = auth_service.linked_actor_context(connection, principal)
            internal_request.state.authority_context = current
            authority_token = AUTHORITY_CONTEXT.set(current)
        token = _TRUSTED_COMMAND_ORIGIN.set("github_rest")
        context_token = _TRUSTED_GITHUB_CONTEXT.set(trusted_context)
        try:
            return submit_command(body, internal_request, principal=principal)
        finally:
            _TRUSTED_GITHUB_CONTEXT.reset(context_token)
            _TRUSTED_COMMAND_ORIGIN.reset(token)
            if authority_token is not None:
                AUTHORITY_CONTEXT.reset(authority_token)

    app.state.g4_assessment_executor = execute_github_assessment_command
