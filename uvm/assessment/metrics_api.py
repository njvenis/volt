"""Persisted, current-authorised G5 metric report API."""
from __future__ import annotations

import base64
import copy
import csv
import hashlib
import hmac
import io
import json
import logging
import os
import threading
import time
import uuid
import zipfile
from datetime import datetime, timedelta, timezone
from decimal import Decimal, ROUND_HALF_UP

import sqlalchemy as sa
from fastapi import Depends, FastAPI, HTTPException, Query, Request
from fastapi.responses import Response

from uvm.persistence.assessment_schema import (assessment_audit_events,
    assessment_command_receipts, assessment_group_state, assessment_policy)
from uvm.persistence.g4_schema import exposure_episodes, exposure_episode_members, exposure_episode_events
from uvm.persistence.metrics_schema import (metrics_report_atoms,
    report_requests, reporting_projection_intents, sla_evaluations,
    sla_policy_heads, sla_policy_versions, inventory_policy_heads,
    inventory_policy_versions, g7_sla_evaluations)
from uvm.persistence.exception_sla_schema import (source_observation_receipts, sla_clock_events,
    sla_episode_contracts, sla_ingest_receipts)
from uvm.persistence.observation_schema import source_observations
from uvm.persistence.lineage_schema import identity_resolutions, correction_records
from uvm.persistence.identity_graph_lock import lock_identity_graph
from uvm.persistence.scalar_schema import identity_scalar_correction_receipts
from uvm.persistence.scalar_history import (scalar_record_at_context, ScalarHistoryUnavailable,
    ScalarHistoryProofRead)
from uvm.persistence.schema import exposures, groups, incarnations, occurrences, workloads
from uvm.assessment.sla_references import resolve_policy_reference
from uvm.assessment.sla_classification import resolve_classification, elapsed_deadline
from uvm.assessment.report_authority import report_scope_read
from uvm.auth.schema import AUTHORITY_CONTEXT
from uvm.auth.native_authority import NATIVE_ACTIONS, effective_team_members, native_state
from uvm.persistence.deadline_reference_store import DeadlineReferenceStore
from uvm.persistence.deadline_reference_schema import identity_deadline_references
from uvm.persistence.ingestion_schema import (collection_runs, expected_runs,
    collection_schedules, expected_run_events, run_pages)
from uvm.persistence.observation_schema import source_observations as retained_source_observations

UTC = timezone.utc
ZERO = "00000000-0000-4000-8000-000000000000"
DEFINITION = "g5-metrics-v1"
G7_DEFINITION = "g7-exception-sla-v1"
_LOG = logging.getLogger("uvm.metrics")
GROUP_STATE_ACTIONS = {"owners.assign", "portion.define", "portion.transfer", "portion.split",
    "severity.override", "acceptance.submit", "acceptance.approve", "acceptance.reject",
    "acceptance.revoke", "acceptance.expire", "acceptance.reconcile", "remediation.confirm_portion",
    "remediation.confirm_group", "routing.override", "routing.expire"}


def _error(status: int, code: str, message: str):
    raise HTTPException(status, {"code": code, "message": message, "details": {}})


def _uuid(value, field):
    try:
        parsed = uuid.UUID(value)
    except (ValueError, TypeError, AttributeError):
        _error(422, "invalid_request", f"{field} must be a UUID")
    if str(parsed) != value:
        _error(422, "invalid_request", f"{field} must be a canonical UUID")
    return value


def _time(value, field, *, optional=False):
    if value is None and optional:
        return None
    if not isinstance(value, str):
        _error(422, "invalid_request", f"{field} must be a UTC RFC 3339 instant")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        _error(422, "invalid_request", f"{field} must be a UTC RFC 3339 instant")
    if parsed.tzinfo is None or parsed.utcoffset() != UTC.utcoffset(parsed):
        _error(422, "invalid_request", f"{field} must be an explicit UTC instant")
    return parsed.astimezone(UTC)


def _instant(value):
    if value is None:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=UTC)
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _report_failure_target(row, *, command_id, principal_id, request_digest):
    """Return the exact accepted report this request is authorised to clean up."""
    if (row is None or row["command_id"] != command_id
            or row["principal_id"] != principal_id
            or row["request_digest"] != request_digest
            or not row["report_id"] or not row["projection_intent_id"]):
        return None
    return {key: row[key] for key in ("report_id", "command_id", "principal_id",
        "request_digest", "projection_intent_id")}


def _internal_report_request(context_document, principal_id, *, oidc_enabled):
    """Adapt a durable accepted-report authority snapshot to the writer Request API."""
    from starlette.requests import Request as StarletteRequest
    authority = None
    if oidc_enabled:
        if not isinstance(context_document, dict):
            raise RuntimeError("accepted report has no durable authority context")
        from uvm.auth.schema import AuthorityContext
        evaluated_at = context_document["evaluated_at"]
        authority = AuthorityContext(
            principal_id=context_document["principal_id"],
            credential_mode=context_document["credential_mode"],
            issuer=context_document.get("issuer"), subject=context_document.get("subject"),
            link_id=context_document.get("link_id"), link_revision=context_document.get("link_revision"),
            session_id=context_document.get("session_id"),
            session_revision=context_document.get("session_revision"),
            access_groups=tuple(context_document.get("access_groups", ())),
            group_revision=context_document["group_revision"],
            mapping_revision=context_document["mapping_revision"],
            policy_revision=context_document["policy_revision"],
            source_scopes=tuple(tuple(item) for item in context_document.get("source_scopes", ())),
            role_ids=tuple(context_document.get("role_ids", ())),
            evaluated_at=datetime.fromisoformat(evaluated_at.replace("Z", "+00:00")),
            group_roles=tuple((key, tuple(value)) for key, value in
                context_document.get("group_roles", {}).items()),
            group_scopes=tuple((key, tuple(tuple(scope) for scope in value)) for key, value in
                context_document.get("group_scopes", {}).items()))
        if authority.principal_id != principal_id:
            raise RuntimeError("accepted report authority context principal mismatch")
    request = StarletteRequest({"type": "http", "method": "POST", "path": "/api/v1/reports",
        "headers": [], "query_string": b"", "server": ("internal", 0),
        "client": ("internal", 0), "scheme": "http"})
    request.state.authority_context = authority
    return request


def _mark_report_failure(engine, target):
    if target is None:
        return
    with engine.begin() as connection:
        accepted = connection.execute(sa.select(report_requests.c.report_id).where(
            report_requests.c.report_id == target["report_id"],
            report_requests.c.command_id == target["command_id"],
            report_requests.c.principal_id == target["principal_id"],
            report_requests.c.request_digest == target["request_digest"],
            report_requests.c.projection_intent_id == target["projection_intent_id"],
            report_requests.c.status == "pending").with_for_update()).first()
        if accepted is None:
            return
        connection.execute(report_requests.update().where(
            report_requests.c.report_id == target["report_id"],
            report_requests.c.command_id == target["command_id"],
            report_requests.c.principal_id == target["principal_id"],
            report_requests.c.request_digest == target["request_digest"],
            report_requests.c.projection_intent_id == target["projection_intent_id"],
            report_requests.c.status == "pending").values(status="failed",
                error_code="materialisation_failed"))
        connection.execute(reporting_projection_intents.update().where(
            reporting_projection_intents.c.intent_id == target["projection_intent_id"],
            reporting_projection_intents.c.report_id == target["report_id"],
            reporting_projection_intents.c.status == "pending").values(status="failed",
                last_error="materialisation_failed", updated_at=datetime.now(UTC)))


def _jsonable(value):
    if isinstance(value, datetime):
        return _instant(value)
    if isinstance(value, dict):
        return {str(key): _jsonable(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_jsonable(item) for item in value]
    return value


def _identity_record_at_context(connection, record_type, row, as_of, known_at, scalar_proof=None):
    """Reconstruct revisioned core identity fields from retained corrections.

    Core identity rows are updated in place by the guarded correction writer;
    correction_records retains each changed field and its prior revision. For
    a historical report, reverse only transitions after its effective/known
    cut. The correction rows are returned separately as scoped provenance.
    """
    if record_type in {"workload", "incarnation"}:
        snapshot = connection.info.get("uvm_scalar_snapshot_boundary")
        sequence = snapshot[1] if snapshot and snapshot[0] is connection.get_transaction() else None
        if sequence is None:
            sequence = int(connection.execute(sa.select(sa.func.coalesce(
                sa.func.max(identity_scalar_correction_receipts.c.knowledge_sequence), 0))).scalar_one())
        try:
            return scalar_record_at_context(connection, record_type, row, as_of, known_at, sequence, scalar_proof)
        except ScalarHistoryUnavailable:
            _error(503, "identity_history_unavailable", "Identity history unavailable")
    value = dict(row)
    id_field = {"group":"group_id", "workload":"workload_id", "incarnation":"incarnation_id",
        "exposure":"exposure_id", "occurrence":"occurrence_id"}[record_type]
    records = connection.execute(sa.select(correction_records).where(
        correction_records.c.record_type == record_type,
        correction_records.c.record_id == row[id_field])
        .order_by(correction_records.c.created_at, correction_records.c.correction_id)
        ).mappings().all()
    boundary = min(as_of, known_at)
    for event in reversed(records):
        if event["created_at"] <= boundary:
            continue
        field = event["field_name"]
        if field not in value:
            continue
        previous = event["old_value"]
        current = value[field]
        if previous is not None:
            if isinstance(current, uuid.UUID):
                previous = uuid.UUID(str(previous))
            elif isinstance(current, datetime):
                previous = datetime.fromisoformat(str(previous).replace("Z", "+00:00"))
        value[field] = previous
        value["revision"] = int(event["previous_revision"])
    if record_type == "occurrence" and any(event["created_at"] > boundary
            and event["field_name"] == "incarnation_id" for event in records):
        # The populated-exposure writer records the incarnation transition
        # and updates redundant occurrence.workload_id in the same transaction.
        # Restore that redundant field from its retained historical parent;
        # current workload metadata must not leak into the earlier context.
        parent = connection.execute(sa.select(incarnations).where(
            incarnations.c.incarnation_id == value["incarnation_id"])).mappings().first()
        if parent is not None:
            historical_parent, _ = _identity_record_at_context(
                connection, "incarnation", parent, as_of, known_at)
            value["workload_id"] = historical_parent["workload_id"]
    return value, records


def _digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _membership_state_at(episode, member, events):
    """Reconstruct exact G4 member coverage from its baseline and retained events."""
    state = dict(member)
    original_at = state.get("original_confirmed_at")
    baseline_confirmed = original_at is not None and original_at <= episode["created_at"]
    if episode["episode_number"] > 1:
        trigger = next((event.get("details", {}).get("trigger_occurrence_id")
            for event in events if event["event_type"] == "recurrence_opened"), None)
        baseline_confirmed = baseline_confirmed and member["occurrence_id"] != trigger
        state["status"] = "continuity_covered" if baseline_confirmed else "outstanding"
        state["coverage_reason"] = "verified_continuity" if baseline_confirmed else "new_positive_observation"
    elif baseline_confirmed:
        state["status"] = "confirmed"
        state["coverage_reason"] = "direct_confirmation"
    elif member.get("status") == "review" and member.get("coverage_reason") == "review":
        state["status"] = "review"
    else:
        state["status"] = "outstanding"
        state["coverage_reason"] = "outstanding"
    state["confirmation_decision_id"] = (state.get("original_decision_id") if baseline_confirmed else None)
    state["confirmed_at"] = (original_at if baseline_confirmed else None)
    latest_event = None
    for event in events:
        occurrence_id = member["occurrence_id"]
        if occurrence_id not in (event.get("occurrence_ids") or []):
            continue
        event_type = event["event_type"]
        if event_type == "remediation_confirmed":
            state.update(status="confirmed", coverage_reason="direct_confirmation",
                confirmation_decision_id=event["decision_id"], confirmed_at=event["recorded_at"])
        elif event_type == "coverage_reopened":
            state.update(status="outstanding", coverage_reason="new_positive_observation",
                confirmation_decision_id=None, confirmed_at=None)
        elif event_type == "recurrence_opened":
            if occurrence_id == event.get("details", {}).get("trigger_occurrence_id"):
                state.update(status="outstanding", coverage_reason="new_positive_observation",
                    confirmation_decision_id=None, confirmed_at=None)
            elif state.get("original_decision_id") and state.get("original_confirmed_at"):
                state.update(status="continuity_covered", coverage_reason="verified_continuity",
                    confirmation_decision_id=state["original_decision_id"],
                    confirmed_at=state["original_confirmed_at"])
        elif event_type == "membership_added":
            state.update(status="outstanding", coverage_reason="outstanding",
                confirmation_decision_id=None, confirmed_at=None)
        elif event_type == "observation_requires_review":
            state.update(status="review", coverage_reason="observation_requires_review",
                confirmation_decision_id=None, confirmed_at=None)
        latest_event = event
    return state, latest_event


def _sla_policy_applies_to_member(document: dict, stable_attrs: dict) -> bool:
    """Fail closed when a selector lacks retained workload context."""
    scope = document.get("scope", {})
    for selector, attribute in (("environments", "environment"), ("service_ids", "service_id")):
        selected = scope.get(selector, [])
        if selected and stable_attrs.get(attribute) not in selected:
            return False
    return True


def _owner_effective_at(owner, principal_state, as_of: datetime, group_id: str) -> bool:
    """Resolve owner, principal and declared group validity at report context."""
    if not owner or owner.get("enabled", True) is not True:
        return False
    if principal_state.get("enabled", True) is not True:
        return False
    scope = owner.get("scope_group_ids")
    if scope is not None and (not isinstance(scope, list) or group_id not in scope):
        return False
    for value in (owner, principal_state):
        try:
            start = datetime.fromisoformat(value["effective_from"].replace("Z", "+00:00")) if value.get("effective_from") else None
            end = datetime.fromisoformat(value["effective_until"].replace("Z", "+00:00")) if value.get("effective_until") else None
        except (ValueError, TypeError, AttributeError):
            return False
        if start and (start.tzinfo is None or start > as_of):
            return False
        if end and (end.tzinfo is None or end <= as_of):
            return False
    return True


def _outstanding_intervals_at(episode, occurrence, member, events, as_of):
    """Return retained outstanding intervals for one exact episode membership."""
    occurrence_id = occurrence["occurrence_id"]
    original_confirmed = member.get("original_confirmed_at")
    baseline_covered = (episode["episode_number"] > 1 and original_confirmed is not None
        and original_confirmed <= episode["created_at"] and
        not any(event["event_type"] == "recurrence_opened" and
            event.get("details", {}).get("trigger_occurrence_id") == occurrence_id for event in events))
    if baseline_covered:
        open_at = None
    elif episode["episode_number"] > 1:
        trigger = next((event for event in events if event["event_type"] == "recurrence_opened"
            and event.get("details", {}).get("trigger_occurrence_id") == occurrence_id), None)
        open_at = ((trigger.get("observed_at") or trigger["recorded_at"]) if trigger else None)
    elif original_confirmed is not None and original_confirmed <= episode["created_at"]:
        open_at = None
    else:
        open_at = occurrence.get("first_observed_at")
    intervals = []
    for event in events:
        if occurrence_id not in (event.get("occurrence_ids") or []):
            continue
        event_type = event["event_type"]
        if event_type == "remediation_confirmed":
            close_at = event["recorded_at"]
            if open_at is not None and close_at > open_at:
                intervals.append((open_at, min(close_at, as_of)))
            open_at = None
        elif event_type == "coverage_reopened":
            if open_at is None:
                open_at = event.get("observed_at") or event["recorded_at"]
        elif event_type == "recurrence_opened" and event.get("details", {}).get("trigger_occurrence_id") == occurrence_id:
            if open_at is None:
                open_at = event.get("observed_at") or event["recorded_at"]
        elif event_type in {"membership_added", "observation_requires_review"} and open_at is None:
            open_at = occurrence.get("first_observed_at") or event["recorded_at"]
    if open_at is not None and member.get("status") in {"outstanding", "review"} and as_of > open_at:
        intervals.append((open_at, as_of))
    return [(start, end) for start, end in intervals if start < end]


def _metric(key, numerator, denominator, unit, basis):
    ratio = (Decimal(numerator) / Decimal(denominator) * 100) if denominator else None
    rounded = ratio.quantize(Decimal("0.1"), rounding=ROUND_HALF_UP) if ratio is not None else None
    display = ("<0.1" if ratio and ratio > 0 and rounded == 0 else
        "<100" if ratio is not None and ratio < 100 and rounded == 100 else
        str(rounded) if rounded is not None else None)
    return {"key": key, "numerator": numerator, "denominator": denominator,
        "unit": unit, "basis": basis, "value": numerator,
        "percentage": display, "percentage_display": display,
        "status": "known" if denominator else "not_applicable"}


def _qualifying_populations(atoms, *, as_of, period_start, period_end):
    """Resolve all atom/group metric populations from the same frozen context."""
    populations = {key: set() for key in (
        "eligible_outstanding", "covered_outstanding", "current_breach", "sla_gaps",
        "original_deadline_outstanding", "original_policy_current_breach",
        "historical_deadline_applicable", "historical_breach",
        "original_historical_deadline_applicable", "original_policy_historical_breach",
        "ownership_covered", "assessment_covered", "new_completions",
        "known_deadline_completions", "on_time_completions", "unknown_deadline_completions",
        "carried_confirmation", "excluded_exposure", "eligible_native_groups",
        "breached_native_groups", "completed_during_exception", "running_covered", "paused_covered")}
    atom_by_id = {atom["atom_id"]: atom for atom in atoms}
    for atom_id, atom in atom_by_id.items():
        if atom["eligible"]:
            populations["eligible_outstanding"].add(atom_id)
            if atom["clock"]["deadline"] and not atom["gap_reasons"]:
                populations["covered_outstanding"].add(atom_id)
                populations["paused_covered" if atom.get("exception_clock", {}).get("state") == "paused"
                    else "running_covered"].add(atom_id)
            if atom["clock"]["original_deadline_at"]:
                populations["original_deadline_outstanding"].add(atom_id)
            if atom["ownership"]["covered"]:
                populations["ownership_covered"].add(atom_id)
            if atom["assessment_covered"]:
                populations["assessment_covered"].add(atom_id)
            populations["eligible_native_groups"].add(atom["native_group_id"])
        if atom.get("exclusion", {}).get("excluded") and atom["completion"]["state"] == "outstanding":
            populations["excluded_exposure"].add(atom_id)
        if atom["clock"]["historical_deadline_applicable"]:
            populations["historical_deadline_applicable"].add(atom_id)
        if atom["clock"]["historical_breach_seconds"] > 0:
            populations["historical_breach"].add(atom_id)
        if atom["clock"]["original_historical_deadline_applicable"]:
            populations["original_historical_deadline_applicable"].add(atom_id)
        if atom["clock"]["original_historical_breach_seconds"] > 0:
            populations["original_policy_historical_breach"].add(atom_id)
        if atom["completion"]["state"] == "carried":
            populations["carried_confirmation"].add(atom_id)
        confirmed = atom["completion"].get("confirmed_at")
        if confirmed and atom["completion"]["state"] != "carried":
            completed_at = datetime.fromisoformat(confirmed.replace("Z", "+00:00"))
            if ((period_start is None or completed_at >= period_start)
                    and (period_end is None or completed_at < period_end)):
                populations["new_completions"].add(atom_id)
                if atom["completion"]["state"] == "completed_during_exception":
                    populations["completed_during_exception"].add(atom_id)
                    continue
                confirmation_deadline = atom["completion"].get("deadline_at_confirmation")
                if confirmation_deadline:
                    populations["known_deadline_completions"].add(atom_id)
                    if (atom["completion"]["state"] == "on_time"
                            and completed_at <= datetime.fromisoformat(confirmation_deadline.replace("Z", "+00:00"))):
                        populations["on_time_completions"].add(atom_id)
                else:
                    populations["unknown_deadline_completions"].add(atom_id)
    for atom_id in populations["covered_outstanding"]:
        atom = atom_by_id[atom_id]
        if atom.get("exception_clock", {}).get("state") == "paused":
            continue
        deadline = datetime.fromisoformat(atom["clock"]["deadline"].replace("Z", "+00:00"))
        if as_of > deadline:
            populations["current_breach"].add(atom_id)
    for atom_id in populations["original_deadline_outstanding"]:
        atom = atom_by_id[atom_id]
        if atom.get("exception_clock", {}).get("state") == "paused":
            continue
        deadline = datetime.fromisoformat(atom["clock"]["original_deadline_at"].replace("Z", "+00:00"))
        if as_of > deadline:
            populations["original_policy_current_breach"].add(atom_id)
    populations["sla_gaps"] = (populations["eligible_outstanding"]
        - populations["covered_outstanding"])
    populations["breached_native_groups"] = {
        atom_by_id[atom_id]["native_group_id"] for atom_id in populations["current_breach"]}
    return populations, atom_by_id


def _weighted_cohorts(atoms, populations):
    """Build deterministic, weighted presentation cohorts from frozen atoms."""
    atom_by_id = {atom["atom_id"]: atom for atom in atoms}
    metric_sets = {
        "sla_coverage": (populations["covered_outstanding"], populations["eligible_outstanding"]),
        "current_breach": (populations["current_breach"], populations["running_covered"]),
        "sla_gaps": (populations["sla_gaps"], populations["eligible_outstanding"]),
        "on_time_completion": (populations["on_time_completions"], populations["known_deadline_completions"]),
        "unknown_deadline_completion": (populations["unknown_deadline_completions"], populations["new_completions"]),
    }
    buckets = {}
    for atom_id, atom in atom_by_id.items():
        acceptance = atom.get("acceptance", {})
        exclusion = atom.get("exclusion", {})
        dimensions = {
            "episode_id": atom["episode_id"],
            "eligible": atom["eligible"],
            "covered": atom_id in populations["covered_outstanding"],
            "start": atom.get("clock", {}).get("start"),
            "original_deadline_at": atom.get("clock", {}).get("original_deadline_at"),
            "deadline": atom.get("clock", {}).get("deadline"),
            "policy_id": atom.get("policy", {}).get("policy_id"),
            "policy_version": atom.get("policy", {}).get("version"),
            "severity": atom.get("severity", {}).get("value"),
            "classification_basis": atom.get("severity", {}).get("basis"),
            "gap_reasons": sorted(atom.get("gap_reasons", [])),
            "completion_state": atom.get("completion", {}).get("state"),
            "acceptance_state": acceptance.get("state"),
            "exclusion": bool(exclusion.get("excluded")),
        }
        key = json.dumps(dimensions, sort_keys=True, separators=(",", ":"))
        buckets.setdefault(key, {"dimensions": dimensions, "atom_ids": []})["atom_ids"].append(atom_id)
    result = []
    for key, bucket in buckets.items():
        atom_ids = sorted(bucket["atom_ids"])
        members = set(atom_ids)
        cohort_id = "cohort:" + hashlib.sha256(key.encode()).hexdigest()
        result.append({"cohort_id": cohort_id, "dimensions": bucket["dimensions"],
            "atom_ids": atom_ids, "weight": len(atom_ids),
            "metric_membership": {metric: {"numerator": len(members & numerator),
                "denominator": len(members & denominator)}
                for metric, (numerator, denominator) in metric_sets.items()}})
    return sorted(result, key=lambda item: item["cohort_id"])


def _age_display(seconds):
    if seconds is None:
        return "Unknown"
    if 0 < seconds < 864:
        return "<0.01 days"
    return f"{seconds / 86400:.2f} days"


def _sign(secret, payload):
    body = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    sig = hmac.new(secret, body, hashlib.sha256).digest()
    return base64.urlsafe_b64encode(body + b"." + sig).decode().rstrip("=")


def _verify(secret, value):
    try:
        raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
        body, signature = raw[:-33], raw[-32:]
        if raw[-33:-32] != b"." or not hmac.compare_digest(signature, hmac.new(secret, body, hashlib.sha256).digest()):
            raise ValueError
        return json.loads(body)
    except Exception:
        _error(400, "invalid_cursor", "Cursor is invalid")


def install_metrics_routes(app: FastAPI, auth):
    from uvm.assessment.report_diagnostics import install as install_report_trace, stage as report_stage
    install_report_trace(app)
    engine, secret = app.state.engine, app.state.cursor_secret
    now_utc = app.state.utc_now
    projection_worker_stop = threading.Event()
    projection_worker = None
    sla_refresh_worker = None
    exception_expiry_worker = None
    native_admin_worker = None

    def policy_for(connection, *, lock=False):
        statement = sa.select(assessment_policy).where(assessment_policy.c.policy_id == 1)
        if lock:
            statement = statement.with_for_update()
        row = connection.execute(statement).mappings().first()
        if row is None:
            _error(503, "persistence_unavailable", "Assessment policy is not configured")
        return int(row["revision"]), row["document"]

    def disclose_policy_document(connection, document, group_ids):
        """Remove cross-group selectors/targets before exposing a policy snapshot."""
        visible_group_ids = set(group_ids)
        visible_episodes = set(connection.execute(sa.select(exposure_episodes.c.episode_id).where(
            exposure_episodes.c.group_id.in_(visible_group_ids))).scalars()) if visible_group_ids else set()
        disclosed = json.loads(json.dumps(document))
        scope = disclosed.get("scope", {})
        if isinstance(scope, dict) and isinstance(scope.get("group_ids"), list):
            scope["group_ids"] = sorted(set(scope["group_ids"]) & visible_group_ids)
        backfill = disclosed.get("backfill", {})
        if isinstance(backfill, dict) and isinstance(backfill.get("targets"), list):
            backfill["targets"] = [target for target in backfill["targets"]
                if target.get("episode_id") in visible_episodes]
        rules = disclosed.get("deadline_reference_rules", {})
        if isinstance(rules, dict) and isinstance(rules.get("bindings"), list):
            rules["bindings"] = [binding for binding in rules["bindings"]
                if binding.get("episode_id") in visible_episodes]
        return disclosed

    def allowed(connection, policy, principal, action, group_id):
        source_family = connection.execute(sa.select(groups.c.source_family).where(
            groups.c.group_id == group_id)).scalar_one_or_none()
        if source_family is None:
            return False
        from uvm.assessment.api import _complete_target_grants
        return bool(_complete_target_grants(connection, policy, principal,
            action, group_id, source_family))

    def grants_for_group(connection, policy, principal, action, group_id):
        source_family = connection.execute(sa.select(groups.c.source_family).where(
            groups.c.group_id == group_id)).scalar_one_or_none()
        if source_family is None:
            return []
        from uvm.assessment.api import _complete_target_grants
        return _complete_target_grants(connection, policy, principal,
            action, group_id, source_family)

    def report_row(connection, report_id, principal, action="report.read"):
        _, policy = policy_for(connection)
        row, authorized = report_scope_read(connection, report_id, principal, policy, action, allowed)
        if row is None:
            _error(404, "not_found", "Report not found")
        if not authorized:
            _error(403, "forbidden", "Current report authority is required")
        from uvm.auth.service import group_scope_covered
        context = AUTHORITY_CONTEXT.get()
        if context is not None:
            for group_id in row["scope"].get("group_ids", []):
                grants = grants_for_group(connection, policy, principal, action, group_id)
                if not grants or not group_scope_covered(connection, context, [group_id],
                        granting_identity_groups=[grant.get("principal_id") for grant in grants]):
                    _error(403, "source_scope_forbidden", "Current exact source scope is required")
        return row

    def report_projection(row):
        if row["status"] == "ready":
            return row["result"]
        return {"report_id": row["report_id"], "status": row["status"],
            "projection": {"status": row["status"], "intent_id": row["projection_intent_id"],
                "error_code": row["error_code"]}}

    def report_receipt(connection, row):
        receipt = connection.execute(sa.select(assessment_command_receipts.c.result).where(
            assessment_command_receipts.c.command_id == row["command_id"])).scalar_one_or_none()
        result = dict(receipt or {})
        result.update(report_id=row["report_id"], projection=row["status"], error_code=row["error_code"])
        return result

    def atom_documents(connection, report_id):
        rows = connection.execute(sa.select(metrics_report_atoms.c.document).where(
            metrics_report_atoms.c.report_id == report_id).order_by(metrics_report_atoms.c.ordinal)).scalars()
        return list(rows)

    def inventory_projection(connection, group_ids, as_of, known_at, input_rows, source_watermark):
        versions = connection.execute(sa.select(inventory_policy_versions).where(
            inventory_policy_versions.c.created_at <= known_at).order_by(
            inventory_policy_versions.c.revision)).mappings().all()
        selected = None
        for row in reversed(versions):
            doc = row["document"]
            starts = _time(doc.get("effective_from"), "inventory.effective_from")
            ends = _time(doc.get("effective_until"), "inventory.effective_until", optional=True)
            if starts <= as_of and (ends is None or as_of < ends):
                selected = row
                break
        if selected is None:
            return {"configured": False, "revision": None, "targets": [], "sources": [],
                "expected": 0, "covered": 0, "unexpected_count": 0, "unmapped_count": 0}
        document = selected["document"]
        if not set(group_ids) <= set(document.get("scope_group_ids", [])):
            return {"configured": False, "revision": int(selected["revision"]), "targets": [], "sources": [],
                "expected": 0, "covered": 0, "unexpected_count": 0, "unmapped_count": 0}
        full_inventory_scope = set(group_ids) == set(document.get("scope_group_ids", []))
        scoped_document = {**document, "scope_group_ids": sorted(group_ids),
            "targets": [target for target in document["targets"] if target["group_id"] in group_ids]}
        input_rows.append({"kind": "inventory_policy_version", "stable_id": str(selected["revision"]),
            "revision": int(selected["revision"]), "effective_at": document["effective_from"],
            "known_at": _instant(selected["created_at"]), "retained_value": scoped_document})
        horizon = timedelta(seconds=document["freshness_horizon_seconds"])
        target_rows, source_aggregates = [], {}
        required_match_keys = {}
        unexpected_target_keys, unmapped_observation_ids = set(), set()
        manifested_inventory_observations = set()
        selected_targets = [target for target in document["targets"] if target["group_id"] in group_ids]
        for target in selected_targets:
            for source in target["required_sources"]:
                source_key = (source["source_family"], source["source_account_id"], source["scope_key"])
                match = source["target_match"]
                expected_key = (("asset_locator", match["value"]) if match["field"] == "asset_locator" else
                    ("native_id", match["scheme"], match["authority"], match["value"]))
                required_match_keys.setdefault(source_key, set()).add(expected_key)
        for target in selected_targets:
            source_results = []
            for source in target["required_sources"]:
                source_key = (source["source_family"], source["source_account_id"], source["scope_key"])
                aggregate_key = ":".join(source_key)
                aggregate = source_aggregates.setdefault(aggregate_key, {"source_id": aggregate_key,
                    "source_family": source_key[0], "source_account_id": source_key[1],
                    "expected_targets": 0, "observed_targets": 0, "latest_successful_collection_at": None,
                    "latest_trustworthy_observed_at": None, "last_attempt_at": None,
                    "completeness": "unknown", "missed_run": False, "stale": False,
                    "watermark": None, "failure_reasons": [], "_fresh_targets": 0})
                aggregate["expected_targets"] += 1
                candidates = connection.execute(sa.select(collection_runs).where(
                    collection_runs.c.source_family == source_key[0],
                    collection_runs.c.source_account_id == source_key[1],
                    collection_runs.c.scope_key == source_key[2],
                    collection_runs.c.created_at <= known_at,
                    sa.func.coalesce(collection_runs.c.ended_at, collection_runs.c.started_at,
                        collection_runs.c.created_at) <= as_of).order_by(
                    collection_runs.c.created_at.desc(), collection_runs.c.revision.desc())).mappings().all()
                # Latest transition per immutable run ID; choose the latest run transition by receipt time.
                latest_by_run = {}
                for candidate in candidates:
                    latest_by_run.setdefault(candidate["run_id"], candidate)
                latest_run = next(iter(sorted(latest_by_run.values(),
                    key=lambda row: (row["ended_at"] or row["created_at"], row["created_at"]), reverse=True)), None)
                latest_successful_run = next(iter(sorted(
                    (row for row in candidates if row["state"] == "completed"),
                    key=lambda row: (row["ended_at"] or row["created_at"], row["created_at"]),
                    reverse=True)), None)
                if latest_successful_run:
                    successful_at = latest_successful_run["ended_at"] or latest_successful_run["created_at"]
                    aggregate["latest_successful_collection_at"] = _instant(successful_at)
                    input_rows.append({"kind": "inventory_last_successful_run",
                        "stable_id": f"{latest_successful_run['run_id']}:{latest_successful_run['revision']}",
                        "revision": int(latest_successful_run["revision"]),
                        "effective_at": _instant(successful_at),
                        "known_at": _instant(latest_successful_run["created_at"]),
                        "retained_value": _jsonable(dict(latest_successful_run))})
                reason = None
                run_receipt = latest_run["ended_at"] or latest_run["created_at"] if latest_run else None
                latest_observed, matched_observations = None, []
                expected_cutoff = as_of - timedelta(seconds=document["expected_schedule_seconds"])
                due_run_rows = connection.execute(sa.select(expected_runs).where(
                    expected_runs.c.schedule_id == source["schedule_id"],
                    expected_runs.c.schedule_revision == source["schedule_revision"],
                    expected_runs.c.due_at <= as_of, expected_runs.c.due_at >= expected_cutoff)
                    .order_by(expected_runs.c.due_at.desc())).mappings().all()
                registered_due_runs = []
                for due_row in due_run_rows:
                    visible_history = connection.execute(sa.select(expected_run_events).where(
                        expected_run_events.c.expected_run_id == due_row["expected_run_id"],
                        expected_run_events.c.recorded_at <= known_at,
                        expected_run_events.c.effective_at <= as_of)
                        .order_by(expected_run_events.c.revision)).mappings().all()
                    # An expected-run row has no registration timestamp of its
                    # own. Its retained due event is therefore the only safe
                    # knowledge boundary; the mutable row is never a fallback.
                    if visible_history and visible_history[0]["state"] == "due":
                        registered_due_runs.append((dict(due_row), visible_history))
                latest_due, latest_due_events = (registered_due_runs[0]
                    if registered_due_runs else (None, []))
                first_start_event = None
                if latest_due is not None:
                    for event in latest_due_events:
                        input_rows.append({"kind": "inventory_expected_run_event",
                            "stable_id": event["event_id"], "revision": int(event["revision"]),
                            "effective_at": _instant(event["effective_at"]),
                            "known_at": _instant(event["recorded_at"]),
                            "retained_value": _jsonable(dict(event))})
                    if latest_due_events:
                        current_expected_event = latest_due_events[-1]
                        latest_due["state"] = current_expected_event["state"]
                        latest_due["run_id"] = current_expected_event["run_id"]
                        first_start_event = next((event for event in latest_due_events
                            if event["state"] == "started"), None)
                    immutable_expected = {key: latest_due[key] for key in (
                        "expected_run_id", "schedule_id", "schedule_revision", "scope_key",
                        "due_at", "grace_deadline")}
                    input_rows.append({"kind": "inventory_expected_run",
                        "stable_id": latest_due["expected_run_id"], "revision": int(latest_due["schedule_revision"]),
                        "effective_at": _instant(latest_due["due_at"]),
                        "known_at": _instant(latest_due_events[0]["recorded_at"]) if latest_due_events else None,
                        "retained_value": {**_jsonable(immutable_expected),
                            "state_at_context": latest_due["state"],
                            "run_id_at_context": latest_due["run_id"],
                            "event_history_available": bool(latest_due_events)}})
                if latest_due is not None:
                    missed_after_run = bool(latest_due["state"] == "missed" or
                        latest_due["grace_deadline"] <= as_of and
                        (first_start_event is None or first_start_event["effective_at"] > latest_due["grace_deadline"]))
                else:
                    missed_after_run = False
                if missed_after_run:
                    aggregate["last_attempt_at"] = _instant(latest_due["due_at"])
                if latest_run:
                    aggregate["watermark"] = str(latest_run["run_id"])
                    aggregate["last_attempt_at"] = _instant(latest_run["ended_at"] or latest_run["started_at"] or latest_run["created_at"])
                    page_rows = connection.execute(sa.select(run_pages).where(
                        run_pages.c.run_id == latest_run["run_id"],
                        run_pages.c.run_revision == latest_run["revision"])).mappings().all()
                    ordered_pages = sorted(page_rows, key=lambda page: page["ordinal"])
                    pages_complete = (bool(ordered_pages) and
                        [page["ordinal"] for page in ordered_pages] == list(range(1, len(ordered_pages) + 1)) and
                        ordered_pages[0]["cursor"] is None and
                        all(not page["failed"] for page in ordered_pages) and
                        all(page["next_cursor"] == ordered_pages[index + 1]["cursor"]
                            for index, page in enumerate(ordered_pages[:-1])) and
                        all(page["next_cursor"] for page in ordered_pages[:-1]) and
                        ordered_pages[-1]["is_terminal"] and ordered_pages[-1]["next_cursor"] is None and
                        sum(bool(page["is_terminal"]) for page in ordered_pages) == 1)
                    for page in ordered_pages:
                        input_rows.append({"kind": "inventory_collection_page",
                            "stable_id": f"{latest_run['run_id']}:{latest_run['revision']}:{page['ordinal']}",
                            "revision": int(page["ordinal"]), "effective_at": _instant(run_receipt),
                            "known_at": _instant(latest_run["created_at"]),
                            "retained_value": _jsonable(dict(page))})
                    match = source["target_match"]
                    all_run_observations = connection.execute(sa.select(retained_source_observations).where(
                        retained_source_observations.c.run_id == str(latest_run["run_id"]),
                        retained_source_observations.c.source_family == source_key[0],
                        retained_source_observations.c.source_account_id == source_key[1],
                        retained_source_observations.c.retention_order <= source_watermark,
                        retained_source_observations.c.collected_at <= known_at)).mappings().all()
                    configured_matches = required_match_keys.get(source_key, set())
                    for retained in all_run_observations:
                        observed_keys = set()
                        if retained["asset_locator"]:
                            observed_keys.add(("asset_locator", retained["asset_locator"]))
                        if all(retained[key] for key in ("native_id_scheme", "native_id_authority", "native_id_value")):
                            observed_keys.add(("native_id", retained["native_id_scheme"],
                                retained["native_id_authority"], retained["native_id_value"]))
                        if full_inventory_scope and not observed_keys:
                            unmapped_observation_ids.add(retained["observation_id"])
                        elif full_inventory_scope and not observed_keys & configured_matches:
                            stable_key = sorted(observed_keys, key=lambda key: (key[0], *map(str, key)))[0]
                            unexpected_target_keys.add((source_key, stable_key))
                        # A narrow report manifests only observations that map to
                        # one of its own frozen expected targets.
                        if (observed_keys & configured_matches
                                and retained["observation_id"] not in manifested_inventory_observations):
                            input_rows.append({"kind": "inventory_observation", "stable_id": retained["observation_id"],
                                "revision": int(retained["revision"]), "effective_at": _instant(retained["observed_at"]),
                                "known_at": _instant(retained["collected_at"]),
                                "retained_value": {"run_id": str(latest_run["run_id"]),
                                    "collection_status": retained["collection_status"],
                                    "observed_at": _instant(retained["observed_at"]),
                                    "collected_at": _instant(retained["collected_at"]),
                                    "asset_locator": retained["asset_locator"],
                                    "native_id_scheme": retained["native_id_scheme"],
                                    "native_id_authority": retained["native_id_authority"],
                                    "native_id_value": retained["native_id_value"]}})
                            manifested_inventory_observations.add(retained["observation_id"])
                    q = sa.select(retained_source_observations).where(
                        retained_source_observations.c.run_id == str(latest_run["run_id"]),
                        retained_source_observations.c.source_family == source_key[0],
                        retained_source_observations.c.source_account_id == source_key[1],
                        retained_source_observations.c.retention_order <= source_watermark,
                        retained_source_observations.c.collected_at <= known_at)
                    if match["field"] == "asset_locator":
                        q = q.where(retained_source_observations.c.asset_locator == match["value"])
                    else:
                        q = q.where(retained_source_observations.c.native_id_scheme == match["scheme"],
                            retained_source_observations.c.native_id_authority == match["authority"],
                            retained_source_observations.c.native_id_value == match["value"])
                    matched_observations = connection.execute(q).mappings().all()
                    trustworthy = [row for row in matched_observations if row["collection_status"] == "success"
                        and row["observed_at"] is not None and row["observed_at"] <= as_of]
                    latest_observed = max((row["observed_at"] for row in trustworthy), default=None)
                    fresh_observations = [row for row in trustworthy if row["observed_at"] >= as_of - horizon]
                    complete_run = (latest_run["state"] == "completed"
                        and latest_run["retrieval_status"] == "complete"
                        and pages_complete)
                    # A retained failed terminal transition remains the latest
                    # source outcome even when its scheduled run also missed
                    # grace. Preserve the missed condition separately below;
                    # it must not mask an actual failed run as a missing scan.
                    if latest_run["state"] == "failed":
                        reason = "source_run_failed"
                    elif latest_run["state"] == "missed" or missed_after_run:
                        reason = "source_run_missed"
                    elif latest_run["state"] in {"failed", "missed"}:
                        reason = "source_run_" + latest_run["state"]
                    elif latest_run["state"] == "partial" or not pages_complete:
                        reason = "partial_or_incomplete_scan"
                    elif not matched_observations:
                        reason = "expected_target_not_observed"
                    elif not fresh_observations:
                        reason = "observation_missing_future_or_stale"
                    elif not complete_run:
                        reason = "source_run_not_complete"
                    else:
                        reason = None
                    input_rows.append({"kind": "inventory_collection_run", "stable_id": str(latest_run["run_id"]),
                        "revision": int(latest_run["revision"]), "effective_at": _instant(run_receipt),
                        "known_at": _instant(latest_run["created_at"]), "retained_value": _jsonable(dict(latest_run))})
                else:
                    if missed_after_run or latest_due and (latest_due["state"] == "missed" or
                            latest_due["state"] in {"due", "started"} and latest_due["grace_deadline"] <= as_of):
                        reason = "source_run_missed"
                        aggregate["last_attempt_at"] = _instant(latest_due["due_at"])
                    else:
                        reason = "no_retained_collection_run"
                stale = reason == "observation_missing_future_or_stale"
                if matched_observations:
                    aggregate["observed_targets"] += 1
                if reason:
                    aggregate["failure_reasons"].append(reason)
                else:
                    aggregate["_fresh_targets"] += 1
                aggregate["missed_run"] = aggregate["missed_run"] or missed_after_run or reason == "source_run_missed"
                aggregate["stale"] = aggregate["stale"] or stale
                if run_receipt and (aggregate["latest_successful_collection_at"] is None or
                        latest_run["state"] == "completed" and run_receipt > datetime.fromisoformat(aggregate["latest_successful_collection_at"].replace("Z", "+00:00"))):
                    if latest_run["state"] == "completed":
                        aggregate["latest_successful_collection_at"] = _instant(run_receipt)
                if latest_observed and (aggregate["latest_trustworthy_observed_at"] is None or
                        latest_observed > datetime.fromisoformat(aggregate["latest_trustworthy_observed_at"].replace("Z", "+00:00"))):
                    aggregate["latest_trustworthy_observed_at"] = _instant(latest_observed)
                source_results.append({"source_id": aggregate_key, "source_family": source_key[0],
                    "source_account_id": source_key[1], "scope_key": source_key[2],
                    "status": "fresh" if reason is None else "stale" if stale else "failed" if reason.startswith("source_run_failed") else "partial" if "partial" in reason else "missing",
                    "collection_at": _instant(run_receipt), "observed_at": _instant(latest_observed),
                    "last_attempt_at": aggregate["last_attempt_at"], "watermark": aggregate["watermark"],
                    "failure_reason": reason})
            complete_count = sum(source["status"] == "fresh" for source in source_results)
            target_status = "fresh" if complete_count == len(source_results) else (
                "failed" if any(source["status"] == "failed" for source in source_results) else
                "stale" if any(source["status"] == "stale" for source in source_results) else
                "partial" if any(source["status"] == "partial" for source in source_results) else "missing")
            target_rows.append({"target_id": target["target_id"], "group_id": target["group_id"],
                "status": target_status, "required_source_count": len(source_results),
                "complete_source_count": complete_count,
                "metric_membership": {"inventory_scan_coverage": {
                    "numerator": target_status == "fresh", "denominator": True}},
                "failure_reasons": sorted({source["failure_reason"] for source in source_results if source["failure_reason"]}),
                "sources": source_results})
        covered = sum(target["status"] == "fresh" for target in target_rows)
        for source in source_aggregates.values():
            reasons = sorted(set(source["failure_reasons"]))
            source["failure_reasons"] = reasons
            source["completeness"] = ("complete" if source["_fresh_targets"] == source["expected_targets"] else
                "failed" if any(reason.startswith("source_run_failed") for reason in reasons) else
                "missed" if source["missed_run"] else
                "stale" if source["stale"] else
                "partial" if any("partial" in reason for reason in reasons) else "unknown")
            source.pop("_fresh_targets", None)
        return {"configured": True, "revision": int(selected["revision"]), "targets": target_rows,
            "sources": list(source_aggregates.values()), "expected": len(target_rows),
            "covered": covered, "unexpected_count": len(unexpected_target_keys) if full_inventory_scope else None,
            "unmapped_count": len(unmapped_observation_ids) if full_inventory_scope else None,
            "scope_complete": full_inventory_scope}

    @app.get("/api/v1/reports/inventory")
    def inventory_catalogue(group_id: str = Query(...), principal=Depends(auth)):
        group_id = _uuid(group_id, "group_id")
        with engine.connect() as connection:
            policy_revision, policy = policy_for(connection)
            group = connection.execute(sa.select(groups).where(
                groups.c.group_id == group_id)).mappings().first()
            from uvm.assessment.api import _complete_target_grants
            grants = (_complete_target_grants(connection, policy, principal["name"],
                "policy.read", group_id, group["source_family"]) if group else [])
            if not grants:
                _error(403, "forbidden", "Current policy-read authority is required")
            from uvm.auth.service import group_scope_covered
            if not group_scope_covered(connection, AUTHORITY_CONTEXT.get(), [group_id],
                    granting_identity_groups=[grant.get("principal_id") for grant in grants]):
                _error(403, "source_scope_forbidden", "Current exact source scope is required")
            head = connection.execute(sa.select(inventory_policy_heads.c.revision).where(
                inventory_policy_heads.c.head_id == 1)).scalar_one()
            versions = connection.execute(sa.select(inventory_policy_versions).order_by(
                inventory_policy_versions.c.revision)).mappings().all()
            current = next((row for row in reversed(versions)
                if group_id in row["document"].get("scope_group_ids", [])), None)
            current_document = None
            if current:
                current_document = {**current["document"],
                    "scope_group_ids": [group_id],
                    "targets": [target for target in current["document"].get("targets", [])
                        if target.get("group_id") == group_id]}
            return {"schema_version": 1, "group_id": group_id,
                "assessment_policy_revision": policy_revision,
                "inventory_head": int(head),
                "current": ({"revision": current["revision"], "document": current_document,
                    "created_at": _instant(current["created_at"]), "created_by": current["created_by"]}
                    if current else None)}

    @app.post("/api/v1/reports/inventory")
    def publish_inventory(body: dict, principal=Depends(auth)):
        """Reject the superseded standalone writer; publish through policy.sla.publish."""
        _error(410, "use_sla_policy_command",
            "Inventory versions require the scoped policy.sla.publish command envelope")
        # Retained below as the historical validation specification; no
        # standalone inventory action can persist state or create a receipt.
        if not isinstance(body, dict) or body.get("schema_version") != 1:
            _error(422, "invalid_request", "Inventory command schema_version must be 1")
        command_id = _uuid(body.get("command_id"), "command_id")
        expected_revision = body.get("expected_inventory_revision")
        expected_policy_revision = body.get("expected_policy_revision")
        if type(expected_revision) is not int or expected_revision < 0 or type(expected_policy_revision) is not int:
            _error(422, "invalid_request", "Inventory and policy expected revisions are required")
        config = body.get("configuration")
        required = {"effective_from", "effective_until", "freshness_horizon_seconds",
            "expected_schedule_seconds", "targets"}
        if not isinstance(config, dict) or set(config) != required:
            _error(422, "invalid_request", "Inventory configuration fields are invalid")
        effective_from = _time(config["effective_from"], "configuration.effective_from")
        effective_until = _time(config["effective_until"], "configuration.effective_until", optional=True)
        now = now_utc()
        horizon, schedule = config["freshness_horizon_seconds"], config["expected_schedule_seconds"]
        if (effective_from < now or (effective_until and effective_until <= effective_from)
                or type(horizon) is not int or horizon <= 0 or type(schedule) is not int or schedule <= 0):
            _error(422, "invalid_request", "Inventory interval, freshness horizon or schedule is invalid")
        targets = config["targets"]
        if not isinstance(targets, list) or not targets:
            _error(422, "invalid_request", "Inventory requires explicit expected targets")
        target_ids, scope_group_ids = set(), set()
        for target in targets:
            if not isinstance(target, dict) or set(target) != {"target_id", "group_id", "required_sources"}:
                _error(422, "invalid_request", "Expected target fields are invalid")
            target_id = target["target_id"]
            if not isinstance(target_id, str) or not target_id.strip() or target_id in target_ids:
                _error(422, "invalid_request", "Expected target IDs must be unique stable strings")
            target_ids.add(target_id)
            target["group_id"] = _uuid(target["group_id"], "target.group_id")
            scope_group_ids.add(target["group_id"])
            required_sources = target["required_sources"]
            if not isinstance(required_sources, list) or not required_sources:
                _error(422, "invalid_request", "Each expected target requires at least one source")
            source_keys = set()
            for source in required_sources:
                if not isinstance(source, dict) or set(source) != {"source_family", "source_account_id", "scope_key",
                        "schedule_id", "schedule_revision", "target_match"}:
                    _error(422, "invalid_request", "Required source fields are invalid")
                if any(not isinstance(source[key], str) or not source[key].strip()
                        for key in ("source_family", "source_account_id", "scope_key", "schedule_id")):
                    _error(422, "invalid_request", "Required source identity fields must be non-empty")
                if type(source["schedule_revision"]) is not int or source["schedule_revision"] < 1:
                    _error(422, "invalid_request", "Required source schedule revision must be positive")
                match = source["target_match"]
                if not isinstance(match, dict):
                    _error(422, "invalid_request", "Source target_match is required")
                allowed_matches = ({"field", "value"}, {"field", "scheme", "authority", "value"})
                if (set(match) not in allowed_matches or match.get("field") not in {"asset_locator", "native_id"}
                        or not isinstance(match.get("value"), str) or not match["value"].strip()
                        or match["field"] == "native_id" and (not match.get("scheme") or not match.get("authority"))
                        or match["field"] == "asset_locator" and set(match) != {"field", "value"}):
                    _error(422, "invalid_request", "Source target_match must name an exact retained asset or native identity")
                key = (source["source_family"], source["source_account_id"], source["scope_key"])
                if key in source_keys:
                    _error(422, "invalid_request", "Required sources must be unique per target")
                source_keys.add(key)
        document = {**config, "scope_group_ids": sorted(scope_group_ids)}
        with engine.begin() as connection:
            policy_row = connection.execute(sa.select(assessment_policy).where(
                assessment_policy.c.policy_id == 1).with_for_update()).mappings().first()
            if not policy_row or int(policy_row["revision"]) != expected_policy_revision:
                _error(409, "revision_conflict", "Assessment policy revision changed")
            from uvm.assessment.api import _complete_target_grants
            for group in scope_group_ids:
                source_family = connection.execute(sa.select(groups.c.source_family).where(
                    groups.c.group_id == group)).scalar_one_or_none()
                if source_family is None or not _complete_target_grants(connection,
                        policy_row["document"], principal["name"], "policy.sla.publish",
                        group, source_family):
                    _error(403, "forbidden", "Current scoped SLA publication authority is required for every inventory group")
            for target in targets:
                for source in target["required_sources"]:
                    schedule_row = connection.execute(sa.select(collection_schedules).where(
                        collection_schedules.c.schedule_id == source["schedule_id"],
                        collection_schedules.c.revision == source["schedule_revision"])).mappings().first()
                    if (schedule_row is None or not schedule_row["enabled"]
                            or (schedule_row["source_family"], schedule_row["source_account_id"], schedule_row["scope_key"])
                                != (source["source_family"], source["source_account_id"], source["scope_key"])):
                        _error(422, "invalid_request", "Every required source must reference its exact enabled retained collection schedule")
            head_row = connection.execute(sa.select(inventory_policy_heads).where(
                inventory_policy_heads.c.head_id == 1).with_for_update()).mappings().one()
            head = int(head_row["revision"])
            existing = connection.execute(sa.select(inventory_policy_versions).where(
                inventory_policy_versions.c.command_id == command_id)).mappings().first()
            if existing:
                if existing["created_by"] != principal["name"] or existing["document"] != document:
                    _error(409, "idempotency_conflict", "Inventory command ID was used for different content")
                return {"schema_version": 1, "command_id": command_id,
                    "revision": existing["revision"], "audit_event_id": existing["audit_event_id"],
                    "replayed": True}
            if head != expected_revision:
                _error(409, "revision_conflict", "Inventory head changed")
            revision, event_id = head + 1, str(uuid.uuid4())
            seq = connection.execute(sa.select(sa.func.coalesce(
                sa.func.max(assessment_audit_events.c.event_sequence), 0) + 1)).scalar_one()
            connection.execute(assessment_audit_events.insert().values(
                event_id=event_id, event_sequence=seq, actor_id=principal["name"],
                actor_kind="principal", origin="public_api", action="policy.inventory.publish",
                target_id=ZERO, before_value={"inventory_revision": head},
                after_value={"inventory_revision": revision, "inventory": document},
                membership_ids=[], membership_revision=0, rationale="Publish expected inventory and source freshness contract",
                evidence_ref="inventory:" + command_id, policy_revision=expected_policy_revision,
                identity_revision=0, occurred_at=now, received_at=now,
                correlation_id=command_id, command_id=command_id))
            connection.execute(inventory_policy_versions.insert().values(
                revision=revision, command_id=command_id, document=document,
                created_at=now, created_by=principal["name"], audit_event_id=event_id))
            connection.execute(inventory_policy_heads.update().where(
                inventory_policy_heads.c.head_id == 1).values(revision=revision, updated_at=now))
            return {"schema_version": 1, "command_id": command_id,
                "revision": revision, "audit_event_id": event_id, "replayed": False}

    @app.post("/api/v1/reports")
    def create_report(body: dict, request: Request, principal=Depends(auth)):
        if not isinstance(body, dict) or body.get("schema_version", 1) != 1:
            _error(422, "invalid_request", "Report request schema is invalid")
        if "identity_scalar_sequence" in body:
            _error(422, "invalid_request", "Identity snapshot boundaries are server-captured")
        if "now" in body:
            _error(422, "invalid_request", "as_of is the sole report evaluation clock")
        definition_version = body.get("definition_version", DEFINITION)
        if definition_version not in {DEFINITION, G7_DEFINITION}:
            _error(422, "invalid_request", "Unsupported report definition version")
        command_id = _uuid(body.get("command_id"), "command_id")
        report_stage("authenticated_handler_start", command_id)
        mode = body.get("mode", "as_known_at")
        if mode not in {"as_known_at", "corrected_history"}:
            _error(422, "invalid_request", "Report mode is invalid")
        scope = body.get("scope")
        if not isinstance(scope, dict) or not isinstance(scope.get("group_ids"), list) or not scope["group_ids"]:
            _error(422, "invalid_request", "Explicit non-empty group_ids scope is required")
        group_ids = sorted(set(_uuid(g, "group_ids item") for g in scope["group_ids"]))
        filters = body.get("filters", {})
        if not isinstance(filters, dict) or filters:
            _error(422, "invalid_request", "Report filters are not configured; use explicit group_ids scope")
        as_of = _time(body.get("as_of"), "as_of", optional=True)
        known_at = _time(body.get("known_at"), "known_at", optional=True)
        omitted_clock_context = as_of is None and known_at is None
        if not omitted_clock_context and (as_of is None or known_at is None):
            _error(422, "invalid_request", "as_of and known_at must be supplied together")
        if not omitted_clock_context and as_of > known_at:
            _error(422, "invalid_request", "Report context must satisfy as_of <= known_at <= server time")
        period = body.get("period") or {}
        if not isinstance(period, dict):
            _error(422, "invalid_request", "period must be an object")
        period_start = _time(period.get("start"), "period.start", optional=True)
        period_end = _time(period.get("end"), "period.end", optional=True)
        if period_start and period_end and period_start >= period_end:
            _error(422, "invalid_request", "Completion period must have positive duration")
        if period_end is not None and as_of is not None and period_end > as_of:
            _error(422, "invalid_request", "Completion period end cannot be after as_of")
        timezone_name = body.get("display_timezone", "UTC")
        if not isinstance(timezone_name, str) or not timezone_name:
            _error(422, "invalid_request", "display_timezone is required")
        predecessor = body.get("predecessor_report_id")
        if mode == "as_known_at" and predecessor is not None:
            _error(422, "invalid_request", "as_known_at reports cannot name a predecessor")
        if mode == "corrected_history" and predecessor is None:
            _error(422, "invalid_request", "Corrected history requires an authorised predecessor")
        now = now_utc()
        report_id, decision_id, audit_id, intent_id = (str(uuid.uuid4()) for _ in range(4))
        accepted_cleanup_target = getattr(request.state,
            "_accepted_report_cleanup_target", None)
        def remember_accepted_cleanup_target(target):
            nonlocal accepted_cleanup_target
            accepted_cleanup_target = target
            if target is not None:
                # A serialisation retry calls this route function again with
                # the same Request. Preserve the exact accepted outcome across
                # that retry so a subsequent revocation denial can clean it up.
                request.state._accepted_report_cleanup_target = target

        def mark_accepted_report_failed():
            _mark_report_failure(engine, accepted_cleanup_target)
        try:
            # Commit the command, audit, receipt and pending materialisation
            # intent first. A process loss during the expensive snapshot build
            # therefore leaves an exact replayable durable outcome.
            report_stage("acceptance_connection_acquisition_start", command_id)
            with engine.begin() as connection:
                report_stage("acceptance_connection_acquired", command_id)
                lock_identity_graph(connection)
                report_stage("acceptance_policy_lock_wait_start", command_id)
                policy_revision, policy = policy_for(connection, lock=True)
                report_stage("acceptance_policy_lock_acquired", command_id)
                auth_service = getattr(app.state, "oidc_auth", None)
                auth_context = auth_service.final_context(connection, request) if auth_service else None
                from uvm.auth.service import group_scope_covered
                now = now_utc()
                if omitted_clock_context:
                    # Resolve first-use omitted clocks under the same transaction
                    # lock as command acceptance. Concurrent identical submissions
                    # therefore observe the first committed context before hashing.
                    prior_context = connection.execute(sa.select(report_requests.c.as_of,
                        report_requests.c.known_at).where(
                        report_requests.c.command_id == command_id,
                        report_requests.c.principal_id == principal["name"])).first()
                    as_of, known_at = prior_context if prior_context else (now, now)
                if as_of > known_at or known_at > now:
                    _error(422, "invalid_request", "Report context must satisfy as_of <= known_at <= server time")
                if period_end is not None and period_end > as_of:
                    _error(422, "invalid_request", "Completion period end cannot be after as_of")
                normalized = {"schema_version": 1, "command_id": command_id, "mode": mode,
                    "scope": {"group_ids": group_ids}, "filters": {},
                    "as_of": _instant(as_of), "known_at": _instant(known_at),
                    "period": {"start": _instant(period_start), "end": _instant(period_end)},
                    "display_timezone": timezone_name, "predecessor_report_id": predecessor}
                # The historical G5 command digest predates the optional
                # definition field. Keep same-ID replay stable across upgrade.
                if definition_version != DEFINITION:
                    normalized["definition_version"] = definition_version
                digest = _digest({"principal": principal["name"], **normalized})
                previous = connection.execute(sa.select(report_requests).where(
                    report_requests.c.command_id == command_id).with_for_update()).mappings().first()
                if previous:
                    if (previous["request_digest"] != digest
                            or previous["principal_id"] != principal["name"]):
                        _error(409, "command_id_reused", "Command ID is bound to different report content")
                    # Only an exact accepted command from this principal may
                    # be marked failed if its current authority has since been
                    # revoked. Conflicting submissions never acquire a cleanup
                    # target.
                    remember_accepted_cleanup_target(_report_failure_target(previous,
                        command_id=command_id, principal_id=principal["name"],
                        request_digest=digest))
                    report_id = previous["report_id"]
                    intent_id = previous["projection_intent_id"]
                    if any(not allowed(connection, policy, principal["name"], "report.read", g)
                            for g in previous["scope"].get("group_ids", [])):
                        _error(403, "forbidden", "Current report authority is required")
                    if any(not group_scope_covered(connection, auth_context, [g],
                            granting_identity_groups=[grant.get("principal_id") for grant in
                                grants_for_group(connection, policy, principal["name"], "report.read", g)])
                            for g in previous["scope"].get("group_ids", [])):
                        _error(403, "source_scope_forbidden", "Current exact source scope is required")
                    if previous["status"] == "ready":
                        return report_receipt(connection, previous)
                    stored_receipt = connection.execute(sa.select(assessment_command_receipts).where(
                        assessment_command_receipts.c.command_id == command_id)).mappings().first()
                    decision_id, audit_id = stored_receipt["decision_id"], stored_receipt["audit_event_id"]
                    connection.execute(report_requests.update().where(
                        report_requests.c.report_id == report_id).values(status="pending", error_code=None))
                    connection.execute(reporting_projection_intents.update().where(
                        reporting_projection_intents.c.intent_id == intent_id).values(status="pending",
                            attempts=reporting_projection_intents.c.attempts + 1, last_error=None,
                            updated_at=now))
                else:
                    group_rows = connection.execute(sa.select(groups).where(groups.c.group_id.in_(group_ids))).mappings().all()
                    if len(group_rows) != len(group_ids) or any(not allowed(connection, policy, principal["name"], "report.create", g)
                            for g in group_ids):
                        _error(403, "forbidden", "Current report authority is required for the requested scope")
                    if any(not group_scope_covered(connection, auth_context, [g],
                            granting_identity_groups=[grant.get("principal_id") for grant in
                                grants_for_group(connection, policy, principal["name"], "report.create", g)])
                            for g in group_ids):
                        _error(403, "source_scope_forbidden", "Current exact source scope is required")
                    event_watermark = int(connection.execute(sa.select(sa.func.coalesce(
                        sa.func.max(assessment_audit_events.c.event_sequence), 0)).where(
                        assessment_audit_events.c.received_at <= known_at)).scalar_one())
                    source_watermark = int(connection.execute(sa.select(sa.func.coalesce(
                        sa.func.max(source_observations.c.retention_order), 0)).where(
                        source_observations.c.collected_at <= known_at)).scalar_one())
                    connection.execute(report_requests.insert().values(report_id=report_id, command_id=command_id,
                        principal_id=principal["name"], request_digest=digest, mode=mode, as_of=as_of, known_at=known_at,
                        period_start=period_start, period_end=period_end, display_timezone=timezone_name,
                        scope={"group_ids": group_ids, "filters": {}}, definition_version=definition_version,
                        predecessor_report_id=predecessor, snapshot_sequence=event_watermark,
                        source_retention_watermark=source_watermark,
                        identity_scalar_sequence=int(connection.execute(sa.select(sa.func.coalesce(
                            sa.func.max(identity_scalar_correction_receipts.c.knowledge_sequence), 0)).where(
                            identity_scalar_correction_receipts.c.recorded_at <= known_at)).scalar_one()),
                        input_manifest=[],
                        assessment_policy_snapshot={"revision": policy_revision, "document": policy},
                        status="pending", projection_intent_id=intent_id, result=None, created_at=now, ready_at=None))
                    connection.execute(reporting_projection_intents.insert().values(intent_id=intent_id,
                        report_id=report_id, audit_event_id=audit_id,
                        kind="report.materialise", status="pending", attempts=0,
                        last_error=None, created_at=now, updated_at=now))
                    event_sequence = int(connection.execute(sa.select(sa.func.coalesce(
                        sa.func.max(assessment_audit_events.c.event_sequence), 0) + 1)).scalar_one())
                    connection.execute(assessment_audit_events.insert().values(event_id=audit_id,
                        event_sequence=event_sequence, actor_id=principal["name"], actor_kind="principal",
                        origin="local_api", action="report.create", target_id=group_ids[0], before_value={},
                        after_value={"report_id": report_id, "request": normalized}, membership_ids=[],
                        membership_revision=0, rationale="Create immutable stakeholder report", evidence_ref="",
                        policy_revision=policy_revision, identity_revision=0, occurred_at=now, received_at=now,
                        correlation_id=command_id, command_id=command_id,
                        authorization_context=auth_context.document() if auth_context else None))
                    pending_receipt = {"schema_version": 1, "command_id": command_id,
                        "decision_id": decision_id, "audit_event_id": audit_id, "intent_id": intent_id,
                        "committed_revision": policy_revision, "projection": "pending", "report_id": report_id,
                        "error_code": None}
                    connection.execute(assessment_command_receipts.insert().values(command_id=command_id,
                        principal_id=principal["name"], action="report.create", target_id=group_ids[0],
                        request_digest=digest, decision_id=decision_id, audit_event_id=audit_id,
                        intent_id=intent_id, result=pending_receipt, created_at=now,
                        authorization_context=auth_context.document() if auth_context else None))
            if previous is None:
                remember_accepted_cleanup_target(_report_failure_target({
                    "report_id": report_id, "command_id": command_id,
                    "principal_id": principal["name"], "request_digest": digest,
                    "projection_intent_id": intent_id}, command_id=command_id,
                    principal_id=principal["name"], request_digest=digest))
            report_stage("accepted_receipt_commit", command_id, report_id=report_id)
            report_stage("materialisation_connection_acquisition_start", command_id)
            with engine.begin() as connection:
                report_stage("materialisation_connection_acquired", command_id)
                if engine.dialect.name == "postgresql":
                    connection.execute(sa.text("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ"))
                lock_identity_graph(connection)
                report_stage("materialisation_policy_lock_wait_start", command_id)
                policy_revision, policy = policy_for(connection, lock=True)
                report_stage("materialisation_policy_lock_acquired", command_id)
                auth_service = getattr(app.state, "oidc_auth", None)
                auth_context = (auth_service.final_context_after_snapshot_lock(connection, request)
                    if auth_service else None)
                from uvm.auth.service import group_scope_covered
                report_stage("materialisation_start", command_id, report_id=report_id)
                previous = connection.execute(sa.select(report_requests).where(
                    report_requests.c.command_id == command_id).with_for_update()).mappings().first()
                if previous:
                    if previous["request_digest"] != digest:
                        _error(409, "command_id_reused", "Command ID is bound to different report content")
                    if any(not allowed(connection, policy, principal["name"], "report.read", g) for g in previous["scope"]["group_ids"]):
                        _error(403, "forbidden", "Current report authority is required")
                    if any(not group_scope_covered(connection, auth_context, [g],
                            granting_identity_groups=[grant.get("principal_id") for grant in
                                grants_for_group(connection, policy, principal["name"], "report.read", g)])
                            for g in previous["scope"]["group_ids"]):
                        _error(403, "source_scope_forbidden", "Current exact source scope is required")
                    if previous["status"] == "ready":
                        return report_receipt(connection, previous)
                    report_id, intent_id = previous["report_id"], previous["projection_intent_id"]
                    stored_receipt = connection.execute(sa.select(assessment_command_receipts).where(
                        assessment_command_receipts.c.command_id == command_id)).mappings().first()
                    decision_id, audit_id = stored_receipt["decision_id"], stored_receipt["audit_event_id"]
                group_rows = connection.execute(sa.select(groups).where(groups.c.group_id.in_(group_ids))).mappings().all()
                if len(group_rows) != len(group_ids) or any(not allowed(connection, policy, principal["name"], "report.create", gid) for gid in group_ids):
                    _error(403, "forbidden", "Current report authority is required for the requested scope")
                if any(not group_scope_covered(connection, auth_context, [gid],
                        granting_identity_groups=[grant.get("principal_id") for grant in
                            grants_for_group(connection, policy, principal["name"], "report.create", gid)])
                        for gid in group_ids):
                    _error(403, "source_scope_forbidden", "Current exact source scope is required")
                if mode == "corrected_history":
                    prior = report_row(connection, predecessor, principal["name"], action="report.read")
                    if (prior["as_of"] != as_of or prior["scope"].get("group_ids") != group_ids
                            or prior["period_start"] != period_start or prior["period_end"] != period_end
                            or prior["definition_version"] != definition_version or known_at <= prior["known_at"]):
                        _error(409, "report_context_conflict", "Corrected report context must match its predecessor")
                    predecessor_result = prior["result"]
                else:
                    predecessor_result = None
                event_watermark = int(previous["snapshot_sequence"])
                source_watermark = int(previous["source_retention_watermark"])
                scalar_sequence = int(previous["identity_scalar_sequence"])
                connection.info["uvm_scalar_snapshot_boundary"] = (connection.get_transaction(), scalar_sequence)
                atom_rows = []
                input_rows = []
                manifested_identity_resolution_ids = set()
                manifested_reference_ids = set()
                historical_state_docs = {}
                assessment_members_by_group = {}
                severity_overrides_by_group = {}
                reference_history_cache = {}
                reference_recorded_at_cache = {}

                def reference_history_for(current_connection, occurrence_id):
                    if occurrence_id not in reference_history_cache:
                        reference_history_cache[occurrence_id] = DeadlineReferenceStore.read_history_on_connection(
                            current_connection, occurrence_id)
                    return reference_history_cache[occurrence_id]

                def reference_recorded_at_for(current_connection, reference_id):
                    if reference_id not in reference_recorded_at_cache:
                        reference_recorded_at_cache[reference_id] = current_connection.execute(sa.select(
                            identity_deadline_references.c.recorded_at).where(
                            identity_deadline_references.c.reference_id == reference_id
                            )).scalar_one_or_none()
                    return reference_recorded_at_cache[reference_id]
                # Calculation uses the authority document accepted with the
                # report command. Current policy above remains authoritative
                # for live disclosure and reauthorisation checks only.
                policy_snapshot = previous.get("assessment_policy_snapshot") or {}
                calculation_policy = (policy_snapshot.get("document") if isinstance(policy_snapshot, dict)
                    and "document" in policy_snapshot else policy_snapshot) or policy
                policy_events = connection.execute(sa.select(assessment_audit_events).where(
                    assessment_audit_events.c.action.in_({"principal.update", "policy.role.create",
                        "policy.role.assign", "policy.role.update", "policy.sla.publish", *NATIVE_ACTIONS}),
                    assessment_audit_events.c.event_sequence <= event_watermark,
                    assessment_audit_events.c.received_at <= known_at)
                    .order_by(assessment_audit_events.c.event_sequence)).mappings().all()
                effective_policy_events = [event for event in policy_events if event["occurred_at"] <= as_of]
                future_policy_events = [event for event in policy_events if event["occurred_at"] > as_of]
                selected_policy_event = (effective_policy_events[-1] if effective_policy_events else
                    future_policy_events[0] if future_policy_events else None)
                if selected_policy_event is not None:
                    raw_policy = (selected_policy_event["after_value"] if effective_policy_events
                        else selected_policy_event["before_value"])
                    if isinstance(raw_policy, dict) and isinstance(raw_policy.get("assessment_policy"), dict):
                        raw_policy = raw_policy["assessment_policy"]
                    if isinstance(raw_policy, dict) and "principals" in raw_policy:
                        calculation_policy = raw_policy
                # Audit policy_revision is the guarded pre-publication head.
                # Bind historical authority to the selected document's head,
                # not the newer authorisation snapshot accepted by this request.
                calculation_policy_revision = (int(selected_policy_event["policy_revision"])
                    + (1 if effective_policy_events else 0) if selected_policy_event else 1)
                # Reuse the same report-context policy version set throughout this
                # repeatable-read projection. Candidate checks below retain their
                # per-row effective/created-at predicates.
                policy_rows_as_known = connection.execute(sa.select(sla_policy_versions).where(
                    sla_policy_versions.c.created_at <= known_at).order_by(
                        sla_policy_versions.c.revision)).mappings().all()
                policy_rows_as_known = [row for row in policy_rows_as_known
                    if ((definition_version == G7_DEFINITION) ==
                        (row["document"].get("start_source") == "uvm_ingest_commit_v1"))]
                policy_versions_by_key = {(row["policy_id"], row["version"]): row
                    for row in policy_rows_as_known}
                for group in group_rows:
                    historical_group, group_corrections = _identity_record_at_context(
                        connection, "group", group, as_of, known_at)
                    input_rows.append({"kind": "group_identity", "stable_id": group["group_id"],
                        "revision": int(historical_group["revision"]),
                        "effective_at": _instant(group["created_at"]),
                        "known_at": _instant(group["created_at"]),
                        "retained_value": _jsonable(historical_group)})
                    for correction in group_corrections:
                        if correction["created_at"] > known_at:
                            continue
                        input_rows.append({"kind": "identity_correction", "stable_id": correction["correction_id"],
                            "revision": int(correction["new_revision"]),
                            "effective_at": _instant(correction["created_at"]),
                            "known_at": _instant(correction.get("recorded_at", correction["created_at"])),
                            "retained_value": _jsonable(dict(correction))})
                    state = connection.execute(sa.select(assessment_group_state).where(
                        assessment_group_state.c.group_id == group["group_id"])).mappings().first()
                    # Corrected history changes what was known, not what was
                    # effective at as_of. Reconstruct assessment state from
                    # retained events within both clocks for either report mode;
                    # the later known_at admits backdated facts without making
                    # later owner/assessment decisions effective retroactively.
                    state_events = connection.execute(sa.select(assessment_audit_events).where(
                        assessment_audit_events.c.target_id == group["group_id"],
                        assessment_audit_events.c.action.in_(GROUP_STATE_ACTIONS),
                        assessment_audit_events.c.event_sequence <= event_watermark,
                        assessment_audit_events.c.occurred_at <= as_of,
                        assessment_audit_events.c.received_at <= known_at)
                        .order_by(assessment_audit_events.c.event_sequence)).mappings().all()
                    for event in state_events:
                        input_rows.append({"kind": "assessment_audit_event", "stable_id": event["event_id"],
                            "revision": int(event["event_sequence"]), "effective_at": _instant(event["occurred_at"]),
                            "known_at": _instant(event["received_at"]), "retained_value": _jsonable(dict(event))})
                    latest_state_event = state_events[-1] if state_events else None
                    state_doc = (latest_state_event["after_value"] if latest_state_event else
                        state["document"] if state and state["updated_at"] <= known_at and state["updated_at"] <= as_of else {})
                    state_revision = int(latest_state_event["event_sequence"]) if latest_state_event else (int(state["revision"]) if state and state["updated_at"] <= known_at and state["updated_at"] <= as_of else 0)
                    state_effective = latest_state_event["occurred_at"] if latest_state_event else (state["updated_at"] if state and state["updated_at"] <= known_at and state["updated_at"] <= as_of else None)
                    state_known = latest_state_event["received_at"] if latest_state_event else state_effective
                    historical_state_docs[group["group_id"]] = state_doc
                    referenced_owner_ids = {item.get("owner_id") for item in state_doc.get("owners", [])}
                    for portion in state_doc.get("portions", []):
                        if portion.get("active", True):
                            referenced_owner_ids.update(portion.get("owner_ids", []))
                    owner_directory_snapshot = [{**item, **({"scope_group_ids": [group["group_id"]]
                            if group["group_id"] in item["scope_group_ids"] else []}
                            if isinstance(item.get("scope_group_ids"), list) else {})}
                        for item in calculation_policy.get("owner_directory", [])
                        if item.get("owner_id") in referenced_owner_ids]
                    principal_snapshot = {}
                    for owner_id in referenced_owner_ids:
                        principal_snapshot[owner_id] = calculation_policy.get("principals", {}).get(owner_id,
                            {"enabled": True, "team_ids": [], "effective_from": None,
                                "effective_until": None})
                    team_ids = {item.get("owner_id") for item in owner_directory_snapshot
                        if item.get("owner_type") == "team"}
                    for principal_id, principal_state in calculation_policy.get("principals", {}).items():
                        if team_ids.intersection(principal_state.get("team_ids", [])):
                            principal_snapshot[principal_id] = principal_state
                    native = native_state(calculation_policy)
                    native_team_members = {team_id: list(effective_team_members(
                        calculation_policy, team_id, as_of)) for team_id in team_ids
                        if team_id in native.get("ownership_teams", {})}
                    for member_ids in native_team_members.values():
                        for member_id in member_ids:
                            principal_snapshot.setdefault(member_id,
                                calculation_policy.get("principals", {}).get(member_id,
                                    {"enabled": True, "team_ids": []}))
                    input_rows.append({"kind": "historical_owner_authority", "stable_id": group["group_id"],
                        # Bind this retained authority row to the policy event
                        # actually selected by (as_of, known_at). A report's
                        # global event watermark and creation timestamp are
                        # request-local and can advance when another context
                        # is calculated; including them made an identical
                        # context produce a different frozen manifest.
                        "revision": (int(selected_policy_event["event_sequence"])
                            if selected_policy_event else 0),
                        "effective_at": (_instant(selected_policy_event["occurred_at"])
                            if selected_policy_event else None),
                        "known_at": (_instant(selected_policy_event["received_at"])
                            if selected_policy_event else None),
                        "retained_value": {"owner_directory": owner_directory_snapshot,
                            "principals": principal_snapshot,
                            "native_ownership": {"authority_revision": native.get("revision", 0),
                                "ownership_revision": native.get("ownership_revision", 0),
                                "teams": {team_id: {"team_id": native["ownership_teams"][team_id]["team_id"],
                                    "revision": native["ownership_teams"][team_id]["revision"],
                                    "enabled": native["ownership_teams"][team_id].get("enabled", True),
                                    "memberships": copy.deepcopy(native["ownership_teams"][team_id].get("memberships", [])),
                                    "effective_members": native_team_members.get(team_id, [])}
                                    for team_id in native_team_members}},
                            "source_policy_event": ({"event_id": selected_policy_event["event_id"],
                                "action": selected_policy_event["action"],
                                "event_sequence": int(selected_policy_event["event_sequence"]),
                                "effective_at": _instant(selected_policy_event["occurred_at"]),
                                "known_at": _instant(selected_policy_event["received_at"])}
                                if selected_policy_event else None),
                            "accepted_policy_revision": calculation_policy_revision}})
                    assessment_member_ids = set()
                    severity_overrides = {}
                    severity_override_known_at = {}
                    severity_events = connection.execute(sa.select(assessment_audit_events).where(
                        assessment_audit_events.c.target_id == group["group_id"],
                        assessment_audit_events.c.action == "severity.override",
                        assessment_audit_events.c.event_sequence <= event_watermark,
                        assessment_audit_events.c.occurred_at <= as_of,
                        assessment_audit_events.c.received_at <= known_at)
                        .order_by(assessment_audit_events.c.event_sequence)).mappings().all()
                    for severity_event in severity_events:
                        assessed_severity = ((severity_event["after_value"] or {}).get(
                            "assessed_severity") or {}).get("value")
                        if assessed_severity:
                            affected = severity_event["membership_ids"] or []
                            assessment_member_ids.update(affected)
                            for occurrence_id in affected:
                                severity_overrides[occurrence_id] = assessed_severity
                                severity_override_known_at[occurrence_id] = severity_event["received_at"]
                    assessment_members_by_group[group["group_id"]] = assessment_member_ids
                    severity_overrides_by_group[group["group_id"]] = severity_overrides
                    input_rows.append({"kind": "assessment_group_state", "stable_id": group["group_id"],
                        "revision": state_revision,
                        "effective_at": _instant(state_effective),
                        "known_at": _instant(state_known),
                        "retained_value": state_doc})
                    for policy_row in policy_rows_as_known:
                        if group["group_id"] in policy_row["document"].get("scope", {}).get("group_ids", []):
                            policy_snapshot = disclose_policy_document(connection,
                                policy_row["document"], group_ids)
                            input_rows.append({"kind": "sla_policy_version",
                                "stable_id": f"{policy_row['policy_id']}:{policy_row['version']}",
                                "revision": int(policy_row["revision"]),
                                "effective_at": policy_row["document"].get("effective_from"),
                                "known_at": _instant(policy_row["created_at"]),
                                "retained_value": policy_snapshot})
                    episodes = connection.execute(sa.select(exposure_episodes).where(
                        exposure_episodes.c.group_id == group["group_id"],
                        exposure_episodes.c.created_at <= known_at,
                        exposure_episodes.c.created_at <= as_of)).mappings().all()
                    for episode in episodes:
                        members = connection.execute(sa.select(exposure_episode_members).where(
                            exposure_episode_members.c.episode_id == episode["episode_id"])).mappings().all()
                        episode_events = connection.execute(sa.select(exposure_episode_events).where(
                            exposure_episode_events.c.episode_id == episode["episode_id"],
                            exposure_episode_events.c.recorded_at <= known_at,
                            exposure_episode_events.c.recorded_at <= as_of)
                            .order_by(exposure_episode_events.c.state_revision)).mappings().all()
                        # Membership rows are the current materialised set. Only the
                        # retained introduction event makes a member applicable to
                        # this report context; otherwise a later `membership_added`
                        # row would leak into an earlier as_of despite its event being
                        # correctly filtered above.
                        introduced_member_ids = set()
                        for event in episode_events:
                            if event["event_type"] in {
                                    "g3_baseline_materialized", "membership_added", "recurrence_opened"}:
                                introduced_member_ids.update(event.get("occurrence_ids") or [])
                        members = [member for member in members
                            if member["occurrence_id"] in introduced_member_ids]
                        for event in episode_events:
                            input_rows.append({"kind": "episode_event", "stable_id": event["event_id"],
                                "revision": int(event["state_revision"]), "effective_at": _instant(event["recorded_at"]),
                                "known_at": _instant(event["recorded_at"]), "retained_value": _jsonable(dict(event))})
                        effective_members = [_membership_state_at(episode, member, episode_events)
                            for member in members]
                        member_statuses = [member["status"] for member, _ in effective_members]
                        outstanding_count = member_statuses.count("outstanding")
                        episode_state = ("review" if "review" in member_statuses else
                            "open" if member_statuses and outstanding_count == len(member_statuses) else
                            "partially_remediated" if outstanding_count else "remediated")
                        episode_revision = max((int(event["state_revision"]) for event in episode_events), default=1)
                        episode_event = episode_events[-1] if episode_events else None
                        successors = [row for row in episodes if row["exposure_id"] == episode["exposure_id"]
                            and row["episode_number"] > episode["episode_number"]]
                        context_updated_at = (episode_event["recorded_at"] if episode_event else episode["created_at"])
                        if successors:
                            context_updated_at = max(context_updated_at,
                                min(row["created_at"] for row in successors))
                        effective_episode = {**dict(episode), "state": episode_state,
                            "state_revision": episode_revision,
                            "is_current": not successors, "updated_at": context_updated_at,
                            "closed_at": (episode_event["recorded_at"] if episode_state == "remediated"
                                and episode_event else None)}
                        input_rows.append({"kind": "exposure_episode", "stable_id": episode["episode_id"],
                            "revision": episode_revision,
                            "effective_at": _instant(episode_event["recorded_at"]
                                if episode_event else episode["created_at"]),
                            "known_at": _instant(episode_event["recorded_at"] if episode_event else episode["created_at"]),
                            "retained_value": _jsonable(effective_episode)})
                        # Read identity/proof rows in batches for this episode's
                        # exact introduced members. All reads share this guarded
                        # repeatable-read transaction and captured scalar cut.
                        # Historical parents outside the batch use the same
                        # individual reads as before, never a current fallback.
                        member_ids = [member["occurrence_id"] for member, _ in effective_members]
                        occurrence_rows = {row["occurrence_id"]: row for row in connection.execute(
                            sa.select(occurrences).where(occurrences.c.occurrence_id.in_(member_ids))).mappings()} if member_ids else {}
                        incarnation_rows = {row["incarnation_id"]: row for row in connection.execute(
                            sa.select(incarnations).where(incarnations.c.incarnation_id.in_(
                                {row["incarnation_id"] for row in occurrence_rows.values()}))).mappings()} if occurrence_rows else {}
                        workload_rows = {row["workload_id"]: row for row in connection.execute(
                            sa.select(workloads).where(workloads.c.workload_id.in_(
                                {row["workload_id"] for row in occurrence_rows.values()}))).mappings()} if occurrence_rows else {}
                        scalar_proof = ScalarHistoryProofRead(connection,
                            {("incarnation", identifier) for identifier in incarnation_rows}
                            | {("workload", identifier) for identifier in workload_rows})
                        for member, member_state_event in effective_members:
                            input_rows.append({"kind": "episode_membership", "stable_id": episode["episode_id"] + ":" + member["occurrence_id"],
                                "revision": int(member_state_event["state_revision"] if member_state_event else 1),
                                "effective_at": _instant(member_state_event["recorded_at"]
                                    if member_state_event else episode["created_at"]),
                                "known_at": _instant(member_state_event["recorded_at"] if member_state_event else episode["created_at"]),
                                "retained_value": _jsonable(member)})
                            occurrence = occurrence_rows.get(member["occurrence_id"])
                            if occurrence is None:
                                continue
                            occurrence, occurrence_corrections = _identity_record_at_context(
                                connection, "occurrence", occurrence, as_of, known_at)
                            input_rows.append({"kind": "occurrence_identity", "stable_id": occurrence["occurrence_id"],
                                "revision": int(occurrence["revision"]),
                                "effective_at": _instant(occurrence["created_at"]),
                                "known_at": _instant(occurrence["first_ingested_at"]),
                                "retained_value": _jsonable(dict(occurrence))})
                            for correction in occurrence_corrections:
                                if correction["created_at"] > known_at:
                                    continue
                                input_rows.append({"kind": "identity_correction", "stable_id": correction["correction_id"],
                                    "revision": int(correction["new_revision"]),
                                    "effective_at": _instant(correction["created_at"]),
                                    "known_at": _instant(correction.get("recorded_at", correction["created_at"])),
                                    "retained_value": _jsonable(dict(correction))})
                            incarnation = (incarnation_rows[occurrence["incarnation_id"]]
                                if occurrence["incarnation_id"] in incarnation_rows else
                                connection.execute(sa.select(incarnations).where(
                                    incarnations.c.incarnation_id == occurrence["incarnation_id"])).mappings().first())
                            workload = (workload_rows[occurrence["workload_id"]]
                                if occurrence["workload_id"] in workload_rows else
                                connection.execute(sa.select(workloads).where(
                                    workloads.c.workload_id == occurrence["workload_id"])).mappings().first())
                            if incarnation is not None:
                                incarnation, incarnation_corrections = _identity_record_at_context(
                                    connection, "incarnation", incarnation, as_of, known_at, scalar_proof)
                                input_rows.append({"kind": "incarnation_identity", "stable_id": incarnation["incarnation_id"],
                                    "revision": int(incarnation["revision"]),
                                    "effective_at": _instant(incarnation["created_at"]),
                                    "known_at": _instant(incarnation["created_at"]),
                                    "retained_value": _jsonable(dict(incarnation))})
                                for correction in incarnation_corrections:
                                    if correction["created_at"] > known_at:
                                        continue
                                    input_rows.append({"kind": "identity_correction", "stable_id": correction["correction_id"],
                                        "revision": int(correction["new_revision"]),
                                        "effective_at": _instant(correction["created_at"]),
                                        "known_at": _instant(correction.get("recorded_at", correction["created_at"])),
                                        "retained_value": _jsonable(dict(correction))})
                            if workload is not None:
                                workload, workload_corrections = _identity_record_at_context(
                                    connection, "workload", workload, as_of, known_at, scalar_proof)
                                input_rows.append({"kind": "workload_identity", "stable_id": workload["workload_id"],
                                    "revision": int(workload["revision"]),
                                    "effective_at": _instant(workload["created_at"]),
                                    "known_at": _instant(workload["created_at"]),
                                    "retained_value": _jsonable(dict(workload))})
                                for correction in workload_corrections:
                                    if correction["created_at"] > known_at:
                                        continue
                                    input_rows.append({"kind": "identity_correction", "stable_id": correction["correction_id"],
                                        "revision": int(correction["new_revision"]),
                                        "effective_at": _instant(correction["created_at"]),
                                        "known_at": _instant(correction.get("recorded_at", correction["created_at"])),
                                        "retained_value": _jsonable(dict(correction))})
                            resolution_query = sa.select(identity_resolutions).where(
                                identity_resolutions.c.occurrence_id == occurrence["occurrence_id"],
                                identity_resolutions.c.evaluated_at <= known_at)
                            if mode != "corrected_history":
                                resolution_query = resolution_query.where(
                                    identity_resolutions.c.evaluated_at <= as_of)
                            identity_rows = connection.execute(resolution_query.order_by(
                                identity_resolutions.c.observation_id,
                                identity_resolutions.c.revision)).mappings().all()
                            for identity_row in identity_rows:
                                if identity_row["resolution_id"] in manifested_identity_resolution_ids:
                                    continue
                                input_rows.append({"kind": "identity_resolution", "stable_id": identity_row["resolution_id"],
                                    "revision": int(identity_row["revision"]), "effective_at": _instant(identity_row["evaluated_at"]),
                                    "known_at": _instant(identity_row["evaluated_at"]), "retained_value": _jsonable(dict(identity_row))})
                                manifested_identity_resolution_ids.add(identity_row["resolution_id"])
                            occurrence_exposure = connection.execute(sa.select(exposures).where(
                                exposures.c.exposure_id == occurrence["exposure_id"])).mappings().first()
                            if occurrence_exposure is not None:
                                occurrence_exposure, exposure_corrections = _identity_record_at_context(
                                    connection, "exposure", occurrence_exposure, as_of, known_at)
                                for correction in exposure_corrections:
                                    if correction["created_at"] > known_at:
                                        continue
                                    input_rows.append({"kind": "identity_correction", "stable_id": correction["correction_id"],
                                        "revision": int(correction["new_revision"]),
                                        "effective_at": _instant(correction["created_at"]),
                                        "known_at": _instant(correction.get("recorded_at", correction["created_at"])),
                                        "retained_value": _jsonable(dict(correction))})
                            if occurrence_exposure is None or occurrence_exposure["group_id"] != group["group_id"]:
                                continue
                            input_rows.append({"kind": "exposure_identity", "stable_id": occurrence_exposure["exposure_id"],
                                "revision": int(occurrence_exposure["revision"]),
                                "effective_at": _instant(occurrence_exposure["created_at"]),
                                "known_at": _instant(occurrence_exposure["created_at"]),
                                "retained_value": _jsonable(dict(occurrence_exposure))})
                            current = member["status"] in {"outstanding", "review"}
                            confirmed_at = member["confirmed_at"] if member["status"] in {"confirmed", "continuity_covered"} else None
                            source_rating_rows = connection.execute(sa.select(
                                source_observations.c.source_rating, source_observations.c.observed_at,
                                source_observations.c.collected_at, source_observations.c.collection_status,
                                source_observations.c.source_family, source_observations.c.source_account_id,
                                source_observations.c.retention_order, source_observations.c.observation_id)
                                .where(source_observations.c.occurrence_id == occurrence["occurrence_id"],
                                    source_observations.c.retention_order <= source_watermark,
                                    sa.or_(sa.literal(definition_version != G7_DEFINITION),
                                        source_observations.c.observation_id.in_(sa.select(
                                            source_observation_receipts.c.source_observation_id).where(
                                            source_observation_receipts.c.retained_at <= known_at))),
                                    source_observations.c.collected_at <= known_at,
                                    sa.or_(source_observations.c.observed_at.is_(None),
                                        source_observations.c.observed_at <= as_of))
                                .order_by(source_observations.c.observed_at.desc().nullslast(),
                                    source_observations.c.retention_order.desc())).all()
                            # The all-source query has the same context predicate
                            # and ordering as the former latest-row query.
                            rating = source_rating_rows[0] if source_rating_rows else None
                            latest_source_ratings = {}
                            for evidence_row in source_rating_rows:
                                latest_source_ratings.setdefault((evidence_row[4], evidence_row[5]), evidence_row)
                            source_severity = str(rating[0]).lower() if rating and rating[0] else "unknown"
                            assessed_severity = severity_overrides_by_group.get(group["group_id"], {}).get(
                                occurrence["occurrence_id"])
                            severity = str(assessed_severity).lower() if assessed_severity else source_severity
                            workload_context = (workload or {}).get("stable_attrs") or {}
                            evaluation_table = (g7_sla_evaluations if definition_version == G7_DEFINITION
                                else sla_evaluations)
                            evaluation_history = [dict(row) for row in connection.execute(
                                sa.select(evaluation_table).where(
                                    evaluation_table.c.episode_id == episode["episode_id"],
                                    evaluation_table.c.occurrence_id == occurrence["occurrence_id"])
                                .order_by(evaluation_table.c.effective_at,
                                    evaluation_table.c.revision)).mappings().all()]
                            from uvm.assessment.sla_classification import (
                                evaluation_for_context, evaluation_is_authoritative_in_context,
                                evaluation_revision_head, next_evaluation_revision,
                                trustworthy_causal_transition, select_reset_policy,
                                reset_original_baseline, guard_pending_anchor,
                            )
                            latest_evaluation = evaluation_revision_head(evaluation_history)
                            evaluation = evaluation_for_context(evaluation_history, as_of, known_at)
                            derivation_is_authoritative = evaluation_is_authoritative_in_context(
                                evaluation_history, as_of, known_at)
                            causal_transition = trustworthy_causal_transition(
                                [dict(event) for event in episode_events], occurrence["occurrence_id"],
                                [dict(row._mapping) for row in source_rating_rows])
                            clock_reset_event = causal_transition["event"]
                            transition_start = causal_transition["started_at"]
                            if definition_version == G7_DEFINITION:
                                from uvm.assessment.g7_clock import ensure_current_evaluation
                                current_g7 = ensure_current_evaluation(connection,
                                    episode_id=episode["episode_id"],
                                    occurrence_id=occurrence["occurrence_id"],
                                    known_at=known_at, assessed_severity=assessed_severity)
                                if current_g7:
                                    evaluation_history = [dict(row) for row in connection.execute(
                                        sa.select(g7_sla_evaluations).where(
                                            g7_sla_evaluations.c.episode_id == episode["episode_id"],
                                            g7_sla_evaluations.c.occurrence_id == occurrence["occurrence_id"])
                                        .order_by(g7_sla_evaluations.c.effective_at,
                                            g7_sla_evaluations.c.revision)).mappings().all()]
                                    latest_evaluation = evaluation_revision_head(evaluation_history)
                                    evaluation = evaluation_for_context(evaluation_history, as_of, known_at)
                                    derivation_is_authoritative = True
                                transition_start = (evaluation or {}).get("started_at")
                                clock_reset_event = None
                            reset_evaluation = bool(current and evaluation and clock_reset_event
                                and transition_start and (
                                    evaluation["started_at"] != transition_start
                                    or (evaluation.get("clock_reset_event_id") is not None
                                        and evaluation["clock_reset_event_id"] != clock_reset_event["event_id"])
                                    or (evaluation.get("clock_reset_event_id") is None
                                        and clock_reset_event["recorded_at"] > evaluation["known_at"])))
                            trustworthy_start = causal_transition["started_at"]
                            start_at = (transition_start if reset_evaluation else
                                (evaluation["started_at"] if evaluation else None) or transition_start
                                or trustworthy_start)
                            if definition_version == G7_DEFINITION:
                                start_at = (evaluation or {}).get("started_at")
                                reset_evaluation = False
                            if reset_evaluation:
                                policy_rows = policy_rows_as_known
                                candidates = []
                                reset_policy_gap = "no_applicable_sla_policy"
                                if start_at:
                                    selected_reset_policy, reset_policy_gap = select_reset_policy(
                                        policy_rows, group["group_id"], workload_context, start_at,
                                        policy_scope_matches=_sla_policy_applies_to_member)
                                    if selected_reset_policy is not None:
                                        candidates.append(selected_reset_policy)
                                recalculation_gaps = []
                                selected_policy = candidates[0] if len(candidates) == 1 else None
                                policy_id = selected_policy["policy_id"] if selected_policy else None
                                policy_version = selected_policy["version"] if selected_policy else None
                                binding_id = None
                                deadline_value = None
                                deadline_basis = "unknown"
                                reference_result = None
                                if selected_policy:
                                    doc = selected_policy["document"]
                                    mapping = doc.get("classification", {}).get("source_rating_map", {})
                                    mapped, classification_gaps = resolve_classification(
                                        [row[0] for row in latest_source_ratings.values()], mapping,
                                        override=assessed_severity)
                                    recalculation_gaps.extend(classification_gaps)
                                    duration = doc.get("duration_seconds_by_severity", {}).get(mapped) if mapped else None
                                    if mapped is None and "missing_classification" not in recalculation_gaps:
                                        recalculation_gaps.append("missing_classification")
                                    if doc.get("eligibility", {}).get("included_severities", []) and mapped not in doc["eligibility"]["included_severities"]:
                                        recalculation_gaps.append("severity_not_eligible")
                                    if type(duration) is not int or duration <= 0:
                                        recalculation_gaps.append("missing_sla_duration")
                                    elif start_at and start_at <= as_of:
                                        deadline_value = elapsed_deadline(start_at, duration)
                                        deadline_basis = "policy_calculation"
                                    reference_result = resolve_policy_reference(connection, doc,
                                        policy_id=policy_id, policy_version=int(policy_version),
                                        episode_id=episode["episode_id"], occurrence_id=occurrence["occurrence_id"],
                                        started_at=start_at, as_of=as_of, known_at=known_at,
                                        reference_history_cache=reference_history_cache,
                                        reference_recorded_at_cache=reference_recorded_at_cache)
                                    if reference_result is not None:
                                        if reference_result["status"] == "incomplete":
                                            recalculation_gaps.extend("warning:" + reason
                                                for reason in reference_result["gap_reasons"])
                                        else:
                                            recalculation_gaps.extend(reference_result["gap_reasons"])
                                        binding_id = reference_result["reference_binding_id"]
                                        if reference_result["status"] == "complete":
                                            deadline_value = datetime.fromisoformat(
                                                reference_result["deadline_at"].replace("Z", "+00:00"))
                                            deadline_basis = "supplied_reference"
                                        elif reference_result["status"] == "conflict":
                                            deadline_value = None
                                            deadline_basis = "unknown"
                                else:
                                    recalculation_gaps.append(reset_policy_gap)
                                if start_at and start_at > as_of:
                                    recalculation_gaps.append("awaiting_source_time")
                                evaluation_id = str(uuid.uuid4())
                                reset_known_inputs = [clock_reset_event["recorded_at"]]
                                reset_known_inputs.extend(row[2] for row in latest_source_ratings.values() if row[2])
                                reset_known_inputs.extend(row["created_at"] for row in candidates)
                                if reference_result is not None and reference_result.get("known_at"):
                                    reset_known_inputs.append(reference_result["known_at"])
                                reset_override_known = severity_override_known_at.get(occurrence["occurrence_id"])
                                if reset_override_known is not None:
                                    reset_known_inputs.append(reset_override_known)
                                reset_known_at = max(item for item in reset_known_inputs if item is not None)
                                reset_revision = next_evaluation_revision(evaluation_history)
                                reset_predecessor = evaluation
                                reset_original = reset_original_baseline(connection, selected_policy,
                                    group_id=group["group_id"], episode_id=episode["episode_id"],
                                    occurrence_id=occurrence["occurrence_id"], started_at=start_at,
                                    known_at=known_at, source_watermark=source_watermark,
                                    event_watermark=event_watermark, as_of=as_of) or deadline_value
                                reset_original, deadline_value, deadline_basis, recalculation_gaps = guard_pending_anchor(
                                    start_at, as_of, reset_original, deadline_value, deadline_basis, recalculation_gaps)
                                connection.execute(evaluation_table.insert().values(
                                    evaluation_id=evaluation_id, episode_id=episode["episode_id"],
                                    occurrence_id=occurrence["occurrence_id"],
                                    revision=reset_revision,
                                    policy_id=policy_id, policy_version=policy_version,
                                    reference_binding_id=binding_id, started_at=start_at,
                                    original_deadline_at=reset_original, current_deadline_at=deadline_value,
                                    deadline_basis=deadline_basis, gap_reasons=sorted(set(recalculation_gaps)),
                                    predecessor_evaluation_id=reset_predecessor["evaluation_id"],
                                    derivation_kind="report",
                                    clock_reset_event_id=clock_reset_event["event_id"],
                                    clock_reset_absorbed=False,
                                    is_authoritative=derivation_is_authoritative,
                                    head_decision_id=None, effective_at=clock_reset_event["recorded_at"],
                                    known_at=reset_known_at))
                                evaluation = {"evaluation_id": evaluation_id, "episode_id": episode["episode_id"],
                                    "occurrence_id": occurrence["occurrence_id"],
                                    "revision": reset_revision,
                                    "policy_id": policy_id, "policy_version": policy_version,
                                    "reference_binding_id": binding_id, "started_at": start_at,
                                    "original_deadline_at": reset_original, "current_deadline_at": deadline_value,
                                    "deadline_basis": deadline_basis, "gap_reasons": sorted(set(recalculation_gaps)),
                                    "predecessor_evaluation_id": reset_predecessor["evaluation_id"],
                                    "derivation_kind": "report",
                                    "clock_reset_event_id": clock_reset_event["event_id"],
                                    "clock_reset_absorbed": False,
                                    "is_authoritative": derivation_is_authoritative,
                                    "head_decision_id": None, "effective_at": clock_reset_event["recorded_at"],
                                    "known_at": reset_known_at}
                                evaluation_history.append(dict(evaluation))
                                if derivation_is_authoritative:
                                    latest_evaluation = evaluation
                            if evaluation is None:
                                policy_rows = policy_rows_as_known
                                selected_policy = None
                                initial_policy_gap = "no_applicable_sla_policy"
                                if start_at:
                                    selected_policy, initial_policy_gap = select_reset_policy(
                                        policy_rows, group["group_id"], workload_context, start_at,
                                        policy_scope_matches=_sla_policy_applies_to_member)
                                if (definition_version == G7_DEFINITION and selected_policy is not None
                                        and selected_policy["document"].get("start_source") != "uvm_ingest_commit_v1"):
                                    selected_policy = None
                                    initial_policy_gap = "no_ingestion_based_sla_policy"
                                gap_reasons = []
                                selected_severity = severity
                                reference_binding_id = None
                                reference_result = None
                                deadline_basis = "policy_calculation"
                                if selected_policy:
                                    mapping = selected_policy["document"].get("classification", {}).get("source_rating_map", {})
                                    mapped, classification_gaps = resolve_classification(
                                        [row[0] for row in latest_source_ratings.values()], mapping,
                                        override=assessed_severity)
                                    gap_reasons.extend(classification_gaps)
                                    selected_severity = mapped or "unknown"
                                    eligible_severities = selected_policy["document"].get("eligibility", {}).get("included_severities", [])
                                    if eligible_severities and selected_severity not in eligible_severities:
                                        gap_reasons.append("severity_not_eligible")
                                    duration = selected_policy["document"].get("duration_seconds_by_severity", {}).get(selected_severity)
                                    if type(duration) is not int or duration <= 0:
                                        gap_reasons.append("missing_sla_duration")
                                        duration = None
                                    deadline_value = elapsed_deadline(start_at, duration) if duration and start_at <= as_of else None
                                    policy_id, policy_version = selected_policy["policy_id"], selected_policy["version"]
                                    reference_result = resolve_policy_reference(connection,
                                        selected_policy["document"], policy_id=policy_id,
                                        policy_version=policy_version, episode_id=episode["episode_id"],
                                        occurrence_id=occurrence["occurrence_id"], started_at=start_at,
                                        as_of=as_of, known_at=known_at,
                                        reference_history_cache=reference_history_cache,
                                        reference_recorded_at_cache=reference_recorded_at_cache)
                                    if reference_result is not None:
                                        if reference_result["status"] == "incomplete":
                                            gap_reasons.extend("warning:" + reason
                                                for reason in reference_result["gap_reasons"])
                                        else:
                                            gap_reasons.extend(reference_result["gap_reasons"])
                                        reference_binding_id = reference_result["reference_binding_id"]
                                        if reference_result["status"] == "complete":
                                            deadline_value = datetime.fromisoformat(
                                                reference_result["deadline_at"].replace("Z", "+00:00"))
                                            deadline_basis = "supplied_reference"
                                        elif reference_result["status"] == "conflict":
                                            deadline_value = None
                                else:
                                    gap_reasons.extend([initial_policy_gap, "missing_classification"] if severity == "unknown" else [initial_policy_gap])
                                    deadline_value, policy_id, policy_version, selected_severity = None, None, None, severity
                                _, deadline_value, deadline_basis, gap_reasons = guard_pending_anchor(
                                    start_at, as_of, deadline_value, deadline_value, deadline_basis, gap_reasons)
                                eval_id = str(uuid.uuid4())
                                evaluation_known_inputs = [occurrence.get("first_ingested_at")]
                                if clock_reset_event is not None:
                                    evaluation_known_inputs.append(clock_reset_event["recorded_at"])
                                evaluation_known_inputs.extend(row[2] for row in latest_source_ratings.values() if row[2])
                                if selected_policy is not None:
                                    evaluation_known_inputs.append(selected_policy["created_at"])
                                if reference_result is not None and reference_result.get("known_at"):
                                    evaluation_known_inputs.append(reference_result["known_at"])
                                override_known = severity_override_known_at.get(occurrence["occurrence_id"])
                                if override_known is not None:
                                    evaluation_known_inputs.append(override_known)
                                evaluation_known_at = max((item for item in evaluation_known_inputs if item is not None),
                                    default=occurrence["created_at"])
                                reset_lineage_event_id = (clock_reset_event["event_id"]
                                    if current and clock_reset_event and start_at == transition_start else None)
                                evaluation = {"evaluation_id": eval_id, "episode_id": episode["episode_id"],
                                    "occurrence_id": occurrence["occurrence_id"], "revision": next_evaluation_revision(evaluation_history),
                                    "policy_id": policy_id, "policy_version": policy_version,
                                    "reference_binding_id": reference_binding_id,
                                    "started_at": start_at, "original_deadline_at": deadline_value,
                                    "current_deadline_at": deadline_value,
                                    "deadline_basis": deadline_basis if deadline_value else "unknown",
                                    "gap_reasons": sorted(set(gap_reasons)), "predecessor_evaluation_id": evaluation["evaluation_id"] if evaluation else None,
                                    "derivation_kind": "report",
                                    "clock_reset_event_id": reset_lineage_event_id,
                                    "clock_reset_absorbed": reset_lineage_event_id is None,
                                    "is_authoritative": derivation_is_authoritative,
                                    "head_decision_id": None,
                                    "effective_at": (clock_reset_event["recorded_at"] if clock_reset_event else
                                        start_at or occurrence.get("first_observed_at") or occurrence["created_at"]),
                                    "known_at": evaluation_known_at}
                                connection.execute(evaluation_table.insert().values(**evaluation))
                                evaluation_history.append(dict(evaluation))
                                if derivation_is_authoritative:
                                    latest_evaluation = evaluation
                                evaluation = {**evaluation, "gap_reasons": evaluation["gap_reasons"]}
                                severity = selected_severity
                            # Refresh from the same context-selected evidence used for
                            # classification/eligibility/exclusion. A later derived head
                            # cannot contribute to an earlier effective/known context.
                            if evaluation and evaluation.get("policy_id") and evaluation.get("policy_version"):
                                pinned_policy = policy_versions_by_key.get(
                                    (evaluation["policy_id"], evaluation["policy_version"]))
                                if pinned_policy is None:
                                    pinned_policy = connection.execute(sa.select(sla_policy_versions).where(
                                        sla_policy_versions.c.policy_id == evaluation["policy_id"],
                                        sla_policy_versions.c.version == evaluation["policy_version"])).mappings().first()
                                evidence_known = max([evaluation["known_at"]] +
                                    [row[2] for row in latest_source_ratings.values() if row[2]] +
                                    ([severity_override_known_at[occurrence["occurrence_id"]]]
                                        if occurrence["occurrence_id"] in severity_override_known_at else []))
                                if definition_version != G7_DEFINITION and pinned_policy and (evidence_known > evaluation["known_at"] or (
                                        "awaiting_source_time" in evaluation["gap_reasons"]
                                        and evaluation["started_at"] <= as_of)):
                                    doc = pinned_policy["document"]
                                    canonical, reasons = resolve_classification(
                                        [row[0] for row in latest_source_ratings.values()],
                                        doc.get("classification", {}).get("source_rating_map", {}),
                                        override=assessed_severity)
                                    reasons = list(reasons)
                                    included = doc.get("eligibility", {}).get("included_severities", [])
                                    if included and canonical not in included:
                                        reasons.append("severity_not_eligible")
                                    duration = doc.get("duration_seconds_by_severity", {}).get(canonical)
                                    refresh_start = evaluation["started_at"]
                                    fresh_deadline = None
                                    if type(duration) is not int or duration <= 0:
                                        reasons.append("missing_sla_duration")
                                    elif refresh_start is None:
                                        reasons.append("unknown_start")
                                    else:
                                        fresh_deadline = elapsed_deadline(refresh_start, duration) if refresh_start <= as_of else None
                                    if refresh_start and refresh_start > as_of:
                                        reasons.append("awaiting_source_time")
                                    fresh_basis = "policy_calculation" if fresh_deadline else "unknown"
                                    fresh_binding = None
                                    ref = resolve_policy_reference(connection, doc,
                                        policy_id=evaluation["policy_id"], policy_version=evaluation["policy_version"],
                                        episode_id=episode["episode_id"], occurrence_id=occurrence["occurrence_id"],
                                        started_at=refresh_start, as_of=as_of, known_at=known_at,
                                        reference_history_cache=reference_history_cache,
                                        reference_recorded_at_cache=reference_recorded_at_cache)
                                    if ref:
                                        evidence_known = max(evidence_known, ref["known_at"])
                                        reasons.extend(("warning:" + value if ref["status"] == "incomplete" else value)
                                            for value in ref["gap_reasons"])
                                        fresh_binding = ref["reference_binding_id"]
                                        if ref["status"] == "complete":
                                            fresh_deadline = datetime.fromisoformat(ref["deadline_at"].replace("Z", "+00:00"))
                                            fresh_basis = "supplied_reference"
                                        elif ref["status"] == "conflict":
                                            fresh_deadline, fresh_basis = None, "unknown"
                                    if evaluation["head_decision_id"]:
                                        fresh_deadline = evaluation["current_deadline_at"]
                                        fresh_basis = evaluation["deadline_basis"]
                                    effective_inputs = [evaluation["effective_at"]] + [
                                        row[1] for row in latest_source_ratings.values() if row[1]]
                                    fresh_original = evaluation["original_deadline_at"]
                                    if fresh_original is None and fresh_deadline is not None:
                                        fresh_original = (reset_original_baseline(connection, pinned_policy,
                                            group_id=group["group_id"], episode_id=episode["episode_id"],
                                            occurrence_id=occurrence["occurrence_id"], started_at=refresh_start,
                                            known_at=known_at, source_watermark=source_watermark,
                                            event_watermark=event_watermark, as_of=as_of)
                                            if evaluation.get("clock_reset_event_id") else None) or fresh_deadline
                                    fresh_original, fresh_deadline, fresh_basis, reasons = guard_pending_anchor(
                                        refresh_start, as_of, fresh_original, fresh_deadline, fresh_basis, reasons)
                                    refreshed = {**dict(evaluation), "evaluation_id": str(uuid.uuid4()),
                                        "revision": next_evaluation_revision(evaluation_history),
                                        "predecessor_evaluation_id": evaluation["evaluation_id"],
                                        "derivation_kind": "report",
                                        "is_authoritative": derivation_is_authoritative,
                                        "original_deadline_at": fresh_original,
                                        "current_deadline_at": fresh_deadline, "deadline_basis": fresh_basis,
                                        "reference_binding_id": fresh_binding, "gap_reasons": sorted(set(reasons)),
                                        "effective_at": max(effective_inputs), "known_at": evidence_known}
                                    connection.execute(evaluation_table.insert().values(**refreshed))
                                    evaluation_history.append(dict(refreshed))
                                    evaluation = refreshed
                                    if derivation_is_authoritative:
                                        latest_evaluation = refreshed
                            start_at = evaluation["started_at"] if evaluation else trustworthy_start
                            original_deadline = evaluation["original_deadline_at"] if evaluation else None
                            deadline = evaluation["current_deadline_at"] if evaluation else None
                            stored_reasons = list(evaluation["gap_reasons"] or []) if evaluation else ["no_applicable_sla_policy"]
                            reference_warnings = [reason.removeprefix("warning:") for reason in stored_reasons
                                if reason.startswith("warning:")]
                            gap_reasons = [reason for reason in stored_reasons if not reason.startswith("warning:")]
                            classification_mapping = {}
                            if evaluation and evaluation.get("policy_id") and evaluation.get("policy_version"):
                                classification_policy = connection.execute(sa.select(sla_policy_versions.c.document).where(
                                    sla_policy_versions.c.policy_id == evaluation["policy_id"],
                                    sla_policy_versions.c.version == evaluation["policy_version"])).scalar_one_or_none() or {}
                                classification_mapping = classification_policy.get("classification", {}).get("source_rating_map", {})
                            source_quality = []
                            for source_evidence in latest_source_ratings.values():
                                raw_class = str(source_evidence[0]).strip().casefold() if source_evidence[0] else "unknown"
                                canonical = next((value for label, value in classification_mapping.items()
                                    if isinstance(label, str) and label.casefold() == raw_class), None)
                                source_quality.append({"source_id": str(source_evidence[4]) + ":" + str(source_evidence[5]),
                                    "source_family": source_evidence[4], "source_account_id": source_evidence[5],
                                    "source_rating": source_evidence[0], "canonical_classification": canonical,
                                    "completeness": {"success":"complete","partial":"partial","failed":"failed"}.get(source_evidence[3],"unknown"),
                                    "observed_at": _instant(source_evidence[1]),
                                    "received_at": _instant(source_evidence[2])})
                            resolved_classification, source_classification_gaps = resolve_classification(
                                [row[0] for row in latest_source_ratings.values()],
                                classification_mapping, override=assessed_severity)
                            severity = resolved_classification or "unknown"
                            gap_reasons.extend(source_classification_gaps)
                            if source_classification_gaps:
                                if not assessed_severity:
                                    severity = "unknown"
                                included_classes = classification_policy.get("eligibility", {}).get(
                                    "included_severities", []) if evaluation and evaluation.get("policy_id") else []
                                if included_classes and definition_version != G7_DEFINITION:
                                    gap_reasons.append("severity_not_eligible")
                            if evaluation is None and latest_evaluation is not None:
                                gap_reasons.append("evaluation_not_effective_or_known_at_report_context")
                            if not start_at:
                                gap_reasons.append("unknown_start")
                            if not deadline:
                                gap_reasons.append("unknown_deadline")
                            if start_at and start_at > as_of:
                                gap_reasons.append("awaiting_source_time")
                            owners = []
                            directory = {item.get("owner_id"): item for item in calculation_policy.get("owner_directory", [])
                                if item.get("enabled", True)}
                            portions_for_member = [portion for portion in state_doc.get("portions", [])
                                if portion.get("active", True) and occurrence["occurrence_id"] in portion.get("membership_ids", [])]
                            if portions_for_member:
                                owner_pairs = [(owner_id, directory.get(owner_id, {}).get("owner_type", "person"))
                                    for portion in portions_for_member for owner_id in portion.get("owner_ids", [])]
                            else:
                                owner_pairs = [(item.get("owner_id"), item.get("owner_type", "person"))
                                    for item in state_doc.get("owners", [])]
                            for owner_id, owner_type in owner_pairs:
                                entry = directory.get(owner_id, {})
                                principal_state = calculation_policy.get("principals", {}).get(owner_id, {})
                                effective = _owner_effective_at(entry, principal_state, as_of, group["group_id"])
                                if owner_type == "team":
                                    effective = effective and entry.get("owner_type") == "team"
                                    active_members = []
                                    if owner_id in native.get("ownership_teams", {}):
                                        active_members = list(effective_team_members(
                                            calculation_policy, owner_id, as_of))
                                    else:
                                        for member_id, member_state in calculation_policy.get("principals", {}).items():
                                            member_entry = directory.get(member_id, {})
                                            if (owner_id in member_state.get("team_ids", [])
                                                    and _owner_effective_at(member_entry, member_state, as_of,
                                                        group["group_id"])):
                                                active_members.append(member_id)
                                    effective = effective and bool(active_members)
                                owners.append({"principal_id": owner_id, "kind": owner_type,
                                    "effective": effective})
                            accepted = next((item for item in reversed(state_doc.get("acceptances", []))
                                if occurrence["occurrence_id"] in item.get("membership_ids", [])), None)
                            acceptance_assesses = False
                            if (accepted and accepted.get("state") == "active"
                                    and occurrence["occurrence_id"] not in accepted.get("suspended_membership_ids", [])):
                                expiry_raw = accepted.get("expires_at")
                                try:
                                    expiry = datetime.fromisoformat(expiry_raw.replace("Z", "+00:00")) if expiry_raw else None
                                except (ValueError, TypeError):
                                    expiry = None
                                acceptance_assesses = expiry is not None and as_of < expiry
                                if accepted.get("exception_contract_version") == 1:
                                    acceptance_assesses = acceptance_assesses and any(
                                        snapshot["episode_id"] == episode["episode_id"]
                                        and snapshot["occurrence_id"] == occurrence["occurrence_id"]
                                        for snapshot in accepted.get("pause_snapshots", []))
                            exception_clock_state = None
                            event_rows = []
                            if definition_version == G7_DEFINITION:
                                from uvm.assessment.g7_clock import read_clock
                                event_rows = connection.execute(sa.select(sla_clock_events).where(
                                    sla_clock_events.c.episode_id == episode["episode_id"],
                                    sla_clock_events.c.occurrence_id == occurrence["occurrence_id"],
                                    sla_clock_events.c.recorded_at <= known_at,
                                    sla_clock_events.c.effective_at <= as_of)
                                    .order_by(sla_clock_events.c.sequence)).mappings().all()
                                for clock_event in event_rows:
                                    input_rows.append({"kind": "g7_clock_event", "stable_id": clock_event["event_id"],
                                        "revision": int(clock_event["sequence"]), "effective_at": _instant(clock_event["effective_at"]),
                                        "known_at": _instant(clock_event["recorded_at"]), "retained_value": _jsonable(dict(clock_event))})
                                for table, kind, key, effective_key, known_key in (
                                    (sla_episode_contracts, "g7_episode_contract", "episode_id", "pinned_at", "created_at"),
                                    (sla_ingest_receipts, "g7_ingest_receipt", "receipt_id", "ingested_at", "created_at")):
                                    query = sa.select(table).where(table.c.episode_id == episode["episode_id"],
                                        table.c[known_key] <= known_at)
                                    if "occurrence_id" in table.c:
                                        query = query.where(table.c.occurrence_id == occurrence["occurrence_id"])
                                    for retained in connection.execute(query).mappings():
                                        input_rows.append({"kind": kind, "stable_id": retained[key], "revision": 1,
                                            "effective_at": _instant(retained[effective_key]), "known_at": _instant(retained[known_key]),
                                            "retained_value": _jsonable(dict(retained))})
                                        if retained.get("retention_receipt_id"):
                                            source_receipt = connection.execute(sa.select(source_observation_receipts).where(
                                                source_observation_receipts.c.receipt_id == retained["retention_receipt_id"],
                                                source_observation_receipts.c.created_at <= known_at)).mappings().first()
                                            if source_receipt:
                                                input_rows.append({"kind": "g7_retention_receipt", "stable_id": source_receipt["receipt_id"],
                                                    "revision": 1, "effective_at": _instant(source_receipt["retained_at"]),
                                                    "known_at": _instant(source_receipt["created_at"]),
                                                    "retained_value": _jsonable(dict(source_receipt))})
                                # Project the authoritative event chain even after
                                # the acceptance's presentation state becomes expired,
                                # revoked, or suspended.
                                if event_rows:
                                    exception_clock_state = read_clock(connection,
                                        episode["episode_id"], occurrence["occurrence_id"], as_of, known_at=known_at)
                                    if exception_clock_state.get("state") in {"paused", "running"}:
                                        deadline = exception_clock_state.get("target_at")
                                    if not start_at and not exception_clock_state.get("requires_authorised_correction"):
                                        receipt = connection.execute(sa.select(
                                            sla_ingest_receipts.c.ingested_at).where(
                                            sla_ingest_receipts.c.episode_id == episode["episode_id"],
                                            sla_ingest_receipts.c.occurrence_id == occurrence["occurrence_id"])
                                            .order_by(sla_ingest_receipts.c.ingested_at).limit(1)).first()
                                        if receipt:
                                            start_at = receipt[0]
                            completion_deadline = deadline
                            completion_evaluation = None
                            if confirmed_at is not None:
                                confirmation_evaluation = evaluation_for_context(
                                    evaluation_history, confirmed_at, confirmed_at)
                                completion_evaluation = confirmation_evaluation
                                completion_deadline = confirmation_evaluation["current_deadline_at"] if confirmation_evaluation else None
                            completion_clock = None
                            if definition_version == G7_DEFINITION and confirmed_at is not None:
                                from uvm.assessment.g7_clock import read_clock
                                # Project immediately before the terminal event at this instant.
                                from uvm.assessment.g7_clock import project_clock
                                completion_clock = project_clock([event for event in event_rows
                                    if event["event_type"] != "completed" or event["effective_at"] < confirmed_at],
                                    confirmed_at, [row for row in evaluation_history if row["known_at"] <= known_at])
                                completion_deadline = completion_clock.get("target_at")
                            if current:
                                completion_state = "outstanding"
                            elif member["status"] == "continuity_covered":
                                completion_state = "carried"
                            elif confirmed_at is not None and completion_clock and completion_clock["state"] == "paused":
                                completion_state = "completed_during_exception"
                                completion_deadline = None
                            elif confirmed_at is not None and completion_deadline is not None:
                                completion_state = "on_time" if confirmed_at <= completion_deadline else "late"
                            elif confirmed_at is not None:
                                completion_state = "unknown_deadline"
                            else:
                                completion_state = "unknown_deadline"
                            # Historical intervals select the evaluation visible
                            # at each segment's own effective/knowledge context.
                            # This includes report-derived reset rows when they
                            # are the applicable lineage, without promoting an
                            # out-of-context row to the current writer head.
                            evaluations = sorted((item for item in evaluation_history
                                if item["effective_at"] <= as_of and item["known_at"] <= known_at
                                ), key=lambda item: (item["effective_at"], item["known_at"],
                                    int(item["revision"])))
                            # Preserve report-derived rows only when they are
                            # actual ancestors named by a retained writer row.
                            # Unrelated report branches are materialisation
                            # outputs and would make an identical context's
                            # manifest depend on request order; a referenced
                            # predecessor is causal provenance and must remain
                            # available for complete history reconstruction.
                            contextual_by_id = {item["evaluation_id"]: item
                                for item in evaluations}
                            predecessor_ids = set()
                            for writer_row in evaluations:
                                if writer_row.get("derivation_kind") == "report":
                                    continue
                                predecessor_id = writer_row.get("predecessor_evaluation_id")
                                seen_predecessors = set()
                                while predecessor_id and predecessor_id not in seen_predecessors:
                                    seen_predecessors.add(predecessor_id)
                                    predecessor_ids.add(predecessor_id)
                                    predecessor_evaluation = contextual_by_id.get(predecessor_id)
                                    predecessor_id = (predecessor_evaluation.get("predecessor_evaluation_id")
                                        if predecessor_evaluation else None)
                            for history_evaluation in evaluations:
                                if (history_evaluation.get("derivation_kind") == "report"
                                        and history_evaluation["evaluation_id"] not in predecessor_ids):
                                    continue
                                input_rows.append({"kind": "sla_history_evaluation",
                                    "stable_id": history_evaluation["evaluation_id"],
                                    "revision": int(history_evaluation["revision"]),
                                    "effective_at": _instant(history_evaluation["effective_at"]),
                                    "known_at": _instant(history_evaluation["known_at"]),
                                    "retained_value": _jsonable(dict(history_evaluation))})
                            historical_breach_seconds = 0.0
                            original_breach_seconds = 0.0
                            historical_deadline_applicable = False
                            original_historical_deadline_applicable = False
                            outstanding_intervals = _outstanding_intervals_at(
                                episode, occurrence, member, episode_events, as_of)
                            for interval_start, interval_end in outstanding_intervals:
                                boundaries = {interval_start, interval_end}
                                boundaries.update(item["effective_at"] for item in evaluations
                                    if interval_start < item["effective_at"] < interval_end)
                                if definition_version == G7_DEFINITION:
                                    for clock_event in event_rows:
                                        if interval_start < clock_event["effective_at"] < interval_end:
                                            boundaries.add(clock_event["effective_at"])
                                        expiry_value = (clock_event.get("data") or {}).get("expires_at")
                                        if expiry_value:
                                            expiry_boundary = datetime.fromisoformat(expiry_value.replace("Z", "+00:00"))
                                            if interval_start < expiry_boundary < interval_end:
                                                boundaries.add(expiry_boundary)
                                ordered_boundaries = sorted(boundaries)
                                for segment_start, segment_end in zip(ordered_boundaries, ordered_boundaries[1:]):
                                    evaluation_item = evaluation_for_context(
                                        evaluation_history, segment_start, known_at)
                                    if evaluation_item is None:
                                        continue
                                    # Retain the exact context-selected row used
                                    # for each historical interval segment. A
                                    # report-derived row can govern a later
                                    # reset segment without being a predecessor
                                    # of the current writer head; omitting it
                                    # makes the public manifest insufficient to
                                    # reproduce the historical population.
                                    input_rows.append({"kind": "sla_history_evaluation",
                                        "stable_id": evaluation_item["evaluation_id"],
                                        "revision": int(evaluation_item["revision"]),
                                        "effective_at": _instant(evaluation_item["effective_at"]),
                                        "known_at": _instant(evaluation_item["known_at"]),
                                        "retained_value": _jsonable(dict(evaluation_item))})
                                    segment_deadline = evaluation_item["current_deadline_at"]
                                    if definition_version == G7_DEFINITION:
                                        from uvm.assessment.g7_clock import project_clock
                                        segment_clock = project_clock(event_rows, segment_start,
                                            [row for row in evaluation_history if row["known_at"] <= known_at])
                                        segment_deadline = segment_clock.get("target_at")
                                        if segment_clock["state"] in {"paused", "completed", "completed_during_exception"}:
                                            historical_deadline_applicable |= evaluation_item["original_deadline_at"] is not None
                                            original_historical_deadline_applicable |= evaluation_item["original_deadline_at"] is not None
                                            continue
                                    historical_deadline_applicable = historical_deadline_applicable or segment_deadline is not None
                                    if (segment_deadline is not None
                                            and segment_end > max(segment_start, segment_deadline)):
                                        historical_breach_seconds += round((segment_end -
                                            max(segment_start, segment_deadline)).total_seconds(), 6)
                                    baseline_deadline = evaluation_item["original_deadline_at"]
                                    original_historical_deadline_applicable = (original_historical_deadline_applicable
                                        or baseline_deadline is not None)
                                    if (baseline_deadline is not None
                                            and segment_end > max(segment_start, baseline_deadline)):
                                        original_breach_seconds += round((segment_end -
                                            max(segment_start, baseline_deadline)).total_seconds(), 6)
                            atom_id = episode["episode_id"] + ":" + occurrence["occurrence_id"]
                            exclusion = None
                            if evaluation and evaluation.get("policy_id") and evaluation.get("policy_version"):
                                evaluation_policy = policy_versions_by_key.get(
                                    (evaluation["policy_id"], evaluation["policy_version"]))
                                if evaluation_policy is None:
                                    evaluation_policy = connection.execute(sa.select(sla_policy_versions).where(
                                        sla_policy_versions.c.policy_id == evaluation["policy_id"],
                                        sla_policy_versions.c.version == evaluation["policy_version"])).mappings().first()
                                if evaluation_policy:
                                    exclusion_doc = evaluation_policy["document"]
                                    excluded_classes = exclusion_doc.get("eligibility", {}).get("excluded_classifications", [])
                                    frozen_targets = exclusion_doc.get("backfill", {}).get("targets", [])
                                    exact_target = any(target.get("episode_id") == episode["episode_id"]
                                        and target.get("occurrence_id") == occurrence["occurrence_id"]
                                        for target in frozen_targets if isinstance(target, dict))
                                    activation = datetime.fromisoformat(exclusion_doc["effective_from"].replace("Z", "+00:00"))
                                    expiry = (datetime.fromisoformat(exclusion_doc["effective_until"].replace("Z", "+00:00"))
                                        if exclusion_doc.get("effective_until") else None)
                                    canonical_class = resolved_classification
                                    if (exact_target and canonical_class in excluded_classes
                                            and activation <= as_of and (expiry is None or as_of < expiry)):
                                        exclusion = {"excluded": True, "code": "policy_classification_excluded",
                                            "classification": canonical_class,
                                            "rationale": exclusion_doc.get("publication_rationale"),
                                            "policy_id": evaluation["policy_id"],
                                            "policy_version": int(evaluation["policy_version"]),
                                            "evaluation_id": evaluation["evaluation_id"],
                                            "episode_id": episode["episode_id"],
                                            "occurrence_id": occurrence["occurrence_id"],
                                            "effective_from": _instant(activation),
                                            "effective_until": _instant(expiry)}
                            is_excluded_exposure = bool(exclusion and current and completion_state == "outstanding")
                            atom = {"atom_id": atom_id, "native_group_id": group["group_id"],
                                "episode_id": episode["episode_id"], "occurrence_id": occurrence["occurrence_id"],
                                "membership_id": occurrence["occurrence_id"],
                                "eligible": current and "severity_not_eligible" not in gap_reasons and not is_excluded_exposure,
                                "exclusion": exclusion or {"excluded": False},
                                "warnings": sorted(set(reference_warnings)),
                                "gap_reasons": sorted(set(gap_reasons)),
                                "severity": {"value": severity,
                                    "basis": "assessment_override" if assessed_severity else "source" if severity != "unknown" else "unresolved",
                                    "revision": str(occurrence["revision"])},
                                "clock": {"start": _instant(start_at), "start_basis": "persisted_evaluation" if evaluation and evaluation["started_at"] else "first_trustworthy_observation",
                                    "deadline": _instant(deadline), "original_deadline_at": _instant(original_deadline),
                                    "deadline_basis": evaluation["deadline_basis"] if evaluation else "unknown",
                                    "elapsed_seconds": max(0.0, (as_of - start_at).total_seconds()) if current and start_at and as_of >= start_at else None,
                                    "overdue_seconds": max(0.0, round((as_of - deadline).total_seconds(), 6)) if current and deadline and as_of > deadline else 0 if current and deadline else None,
                                    "historical_breach_seconds": historical_breach_seconds,
                                    "original_historical_breach_seconds": original_breach_seconds,
                                    "historical_deadline_applicable": historical_deadline_applicable,
                                    "original_historical_deadline_applicable": original_historical_deadline_applicable,
                                    "first_detection_at": _instant(occurrence["first_observed_at"]),
                                    "first_detection_age_seconds": max(0.0, (as_of - occurrence["first_observed_at"]).total_seconds()) if occurrence["first_observed_at"] and as_of >= occurrence["first_observed_at"] else None},
                                "policy": {"policy_id": evaluation["policy_id"] if evaluation else None,
                                    "version": str(evaluation["policy_version"]) if evaluation and evaluation["policy_version"] else None,
                                    "evaluation_id": evaluation["evaluation_id"] if evaluation else None,
                                    "evaluation_revision": int(evaluation["revision"]) if evaluation else 0,
                                    "reference_binding_id": evaluation.get("reference_binding_id") if evaluation else None},
                                "completion": {"state": completion_state,
                                    "confirmed_at": _instant(confirmed_at), "confirmation_id": member["confirmation_decision_id"], "coverage_id": member["original_decision_id"],
                                    "deadline_at_confirmation": _instant(completion_deadline),
                                    "deadline_evaluation_id": completion_evaluation["evaluation_id"] if completion_evaluation else None,
                                    "deadline_evaluation_revision": int(completion_evaluation["revision"]) if completion_evaluation else None},
                                "acceptance": {"state": accepted.get("state", "none") if accepted else "none", "accepted": acceptance_assesses},
                                "ownership": {"covered": any(owner["effective"] for owner in owners), "owners": owners},
                                "assessment_covered": (occurrence["occurrence_id"] in assessment_members_by_group.get(group["group_id"], set())
                                    or acceptance_assesses),
                                "source_quality": (source_quality or [{"source_id": (str(rating[4]) + ":" + str(rating[5])) if rating else group["source_family"],
                                    "completeness": ({"success":"complete","partial":"partial","failed":"failed"}.get(rating[3],"unknown") if rating else "unknown"),
                                    "observed_at": _instant(rating[1]) if rating else None, "received_at": _instant(rating[2]) if rating else None}])}
                            if definition_version == G7_DEFINITION:
                                atom["clock"].update({
                                    "state": exception_clock_state.get("state") if exception_clock_state else "running" if deadline else "gap",
                                    "exception_target_at": _instant(exception_clock_state.get("target_at"))
                                        if exception_clock_state and exception_clock_state.get("state") == "paused" else None,
                                    "frozen_sla_seconds": exception_clock_state.get("frozen_sla_seconds")
                                        if exception_clock_state and exception_clock_state.get("state") == "paused" else None,
                                    "prior_breach": exception_clock_state.get("prior_breach", False)
                                        if exception_clock_state else False,
                                })
                                atom["exception_clock"] = _jsonable(exception_clock_state or {"state": "running"})
                            atom_rows.append((group, episode, occurrence, atom, state))
                            if completion_evaluation is not None:
                                input_rows.append({"kind": "sla_completion_evaluation",
                                    "stable_id": completion_evaluation["evaluation_id"],
                                    "revision": int(completion_evaluation["revision"]),
                                    "effective_at": _instant(completion_evaluation["effective_at"]),
                                    "known_at": _instant(completion_evaluation["known_at"]),
                                    "retained_value": _jsonable(dict(completion_evaluation))})
                            input_rows.append({"kind": "occurrence", "stable_id": occurrence["occurrence_id"], "revision": int(occurrence["revision"]),
                                "effective_at": _instant(occurrence["created_at"]), "known_at": _instant(occurrence["first_ingested_at"]),
                                "retained_value": {"first_observed_at": _instant(occurrence["first_observed_at"]), "exposure_id": occurrence["exposure_id"]}})
                            if evaluation:
                                input_rows.append({"kind": "sla_evaluation", "stable_id": evaluation["evaluation_id"],
                                    "revision": int(evaluation["revision"]), "effective_at": _instant(evaluation["effective_at"]),
                                    "known_at": _instant(evaluation["known_at"]), "retained_value": _jsonable(dict(evaluation))})
                                if evaluation["reference_binding_id"]:
                                    policy_row = policy_versions_by_key.get(
                                        (evaluation["policy_id"], evaluation["policy_version"]))
                                    if policy_row is None:
                                        policy_row = connection.execute(sa.select(sla_policy_versions).where(
                                            sla_policy_versions.c.policy_id == evaluation["policy_id"],
                                            sla_policy_versions.c.version == evaluation["policy_version"])).mappings().first()
                                    policy_doc = policy_row["document"] if policy_row else {}
                                    binding = next((item for item in policy_doc.get("deadline_reference_rules", {}).get("bindings", [])
                                        if item.get("binding_id") == evaluation["reference_binding_id"]), None)
                                    if binding:
                                        history = reference_history_for(connection, occurrence["occurrence_id"])
                                        reference = next((item for item in history
                                            if item["reference"]["reference_id"] == binding["reference_id"]), None)
                                        recorded_at = reference_recorded_at_for(connection, binding["reference_id"])
                                        if reference and recorded_at:
                                            if binding["reference_id"] not in manifested_reference_ids and recorded_at <= known_at:
                                                input_rows.append({"kind": "deadline_reference", "stable_id": binding["reference_id"],
                                                    "revision": int(reference["revision"]), "effective_at": _instant(recorded_at),
                                                    "known_at": _instant(recorded_at), "retained_value": reference["reference"]})
                                                manifested_reference_ids.add(binding["reference_id"])
                                            input_rows.append({"kind": "deadline_reference_binding", "stable_id": binding["binding_id"],
                                                "revision": int(evaluation["policy_version"]),
                                                "effective_at": _instant(policy_row["created_at"] if policy_row else evaluation["effective_at"]),
                                                "known_at": _instant(evaluation["known_at"]), "retained_value": binding})
                            if not evaluation or not evaluation["reference_binding_id"]:
                                for retained_reference in reference_history_for(connection, occurrence["occurrence_id"]):
                                    reference_id = retained_reference["reference"]["reference_id"]
                                    if reference_id in manifested_reference_ids:
                                        continue
                                    recorded_at = reference_recorded_at_for(connection, reference_id)
                                    if recorded_at and recorded_at <= known_at:
                                        input_rows.append({"kind": "deadline_reference", "stable_id": reference_id,
                                            "revision": int(retained_reference["revision"]),
                                            "effective_at": _instant(recorded_at), "known_at": _instant(recorded_at),
                                            "retained_value": retained_reference["reference"]})
                                        manifested_reference_ids.add(reference_id)
                # Atoms from duplicate policy/source/team rows are distinct only by persisted episode and occurrence IDs.
                unique = {}
                for item in atom_rows:
                    unique[(item[1]["episode_id"], item[2]["occurrence_id"])] = item
                atom_rows = sorted(unique.values(), key=lambda item: (item[1]["episode_id"], item[2]["occurrence_id"]))
                atoms = [item[3] for item in atom_rows]
                # Missing/unsupported classification stays inside the default
                # outstanding population as a gap. Only an explicit exact-target
                # exclusion removes an atom from eligibility.
                for atom in atoms:
                    if "severity_not_eligible" in atom["gap_reasons"]:
                        atom["eligible"] = (atom["completion"]["state"] in {"outstanding", "review"}
                            and not atom.get("exclusion", {}).get("excluded"))
                populations, atom_by_id = _qualifying_populations(atoms, as_of=as_of,
                    period_start=period_start, period_end=period_end)
                eligible_ids = populations["eligible_outstanding"]
                covered_ids = populations["covered_outstanding"]
                breached_ids = populations["current_breach"]
                outstanding = [atom_by_id[item] for item in sorted(eligible_ids)]
                covered = [atom_by_id[item] for item in sorted(covered_ids)]
                breached = [atom_by_id[item] for item in sorted(breached_ids)]
                excluded_exposures = [atom_by_id[item] for item in sorted(populations["excluded_exposure"])]
                inventory_data = inventory_projection(connection, group_ids, as_of, known_at, input_rows,
                    source_watermark)
                new_completions = [atom_by_id[item] for item in sorted(populations["new_completions"])]
                on_time_known = [atom_by_id[item] for item in sorted(populations["on_time_completions"])]
                known_completions = [atom_by_id[item] for item in sorted(populations["known_deadline_completions"])]
                unknown_completions = [atom_by_id[item] for item in sorted(populations["unknown_deadline_completions"])]
                carried_atoms = [atom_by_id[item] for item in sorted(populations["carried_confirmation"])]
                historical_breached = [atom_by_id[item] for item in sorted(populations["historical_breach"])]
                historical_original_breached = [atom_by_id[item] for item in sorted(populations["original_policy_historical_breach"])]
                gaps = len(populations["sla_gaps"])
                # Unresolved source evidence has no atom identity to count. Retain
                # the latest visible resolution per observation for the exact
                # authorised native groups and limit completeness explicitly.
                unresolved_query = (sa.select(identity_resolutions,
                    source_observations.c.retention_order,
                    source_observations.c.collected_at).join(source_observations,
                        source_observations.c.observation_id == identity_resolutions.c.observation_id)
                    .where(identity_resolutions.c.group_id.in_(group_ids),
                        identity_resolutions.c.evaluated_at <= known_at,
                        source_observations.c.collected_at <= known_at,
                        source_observations.c.retention_order <= source_watermark))
                if mode != "corrected_history":
                    unresolved_query = unresolved_query.where(
                        identity_resolutions.c.evaluated_at <= as_of)
                unresolved_candidates = connection.execute(unresolved_query.order_by(
                    identity_resolutions.c.observation_id,
                    identity_resolutions.c.revision)).mappings().all()
                latest_identity_inputs = {row["observation_id"]: row for row in unresolved_candidates}
                unresolved_identity_inputs = [row for row in latest_identity_inputs.values()
                    if row["outcome"] in {"ambiguous", "unresolved"}]
                # A later reviewed resolution may repair an ambiguous retained
                # observation in corrected history without creating a new
                # episode atom. Preserve that exact resolution as an input to
                # the corrected population so its provenance is auditable.
                for identity_input in latest_identity_inputs.values():
                    if (identity_input["outcome"] in {"matched", "new"}
                            and identity_input["resolution_id"] not in manifested_identity_resolution_ids):
                        input_rows.append({"kind": "identity_resolution",
                            "stable_id": identity_input["resolution_id"],
                            "revision": int(identity_input["revision"]),
                            "effective_at": _instant(identity_input["evaluated_at"]),
                            "known_at": _instant(identity_input["evaluated_at"]),
                            "retained_value": _jsonable(dict(identity_input))})
                        manifested_identity_resolution_ids.add(identity_input["resolution_id"])
                for identity_input in unresolved_identity_inputs:
                    input_rows.append({"kind": "unresolved_identity_resolution",
                        "stable_id": identity_input["resolution_id"],
                        "revision": int(identity_input["revision"]),
                        "effective_at": _instant(identity_input["evaluated_at"]),
                        "known_at": _instant(identity_input["evaluated_at"]),
                        "retained_value": _jsonable(dict(identity_input))})
                    observation_input = connection.execute(sa.select(source_observations).where(
                        source_observations.c.observation_id == identity_input["observation_id"])).mappings().one()
                    input_rows.append({"kind": "unresolved_source_observation",
                        "stable_id": observation_input["observation_id"],
                        "revision": int(observation_input["revision"]),
                        "effective_at": _instant(observation_input["observed_at"]),
                        "known_at": _instant(observation_input["collected_at"]),
                        "retained_value": _jsonable(dict(observation_input))})
                quality = {"coverage_gaps": gaps, "overdue_atoms": len(breached), "accepted_atoms": sum(a["acceptance"]["accepted"] for a in outstanding),
                    "ambiguous_observations": sum(row["outcome"] == "ambiguous" for row in unresolved_identity_inputs),
                    "unmapped_observations": sum(row["outcome"] == "unresolved" for row in unresolved_identity_inputs),
                    "mapped_population_complete": not bool(unresolved_identity_inputs),
                    "source_failures": 0, "stale_sources": 0, "reference_conflicts": 0, "classification_gaps": sum(a["severity"]["value"] == "unknown" for a in outstanding),
                    "unknown_inventory": not inventory_data["configured"],
                    "excluded_exposure_atoms": len(excluded_exposures),
                    "distinct_breached_native_groups": len(populations["breached_native_groups"]),
                    "unexpected_inventory_targets": inventory_data["unexpected_count"],
                    "unmapped_inventory_targets": inventory_data["unmapped_count"],
                    "warnings": ([{"code": "unknown_inventory", "count": 1}]
                        if not inventory_data["configured"] else [])}
                if unresolved_identity_inputs:
                    quality["warnings"].append({"code": "unresolved_identity_limits_completeness",
                        "count": len(unresolved_identity_inputs)})
                metrics = [
                    _metric("sla_coverage", len(covered_ids), len(eligible_ids), "atoms", "Eligible outstanding mapped membership"),
                    _metric("current_breach", len(breached_ids), len(populations["running_covered"]), "atoms", "Covered eligible outstanding mapped membership"),
                    _metric("sla_gaps", len(populations["sla_gaps"]), len(eligible_ids), "atoms", "Eligible outstanding mapped membership"),
                    _metric("original_policy_current_breach", len(populations["original_policy_current_breach"]), len(populations["original_deadline_outstanding"]), "atoms", "Outstanding atoms with original deadline"),
                    _metric("historical_breach", len(populations["historical_breach"]), len(populations["historical_deadline_applicable"]), "atoms", "Atoms with a retained outstanding interval under an applicable evaluation deadline"),
                    _metric("original_policy_historical_breach", len(populations["original_policy_historical_breach"]), len(populations["original_historical_deadline_applicable"]), "atoms", "Atoms with a retained interval under an original policy deadline"),
                    _metric("ownership_coverage", len(populations["ownership_covered"]), len(eligible_ids), "atoms", "Eligible outstanding mapped membership"),
                    _metric("assessment_coverage", len(populations["assessment_covered"]), len(eligible_ids), "atoms", "Eligible outstanding mapped membership"),
                    _metric("on_time_completion", len(on_time_known), len(known_completions), "atoms", "Newly confirmed period atoms with known deadlines"),
                    _metric("unknown_deadline_completion", len(unknown_completions), len(new_completions), "atoms", "Newly confirmed atoms in the completion period"),
                    _metric("carried_confirmation", len(carried_atoms), 0, "atoms", "Exact membership covered by retained earlier confirmation; not a new completion"),
                    _metric("excluded_exposure", len(excluded_exposures), len(excluded_exposures), "atoms", "Outstanding exact memberships excluded by an explicit versioned SLA policy"),
                    _metric("vulnerabilities_with_breaches", len(populations["breached_native_groups"]), len(populations["eligible_native_groups"]), "native_groups", "Distinct native group IDs with at least one current breached outstanding atom"),
                ]
                if definition_version == G7_DEFINITION:
                    metrics.append(_metric("paused_known_exposure", len(populations["paused_covered"]),
                        len(covered_ids), "atoms", "Known-deadline exposure paused by an effective exception"))
                    metrics.append(_metric("accepted_exposure", sum(atom["acceptance"]["accepted"] for atom in outstanding),
                        len(eligible_ids), "atoms", "Accepted outstanding exposure; distinct from remediation"))
                    metrics.append(_metric("completed_during_exception", len(populations["completed_during_exception"]),
                        len(new_completions), "atoms", "Genuine confirmations during an effective exception"))
                next(item for item in metrics if item["key"] == "carried_confirmation")["status"] = "known"
                inventory_metric = _metric("inventory_scan_coverage", inventory_data["covered"],
                    inventory_data["expected"], "inventory_targets",
                    "Distinct expected targets with fresh complete observations from every required source")
                if not inventory_data["configured"]:
                    inventory_metric["status"] = "unknown"
                    inventory_metric["percentage"] = inventory_metric["percentage_display"] = None
                metrics.append(inventory_metric)
                metric_denominators = {
                    "sla_coverage": populations["eligible_outstanding"],
                    "current_breach": populations["running_covered"],
                    "sla_gaps": populations["eligible_outstanding"],
                    "original_policy_current_breach": populations["original_deadline_outstanding"],
                    "historical_breach": populations["historical_deadline_applicable"],
                    "original_policy_historical_breach": populations["original_historical_deadline_applicable"],
                    "ownership_coverage": populations["eligible_outstanding"],
                    "assessment_coverage": populations["eligible_outstanding"],
                    "on_time_completion": populations["known_deadline_completions"],
                    "unknown_deadline_completion": populations["new_completions"],
                    "carried_confirmation": set(),
                    "excluded_exposure": populations["excluded_exposure"],
                    "inventory_scan_coverage": set(),
                }
                metric_numerators = {
                    "sla_coverage": populations["covered_outstanding"],
                    "current_breach": populations["current_breach"],
                    "sla_gaps": populations["sla_gaps"],
                    "original_policy_current_breach": populations["original_policy_current_breach"],
                    "historical_breach": populations["historical_breach"],
                    "original_policy_historical_breach": populations["original_policy_historical_breach"],
                    "ownership_coverage": populations["ownership_covered"],
                    "assessment_coverage": populations["assessment_covered"],
                    "on_time_completion": populations["on_time_completions"],
                    "unknown_deadline_completion": populations["unknown_deadline_completions"],
                    "carried_confirmation": populations["carried_confirmation"],
                    "excluded_exposure": populations["excluded_exposure"],
                    "inventory_scan_coverage": set(),
                }
                metric_denominators["vulnerabilities_with_breaches"] = populations["eligible_native_groups"]
                metric_numerators["vulnerabilities_with_breaches"] = populations["breached_native_groups"]
                for atom in atoms:
                    atom_id = atom["atom_id"]
                    atom["metric_membership"] = {key: {"numerator": (
                        atom["native_group_id"] in metric_numerators[key]
                            if key == "vulnerabilities_with_breaches" else atom_id in metric_numerators[key]),
                        "denominator": (atom["native_group_id"] in metric_denominators[key]
                            if key == "vulnerabilities_with_breaches" else atom_id in metric_denominators[key])}
                        for key in metric_denominators}
                    atom["start_at"] = atom["clock"]["start"]
                    atom["deadline_at"] = atom["clock"]["deadline"]
                    atom["original_deadline_at"] = atom["clock"]["original_deadline_at"]
                    atom["first_detection_at"] = atom["clock"]["first_detection_at"]
                    age = atom["clock"]["first_detection_age_seconds"]
                    atom["first_detection_age_seconds"] = age
                    atom["first_detection_age_display"] = _age_display(age)
                    open_age = atom["clock"]["elapsed_seconds"]
                    atom["current_open_age_seconds"] = open_age
                    atom["current_open_age_display"] = _age_display(open_age)
                    atom["overdue_display"] = _age_display(atom["clock"]["overdue_seconds"])
                    atom["evaluation"] = {"evaluation_id": atom["policy"]["evaluation_id"],
                        "revision": atom["policy"]["evaluation_revision"]}
                cohorts = _weighted_cohorts(atoms, populations)
                group_rollups = {}
                for atom in atoms:
                    group_id = atom["native_group_id"]
                    row = group_rollups.setdefault(group_id, {"native_group_id": group_id,
                        "atom_count": 0, "eligible_outstanding_count": 0,
                        "current_breached_outstanding_count": 0})
                    row["atom_count"] += 1
                    if atom["atom_id"] in eligible_ids:
                        row["eligible_outstanding_count"] += 1
                    if atom["atom_id"] in breached_ids:
                        row["current_breached_outstanding_count"] += 1
                for group_id, row in group_rollups.items():
                    row["metric_membership"] = {"vulnerabilities_with_breaches": {
                        "numerator": group_id in populations["breached_native_groups"],
                        "denominator": group_id in populations["eligible_native_groups"]}}
                sources_by_id = {}
                for group in group_rows:
                    source_rows = connection.execute(sa.select(source_observations)
                        .select_from(source_observations.join(occurrences,
                            source_observations.c.occurrence_id == occurrences.c.occurrence_id)
                            .join(exposures, occurrences.c.exposure_id == exposures.c.exposure_id))
                        .where(exposures.c.group_id == group["group_id"],
                            source_observations.c.retention_order <= source_watermark,
                            source_observations.c.collected_at <= known_at)).mappings().all()
                    for source_row in source_rows:
                        input_rows.append({"kind": "source_observation", "stable_id": source_row["observation_id"],
                            "revision": int(source_row["revision"]), "effective_at": _instant(source_row["observed_at"]),
                            "known_at": _instant(source_row["collected_at"]),
                            "retained_value": _jsonable(dict(source_row))})
                        source_id = source_row["source_family"] + ":" + source_row["source_account_id"]
                        source = sources_by_id.setdefault(source_id, {"source_id": source_id,
                            "source_family": source_row["source_family"], "source_account_id": source_row["source_account_id"],
                            "expected_targets": None, "observed_targets": 0,
                            "latest_successful_collection_at": None,
                            "latest_trustworthy_observed_at": None, "last_attempt_at": None,
                            # No inventory schedule exists from which a missed
                            # run or stale target can be asserted. Keep these
                            # source-level flags boolean and let the explicit
                            # unknown expectation reason carry the uncertainty.
                            "completeness": "unknown", "missed_run": False, "stale": False,
                            "watermark": None, "failure_reasons": ["inventory_expectation_unconfigured"],
                            "_members": set(), "_statuses": set(), "_latest_collection": None,
                            "_latest_successful": None})
                        source["_members"].add(source_row["occurrence_id"])
                        source["_statuses"].add(source_row["collection_status"])
                        if source_row["collected_at"] and (source["_latest_collection"] is None or source_row["collected_at"] > source["_latest_collection"]):
                            source["_latest_collection"] = source_row["collected_at"]
                            source["last_attempt_at"] = _instant(source_row["collected_at"])
                            source["watermark"] = source_row["run_id"]
                        if source_row["collection_status"] == "success" and source_row["collected_at"] and (source["_latest_successful"] is None or source_row["collected_at"] > source["_latest_successful"]):
                            source["_latest_successful"] = source_row["collected_at"]
                            source["latest_successful_collection_at"] = _instant(source_row["collected_at"])
                        if source_row["observed_at"] and (source["latest_trustworthy_observed_at"] is None or source_row["observed_at"] > datetime.fromisoformat(source["latest_trustworthy_observed_at"].replace("Z", "+00:00"))):
                            source["latest_trustworthy_observed_at"] = _instant(source_row["observed_at"])
                sources = []
                for source in sources_by_id.values():
                    source["observed_targets"] = len(source.pop("_members"))
                    statuses = source.pop("_statuses")
                    if "failed" in statuses:
                        source["completeness"] = "failed"
                        source["failure_reasons"] = ["retained_source_failure", "inventory_expectation_unconfigured"]
                    elif "partial" in statuses:
                        source["completeness"] = "partial"
                    elif "success" in statuses:
                        source["completeness"] = "complete"
                    source.pop("_latest_collection", None)
                    source.pop("_latest_successful", None)
                    sources.append(source)
                quality["source_failures"] = sum(source["completeness"] == "failed" for source in sources)
                inventory_source_pairs = {(source["source_family"], source["source_account_id"])
                    for source in inventory_data["sources"]}
                sources = [source for source in sources if
                    (source["source_family"], source["source_account_id"]) not in inventory_source_pairs]
                sources.extend(inventory_data["sources"])
                quality["stale_sources"] = sum(bool(source.get("stale")) for source in inventory_data["sources"])
                if quality["stale_sources"]:
                    quality["warnings"].append({"code": "stale_source_observation", "count": quality["stale_sources"]})
                if inventory_data["configured"] and inventory_data["expected"] == 0:
                    quality["warnings"].append({"code": "inventory_scope_empty", "count": 1})
                if quality["source_failures"]:
                    quality["warnings"].append({"code": "source_failure", "count": quality["source_failures"]})
                portions = []
                for group in group_rows:
                    state = connection.execute(sa.select(assessment_group_state.c.document).where(
                        assessment_group_state.c.group_id == group["group_id"])).scalar_one_or_none() or {}
                    state = historical_state_docs.get(group["group_id"], state)
                    for portion in state.get("portions", []):
                        members = set(portion.get("membership_ids", []))
                        selected = [a for a in atoms if a["native_group_id"] == group["group_id"]
                            and a["occurrence_id"] in members]
                        for episode_id in sorted({a["episode_id"] for a in selected}):
                            episode_portion = [a for a in selected if a["episode_id"] == episode_id]
                            episode_members = sorted({a["occurrence_id"] for a in episode_portion})
                            outstanding_portion = [a for a in episode_portion if a["eligible"]]
                            deadlines = sorted((a["clock"]["deadline"], a["occurrence_id"])
                                for a in outstanding_portion if a["clock"]["deadline"])
                            portions.append({"portion_id": portion.get("portion_id"),
                                "episode_id": episode_id,
                                "membership_ids": episode_members,
                                "outstanding_atom_count": len(outstanding_portion),
                                "confirmed_atom_count": sum(a["completion"]["state"]
                                    in {"on_time", "late", "carried"} for a in episode_portion),
                                "earliest_outstanding_deadline_at": deadlines[0][0] if deadlines else None,
                                "earliest_outstanding_atom_id": deadlines[0][1] if deadlines else None})
                episode_groups = {}
                for item in atom_rows:
                    group, episode, _, atom, _ = item
                    bucket = episode_groups.setdefault(episode["episode_id"], {"episode_id": episode["episode_id"], "group_id": group["group_id"],
                        "state": episode["state"], "member_count": 0, "outstanding_atom_count": 0,
                        "new_on_time_atom_count": 0, "late_atom_count": 0, "unknown_deadline_atom_count": 0,
                        "carried_confirmation_atom_count": 0, "earliest_outstanding_deadline_at": None, "earliest_outstanding_atom_id": None})
                    bucket["member_count"] += 1
                    bucket["outstanding_atom_count"] += int(atom["eligible"])
                    bucket["new_on_time_atom_count"] += int(atom["completion"]["state"] == "on_time")
                    bucket["late_atom_count"] += int(atom["completion"]["state"] == "late")
                    bucket["unknown_deadline_atom_count"] += int(atom["completion"]["state"] == "unknown_deadline")
                    bucket["carried_confirmation_atom_count"] += int(atom["completion"]["state"] == "carried")
                    deadline = atom["clock"]["deadline"]
                    if atom["eligible"] and deadline and (bucket["earliest_outstanding_deadline_at"] is None or deadline < bucket["earliest_outstanding_deadline_at"]):
                        bucket["earliest_outstanding_deadline_at"], bucket["earliest_outstanding_atom_id"] = deadline, atom["occurrence_id"]
                # Stable-key the manifest so duplicate joins cannot silently
                # discard an input revision; a collision with different content
                # indicates a malformed source snapshot and fails the request.
                retained_inputs = {}
                for item in input_rows:
                    key = (item["kind"], item["stable_id"])
                    previous_input = retained_inputs.get(key)
                    if previous_input is not None and previous_input != item:
                        if previous_input["revision"] != item["revision"] or previous_input["retained_value"] != item["retained_value"]:
                            _error(503, "snapshot_conflict", "A report input changed within its retained snapshot")
                    retained_inputs[key] = item
                input_rows = sorted(retained_inputs.values(), key=lambda item: (item["kind"], item["stable_id"]))
                differences = []
                if predecessor_result is not None:
                    before_inputs = {(item["kind"], item["stable_id"]): item
                        for item in predecessor_result.get("manifest", {}).get("inputs", [])}
                    after_inputs = {(item["kind"], item["stable_id"]): item for item in input_rows}
                    for key in sorted(set(before_inputs) | set(after_inputs)):
                        before_item, after_item = before_inputs.get(key), after_inputs.get(key)
                        if before_item == after_item:
                            continue
                        old_value = before_item.get("retained_value", {}) if before_item else {}
                        new_value = after_item.get("retained_value", {}) if after_item else {}
                        if before_item is None:
                            fields = ["added"]
                        elif after_item is None:
                            fields = ["removed"]
                        else:
                            fields = sorted({name for name in set(old_value) | set(new_value)
                                if old_value.get(name) != new_value.get(name)}) or ["revision"]
                        differences.append({"input_id": key[0] + ":" + key[1],
                            "before_revision": before_item.get("revision") if before_item else None,
                            "after_revision": after_item.get("revision") if after_item else None,
                            "changed_fields": fields})
                result = {"report_id": report_id, "status": "ready", "projection": {"status": "ready", "intent_id": intent_id, "error_code": None},
                    "context": {"mode": mode, "as_of": _instant(as_of), "known_at": _instant(known_at), "period": {"start": _instant(period_start), "end": _instant(period_end), "bounds": "[start,end)"},
                        "display_timezone": timezone_name, "scope": {"scope_id": "explicit:" + ",".join(group_ids), "filter": {"group_ids": group_ids}},
                        "definition_version": definition_version, "predecessor_report_id": predecessor},
                    "manifest": {"snapshot_sequence": event_watermark, "event_watermark": str(event_watermark),
                        "identity_scalar_sequence": scalar_sequence,
                        "source_retention_watermark": source_watermark, "inputs": input_rows},
                    "metrics": metrics, "quality": quality, "differences": differences, "sources": sources,
                    "inventory": inventory_data["targets"],
                    "episodes": list(episode_groups.values()), "portions": portions,
                    "groups": list(group_rollups.values()), "cohorts": cohorts}
                connection.execute(report_requests.update().where(report_requests.c.report_id == report_id).values(
                    snapshot_sequence=event_watermark, input_manifest=_jsonable(input_rows), status="ready",
                    result=_jsonable(result), error_code=None, ready_at=now))
                for ordinal, item in enumerate(atom_rows):
                    group, episode, occurrence, atom, _ = item
                    connection.execute(metrics_report_atoms.insert().values(report_id=report_id,
                        atom_id=episode["episode_id"] + ":" + occurrence["occurrence_id"], group_id=group["group_id"],
                        episode_id=episode["episode_id"], occurrence_id=occurrence["occurrence_id"], ordinal=ordinal, document=atom))
                connection.execute(reporting_projection_intents.update().where(
                    reporting_projection_intents.c.intent_id == intent_id).values(status="complete",
                        attempts=reporting_projection_intents.c.attempts + 1, last_error=None, updated_at=now))
                receipt = {"schema_version": 1, "command_id": command_id, "decision_id": decision_id,
                    "audit_event_id": audit_id, "intent_id": intent_id, "committed_revision": policy_revision,
                    "projection": "ready", "report_id": report_id, "error_code": None}
                connection.execute(assessment_command_receipts.update().where(
                    assessment_command_receipts.c.command_id == command_id).values(result=receipt))
                report_stage("materialisation_precommit", command_id, report_id=report_id)
            report_stage("materialisation_end_committed", command_id, report_id=report_id)
            return receipt
        except HTTPException:
            # The initial receipt/intent transaction is already durable. Leave
            # deterministic validation/auth failures retryable only when the
            # projection itself failed; surface all errors on the report row.
            try:
                mark_accepted_report_failed()
            except sa.exc.SQLAlchemyError:
                _LOG.exception("Could not persist failed report projection state")
            raise
        except sa.exc.SQLAlchemyError as exc:
            # Under REPEATABLE READ, two simultaneous first submissions of the
            # same omitted-clock command can both take a pre-insert snapshot.
            # The loser may then receive 40001 while locking the winner's
            # committed request row. Re-enter through the same idempotent
            # command path so it observes and returns the winner's receipt.
            if getattr(getattr(exc, "orig", None), "sqlstate", None) in {"40001", "40P01"}:
                return create_report(body, request, principal)
            try:
                mark_accepted_report_failed()
            except sa.exc.SQLAlchemyError:
                _LOG.exception("Could not persist failed report projection state")
            _LOG.error("Report persistence failure (%s): %s", type(exc).__name__, getattr(exc, "orig", exc))
            _error(503, "persistence_unavailable", "Report could not be persisted")

    @app.get("/api/v1/reports/{report_id:uuid}")
    def read_report(report_id: uuid.UUID, principal=Depends(auth)):
        report_id = _uuid(str(report_id), "report_id")
        with engine.connect() as connection:
            row = report_row(connection, report_id, principal["name"])
            return report_projection(row)

    @app.get("/api/v1/reports/commands/{command_id:uuid}")
    def read_report_receipt(command_id: uuid.UUID, principal=Depends(auth)):
        """Disclose a durable report receipt only while its frozen scope is readable."""
        command_id = _uuid(str(command_id), "command_id")
        with engine.connect() as connection:
            receipt = connection.execute(sa.select(assessment_command_receipts).where(
                assessment_command_receipts.c.command_id == command_id,
                assessment_command_receipts.c.action == "report.create")).mappings().first()
            if receipt is None:
                _error(404, "not_found", "Report receipt not found")
            row = report_row(connection, receipt["result"]["report_id"], principal["name"])
            return report_receipt(connection, {**row, "command_id": receipt["command_id"]})

    @app.get("/api/v1/reports/{report_id}/atoms")
    def read_atoms(report_id: str, principal=Depends(auth), limit: int = Query(50), cursor: str | None = None,
                   metric: str | None = None, population: str = "all", presentation: str | None = None):
        report_id = _uuid(report_id, "report_id")
        if not 1 <= limit <= 100:
            _error(400, "invalid_limit", "limit must be between 1 and 100")
        if population not in {"all", "numerator", "denominator"}:
            _error(400, "invalid_population", "population must be all, numerator or denominator")
        if presentation not in {None, "days_v1"}:
            _error(400, "invalid_presentation", "presentation must be days_v1 when supplied")
        with engine.connect() as connection:
            row = report_row(connection, report_id, principal["name"])
            if row["status"] != "ready":
                _error(409, "projection_not_ready", "Report atoms are not available until projection is ready")
            result = row["result"]
            keys = {m["key"] for m in result["metrics"]}
            if metric is not None and metric not in keys:
                _error(400, "invalid_metric", "metric is not present in this report")
            if metric is not None and next(m for m in result["metrics"] if m["key"] == metric)["unit"] != "atoms":
                _error(400, "metric_unit_mismatch", "This metric is measured on report group or inventory rows, not atoms")
            offset = 0
            cursor_binding = {"report_id": report_id, "principal": principal["name"],
                "metric": metric, "population": population}
            if presentation is not None:
                cursor_binding["presentation"] = presentation
            if cursor:
                state = _verify(secret, cursor)
                if state != {**cursor_binding, "offset": state.get("offset")}:
                    _error(400, "invalid_cursor", "Cursor is invalid")
                offset = state["offset"]
            all_atoms = atom_documents(connection, report_id)
            if metric:
                m = next(m for m in result["metrics"] if m["key"] == metric)
                if population != "all":
                    all_atoms = [a for a in all_atoms if a.get("metric_membership", {}).get(metric, {}).get(population) is True]
            page = all_atoms[offset:offset + limit]
            if presentation == "days_v1":
                # Present retained durations on copies, never amend issued atoms.
                page = [{**atom, "overdue_display": _age_display(atom["clock"].get("overdue_seconds"))}
                    for atom in page]
            next_cursor = _sign(secret, {**cursor_binding, "offset": offset + limit}) if offset + limit < len(all_atoms) else None
            return {"report_id": report_id, "metric": metric, "population": population,
                "total_count": len(all_atoms), "items": page, "next_cursor": next_cursor}

    @app.get("/api/v1/reports/{report_id}/export")
    def export_report(report_id: str, format: str = Query("json"), principal=Depends(auth)):
        report_id = _uuid(report_id, "report_id")
        if format not in {"json", "csv"}:
            _error(400, "invalid_format", "format must be json or csv")
        with engine.connect() as connection:
            row = report_row(connection, report_id, principal["name"], action="report.export")
            if row["status"] != "ready":
                _error(409, "projection_not_ready", "Report exports are not available until projection is ready")
            result = row["result"]
            atoms = atom_documents(connection, report_id)
        payload = {**result, "atoms": atoms}
        if format == "json":
            return payload
        bundle = io.BytesIO()
        with zipfile.ZipFile(bundle, "w", zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("manifest.json", json.dumps(result["manifest"], sort_keys=True, indent=2))
            archive.writestr("report.json", json.dumps(result, sort_keys=True, indent=2))
            output = io.StringIO()
            fields = ["report_id", "atom_id", "as_of", "known_at", "scope", "definition_version",
                "metric_key", "unit", "basis", "numerator", "denominator", "mode", "period_start",
                "period_end", "display_timezone", "native_group_id", "episode_id", "occurrence_id",
                "eligible", "start", "deadline", "original_deadline_at", "completion_state", "gap_reasons"]
            writer = csv.DictWriter(output, fieldnames=fields)
            writer.writeheader()
            for atom in atoms:
                for metric in result["metrics"]:
                    if metric["unit"] != "atoms":
                        continue
                    population = atom.get("metric_membership", {}).get(metric["key"], {})
                    writer.writerow({"report_id": report_id, "atom_id": atom["atom_id"],
                        "as_of": result["context"]["as_of"], "known_at": result["context"]["known_at"],
                        "scope": json.dumps(result["context"]["scope"], sort_keys=True),
                        "definition_version": result["context"]["definition_version"],
                        "metric_key": metric["key"], "unit": metric["unit"], "basis": metric["basis"],
                        "numerator": population.get("numerator", False),
                        "denominator": population.get("denominator", False),
                        "mode": result["context"]["mode"],
                        "period_start": result["context"]["period"]["start"],
                        "period_end": result["context"]["period"]["end"],
                        "display_timezone": result["context"]["display_timezone"],
                        "native_group_id": atom["native_group_id"], "episode_id": atom["episode_id"],
                        "occurrence_id": atom["occurrence_id"], "eligible": atom["eligible"],
                        "start": atom["clock"]["start"], "deadline": atom["clock"]["deadline"],
                        "original_deadline_at": atom["clock"]["original_deadline_at"],
                        "completion_state": atom["completion"]["state"], "gap_reasons": ";".join(atom["gap_reasons"])})
            archive.writestr("atoms.csv", output.getvalue())
            group_output = io.StringIO()
            group_fields = ["report_id", "native_group_id", "atom_count", "eligible_outstanding_count",
                "current_breached_outstanding_count", "metric_key", "unit", "basis", "numerator", "denominator"]
            group_writer = csv.DictWriter(group_output, fieldnames=group_fields)
            group_writer.writeheader()
            for group in result.get("groups", []):
                for metric in result["metrics"]:
                    if metric["unit"] != "native_groups":
                        continue
                    membership = group.get("metric_membership", {}).get(metric["key"], {})
                    group_writer.writerow({"report_id": report_id, "native_group_id": group["native_group_id"],
                        "atom_count": group["atom_count"],
                        "eligible_outstanding_count": group["eligible_outstanding_count"],
                        "current_breached_outstanding_count": group["current_breached_outstanding_count"],
                        "metric_key": metric["key"], "unit": metric["unit"], "basis": metric["basis"],
                        "numerator": membership.get("numerator", False),
                        "denominator": membership.get("denominator", False)})
            archive.writestr("groups.csv", group_output.getvalue())
            cohort_output = io.StringIO()
            cohort_fields = ["report_id", "cohort_id", "weight", "atom_ids", "episode_id",
                "eligible", "covered", "start", "original_deadline_at", "deadline",
                "policy_id", "policy_version", "severity", "classification_basis",
                "gap_reasons", "completion_state", "acceptance_state", "excluded",
                "metric_key", "unit", "basis", "numerator", "denominator"]
            cohort_writer = csv.DictWriter(cohort_output, fieldnames=cohort_fields)
            cohort_writer.writeheader()
            result_metrics = {metric["key"]: metric for metric in result["metrics"]}
            for cohort in result.get("cohorts", []):
                dimensions = cohort["dimensions"]
                for metric_key, membership in cohort["metric_membership"].items():
                    metric = result_metrics.get(metric_key)
                    if metric is None or metric["unit"] != "atoms":
                        continue
                    cohort_writer.writerow({"report_id": report_id, "cohort_id": cohort["cohort_id"],
                        "weight": cohort["weight"], "atom_ids": ";".join(cohort["atom_ids"]),
                        "episode_id": dimensions["episode_id"], "eligible": dimensions["eligible"],
                        "covered": dimensions["covered"], "start": dimensions["start"],
                        "original_deadline_at": dimensions["original_deadline_at"],
                        "deadline": dimensions["deadline"], "policy_id": dimensions["policy_id"],
                        "policy_version": dimensions["policy_version"], "severity": dimensions["severity"],
                        "classification_basis": dimensions["classification_basis"],
                        "gap_reasons": ";".join(dimensions["gap_reasons"]),
                        "completion_state": dimensions["completion_state"],
                        "acceptance_state": dimensions["acceptance_state"],
                        "excluded": dimensions["exclusion"], "metric_key": metric_key,
                        "unit": metric["unit"], "basis": metric["basis"],
                        "numerator": membership["numerator"], "denominator": membership["denominator"]})
            archive.writestr("cohorts.csv", cohort_output.getvalue())
        return Response(bundle.getvalue(), media_type="application/zip",
            headers={"Content-Disposition": f'attachment; filename="report-{report_id}.zip"'})

    def recover_report_projections(startup_candidates):
        """Consume only work durably pending/failed at process start."""
        batch_size = 20
        for offset in range(0, len(startup_candidates), batch_size):
            for row in startup_candidates[offset:offset + batch_size]:
                if projection_worker_stop.is_set():
                    return
                command_id = row["command_id"]
                try:
                    request_body = {"schema_version": 1, "command_id": command_id,
                        "mode": row["mode"], "scope": row["scope"], "filters": {},
                        "as_of": _instant(row["as_of"]), "known_at": _instant(row["known_at"]),
                        "period": {"start": _instant(row["period_start"]),
                            "end": _instant(row["period_end"])},
                        "display_timezone": row["display_timezone"],
                        "predecessor_report_id": row["predecessor_report_id"]}
                    # This is an internal retry of an already accepted command,
                    # not an HTTP request. Rebuild the request state from the
                    # durable authority snapshot on its receipt so the normal
                    # writer still performs current policy and exact source-scope
                    # checks. In particular, never pass a principal dict where
                    # the HTTP adapter expects Starlette Request.state.
                    with engine.connect() as connection:
                        receipt = connection.execute(sa.select(
                            assessment_command_receipts).where(
                                assessment_command_receipts.c.command_id == command_id
                            )).mappings().first()
                    if receipt is None or receipt["principal_id"] != row["principal_id"]:
                        raise RuntimeError("accepted report receipt is missing or belongs to another principal")
                    request = _internal_report_request(receipt.get("authorization_context"),
                        row["principal_id"], oidc_enabled=getattr(app.state, "oidc_auth", None) is not None)
                    request.state._accepted_report_cleanup_target = _report_failure_target(row,
                        command_id=command_id, principal_id=row["principal_id"],
                        request_digest=row["request_digest"])
                    authority_token = AUTHORITY_CONTEXT.set(
                        getattr(request.state, "authority_context", None))
                    try:
                        create_report(request_body, request, {"name": row["principal_id"]})
                    finally:
                        AUTHORITY_CONTEXT.reset(authority_token)
                except Exception:
                    _LOG.exception("Durable report projection recovery failed for command %s", command_id)

    def consume_sla_refresh(intent_id):
        """Acknowledge a refresh only after its immutable writer evidence is visible."""
        with engine.begin() as connection:
            intent = connection.execute(sa.select(reporting_projection_intents).where(
                reporting_projection_intents.c.intent_id == intent_id,
                reporting_projection_intents.c.kind == "reporting.sla.refresh",
                reporting_projection_intents.c.status == "pending").with_for_update()).mappings().first()
            if intent is None:
                return
            audit_id = intent["audit_event_id"]
            event = connection.execute(sa.select(assessment_audit_events).where(
                assessment_audit_events.c.event_id == audit_id)).mappings().first() if audit_id else None
            receipt = connection.execute(sa.select(assessment_command_receipts).where(
                assessment_command_receipts.c.audit_event_id == audit_id)).mappings().first() if audit_id else None
            failure = None
            if event is None or receipt is None or event["command_id"] != receipt["command_id"]:
                failure = "refresh_audit_or_receipt_missing"
            else:
                action, evidence = event["action"], event["after_value"] or {}
                if action == "policy.sla.publish":
                    policy_doc = evidence.get("sla_policy") or {}
                    retained_policy = {**policy_doc, **({"publication_rationale": event["rationale"]}
                        if event["rationale"] else {}), **({"publication_evidence_ref": event["evidence_ref"]}
                        if event["evidence_ref"] else {})}
                    version = connection.execute(sa.select(sla_policy_versions).where(
                        sla_policy_versions.c.policy_id == policy_doc.get("policy_id"),
                        sla_policy_versions.c.version == policy_doc.get("version"))).mappings().first()
                    if version is None:
                        failure = "published_policy_version_missing"
                    elif version["revision"] != evidence.get("sla_policy_head"):
                        failure = "published_policy_head_mismatch"
                    elif version["document"] != retained_policy:
                        failure = "published_policy_document_mismatch"
                    inventory_doc = evidence.get("inventory_configuration")
                    if failure is None and inventory_doc is not None:
                        inventory = connection.execute(sa.select(inventory_policy_versions).where(
                            inventory_policy_versions.c.audit_event_id == audit_id)).mappings().first()
                        if inventory is None or inventory["document"] != inventory_doc:
                            failure = "published_inventory_projection_missing"
                elif action in {"sla.deadline.revise", "severity.override"}:
                    revisions = evidence.get("deadline_revisions", evidence.get("sla_recalculations", []))
                    for revision in revisions:
                        persisted = connection.execute(sa.select(sla_evaluations).where(
                            sla_evaluations.c.evaluation_id == revision.get("evaluation_id"),
                            sla_evaluations.c.episode_id == revision.get("episode_id"),
                            sla_evaluations.c.occurrence_id == revision.get("occurrence_id"),
                            sla_evaluations.c.revision == revision.get("revision"))).first()
                        if persisted is None:
                            failure = "sla_evaluation_projection_missing"
                            break
                    if not revisions and failure is None:
                        failure = "sla_refresh_has_no_evaluation_targets"
                else:
                    failure = "unsupported_sla_refresh_action"
            now = datetime.now(UTC)
            connection.execute(reporting_projection_intents.update().where(
                reporting_projection_intents.c.intent_id == intent_id,
                reporting_projection_intents.c.status == "pending").values(
                    status="failed" if failure else "complete", attempts=intent["attempts"] + 1,
                    last_error=failure, updated_at=now))

    def consume_sla_refresh_intents():
        while not projection_worker_stop.wait(0.25):
            with engine.connect() as connection:
                pending = connection.execute(sa.select(reporting_projection_intents.c.intent_id).where(
                    reporting_projection_intents.c.kind == "reporting.sla.refresh",
                    reporting_projection_intents.c.status == "pending").order_by(
                    reporting_projection_intents.c.created_at).limit(50)).scalars().all()
            for intent_id in pending:
                if projection_worker_stop.is_set():
                    return
                try:
                    consume_sla_refresh(intent_id)
                except Exception:
                    _LOG.exception("SLA refresh intent consumer failed for %s", intent_id)

    def start_projection_worker():
        nonlocal projection_worker, sla_refresh_worker, exception_expiry_worker, native_admin_worker
        projection_worker_stop.clear()
        def recover_startup_candidates():
            # The gate is a disposable integration seam: it lets the maintained
            # journey change identity state through the supported local fixture
            # after API startup but before the startup recovery snapshot.
            gate = os.environ.get("UVM_G7_TEST_REPORT_RECOVERY_GATE")
            if gate:
                if os.environ.get("UVM_G7_DISPOSABLE_MODE") != "1":
                    raise RuntimeError("report recovery test gate requires disposable mode")
                deadline = time.monotonic() + 180
                while time.monotonic() < deadline and not projection_worker_stop.is_set():
                    try:
                        with open(gate, encoding="ascii") as gate_file:
                            if gate_file.read().strip() == "release":
                                break
                    except FileNotFoundError:
                        pass
                    time.sleep(0.1)
                else:
                    _LOG.error("Disposable report recovery gate timed out")
                    return
            with engine.connect() as connection:
                startup_candidates = connection.execute(sa.select(report_requests).join(
                    reporting_projection_intents,
                    reporting_projection_intents.c.intent_id == report_requests.c.projection_intent_id).where(
                        reporting_projection_intents.c.kind == "report.materialise",
                        report_requests.c.status.in_(["pending", "failed"])).order_by(
                            report_requests.c.created_at)).mappings().all()
            recover_report_projections(startup_candidates)
        projection_worker = threading.Thread(target=recover_startup_candidates,
            name="g5-report-projection-recovery", daemon=True)
        projection_worker.start()
        sla_refresh_worker = threading.Thread(target=consume_sla_refresh_intents,
            name="g5-sla-refresh-consumer", daemon=True)
        sla_refresh_worker.start()
        def consume_exception_expiries():
            from uvm.assessment.g7_clock import process_expired_pauses
            while not projection_worker_stop.is_set():
                try:
                    process_expired_pauses(engine, now_utc())
                except Exception:
                    _LOG.exception("G7 exception expiry worker failed")
                projection_worker_stop.wait(1.0)
        exception_expiry_worker = threading.Thread(target=consume_exception_expiries,
            name="g7-exception-expiry-worker", daemon=True)
        exception_expiry_worker.start()
        from uvm.assessment.native_reconciliation import run as run_native_admin_reconciliation
        native_admin_worker = threading.Thread(target=run_native_admin_reconciliation,
            args=(engine, projection_worker_stop), name="g7-native-admin-reconciliation", daemon=True)
        native_admin_worker.start()

    def stop_projection_worker():
        projection_worker_stop.set()
        if projection_worker is not None:
            projection_worker.join(timeout=5)
        if sla_refresh_worker is not None:
            sla_refresh_worker.join(timeout=5)
        if exception_expiry_worker is not None:
            exception_expiry_worker.join(timeout=5)
        if native_admin_worker is not None:
            native_admin_worker.join(timeout=5)

    app.router.on_startup.append(start_projection_worker)
    app.router.on_shutdown.append(stop_projection_worker)

    @app.get("/api/v1/reports/sla-policies")
    def list_sla_policies(group_id: str | None = None, principal=Depends(auth)):
        if group_id is None:
            _error(422, "invalid_request", "A group_id scope is required")
        group_id = _uuid(group_id, "group_id")
        with engine.connect() as connection:
            policy_revision, policy = policy_for(connection)
            group = connection.execute(sa.select(groups).where(groups.c.group_id == group_id)).mappings().first()
            from uvm.assessment.api import _complete_target_grants
            grants = (_complete_target_grants(connection, policy, principal["name"],
                "policy.read", group_id, group["source_family"]) if group else [])
            if group is None or not grants:
                _error(403, "forbidden", "Current policy-read authority is required")
            from uvm.auth.schema import AUTHORITY_CONTEXT
            from uvm.auth.service import group_scope_covered
            if not group_scope_covered(connection, AUTHORITY_CONTEXT.get(), [group_id],
                    granting_identity_groups=[grant.get("principal_id") for grant in grants]):
                _error(403, "source_scope_forbidden", "Current exact source scope is required")
            head = connection.execute(sa.select(sla_policy_heads.c.revision).where(
                sla_policy_heads.c.head_id == 1)).scalar_one()
            versions = connection.execute(sa.select(sla_policy_versions).order_by(
                sla_policy_versions.c.revision)).mappings().all()
            grants = []
            actions = ["report.read", "report.create", "report.export", "policy.read",
                "policy.sla.publish", "sla.deadline.revise"]
            effective_actions = []
            for action in actions:
                from uvm.assessment.api import _complete_target_grants
                source_family = connection.execute(sa.select(groups.c.source_family).where(
                    groups.c.group_id == group_id)).scalar_one_or_none()
                action_grants = (_complete_target_grants(connection, policy,
                    principal["name"], action, group_id, source_family) if source_family else [])
                if action_grants:
                    effective_actions.append(action)
                for grant in action_grants:
                    grant_key = (grant.get("grant_id"), grant.get("role_id"))
                    if not any((item.get("grant_id"), item.get("role_id")) == grant_key for item in grants):
                        grants.append(grant)
            episode_rows = connection.execute(sa.select(exposure_episodes).where(
                exposure_episodes.c.group_id == group_id,
                exposure_episodes.c.is_current.is_(True)).order_by(exposure_episodes.c.exposure_id)).mappings().all()
            episode_heads = [{"exposure_id": e["exposure_id"], "episode_id": e["episode_id"],
                "state_revision": e["state_revision"], "state": e["state"]} for e in episode_rows]
            evaluation_heads = []
            for episode in episode_rows:
                member_ids = connection.execute(sa.select(exposure_episode_members.c.occurrence_id).where(
                    exposure_episode_members.c.episode_id == episode["episode_id"])).scalars().all()
                for occurrence_id in member_ids:
                    contract = connection.execute(sa.select(sla_episode_contracts).where(
                        sla_episode_contracts.c.episode_id == episode["episode_id"])).mappings().first()
                    evaluation_table = (g7_sla_evaluations if contract and
                        contract["contract_version"] == 7 else sla_evaluations)
                    evaluation = connection.execute(sa.select(evaluation_table).where(
                        evaluation_table.c.episode_id == episode["episode_id"],
                        evaluation_table.c.occurrence_id == occurrence_id,
                        evaluation_table.c.is_authoritative.is_(True))
                        .order_by(evaluation_table.c.revision.desc()).limit(1)).mappings().first()
                    if evaluation:
                        evaluation_heads.append({"episode_id": episode["episode_id"],
                            "occurrence_id": occurrence_id, "evaluation_id": evaluation["evaluation_id"],
                            "revision": evaluation["revision"], "policy_id": evaluation["policy_id"],
                            "deadline_at": _instant(evaluation["current_deadline_at"]),
                            "reference_binding_id": evaluation["reference_binding_id"],
                            "head_decision_id": evaluation["head_decision_id"]})
            return {"schema_version": 1, "group_id": group_id, "policy_revision": policy_revision,
                "sla_policy_head": int(head), "authorisation": {"principal_id": principal["name"],
                    "effective_actions": effective_actions,
                    "grants": grants, "denies": [d for d in policy.get("denies", []) if d.get("principal_id") == principal["name"]],
                    "delegation_envelope": policy.get("delegation_envelopes", {}).get(principal["name"], {})},
                "policies": [disclose_policy_document(connection, row["document"], [group_id]) |
                    {"revision": row["revision"]} for row in versions
                    if group_id in row["document"].get("scope", {}).get("group_ids", [])],
                "current_heads": {"episodes": episode_heads, "evaluations": evaluation_heads}}
