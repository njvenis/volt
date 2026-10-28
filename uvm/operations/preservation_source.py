"""Canonical, permission-scoped source snapshot for the external G7 signer.

This adapter returns digests and bounded metadata only. It never returns source
payload bytes, private locators, or an application signature.
"""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import os
import re
from typing import Any
from uuid import UUID

import sqlalchemy as sa

from uvm.operations.preservation import CLASSES, canonical_json
from uvm.persistence.assessment_schema import assessment_audit_events
from uvm.persistence.exception_sla_schema import source_observation_receipts
from uvm.persistence.ingestion_schema import (
    collection_runs, collection_schedules, expected_runs, expected_run_events,
    run_attempts, run_pages, ingestion_evidence,
)
from uvm.persistence.observation_schema import source_observations
from uvm.persistence.lineage_schema import identity_resolutions

UTC = timezone.utc
SOURCE_CLASS = "product.source_evidence"
AUDIT_CLASS = "product.audit_history"
SCANNER_CLASS = "operational.scanner_collection"


def _wire(value: Any) -> Any:
    if isinstance(value, datetime):
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("naive persisted timestamp")
        return value.astimezone(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")
    if isinstance(value, str) and "T" in value and re.search(r"(?:Z|[+-]\d{2}:\d{2})$", value):
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            parsed = None
        if parsed is not None and parsed.tzinfo is not None and parsed.utcoffset() is not None:
            return parsed.astimezone(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")
    if isinstance(value, dict):
        return {str(key): _wire(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_wire(item) for item in value]
    return value


def _digest(class_id: str, preimage: dict) -> str:
    return hashlib.sha256(b"VOLT-G7-RECORD\0" + class_id.encode() + b"\0" + canonical_json(preimage)).hexdigest()


def _member(class_id: str, kind: str, key: str, preimage: dict, retained_at, *, raw_sha256=None,
            byte_size=None, evidence_id=None) -> dict:
    return {"record_kind": kind, "stable_key": key,
        "retained_at": _wire(retained_at), "record_sha256": _digest(class_id, preimage),
        "raw_sha256": raw_sha256, "byte_size": byte_size,
        "evidence_id": evidence_id}


def _source_members(connection, scope: tuple[str, str, str]) -> tuple[list[dict], bool, str | None, int]:
    family, account, scope_key = scope
    observation_columns = [column.name for column in source_observations.columns
        if column.name not in {"occurrence_id"}]
    # The retained source table intentionally stores run IDs as source-facing
    # strings while ingestion run IDs are PostgreSQL UUIDs. SQLite compares
    # these implicitly; PostgreSQL requires the explicit wire-form cast.
    query = (sa.select(source_observations).select_from(source_observations.join(
        collection_runs, sa.cast(collection_runs.c.run_id, sa.String)
            == source_observations.c.run_id))
        .where(collection_runs.c.source_family == family,
            collection_runs.c.source_account_id == account,
            collection_runs.c.scope_key == scope_key).distinct())
    observations = connection.execute(query).mappings().all()
    members: list[dict] = []
    # This class inventories every committed UVM source-evidence record in the
    # authorized tuple. A scanner run's freshness/coverage assessment is a
    # separate operational fact and cannot make an otherwise coherent,
    # complete DB snapshot unreadable. The read transaction itself and each
    # registered evidence linkage determine inventory completeness below.
    complete = True
    oldest = None
    max_watermark = None
    registrations = connection.execute(sa.select(ingestion_evidence, collection_runs.c.source_family,
            collection_runs.c.source_account_id, collection_runs.c.scope_key)
        .join(collection_runs, sa.and_(collection_runs.c.run_id == ingestion_evidence.c.run_id,
            collection_runs.c.revision == ingestion_evidence.c.run_revision))
        .where(collection_runs.c.source_family == family,
            collection_runs.c.source_account_id == account,
            collection_runs.c.scope_key == scope_key)
        .order_by(ingestion_evidence.c.evidence_id)).mappings().all()
    by_ref_digest: dict[tuple[str, str], list[dict]] = {}
    for registration in registrations:
        by_ref_digest.setdefault((registration["evidence_ref"], registration["sha256"]), []).append(dict(registration))
    observation_owners = {}
    observation_digests = {}
    for row in observations:
        observation = {name: _wire(row[name]) for name in observation_columns}
        key = str(row["observation_id"])
        observation_digests[key] = _digest(SOURCE_CLASS, observation)
        matches = by_ref_digest.get((row["raw_evidence_ref"], row["raw_evidence_sha256"]), [])
        matches = [entry for entry in matches if entry["run_id"] == row["run_id"]]
        selected = matches[0] if matches else None
        observation_owners.setdefault((row["run_id"], row["raw_evidence_ref"],
            row["raw_evidence_sha256"]), "observation:" + key)
        members.append(_member(SOURCE_CLASS, "observation", "observation:" + key, observation,
            row["collected_at"], raw_sha256=row["raw_evidence_sha256"],
            byte_size=selected.get("byte_size") if selected else None,
            evidence_id=selected.get("evidence_id") if selected else None))
        if selected is None or selected.get("byte_size") is None:
            complete = False
        if oldest is None or row["collected_at"] < oldest:
            oldest = row["collected_at"]
        max_watermark = max(max_watermark or row["retention_order"], row["retention_order"])

        resolutions = connection.execute(sa.select(identity_resolutions).where(
            identity_resolutions.c.observation_id == key).order_by(
                identity_resolutions.c.revision)).mappings().all()
        for resolution in resolutions:
            fields = ("schema_version", "resolution_id", "revision", "observation_id", "rule_id",
                "rule_version", "outcome", "evaluated_at", "group_id", "workload_id",
                "incarnation_id", "exposure_id", "occurrence_id", "selected_exposure_revision",
                "selected_occurrence_revision", "known_group_revision", "reason", "supersedes_resolution_id")
            preimage = {name: _wire(resolution[name]) for name in fields}
            preimage["matching_inputs_digest"] = hashlib.sha256(canonical_json(_wire(resolution["matching_inputs"]))).hexdigest()
            preimage["candidate_workload_ids_digest"] = hashlib.sha256(canonical_json(_wire(resolution["candidate_workload_ids"]))).hexdigest()
            preimage["candidate_explanations_digest"] = hashlib.sha256(canonical_json(_wire(resolution["candidate_explanations"]))).hexdigest()
            members.append(_member(SOURCE_CLASS, "observation_linkage",
                f"observation_linkage:{key}:{int(resolution['revision'])}", preimage,
                resolution["evaluated_at"]))

        receipts = connection.execute(sa.select(source_observation_receipts).where(
            source_observation_receipts.c.source_observation_id == key).order_by(
                source_observation_receipts.c.receipt_id)).mappings().all()
        for receipt in receipts:
            preimage = {name: _wire(receipt[name]) for name in (
                "receipt_id", "source_observation_id", "source_account_id", "run_id",
                "source_record_ordinal", "retention_operation_id", "retained_at",
                "source_observed_at", "source_collected_at", "created_at")}
            preimage.update({"evidence_id": selected.get("evidence_id") if selected else None,
                "raw_sha256": row["raw_evidence_sha256"],
                "byte_size": selected.get("byte_size") if selected else None})
            members.append(_member(SOURCE_CLASS, "retention_receipt", "retention_receipt:" + str(receipt["receipt_id"]),
                preimage, receipt["created_at"], raw_sha256=None,
                byte_size=None, evidence_id=None))

    # ScheduledCollector stores canonical SourceObservationV1 records in the
    # immutable run provenance snapshot. Include that established source path
    # as well as the separate source_observations ingress table above.
    provenance_runs = connection.execute(sa.select(collection_runs.c.run_id,
            collection_runs.c.revision, collection_runs.c.created_at,
            collection_runs.c.provenance_snapshot)
        .where(collection_runs.c.source_family == family,
            collection_runs.c.source_account_id == account,
            collection_runs.c.scope_key == scope_key)
        .order_by(collection_runs.c.run_id, collection_runs.c.revision)).mappings().all()
    provenance_observations = {}
    for run in provenance_runs:
        provenance = run["provenance_snapshot"]
        if not isinstance(provenance, dict) or not isinstance(provenance.get("observations"), list):
            complete = False
            continue
        for raw_observation in provenance["observations"]:
            if not isinstance(raw_observation, dict):
                complete = False
                continue
            try:
                observation_id = str(raw_observation["observation_id"])
                evidence_ref = raw_observation["raw_evidence_ref"]
                raw_sha256 = raw_observation["raw_evidence_sha256"]
                if not re.fullmatch(r"[0-9a-f-]{36}", observation_id):
                    raise ValueError
                if not isinstance(evidence_ref, str) or not isinstance(raw_sha256, str) or not re.fullmatch(r"[0-9a-f]{64}", raw_sha256):
                    raise ValueError
                preimage = _wire(raw_observation)
                record_digest = _digest(SOURCE_CLASS, preimage)
                old_digest = observation_digests.get(observation_id)
                if old_digest is not None:
                    if old_digest != record_digest:
                        complete = False
                    continue
                previous = provenance_observations.get(observation_id)
                if previous is not None and _digest(SOURCE_CLASS, previous[0]) != record_digest:
                    complete = False
                    continue
                provenance_observations[observation_id] = (preimage, raw_observation,
                    int(run["revision"]), run["created_at"])
            except (KeyError, TypeError, ValueError, OverflowError):
                complete = False
    for observation_id, (preimage, observation, revision, retained_at) in sorted(provenance_observations.items()):
        evidence_ref = observation["raw_evidence_ref"]
        raw_sha256 = observation["raw_evidence_sha256"]
        owner_key = "observation:" + observation_id
        observation_owners[(str(observation["run_id"]), evidence_ref, raw_sha256)] = owner_key
        matches = by_ref_digest.get((evidence_ref, raw_sha256), [])
        matches = [entry for entry in matches if entry["run_id"] == str(observation["run_id"])]
        selected = max(matches, key=lambda entry: int(entry["run_revision"])) if matches else None
        members.append(_member(SOURCE_CLASS, "observation", owner_key, preimage,
            observation.get("collected_at") or retained_at, raw_sha256=raw_sha256,
            byte_size=selected.get("byte_size") if selected else None,
            evidence_id=selected.get("evidence_id") if selected else None))
        if selected is None or selected.get("byte_size") is None:
            complete = False
        candidate_oldest = _wire(observation.get("collected_at") or retained_at)
        if oldest is None or candidate_oldest < _wire(oldest):
            oldest = candidate_oldest
        max_watermark = max(max_watermark or revision, revision)

    for registration in registrations:
        owner_key = observation_owners.get((registration["run_id"], registration["evidence_ref"], registration["sha256"]))
        if owner_key is None:
            continue
        preimage = {"schema_version": registration["schema_version"],
            "evidence_id": registration["evidence_id"], "owning_class": SOURCE_CLASS,
            "owning_member_key": owner_key, "run_id": registration["run_id"],
            "run_revision": registration["run_revision"],
            "opaque_object_id": registration["evidence_ref"],
            "raw_sha256": registration["sha256"], "size": registration["byte_size"],
            "kind": registration["kind"], "registered_at": _wire(registration["registered_at"])}
        members.append(_member(SOURCE_CLASS, "evidence_registration", "evidence_registration:" + str(registration["evidence_id"]),
            preimage, registration["registered_at"], raw_sha256=registration["sha256"],
            byte_size=registration["byte_size"], evidence_id=registration["evidence_id"]))
    members.sort(key=lambda item: (item["record_kind"].encode(), item["stable_key"].encode()))
    return members, complete, _wire(oldest), int(max_watermark or 0)


def _scanner_members(connection, scope: tuple[str, str, str]) -> tuple[list[dict], bool, str | None, int]:
    family, account, scope_key = scope
    members: list[dict] = []
    schedules = connection.execute(sa.select(collection_schedules).where(
        collection_schedules.c.source_family == family,
        collection_schedules.c.source_account_id == account,
        collection_schedules.c.scope_key == scope_key).order_by(
            collection_schedules.c.schedule_id, collection_schedules.c.revision)).mappings().all()
    expected = connection.execute(sa.select(expected_runs, collection_schedules.c.source_family,
            collection_schedules.c.source_account_id).join(collection_schedules,
                sa.and_(collection_schedules.c.schedule_id == expected_runs.c.schedule_id,
                    collection_schedules.c.revision == expected_runs.c.schedule_revision))
        .where(collection_schedules.c.source_family == family,
            collection_schedules.c.source_account_id == account,
            expected_runs.c.scope_key == scope_key)
        .order_by(expected_runs.c.expected_run_id)).mappings().all()
    oldest = None
    watermark = 0
    # Expected-run inventory is keyed by actual scheduled occurrence. A
    # schedule definition alone does not fabricate an expected run.
    for row in expected:
        preimage = {name: _wire(row[name]) for name in ("expected_run_id", "schedule_id",
            "schedule_revision", "scope_key", "due_at", "grace_deadline")}
        members.append(_member(SCANNER_CLASS, "expected_run", "expected_run:" + str(row["expected_run_id"]), preimage,
            row["due_at"], raw_sha256=None))
        if oldest is None or row["due_at"] < oldest:
            oldest = row["due_at"]
        watermark = max(watermark, int(row["schedule_revision"]))
    run_rows = connection.execute(sa.select(collection_runs).where(
        collection_runs.c.source_family == family,
        collection_runs.c.source_account_id == account,
        collection_runs.c.scope_key == scope_key).order_by(
            collection_runs.c.run_id, collection_runs.c.revision)).mappings().all()
    for row in run_rows:
        preimage = {name: _wire(row[name]) for name in ("schema_version", "run_id", "revision",
            "source_family", "source_account_id", "scope_key", "expected_run_id", "manual_origin",
            "schedule_id", "schedule_revision", "source_report_id", "expected_at", "started_at",
            "ended_at", "state", "retrieval_status", "retrieval_reasons", "coverage_status",
            "coverage_reasons", "freshness_status", "freshness_reasons", "created_at")}
        preimage["facts_snapshot_digest"] = hashlib.sha256(canonical_json(_wire(row["facts_snapshot"]))).hexdigest()
        preimage["provenance_snapshot_digest"] = hashlib.sha256(canonical_json(_wire(row["provenance_snapshot"]))).hexdigest()
        members.append(_member(SCANNER_CLASS, "run_revision", f"run_revision:{row['run_id']}:{int(row['revision'])}",
            preimage, row["created_at"]))
        watermark = max(watermark, int(row["revision"]))
        for attempt in connection.execute(sa.select(run_attempts).where(
                run_attempts.c.run_id == row["run_id"], run_attempts.c.run_revision == row["revision"])
                .order_by(run_attempts.c.attempt_no)).mappings():
            ap = {name: _wire(attempt[name]) for name in ("run_id", "run_revision", "attempt_no",
                "started_at", "finished_at", "response_class", "success", "retry_after_microseconds", "error_code")}
            members.append(_member(SCANNER_CLASS, "attempt", f"attempt:{row['run_id']}:{int(row['revision'])}:{int(attempt['attempt_no'])}", ap,
                attempt["started_at"]))
        for page in connection.execute(sa.select(run_pages).where(
                run_pages.c.run_id == row["run_id"], run_pages.c.run_revision == row["revision"])
                .order_by(run_pages.c.ordinal)).mappings():
            page_registrations = connection.execute(sa.select(ingestion_evidence).where(
                ingestion_evidence.c.run_id == row["run_id"],
                ingestion_evidence.c.run_revision == row["revision"],
                ingestion_evidence.c.evidence_ref == page["page_ref"],
                ingestion_evidence.c.sha256 == page["evidence_digest"]).order_by(
                    ingestion_evidence.c.evidence_id)).mappings().all()
            selected_registration = page_registrations[0] if page_registrations else None
            pp = {name: _wire(page[name]) for name in ("run_id", "run_revision", "ordinal", "attempt_no",
                "response_class", "record_count", "evidence_digest", "is_terminal", "failed")}
            pp["request_identity_digest"] = hashlib.sha256(str(page["request_identity"]).encode()).hexdigest()
            pp["cursor_digest"] = hashlib.sha256((page["cursor"] or "").encode()).hexdigest()
            pp["next_cursor_digest"] = hashlib.sha256((page["next_cursor"] or "").encode()).hexdigest()
            pp["report_digest"] = hashlib.sha256((page["report_id"] or "").encode()).hexdigest()
            pp["query_scope_digest"] = hashlib.sha256((page["query_scope"] or "").encode()).hexdigest()
            pp["evidence_id"] = selected_registration["evidence_id"] if selected_registration else None
            members.append(_member(SCANNER_CLASS, "page", f"page:{row['run_id']}:{int(row['revision'])}:{int(page['ordinal'])}",
                pp, row["created_at"]))
            for registration in page_registrations:
                rp = {"schema_version": registration["schema_version"],
                    "evidence_id": registration["evidence_id"], "owning_class": SCANNER_CLASS,
                    "owning_member_key": f"page:{row['run_id']}:{int(row['revision'])}:{int(page['ordinal'])}",
                    "run_id": registration["run_id"], "run_revision": registration["run_revision"],
                    "opaque_object_id_digest": hashlib.sha256(registration["evidence_ref"].encode()).hexdigest(),
                    "raw_sha256": registration["sha256"], "size": registration["byte_size"],
                    "kind": registration["kind"], "registered_at": _wire(registration["registered_at"])}
                members.append(_member(SCANNER_CLASS, "evidence_registration",
                    f"evidence_registration:{registration['evidence_id']}", rp,
                    registration["registered_at"], raw_sha256=registration["sha256"],
                    byte_size=registration["byte_size"], evidence_id=registration["evidence_id"]))
    for event in connection.execute(sa.select(expected_run_events).join(expected_runs,
            expected_runs.c.expected_run_id == expected_run_events.c.expected_run_id)
            .join(collection_schedules, sa.and_(collection_schedules.c.schedule_id == expected_runs.c.schedule_id,
                collection_schedules.c.revision == expected_runs.c.schedule_revision))
            .where(collection_schedules.c.source_family == family,
                collection_schedules.c.source_account_id == account,
                expected_runs.c.scope_key == scope_key)
            .order_by(expected_run_events.c.expected_run_id, expected_run_events.c.revision)).mappings():
        ep = {name: _wire(event[name]) for name in ("event_id", "expected_run_id", "revision",
            "state", "run_id", "run_revision", "effective_at", "recorded_at")}
        members.append(_member(SCANNER_CLASS, "expected_transition",
            f"expected_transition:{event['expected_run_id']}:{int(event['revision'])}", ep,
            event["recorded_at"]))
        watermark = max(watermark, int(event["revision"]))
    members.sort(key=lambda item: (item["record_kind"].encode(), item["stable_key"].encode()))
    complete = bool(schedules and expected)
    return members, complete, _wire(oldest), watermark


def source_snapshot(connection, scope: tuple[str, str, str], class_ids: list[str], deployment_id: str) -> dict:
    if not deployment_id or len(scope) != 3 or any(not isinstance(item, str) or not item for item in scope):
        raise ValueError("exact deployment and source tuple are required")
    required_classes = {class_id for class_id, _ in CLASSES}
    if (not isinstance(class_ids, list) or set(class_ids) != required_classes
            or len(class_ids) != len(required_classes)):
        raise ValueError("class_ids must contain each reviewed class exactly once")
    generation = os.environ.get("UVM_G7_STORAGE_GENERATION")
    epoch_text = os.environ.get("UVM_G7_RECOVERY_EPOCH")
    volume_set_digest = os.environ.get("UVM_G7_VOLUME_SET_DIGEST")
    try:
        generation = str(UUID(generation)) if generation else None
    except (ValueError, TypeError, AttributeError):
        generation = None
    trust_context_valid = bool(generation and epoch_text and epoch_text.isdigit()
        and volume_set_digest and re.fullmatch(r"[0-9a-f]{64}", volume_set_digest))
    class_watermarks: dict[str, int] = {}
    result = {"schema_version": 1, "deployment_id": deployment_id,
        "scope": {"source_family": scope[0], "source_account_id": scope[1], "scope_key": scope[2]},
        "storage_generation": generation,
        "classes": []}
    for class_id in sorted(class_ids):
        if class_id == SOURCE_CLASS:
            members, complete, oldest, watermark = _source_members(connection, scope)
            reason = None if complete else "evidence_missing"
        elif class_id == SCANNER_CLASS:
            members, complete, oldest, watermark = _scanner_members(connection, scope)
            reason = None
        else:
            # Audit event export has separate deployment-bound authority and
            # is deliberately supplied by its independent exporter adapter.
            members, complete, oldest, watermark, reason = [], False, None, 0, "audit_scope_incomplete"
        if not trust_context_valid:
            complete = False
            reason = "trust_config_mismatch"
        class_watermarks[class_id] = watermark
        result["classes"].append({"class_id": class_id, "complete": complete,
            "coverage_reason": reason,
            "members": [{"record_kind": item["record_kind"],
                "stable_key": item["stable_key"], "record_sha256": item["record_sha256"],
                "raw_sha256": item["raw_sha256"], "byte_size": item["byte_size"],
                "evidence_id": item["evidence_id"], "observed_at": item["retained_at"]}
                for item in members]})
    # Independent namespaces retain their own monotonic value; the vector is
    # read from one repeatable-read database snapshot and cannot imply cross-
    # table transaction ordering that these legacy tables do not store.
    result["source_watermark"] = class_watermarks
    return result
