"""Operator CLI for importing an already retained UVM run into DefectDojo CE.

The CLI deliberately accepts references to retained data, never Finding
associations, Test IDs, or an authorisation verdict from its request file.
"""
from __future__ import annotations

import argparse
import dataclasses
import hashlib
import json
import os
import re
import stat
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import sqlalchemy as sa
import urllib.error
import urllib.request

from uvm.engine.api_codec import (ScanContextV1, canonical_context_key,
    build_import_request, build_reimport_request)
from uvm.engine.ce_lifecycle import CEImportLifecycle
from uvm.engine.ce_read_client import CEReadClient, CEReadError, RawResponse
from uvm.engine.context import (
    CEContextObservationV1, CEContextRegistrationV1, CEObservedResponseV1,
    verify_ce_context,
)
from uvm.engine.occurrence_readback import build_occurrence_finding_links
from uvm.engine.readback_builder import ReadbackError
from uvm.engine.manifest import (
    InventorySealV1, ManifestBindingRegistry, PayloadRecordV1,
    RowDispositionV1, build_occurrence_manifest,
)
from uvm.engine.operation import EngineImportOperationV1, REQUEST_IMPORT, REQUEST_REIMPORT
from uvm.persistence.ce_context_artifacts import CEContextArtifactStore, CEContextArtifactError
from uvm.persistence.ce_context_store import (
    CEContextConfigurationNotFound, CEContextStore,
)
from uvm.persistence.ce_deployment_config import load_ce_deployment_config
from uvm.persistence.engine_operation_store import (
    EngineOperationStore, OperationConflictError, OperationNotFoundError,
    OperationReadError, OperationStoreError,
)
from uvm.identity.model import IdentityResolutionV1
from uvm.persistence.identity_resolution_store import IdentityResolutionTemporalUnverified
from uvm.persistence.ingestion_schema import collection_runs
from uvm.persistence.run_snapshot import RunSnapshotStore

UTC = timezone.utc
_REQ_KEYS = {"schema_version", "operation_id", "source_family", "source_account_id",
             "scope_key", "run_id", "context_alias", "request_kind",
             "prior_operation_id", "prepared_artifact_ref"}
_CONFIG_KEYS = {"schema_version", "service_principal_id", "operator_policy",
                "ce_deployment_config_path", "ce_token_file", "artifact_root",
                "contexts", "do_not_reactivate"}
_REF = re.compile(r"\Ace-context-sha256:([0-9a-f]{64})\Z")

class CLIError(ValueError):
    pass


def _pairs(pairs):
    out = {}
    for key, value in pairs:
        if key in out:
            raise CLIError("duplicate JSON object key")
        out[key] = value
    return out


def _json_bytes(data: Any) -> bytes:
    return json.dumps(data, sort_keys=True, ensure_ascii=False,
                      separators=(",", ":"), allow_nan=False).encode("utf-8")


def _read_secure(path: str, *, max_bytes: int = 1_000_000) -> bytes:
    if not os.path.isabs(path):
        raise CLIError("configured file paths must be absolute")
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    try:
        before = os.fstat(fd)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.geteuid()
                or stat.S_IMODE(before.st_mode) != 0o600 or before.st_size > max_bytes):
            raise CLIError("configured files must be euid-owned regular 0600 files within size limits")
        chunks, remaining = [], before.st_size
        while remaining:
            chunk = os.read(fd, min(65536, remaining))
            if not chunk:
                raise CLIError("configured file changed during read")
            chunks.append(chunk)
            remaining -= len(chunk)
        after = os.fstat(fd)
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
                after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
            raise CLIError("configured file changed during read")
        return b"".join(chunks)
    finally:
        os.close(fd)


def _load_json(path: str) -> tuple[dict, bytes]:
    raw = _read_secure(path)
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs,
                           parse_constant=lambda value: (_ for _ in ()).throw(CLIError("non-finite JSON number")))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CLIError("file must be valid UTF-8 JSON") from exc
    if type(value) is not dict:
        raise CLIError("file must contain a JSON object")
    return value, raw


def _load_request(path: str) -> dict:
    request, _ = _load_json(os.path.abspath(path))
    if set(request) != _REQ_KEYS or request.get("schema_version") != 1 or type(request.get("schema_version")) is not int:
        raise CLIError("request must match the exact Request V1 shape")
    for key in ("source_family", "source_account_id", "scope_key", "run_id", "context_alias"):
        if type(request.get(key)) is not str or not request[key]:
            raise CLIError(f"request {key} must be a non-empty string")
    try:
        if str(uuid.UUID(request["operation_id"])) != request["operation_id"]:
            raise ValueError()
        if request["prior_operation_id"] is not None and str(uuid.UUID(request["prior_operation_id"])) != request["prior_operation_id"]:
            raise ValueError()
    except (ValueError, TypeError, AttributeError):
        raise CLIError("operation IDs must be canonical UUIDs") from None
    if request["request_kind"] not in ("first_import", "reimport"):
        raise CLIError("request_kind must be first_import or reimport")
    if (request["request_kind"] == "first_import") != (request["prior_operation_id"] is None):
        raise CLIError("prior_operation_id is required only for reimport")
    if not isinstance(request["prepared_artifact_ref"], str) or not _REF.fullmatch(request["prepared_artifact_ref"]):
        raise CLIError("prepared_artifact_ref must be a content-addressed artifact reference")
    return request


def _load_config(path: str) -> tuple[dict, bytes]:
    config, raw = _load_json(path)
    if set(config) != _CONFIG_KEYS or type(config.get("schema_version")) is not int or config["schema_version"] != 1:
        raise CLIError("operator configuration must match the exact version 1 shape")
    if not isinstance(config["service_principal_id"], str) or not config["service_principal_id"]:
        raise CLIError("service_principal_id is required")
    policy = config["operator_policy"]
    if type(policy) is not dict or set(policy) != {"schema_version", "revision", "grants"}:
        raise CLIError("operator_policy shape is invalid")
    if policy["schema_version"] != 1 or type(policy["revision"]) is not int or policy["revision"] < 1:
        raise CLIError("operator policy version/revision is invalid")
    if type(policy["grants"]) is not list:
        raise CLIError("operator policy grants must be a list")
    for grant in policy["grants"]:
        if type(grant) is not dict or set(grant) != {"action", "source_family", "source_account_id", "scope_key", "context_alias"}:
            raise CLIError("operator grant must name one complete action and scope tuple")
        if grant["action"] not in ("submit", "show") or any(type(grant[k]) is not str or not grant[k] for k in grant):
            raise CLIError("operator grant values are invalid")
    if type(config["do_not_reactivate"]) is not bool:
        raise CLIError("do_not_reactivate must be explicitly boolean")
    if type(config["contexts"]) is not dict:
        raise CLIError("contexts must be an alias mapping")
    _read_secure(config["ce_token_file"], max_bytes=16384)
    return config, raw


def _authorise(config: dict, action: str, request: dict) -> dict:
    tuple_values = {key: request[key] for key in
                    ("source_family", "source_account_id", "scope_key", "context_alias")}
    for grant in config["operator_policy"]["grants"]:
        if grant["action"] == action and all(grant[k] == tuple_values[k] for k in tuple_values):
            return tuple_values
    raise CLIError("operator policy denied action for this exact source/account/scope/context")


def _iso(value):
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _snapshot_digest(snapshot) -> str:
    rows = []
    for row in snapshot.retained_run.rows:
        obs = row.observation
        rows.append({"retention_order": row.retention_order, "ingest_outcome": row.ingest_outcome,
                     "observation": {field.name: getattr(obs, field.name) for field in dataclasses.fields(obs)}})
    resolutions = []
    for record in snapshot.resolutions:
        histories = []
        for resolution in record.history:
            histories.append({field.name: getattr(resolution, field.name)
                              for field in dataclasses.fields(resolution)})
        resolutions.append({"observation_id": record.observation_id,
                            "status": record.status,
                            "temporal_statuses": [{field.name: getattr(x, field.name) for field in dataclasses.fields(x)}
                                                 for x in record.statuses],
                            "history": histories})
    def default(value):
        if isinstance(value, datetime): return _iso(value)
        if dataclasses.is_dataclass(value): return {field.name: getattr(value, field.name) for field in dataclasses.fields(value)}
        if hasattr(value, "items"): return dict(value)
        if isinstance(value, tuple): return list(value)
        raise TypeError(type(value).__name__)
    return hashlib.sha256(json.dumps({"source_account_id": snapshot.source_account_id,
        "run_id": snapshot.run_id, "rows": rows, "resolutions": resolutions},
        sort_keys=True, ensure_ascii=False, separators=(",", ":"), default=default,
        allow_nan=False).encode()).hexdigest()


def _finding(obs, occurrence_id: str) -> dict:
    native = obs.native_id_value
    if not native or not obs.native_id_scheme or not obs.native_id_authority:
        raise CLIError("verified occurrence lacks a complete native vulnerability identifier")
    severity_map = {"critical": "Critical", "high": "High", "medium": "Medium",
                    "low": "Low", "info": "Info", "informational": "Info"}
    rating = (obs.source_rating or "").strip().lower()
    severity = severity_map.get(rating)
    if rating in {"5", "4", "3", "2", "1"}:
        severity = {"5": "Critical", "4": "High", "3": "Medium", "2": "Low", "1": "Info"}[rating]
    if severity is None:
        raise CLIError("supported retained-run encoder requires an explicit supported source severity")
    record_id = f"uvm:{obs.source_family}:occurrence:{occurrence_id}"
    endpoints = [{"host": obs.asset_locator}] if obs.asset_locator else []
    return {"component_name": obs.component_locator or "unknown component",
            "component_version": "unknown",
            "description": f"{obs.source_family} {obs.native_id_scheme} {native} in {obs.native_id_authority}",
            "endpoints": endpoints,
            "severity": severity,
            "title": f"{obs.source_family} {native}",
            "unique_id_from_tool": record_id,
            "vuln_id_from_tool": native}


def _build_retained(snapshot, request, context_key):
    from uvm.engine.manifest import DISPOSITION_BLOCKED, DISPOSITION_INCLUDED
    retained = snapshot.retained_run
    by_resolution = {item.observation_id: item for item in snapshot.resolutions}
    dispositions, records, histories, row_kinds, findings = [], [], {}, {}, []
    seen_records = set()
    for row in retained.rows:
        obs = row.observation
        history_record = by_resolution.get(obs.observation_id)
        raw_history = tuple(history_record.history) if history_record else ()
        statuses = tuple(history_record.statuses) if history_record else ()
        history = tuple(item if isinstance(item, IdentityResolutionV1) else IdentityResolutionV1(
            schema_version=1, resolution_id=item.resolution_id, revision=item.revision,
            observation_id=item.observation_id, rule_id=item.rule_id,
            rule_version=item.rule_version, matching_inputs=dict(item.matching_inputs),
            candidate_workload_ids=tuple(item.candidate_workload_ids), outcome=item.outcome,
            evaluated_at=item.evaluated_at, group_id=item.group_id,
            workload_id=item.workload_id, incarnation_id=item.incarnation_id,
            exposure_id=item.exposure_id, occurrence_id=item.occurrence_id,
            candidate_explanations=tuple(dict(value) for value in item.candidate_explanations),
            reason=item.reason, supersedes_resolution_id=item.supersedes_resolution_id)
            for item in raw_history)
        head = history[-1] if history else None
        verified = bool(head and statuses and statuses[-1].status == "verified"
                        and head.outcome in ("matched", "new")
                        and head.occurrence_id == obs.occurrence_id)
        if verified and row.ingest_outcome == "created":
            finding = _finding(obs, head.occurrence_id)
            record_id = finding["unique_id_from_tool"]
            if record_id in seen_records:
                raise CLIError("multiple retained rows resolve to one Generic Findings identity")
            seen_records.add(record_id)
            findings.append(finding)
            records.append(PayloadRecordV1(1, record_id, (obs.observation_id,)))
            histories[obs.observation_id] = history
            dispositions.append(RowDispositionV1(1, obs.observation_id,
                obs.source_record_ordinal, obs.raw_evidence_sha256, DISPOSITION_INCLUDED,
                occurrence_id=head.occurrence_id, resolution_id=head.resolution_id,
                resolution_revision=head.revision))
            row_kinds[obs.observation_id] = "candidate_positive"
        else:
            dispositions.append(RowDispositionV1(1, obs.observation_id,
                obs.source_record_ordinal, obs.raw_evidence_sha256, DISPOSITION_BLOCKED,
                blocked_reason="not a temporally verified actionable identity"))
            row_kinds[obs.observation_id] = "unknown"
            if history:
                histories[obs.observation_id] = history
    if not findings:
        raise CLIError("retained run has no temporally verified actionable observations")
    payload = _json_bytes({"findings": findings})
    snapshot_digest = _snapshot_digest(snapshot)
    seal = InventorySealV1(1, retained.rows[0].observation.source_family,
        retained.source_account_id, retained.run_id,
        max(row.retention_order for row in retained.rows), len(retained.rows),
        sum(row.ingest_outcome == "conflict" for row in retained.rows),
        f"retained-snapshot-sha256:{snapshot_digest}")
    return payload, seal, histories, dispositions, records, row_kinds, snapshot_digest


def _token(config):
    token = _read_secure(config["ce_token_file"], max_bytes=16384).decode("utf-8").strip()
    if not token or "\n" in token or "\r" in token:
        raise CLIError("CE token file is empty or malformed")
    return token


def _transports(base_url: str, token: str):
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            return None
    opener = urllib.request.build_opener(NoRedirect)
    def transport(method, url, headers, timeout, *, follow_redirects):
        if follow_redirects:
            raise CLIError("CE transport does not follow redirects")
        req = urllib.request.Request(url, method=method, headers=dict(headers))
        try:
            response = opener.open(req, timeout=timeout)
        except urllib.error.HTTPError as exc:
            body = exc.read()
            return RawResponse(exc.code, dict(exc.headers.items()), body, exc.geturl())
        except (urllib.error.URLError, TimeoutError) as exc:
            raise TimeoutError("CE API transport outcome is uncertain") from exc
        with response:
            return RawResponse(response.status, dict(response.headers.items()),
                               response.read(), response.geturl())
    def read_transport(method, url, headers, timeout, *, follow_redirects):
        if method != "GET":
            raise CLIError("CE read path only permits GET")
        return transport(method, url, headers, timeout, follow_redirects=follow_redirects)
    def write_transport(request):
        headers = dict(request.headers)
        headers["Authorization"] = f"Token {token}"
        req = urllib.request.Request(base_url.rstrip("/") + request.path,
            data=request.body, method=request.method, headers=headers)
        try:
            response = opener.open(req, timeout=30.0)
        except urllib.error.HTTPError as exc:
            return RawResponse(exc.code, dict(exc.headers.items()), exc.read(), exc.geturl())
        except (urllib.error.URLError, TimeoutError) as exc:
            raise TimeoutError("CE POST outcome is uncertain") from exc
        with response:
            return RawResponse(response.status, dict(response.headers.items()),
                               response.read(), response.geturl())
    class Closeable:
        def close(self):
            return None
    return Closeable(), CEReadClient(base_url, read_transport, token=token), write_transport

def _assert_do_not_reactivate(body: bytes, expected: bool) -> None:
    values = re.findall(rb'name="do_not_reactivate"\r\n\r\n(true|false)\r\n', body)
    wanted = b"true" if expected else b"false"
    if values != [wanted]:
        raise CLIError("reimport wire request does not contain the configured do_not_reactivate value")


def _operation_state(engine, operation_id: str):
    from uvm.persistence.engine_operation_schema import engine_operation_states
    with engine.connect() as connection:
        row = connection.execute(sa.select(
            engine_operation_states.c.status,
            engine_operation_states.c.post_issued,
        ).where(engine_operation_states.c.operation_id == operation_id)).mappings().one_or_none()
    return dict(row) if row is not None else None


def _operation_exists(engine, operation_id: str) -> bool:
    from uvm.persistence.engine_operation_schema import engine_operation_states
    with engine.connect() as connection:
        return connection.execute(sa.select(engine_operation_states.c.operation_id).where(
            engine_operation_states.c.operation_id == operation_id
        )).scalar_one_or_none() is not None


def _dependency_result(operation_id: str, request: dict, state, exc: Exception) -> dict:
    current = state or {"status": "not_reserved", "post_issued": False}
    return {"schema_version": 1, "operation_id": operation_id,
        "status": "dependency_error", "operation_status": current["status"],
        "post_issued": bool(current["post_issued"]),
        "source_family": request["source_family"],
        "source_account_id": request["source_account_id"],
        "scope_key": request["scope_key"], "run_id": request["run_id"],
        "dependency": {"kind": "ce_transport_or_readback",
                        "error_type": type(exc).__name__},
        "occurrence_links": []}


def _result(store: EngineOperationStore, operation_id: str, request: dict) -> dict:
    record = store.load(operation_id)
    op = record.operation
    links = store.read_occurrence_links(operation_id)
    if op.status == "settled":
        try:
            readback = store.read_settled_readback(operation_id)
            expected = build_occurrence_finding_links(record.manifest, readback)
            expected_rows = sorted((link.occurrence_id, link.finding_id,
                link.endpoint_id, link.component_name, link.component_version,
                readback.test_id, op.mapping_revision) for link in expected)
            retained_rows = sorted((link.occurrence_id, link.finding_id,
                link.endpoint_id, link.component_name, link.component_version,
                link.test_id, link.mapping_revision) for link in links)
            if not expected_rows or retained_rows != expected_rows:
                raise OperationReadError("settled read-back associations differ from durable occurrence links")
        except (OperationReadError, OperationStoreError, OperationConflictError,
                CEContextArtifactError, ReadbackError, CEReadError) as exc:
            return {"schema_version": 1, "operation_id": operation_id,
                "status": "dependency_error", "operation_status": "settled",
                "source_family": request["source_family"],
                "source_account_id": request["source_account_id"],
                "scope_key": request["scope_key"], "run_id": op.source_run_id,
                "manifest_id": record.manifest.manifest_id,
                "bound_test_id": op.bound_test_id,
                "mapping_revision": op.mapping_revision,
                "dependency": {"kind": "settlement_readback_unavailable",
                               "error_type": type(exc).__name__},
                "occurrence_links": []}
    result = {"schema_version": 1, "operation_id": operation_id,
        "status": op.status, "source_family": request["source_family"],
        "source_account_id": request["source_account_id"], "scope_key": request["scope_key"],
        "run_id": op.source_run_id, "manifest_id": record.manifest.manifest_id,
        "bound_test_id": op.bound_test_id, "mapping_revision": op.mapping_revision,
        "proof_flags": {"run_completeness": record.manifest.run_completeness_status,
                        "run_currency": record.manifest.run_currency_status,
                        "run_coverage": record.manifest.run_coverage_status,
                        "payload_membership": record.manifest.payload_membership_status},
        "occurrence_links": [{"occurrence_id": link.occurrence_id,
            "finding_id": link.finding_id, "endpoint_id": link.endpoint_id,
            "test_id": link.test_id} for link in links]}
    if op.status in ("pending", "uncertain", "quarantined"):
        state = _operation_state(store.engine, operation_id)
        result["operation_status"] = op.status
        result["post_issued"] = bool(state and state["post_issued"])
    return result


def _engine():
    url = os.environ.get("UVM_DB_URL")
    if not url:
        raise CLIError("UVM_DB_URL is required")
    return sa.create_engine(url, pool_pre_ping=True)


def _read_binding(store, op_id, artifacts):
    saved = store.read_cli_request_binding(op_id)
    _validate_binding_artifacts(saved, artifacts)
    return saved


def _validate_binding_artifacts(saved, artifacts):
    binding = saved["binding"]
    try:
        for key in ("snapshot_ref", "prepared_ref", "payload_ref", "wire_request_ref"):
            data = artifacts.get(binding[key], binding[key + "_sha256"])
            expected = binding[key + "_sha256"]
            if hashlib.sha256(data).hexdigest() != expected:
                raise CLIError("retained CLI artifact digest mismatch")
    except (KeyError, TypeError) as exc:
        raise OperationReadError("retained CLI artifact binding is invalid") from exc


def _submit(request_path: str, config_path: str) -> tuple[int, dict]:
    request = _load_request(request_path)
    config, config_raw = _load_config(config_path)
    scope = _authorise(config, "submit", request)
    contexts = config["contexts"]
    if request["context_alias"] not in contexts:
        raise CLIError("context alias has no trusted operator configuration")
    context_config = contexts[request["context_alias"]]
    required_context = {"product_id", "engagement_id", "product_name", "engagement_name", "environment", "product_type_name"}
    if type(context_config) is not dict or set(context_config) != required_context:
        raise CLIError("named CE context configuration has an invalid shape")
    db = _engine()
    root = config["artifact_root"]
    Path(root).mkdir(parents=True, exist_ok=True, mode=0o700)
    artifacts = CEContextArtifactStore(root)
    context_store = CEContextStore(db, artifacts)
    operations = EngineOperationStore(db, context_store)
    try:
        try:
            saved = operations.read_cli_request_binding(request["operation_id"])
        except OperationNotFoundError:
            saved = None
        except OperationReadError as exc:
            # A corrupt canonical binding cannot establish who may inspect the
            # operation. Do not recover operation state in the outer handler.
            raise CLIError("retained operation authority unavailable") from exc
        if saved is None and _operation_exists(db, request["operation_id"]):
            raise CLIError("retained operation authority unavailable")
        if saved is not None:
            try:
                canonical_request = saved["request"]
                _authorise(config, "submit", canonical_request)
            except (KeyError, TypeError) as exc:
                raise CLIError("retained operation authority unavailable") from exc
            if canonical_request != request:
                raise CLIError("operation_id conflicts with its retained canonical request")
            if type(saved.get("binding")) is not dict:
                raise CLIError("retained operation authority unavailable")
            if (saved["binding"].get("operator_config_sha256") != hashlib.sha256(config_raw).hexdigest()
                    or saved["binding"].get("operator_policy_revision") != config["operator_policy"]["revision"]
                    or saved["binding"].get("do_not_reactivate") != config["do_not_reactivate"]):
                raise CLIError("operation_id replay conflicts with retained operator configuration")
            try:
                _validate_binding_artifacts(saved, artifacts)
                operations.load(request["operation_id"])
                result = _result(operations, request["operation_id"], canonical_request)
                return _exit_for_status(result["status"]), result
            except (CEReadError, ReadbackError, OperationReadError,
                    OperationStoreError, TimeoutError, urllib.error.URLError,
                    OperationConflictError, CEContextArtifactError, CLIError) as exc:
                state = _operation_state(operations.engine, request["operation_id"])
                return 4, _dependency_result(request["operation_id"], canonical_request, state, exc)

        ce_snapshot = load_ce_deployment_config(config["ce_deployment_config_path"])
        if not os.environ.get("UVM_DB_URL"):
            raise CLIError("UVM_DB_URL is required")
        run_result = db.connect()
        try:
            row = run_result.execute(sa.select(collection_runs).where(
                collection_runs.c.run_id == request["run_id"]).order_by(
                    collection_runs.c.revision.desc())).mappings().first()
            if row is None:
                raise CLIError("retained collection run was not found")
            authoritative = {"source_family": row["source_family"],
                "source_account_id": row["source_account_id"], "scope_key": row["scope_key"]}
            if any(authoritative[k] != request[k] for k in authoritative):
                raise CLIError("request source tuple differs from retained collection metadata")
        finally:
            run_result.close()
        snapshot = RunSnapshotStore(db).read(request["source_account_id"], request["run_id"])
        if not snapshot.retained_run.rows:
            raise CLIError("retained run is empty")
        if any(item.observation.source_family != request["source_family"] for item in snapshot.retained_run.rows):
            raise CLIError("retained run contains a foreign source family")
        payload, seal, histories, dispositions, payload_records, row_kinds, snapshot_digest = _build_retained(
            snapshot, request, "")
        prepared = artifacts.get(request["prepared_artifact_ref"], _REF.fullmatch(request["prepared_artifact_ref"]).group(1))
        if prepared != payload:
            raise CLIError("prepared Generic Findings artifact differs from trusted retained-run encoding")
        prepared_digest = hashlib.sha256(prepared).hexdigest()
        payload_ref, payload_digest = artifacts.put(payload)
        snapshot_bytes = _json_bytes({"source_family": request["source_family"],
            "source_account_id": request["source_account_id"], "scope_key": request["scope_key"],
            "run_id": request["run_id"], "snapshot_sha256": snapshot_digest})
        snapshot_ref, stored_snapshot_digest = artifacts.put(snapshot_bytes)
        operation_id = request["operation_id"]
        context = ScanContextV1(context_config["product_name"], context_config["engagement_name"],
            context_config["environment"], context_config["product_type_name"])
        context_key = canonical_context_key(context)
        registration_id = verification_id = None
        test_id = None
        prior_mapping_revision = None
        if request["request_kind"] == "reimport":
            prior = operations.load(request["prior_operation_id"])
            prior_binding = operations.read_cli_request_binding(request["prior_operation_id"])["binding"]
            prior_op = prior.operation
            if (prior_op.status != "settled" or prior_op.context_key != context_key
                    or prior_op.bound_test_id is None
                    or any(prior_binding.get(key) != value for key, value in {
                        "source_family": request["source_family"],
                        "source_account_id": request["source_account_id"],
                        "scope_key": request["scope_key"],
                        "context_alias": request["context_alias"],
                    }.items())):
                raise CLIError("prior operation is not a settled same-context mapping to reimport")
            test_id = prior_op.bound_test_id
            prior_mapping_revision = prior_op.mapping_revision
            registration_id, verification_id = prior.registration_id, prior.verification_id
        op = EngineImportOperationV1(1, operation_id, 1, context_key, request["run_id"],
            "Generic Findings Import", payload_digest, "uvm-retained-generic-v1",
            ce_snapshot.configured.ce_release,
            REQUEST_IMPORT if request["request_kind"] == "first_import" else REQUEST_REIMPORT,
            datetime.now(UTC), False, "pending", test_id=test_id,
            prior_mapping_revision=prior_mapping_revision)
        manifest = build_occurrence_manifest(operation=op, retained=snapshot.retained_run,
            seal=seal, resolutions=histories, dispositions=dispositions,
            payload_records=payload_records, row_kinds=row_kinds)
        if request["request_kind"] == "first_import":
            wire_request = build_import_request(op, payload, context,
                filename=f"uvm-{request['run_id']}.json",
                deduplication_execution_mode="sync")
        else:
            wire_request = build_reimport_request(op, payload,
                filename=f"uvm-{request['run_id']}.json",
                deduplication_execution_mode="sync",
                do_not_reactivate=config["do_not_reactivate"])
        if request["request_kind"] == "reimport":
            _assert_do_not_reactivate(wire_request.body, config["do_not_reactivate"])
        wire_ref, wire_digest = artifacts.put(wire_request.body)
        manifest_registry = ManifestBindingRegistry()
        manifest_registry.bind(manifest)
        token = _token(config)
        http_client, read_client, write_transport = _transports(ce_snapshot.configured.ce_base_url, token)
        try:
            if request["request_kind"] == "first_import":
                try:
                    current_configuration = context_store.read(
                        ce_snapshot.configured.deployment_key)
                except CEContextConfigurationNotFound:
                    current_configuration = context_store.provision(ce_snapshot, revision=1)
                if current_configuration.snapshot.config_sha256 != ce_snapshot.config_sha256:
                    raise CLIError(
                        "first import configuration differs from the retained deployment revision")
                try:
                    registration, observation = verify_ce_context(ce_snapshot.configured, read_client,
                        context_key=context_key, product_id=context_config["product_id"],
                        engagement_id=context_config["engagement_id"])
                except CEReadError as exc:
                    return 4, _dependency_result(operation_id, request, None, exc)
                registered = context_store.register_verified_context(registration, observation,
                    configuration_revision=current_configuration.revision)
                registration_id, verification_id = registered.registration_id, registered.verification_id
            binding = {"source_family": request["source_family"],
                "source_account_id": request["source_account_id"], "scope_key": request["scope_key"],
                "context_alias": request["context_alias"], "action": "submit",
                "operator_principal_id": config["service_principal_id"],
                "operator_policy_revision": config["operator_policy"]["revision"],
                "operator_config_sha256": hashlib.sha256(config_raw).hexdigest(),
                "ce_config_sha256": ce_snapshot.config_sha256,
                "do_not_reactivate": config["do_not_reactivate"],
                "snapshot_ref": snapshot_ref, "snapshot_ref_sha256": stored_snapshot_digest,
                "prepared_ref": request["prepared_artifact_ref"], "prepared_ref_sha256": prepared_digest,
                "payload_ref": payload_ref, "payload_ref_sha256": payload_digest,
                "wire_request_ref": wire_ref, "wire_request_ref_sha256": wire_digest,
                "wire_request_method": wire_request.method, "wire_request_path": wire_request.path,
                "manifest_sha256": manifest.manifest_sha256,
                "prior_operation_id": request["prior_operation_id"],
                "context_key": context_key}
            cli_request_binding = {"request": request, "binding": binding}
            lifecycle = CEImportLifecycle(operations)
            def retained_write_transport(encoded_request):
                if (encoded_request.method != wire_request.method
                        or encoded_request.path != wire_request.path
                        or hashlib.sha256(encoded_request.body).hexdigest() != wire_digest):
                    raise CLIError("lifecycle request bytes differ from the retained pre-POST request")
                if request["request_kind"] == "reimport":
                    _assert_do_not_reactivate(encoded_request.body, config["do_not_reactivate"])
                return write_transport(encoded_request)
            common = {"filename": f"uvm-{request['run_id']}.json",
                "registration_id": registration_id, "verification_id": verification_id,
                "read_client": read_client, "write_transport": retained_write_transport,
                "manifest_registry": manifest_registry,
                "post_evidence_ref": f"ce-cli://{operation_id}/post",
                "uncertain_evidence_ref": f"ce-cli://{operation_id}/uncertain",
                "readback_evidence_ref": f"ce-cli://{operation_id}/readback",
                "cli_request_binding": cli_request_binding}
            try:
                if request["request_kind"] == "first_import":
                    lifecycle.first_import(op, manifest, payload, context, **common)
                else:
                    common["engagement_id"] = context_config["engagement_id"]
                    lifecycle.reimport(op, manifest, payload,
                        do_not_reactivate=config["do_not_reactivate"], **common)
            except (CEReadError, ReadbackError, OperationReadError,
                    OperationStoreError, TimeoutError, urllib.error.URLError,
                    OperationConflictError, CEContextArtifactError, ValueError) as exc:
                try:
                    retained = operations.read_cli_request_binding(operation_id)
                except (OperationNotFoundError, OperationReadError):
                    raise
                if retained["request"] != request:
                    raise
                _authorise(config, "submit", retained["request"])
                state = _operation_state(operations.engine, operation_id)
                if isinstance(exc, (CEReadError, ReadbackError, OperationReadError,
                                    OperationStoreError, TimeoutError, urllib.error.URLError)) or (
                        state is not None and state["post_issued"]):
                    return 4, _dependency_result(operation_id, request, state, exc)
                raise
        finally:
            http_client.close()
        result = _result(operations, operation_id, request)
        return _exit_for_status(result["status"]), result
    finally:
        artifacts.close()
        db.dispose()


def _exit_for_status(status: str) -> int:
    return 0 if status == "settled" else 3 if status in ("pending", "quarantined", "conflict") else 4


def _show_exit_for_status(status: str) -> int:
    return 4 if status == "dependency_error" else 0


def _show(operation_id: str, config_path: str) -> tuple[int, dict]:
    config, config_raw = _load_config(config_path)
    db = _engine()
    artifacts = CEContextArtifactStore(config["artifact_root"])
    operations = EngineOperationStore(db, CEContextStore(db, artifacts))
    try:
        # The canonical request is durable in the operation-binding row. Use
        # it to authorise before opening any referenced artifacts or recovering
        # operation state, so a denied caller cannot learn artifact/state data.
        canonical = operations.read_cli_request_binding(operation_id)
        request = canonical["request"]
        _authorise(config, "show", request)
        try:
            saved = _read_binding(operations, operation_id, artifacts)
            if saved != canonical:
                raise OperationReadError("canonical request binding changed during show")
            result = _result(operations, operation_id, request)
            # A readable retained outcome is a successful show regardless of
            # lifecycle status. Dependency errors remain nonzero.
            return _show_exit_for_status(result["status"]), result
        except (CEReadError, ReadbackError, OperationReadError, OperationStoreError,
                TimeoutError, urllib.error.URLError, CEContextArtifactError) as exc:
            state = _operation_state(operations.engine, operation_id)
            return 4, _dependency_result(operation_id, request, state, exc)
    finally:
        artifacts.close()
        db.dispose()


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="python -m uvm.ingestion.ce_import")
    parser.add_argument("--config", required=True)
    sub = parser.add_subparsers(dest="command", required=True)
    submit = sub.add_parser("submit")
    submit.add_argument("--request", required=True)
    show = sub.add_parser("show")
    show.add_argument("--operation-id", required=True)
    args = parser.parse_args(argv)
    try:
        code, result = (_submit(args.request, args.config) if args.command == "submit"
                        else _show(args.operation_id, args.config))
        print(json.dumps(result, sort_keys=True, ensure_ascii=False, separators=(",", ":")))
        return code
    except (CEReadError, ReadbackError, OperationReadError, OperationStoreError,
            TimeoutError, urllib.error.URLError, CEContextArtifactError) as exc:
        if args.command == "show":
            # No authorised canonical request was established. Never inspect
            # or disclose foreign operation state from this error path.
            print(json.dumps({"error": "show denied or retained request unavailable",
                              "status": "denied_or_invalid"}, sort_keys=True), file=sys.stderr)
            return 2
        # Generic recovery has no proof that the caller is authorised for the
        # operation ID. Operation-specific recovery is performed only inside
        # paths that have first authorised the retained canonical request.
        print(json.dumps({"error": "operation dependency unavailable",
                          "status": "dependency_error",
                          "dependency": {"kind": "ce_transport_or_readback",
                                         "error_type": type(exc).__name__}},
                         sort_keys=True, ensure_ascii=False), file=sys.stderr)
        return 4
    except (CLIError, OperationConflictError, OperationNotFoundError,
            OSError, ValueError, CEContextArtifactError,
            sa.exc.SQLAlchemyError) as exc:
        print(json.dumps({"error": str(exc), "status": "denied_or_invalid"},
                         sort_keys=True, ensure_ascii=False), file=sys.stderr)
        return 2 if isinstance(exc, (CLIError, OperationConflictError, ValueError)) else 4

if __name__ == "__main__":
    raise SystemExit(main())
