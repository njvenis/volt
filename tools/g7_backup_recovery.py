#!/usr/bin/env python3
"""Host-side cold backup manifest verification and three-volume recovery tools.

Host credentials, signing keys and archive paths are read only from host-owned
arguments/files. The tool fails closed unless an independently signed fence and
queue-drain record proves that workers and effects are quiescent.
"""
from __future__ import annotations

import argparse
import base64
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import ssl
import sys
import tarfile
import urllib.request
import urllib.error
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from uvm.operations.backup_host import canonical_json, parse_utc, verify_signature


VOLUMES = {
    "postgres_cluster": "/var/lib/postgresql/data",
    "ce_media": "/app/media",
    "uvm_state": "/opt/uvm/state",
}
MANIFEST_FIELDS = {"schema_version", "deployment_id", "archive_id", "generation",
    "recovery_epoch", "capture_started_at", "consistency_point_at", "completed_at", "image_digest",
    "package_manifest_digest", "volumes", "settings_revision", "settings_digest",
    "host_policy_revision", "host_policy_digest", "controller_instance_id",
    "controller_sequence", "queue_inventory_digest", "outcome", "signature"}


class RecoveryError(RuntimeError):
    pass


def _run(argv: list[str], *, capture: bool = True) -> str:
    result = subprocess.run(argv, check=True, text=True,
        stdout=subprocess.PIPE if capture else None,
        stderr=subprocess.PIPE if capture else None)
    return result.stdout.strip() if capture else ""


def _sha(path: Path) -> tuple[str, int]:
    hasher, size = hashlib.sha256(), 0
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            size += len(chunk)
            hasher.update(chunk)
    return hasher.hexdigest(), size


def _fsync_path(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _validate_tar(path: Path) -> None:
    try:
        with tarfile.open(path, "r:gz") as archive:
            seen: set[str] = set()
            for item in archive.getmembers():
                member_path = Path(item.name)
                if (member_path.is_absolute() or ".." in member_path.parts
                        or not (item.isdir() or item.isfile())):
                    raise RecoveryError("archive member contains an unsafe path or non-file entry")
                normalized = str(member_path)
                if normalized in seen:
                    raise RecoveryError("archive member contains a duplicate path")
                seen.add(normalized)
    except (tarfile.TarError, OSError) as exc:
        raise RecoveryError("archive member is corrupt") from exc


def _load_signed(path: Path, public_key: Path, expected_key_id: str) -> dict:
    try:
        value = json.loads(path.read_text(encoding="utf-8"),
            object_pairs_hook=_unique_pairs, parse_float=_reject_float,
            parse_constant=_reject_constant)
        _, _signature = verify_signature(value, str(public_key), expected_key_id)
        return value
    except Exception as exc:
        raise RecoveryError(f"signed host record rejected: {path.name}") from exc


def _unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON member")
        result[key] = value
    return result


def _reject_float(_value):
    raise ValueError("floating point JSON number")


def _reject_constant(_value):
    raise ValueError("non-finite JSON number")


def verify_drain_proof(path: Path, public_key: Path, *, deployment_id: str,
        container_id: str, image_digest: str, expected_key_id: str) -> dict:
    record = _load_signed(path, public_key, expected_key_id)
    required = {"schema_version", "deployment_id", "container_id", "image_digest",
        "ingress_fenced", "writers_paused", "queue_drained", "queue_inventory_digest",
        "queue_inventory", "network_fence_digest", "consistency_point_at",
        "shutdown_status", "forced_shutdown", "observed_at", "signature"}
    if set(record) != required or record["schema_version"] != 1:
        raise RecoveryError("capture fence proof has the wrong shape")
    if (record["deployment_id"] != deployment_id or record["container_id"] != container_id
            or record["image_digest"] != image_digest
            or record["ingress_fenced"] is not True or record["writers_paused"] is not True
            or record["queue_drained"] is not True or record["forced_shutdown"] is not False
            or type(record["shutdown_status"]) is not int or record["shutdown_status"] != 0
            or not isinstance(record["network_fence_digest"], str)
            or not re.fullmatch(r"sha256:[0-9a-f]{64}", record["network_fence_digest"])):
        raise RecoveryError("capture requires a matching ingress fence, stopped writers and proven queue drain")
    inventory = record["queue_inventory"]
    if (not isinstance(inventory, dict) or not isinstance(inventory.get("tasks"), list)
            or inventory.get("unresolved") != []):
        raise RecoveryError("queue inventory contains unresolved or malformed task state")
    if record["queue_inventory_digest"] != "sha256:" + hashlib.sha256(
            canonical_json(inventory)).hexdigest():
        raise RecoveryError("queue inventory digest does not match signed inventory")
    observed_at = parse_utc(record["observed_at"])
    consistency_point = parse_utc(record["consistency_point_at"])
    if observed_at < consistency_point:
        raise RecoveryError("drain proof was observed before the consistency point")
    return record


def _container_mounts(container: str) -> tuple[str, dict[str, str]]:
    inspected = json.loads(_run(["docker", "inspect", container]))[0]
    image = inspected["Image"]
    config = inspected.get("Config", {})
    image_inspect = json.loads(_run(["docker", "image", "inspect", image]))[0]
    declared = image_inspect.get("Config", {}).get("Volumes") or {}
    if set(declared) != set(VOLUMES.values()):
        raise RecoveryError("pinned image declares a volume set other than the exact v1 allowlist")
    runtime_mounts = inspected.get("Mounts", [])
    mounts = [mount for mount in runtime_mounts if mount.get("Type") == "volume"]
    mapping = {mount.get("Destination"): mount.get("Name") for mount in mounts}
    durable_paths = tuple(VOLUMES.values())
    shadow = any(mount.get("Type") != "volume" and any(
        mount.get("Destination", "") == target or
        mount.get("Destination", "").startswith(target + "/") or
        target.startswith(mount.get("Destination", "").rstrip("/") + "/")
        for target in durable_paths) for mount in runtime_mounts)
    if (len(mounts) != len(VOLUMES) or len(set(mapping.values())) != len(VOLUMES)
            or shadow or set(mapping) != set(durable_paths)
            or any(not value for value in mapping.values())):
        raise RecoveryError("runtime volume mounts do not match the exact three-member allowlist")
    state = inspected.get("State", {})
    if state.get("Running") is True:
        raise RecoveryError("cold capture requires the staged source shutdown to complete before archive reads")
    if state.get("ExitCode") != 0:
        raise RecoveryError("cold capture source did not exit cleanly")
    return image, mapping


def observe_queue_state(container: str, *, network_fenced: bool = False,
        writers_stopped: bool = False) -> dict:
    """Capture bounded, read-only worker and broker observations.

    This is explicitly not a drain proof: it neither fences incoming work nor
    stops writers. Its output records failures and unresolved state so the
    maintained journey can fail closed with concrete evidence.
    """
    if not isinstance(container, str) or not re.fullmatch(
            r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", container):
        raise RecoveryError("queue observation container name is invalid")

    def observe(name: str, command: list[str]) -> dict:
        try:
            result = subprocess.run(command, text=True, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, check=False, timeout=20)
            stdout, stderr = result.stdout, result.stderr
            summary = {"name": name, "exit_code": result.returncode,
                "stdout_bytes": len(stdout.encode()),
                "stdout_sha256": hashlib.sha256(stdout.encode()).hexdigest(),
                "stdout_nonempty": bool(stdout.strip()),
                "stderr_bytes": len(stderr.encode()),
                "stderr_sha256": hashlib.sha256(stderr.encode()).hexdigest()}
            if name.startswith("celery_"):
                summary["explicit_empty_task_response"] = bool(re.search(
                    r"(?m)^\s*(?:\* empty \*|- empty -)\s*$", stdout))
                summary["worker_ids"] = sorted(set(re.findall(
                    r"(?m)^->\s+([^:\s]+):\s+OK\s*$", stdout)))
            elif name == "valkey_db0_inventory":
                summary["key_count"] = len([line for line in stdout.splitlines() if line.strip()])
            return summary
        except (OSError, subprocess.TimeoutExpired) as exc:
            message = str(exc).encode()
            return {"name": name, "exit_code": None, "error_type": type(exc).__name__,
                "error_sha256": hashlib.sha256(message).hexdigest()}

    container_id = _run(["docker", "inspect", container, "--format", "{{.Id}}"])
    expected_worker = "celery@" + container_id[:12]

    def observe_valkey() -> dict:
        try:
            result = subprocess.run(["docker", "exec", container, "valkey-cli", "-h",
                "127.0.0.1", "-n", "0", "--scan"], text=True, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, check=False, timeout=20)
        except (OSError, subprocess.TimeoutExpired) as exc:
            message = str(exc).encode()
            return {"name": "valkey_db0_inventory", "exit_code": None,
                "error_type": type(exc).__name__, "error_sha256": hashlib.sha256(message).hexdigest(),
                "key_count": None, "key_types": {}, "cardinality_errors": 1}
        keys = sorted({line.strip() for line in result.stdout.splitlines() if line.strip()})
        key_types: dict[str, int] = {}
        cardinality_errors = 0
        cardinalities: dict[str, int] = {}
        binding_contents: dict[str, dict] = {}
        if result.returncode != 0 or len(keys) > 1000:
            return {"name": "valkey_db0_inventory", "exit_code": result.returncode,
                "key_count": len(keys), "key_types": {}, "cardinality_errors": 1,
                "keys_digest": hashlib.sha256(canonical_json(keys)).hexdigest(),
                "stdout_bytes": len(result.stdout.encode()),
                "stdout_sha256": hashlib.sha256(result.stdout.encode()).hexdigest()}
        for key in keys:
            kind = subprocess.run(["docker", "exec", container, "valkey-cli", "-h",
                "127.0.0.1", "-n", "0", "type", key], text=True,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False, timeout=10)
            value_type = kind.stdout.strip()
            if kind.returncode != 0 or value_type not in {"list", "hash", "zset", "set", "stream", "string"}:
                cardinality_errors += 1
                continue
            count_command = {"list": "llen", "hash": "hlen", "zset": "zcard",
                "set": "scard", "stream": "xlen", "string": "strlen"}[value_type]
            count = subprocess.run(["docker", "exec", container, "valkey-cli", "-h",
                "127.0.0.1", "-n", "0", count_command, key], text=True,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False, timeout=10)
            try:
                cardinality = int(count.stdout.strip())
                if count.returncode != 0 or cardinality < 0:
                    raise ValueError
            except ValueError:
                cardinality_errors += 1
                continue
            key_types[value_type] = key_types.get(value_type, 0) + 1
            cardinalities[value_type] = cardinalities.get(value_type, 0) + cardinality
            if key.startswith("_kombu.binding.") and value_type == "set":
                members = subprocess.run(["docker", "exec", container, "valkey-cli", "-h",
                    "127.0.0.1", "-n", "0", "--raw", "smembers", key], text=True,
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False, timeout=10)
                decoded = sorted(members.stdout.splitlines())
                if members.returncode != 0 or any(len(value) > 256 for value in decoded):
                    cardinality_errors += 1
                    continue
                binding_name = key.removeprefix("_kombu.binding.")
                parsed = [value.split("\x06\x16") for value in decoded]
                expected_binding = None
                if binding_name == "celery":
                    expected_binding = parsed == [["celery", "", "celery"]]
                elif binding_name == "celery.pidbox":
                    expected_binding = parsed == [["", "", expected_worker + ".celery.pidbox"]]
                elif binding_name == "celeryev" and len(parsed) == 1 and len(parsed[0]) == 3:
                    routing, pattern, queue = parsed[0]
                    event_queue = queue.removeprefix("celeryev.")
                    try:
                        valid_event_queue = str(uuid.UUID(event_queue)) == event_queue
                    except (ValueError, AttributeError):
                        valid_event_queue = False
                    expected_binding = routing == "worker.#" and pattern == "" and valid_event_queue
                binding_contents[key.removeprefix("_kombu.binding.")] = {
                    "member_count": len(decoded),
                    "member_digest": hashlib.sha256(canonical_json(decoded)).hexdigest(),
                    "binding_fields": [{"routing_key": parts[0], "pattern": parts[1], "queue": parts[2]}
                        for parts in parsed if len(parts) == 3],
                    "members_valid": bool(expected_binding)}
            elif key not in {"celery", "celery\x06\x03\x00", "unacked", "unacked_index"}:
                cardinality_errors += 1
        return {"name": "valkey_db0_inventory", "exit_code": 0,
            "key_count": len(keys), "key_types": key_types,
            "cardinality_totals_by_type": cardinalities,
            "cardinality_errors": cardinality_errors,
            "key_names_digest": hashlib.sha256(canonical_json(keys)).hexdigest(),
            "binding_contents": binding_contents,
            "keys_digest": hashlib.sha256(canonical_json(keys)).hexdigest(),
            "stdout_bytes": len(result.stdout.encode()),
            "stdout_sha256": hashlib.sha256(result.stdout.encode()).hexdigest()}

    checks = [
        observe("celery_active", ["docker", "exec", container, "celery", "-A", "dojo",
            "inspect", "active", "--timeout=5"]),
        observe("celery_reserved", ["docker", "exec", container, "celery", "-A", "dojo",
            "inspect", "reserved", "--timeout=5"]),
        observe("celery_scheduled", ["docker", "exec", container, "celery", "-A", "dojo",
            "inspect", "scheduled", "--timeout=5"]),
        observe_valkey(),
    ]
    intent_script = r'''import importlib, json, pkgutil
from sqlalchemy import create_engine, select, func, text
import uvm.persistence as persistence
from uvm.persistence.schema import uvm_metadata
for module in pkgutil.iter_modules(persistence.__path__):
    if module.name.endswith("_schema"):
        importlib.import_module("uvm.persistence." + module.name)
expected = {"administration_reconciliation_intents", "assessment_projection_intents",
    "exception_warning_intents", "g7_connector_intents", "g7_incident_notification_intents",
    "g7_observer_application_intents", "github_projection_intents",
    "health_notification_intents", "reporting_projection_intents"}
tables = {name: table for name, table in uvm_metadata.tables.items() if "intent" in name}
missing = sorted(expected - set(tables))
settled = {"applied", "accepted", "sent", "cancelled", "superseded", "acknowledged",
    "delivered", "suppressed", "completed", "complete", "committed", "succeeded"}
engine = create_engine(__import__("os").environ["UVM_DB_URL"])
result = {"schema_version": 1, "tables": {}, "missing_expected_tables": missing,
    "unresolved_count": 0, "held_intents": []}
with engine.connect() as connection:
    connection.execute(text("SET TRANSACTION READ ONLY"))
    for name, table in sorted(tables.items()):
        state = next((table.c[key] for key in ("status", "state", "outcome") if key in table.c), None)
        rows = connection.execute(select(state, func.count()).select_from(table).group_by(state)).all() if state is not None else []
        count = sum(row[1] for row in rows) if state is not None else connection.execute(select(func.count()).select_from(table)).scalar_one()
        states = {str(row[0]): row[1] for row in rows} if state is not None else {}
        held = []
        identifier = next((table.c[key] for key in ("intent_id", "projection_id") if key in table.c), None)
        if state is not None and identifier is not None:
            held = list(connection.execute(select(identifier).where(state == "uncertain")).scalars())
            for intent_id in held:
                if str(__import__('uuid').UUID(intent_id)) != intent_id:
                    raise ValueError("held intent has no stable canonical idempotency identity")
                result["held_intents"].append({"connector_id": name, "intent_id": intent_id, "state": "uncertain"})
        unresolved = sum(value for key, value in states.items() if key not in settled) - len(held)
        if state is None and count:
            unresolved = count
        result["tables"][name] = {"row_count": count, "state_counts": states,
            "unresolved_count": unresolved, "state_column": state.name if state is not None else None}
        result["unresolved_count"] += unresolved
print(json.dumps(result, sort_keys=True, separators=(",", ":")))
'''
    try:
        intent_result = subprocess.run(["docker", "exec", "-i", container, "bash", "-lc",
            'export UVM_DB_URL="postgresql+psycopg://uvm_app:$(cat /run/secrets/uvm_db_password)@127.0.0.1:5432/uvm"; exec /opt/uvm/venv/bin/python -'],
            input=intent_script, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            check=False, timeout=30)
        intent_value = json.loads(intent_result.stdout) if intent_result.returncode == 0 else None
    except (OSError, subprocess.TimeoutExpired, ValueError):
        intent_value = None
    unresolved = []
    if not network_fenced:
        unresolved.append("ingress/effect-egress fence was not enforced")
    if not writers_stopped:
        unresolved.append("producers, admission surfaces and side-effect dispatch are still running")
    if intent_value is None:
        unresolved.append("durable UVM effect-intent inventory could not be read completely")
    elif intent_value.get("missing_expected_tables") or intent_value.get("unresolved_count") != 0:
        unresolved.append("durable UVM effect intents are missing from inventory or unresolved")
    for check in checks[:3]:
        # Celery's inspect response is opaque text here. Even an empty-looking
        # response is not interpreted as an empty task inventory.
        if check["exit_code"] != 0 or not check.get("stdout_nonempty"):
            unresolved.append(f"{check['name']} did not produce a verifiable response")
        elif check.get("explicit_empty_task_response"):
            pass
        else:
            unresolved.append(f"{check['name']} response requires task-state reconciliation")
    worker_sets = [set(check.get("worker_ids", [])) for check in checks[:3]]
    if (worker_sets[0] != {expected_worker}
            or any(workers != worker_sets[0] for workers in worker_sets[1:])):
        unresolved.append("Celery task snapshots do not identify the same single expected worker")
    broker = checks[3]
    if broker["exit_code"] != 0:
        unresolved.append("Valkey DB0 key scan failed")
    elif (broker.get("key_count") != 3 or broker.get("key_types") != {"set": 3}
            or broker.get("cardinality_errors", 0)
            or set(broker.get("binding_contents", {})) != {"celery", "celery.pidbox", "celeryev"}
            or any(not binding.get("members_valid") for binding in broker.get(
                "binding_contents", {}).values())):
        unresolved.append("Valkey DB0 contains unknown queue state or unverified binding contents")
    return {"schema_version": 1, "container": container,
        "observed_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "network_fenced": network_fenced, "writers_stopped": writers_stopped,
        "observations": checks, "intent_inventory": intent_value,
        "tasks": [], "unresolved": unresolved,
        "drain_proof": False}


def sign_drain_proof(*, container: str, deployment_id: str, key_id: str,
        signing_key: Path, queue_path: Path, fence_path: Path,
        supervisor_log: Path, output: Path) -> dict:
    queue = json.loads(queue_path.read_text(encoding="utf-8"), object_pairs_hook=_unique_pairs)
    fence = json.loads(fence_path.read_text(encoding="utf-8"), object_pairs_hook=_unique_pairs)
    inspected = json.loads(_run(["docker", "inspect", container]))[0]
    container_id, image_id = inspected["Id"], inspected["Image"]
    expected_tables = {"administration_reconciliation_intents", "assessment_projection_intents",
        "exception_warning_intents", "g7_connector_intents", "g7_incident_notification_intents",
        "g7_observer_application_intents", "github_projection_intents",
        "health_notification_intents", "reporting_projection_intents"}
    observations = {item.get("name"): item for item in queue.get("observations", [])}
    intent_inventory = queue.get("intent_inventory", {})
    expected_worker = "celery@" + container_id[:12]
    if (queue.get("network_fenced") is not True or queue.get("writers_stopped") is not True
            or queue.get("unresolved") != [] or queue.get("tasks") != []
            or intent_inventory.get("unresolved_count") != 0
            or intent_inventory.get("missing_expected_tables") != []
            or set(intent_inventory.get("tables", {})) != expected_tables
            or any(observations.get(name, {}).get("explicit_empty_task_response") is not True
                or observations.get(name, {}).get("worker_ids") != [expected_worker]
                for name in ("celery_active", "celery_reserved", "celery_scheduled"))):
        raise RecoveryError("host queue/effect inventory is unresolved")
    broker = observations.get("valkey_db0_inventory", {})
    if (broker.get("exit_code") != 0 or broker.get("cardinality_errors") != 0
            or broker.get("key_count") != 3 or broker.get("key_types") != {"set": 3}
            or set(broker.get("binding_contents", {})) != {"celery", "celery.pidbox", "celeryev"}
            or any(not item.get("members_valid") for item in broker.get("binding_contents", {}).values())):
        raise RecoveryError("Valkey queue/binding inventory is incomplete or unknown")
    state = inspected.get("State", {})
    if (state.get("Running") is not False or state.get("ExitCode") != 0
            or state.get("OOMKilled") is not False or state.get("Error")):
        raise RecoveryError("source container shutdown was forced, nonzero or incomplete")
    if (fence.get("schema_version") != 1 or fence.get("endpoint_removed") is not True
            or fence.get("container_id") != container_id or fence.get("image_id") != image_id
            or fence.get("loopback_listener_probes_blocked") != [8000, 8002, 9000]
            or fence.get("existing_external_tcp_count") != 0
            or fence.get("existing_external_udp_count") != 0):
        raise RecoveryError("host ingress/egress fence record is invalid or does not bind this source")
    logs = supervisor_log.read_text(encoding="utf-8")
    required_markers = (
        "G7_STOP_PHASE=quiesce-producers status=0",
        "G7_STOP_PHASE=quiesce-admission status=0",
        "G7_STOP_PHASE=quiesce-effects status=0",
        "G7_STOP_PHASE=quiesce-consumers status=0",
        "G7_STOP_DATABASE_STOPPED service=valkey",
        "G7_STOP_DATABASE_STOPPED service=postgresql",
        "G7_QUIESCE=services-stopped", "G7_QUIESCE=complete")
    if any(marker not in logs for marker in required_markers) or re.search(
            r"G7_STOP_ERROR|action=timeout|action=KILL|G7_QUIESCE_ERROR|status=[1-9]", logs):
        raise RecoveryError("supervisor log lacks clean staged stop acknowledgements")
    finished = parse_utc(state.get("FinishedAt"))
    consistency_point = finished.isoformat().replace("+00:00", "Z")
    network_digest = "sha256:" + hashlib.sha256(canonical_json(fence)).hexdigest()
    queue_digest = "sha256:" + hashlib.sha256(canonical_json(queue)).hexdigest()
    unsigned = {"schema_version": 1, "deployment_id": deployment_id,
        "container_id": container_id, "image_digest": image_id,
        "ingress_fenced": True, "writers_paused": True, "queue_drained": True,
        "queue_inventory_digest": queue_digest, "queue_inventory": queue,
        "network_fence_digest": network_digest,
        "consistency_point_at": consistency_point, "shutdown_status": 0,
        "forced_shutdown": False,
        "observed_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")}
    signed = {**unsigned, "signature": {"algorithm": "Ed25519", "key_id": key_id,
        "value": base64.urlsafe_b64encode(_sign(canonical_json(unsigned), signing_key)).decode().rstrip("=")}}
    output.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    with output.open("xb") as stream:
        stream.write(canonical_json(signed) + b"\n")
        stream.flush()
        os.fsync(stream.fileno())
    output.chmod(0o600)
    return {"signed": True, "queue_inventory_digest": queue_digest,
        "network_fence_digest": network_digest, "consistency_point_at": consistency_point}


def _create_archive_staging(*, container: str, deployment_id: str, archive_dir: Path,
        drain_proof: Path, public_key: Path, signing_key: Path, key_id: str,
        generation: int, recovery_epoch: int, settings_revision: int,
        settings_digest: str, host_policy_revision: int, host_policy_digest: str,
        controller_instance_id: str, controller_sequence: int,
        package_manifest_digest: str, helper_image: str,
        stop_timeout: int = 120, consumer_state: Path | None = None) -> Path:
    if (not isinstance(deployment_id, str) or not re.fullmatch(
            r"[A-Za-z0-9][A-Za-z0-9._:-]{0,255}", deployment_id)
            or type(generation) is not int or generation < 1
            or type(recovery_epoch) is not int or recovery_epoch < 0
            or type(settings_revision) is not int or settings_revision < 1
            or type(host_policy_revision) is not int or host_policy_revision < 1
            or type(controller_sequence) is not int or controller_sequence < 1
            or type(stop_timeout) is not int or not 1 <= stop_timeout <= 3600):
        raise RecoveryError("archive generation or epoch is invalid")
    try:
        if str(uuid.UUID(controller_instance_id)) != controller_instance_id:
            raise ValueError
    except (TypeError, ValueError, AttributeError):
        raise RecoveryError("archive controller instance identity is invalid") from None
    for value in (package_manifest_digest, settings_digest, host_policy_digest):
        if not isinstance(value, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", value):
            raise RecoveryError("capture digest input is malformed")
    if consumer_state is not None:
        from uvm.operations.backup_host import digest
        consumed = json.loads(consumer_state.read_text(encoding="utf-8"), object_pairs_hook=_unique_pairs)
        if (consumed.get("deployment_id") != deployment_id or
                consumed.get("revision") != settings_revision or
                consumed.get("digest") != settings_digest or
                "sha256:" + digest(consumed.get("values")) != settings_digest or
                consumed.get("capture_timeout_seconds") != stop_timeout):
            raise RecoveryError("capture does not match independently consumed settings")
    archive_dir.mkdir(mode=0o700, parents=True, exist_ok=False)
    image, mounts = _container_mounts(container)
    image_digest = _run(["docker", "image", "inspect", image, "--format", "{{.Id}}"])
    helper_digest = _run(["docker", "image", "inspect", helper_image, "--format", "{{.Id}}"])
    if helper_digest != image_digest:
        raise RecoveryError("capture helper must use the exact source image digest")
    source_container_id = _run(["docker", "inspect", container, "--format", "{{.Id}}"])
    proof = verify_drain_proof(drain_proof, public_key, deployment_id=deployment_id,
        container_id=source_container_id, image_digest=image_digest,
        expected_key_id=key_id)
    consistency_point_at = proof["consistency_point_at"]
    capture_started_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    if parse_utc(capture_started_at) < parse_utc(consistency_point_at):
        raise RecoveryError("archive reads began before the verified consistency point")
    members = []
    for name, target in VOLUMES.items():
        member = archive_dir / f"{name}.tar.gz"
        source = mounts[target]
        _run(["docker", "run", "--rm", "--mount", f"type=volume,src={source},dst=/member,readonly",
            "--mount", f"type=bind,src={archive_dir},dst=/archive", "--entrypoint", "/bin/bash",
            helper_image, "-lc", f"tar --numeric-owner --xattrs -czf /archive/{member.name} -C /member ."])
        _fsync_path(member)
        _validate_tar(member)
        digest, size = _sha(member)
        members.append({"name": name, "volume_id": source,
            "member": member.name, "sha256": digest, "byte_length": size})
    completed_at = consistency_point_at
    manifest = {"schema_version": 1, "deployment_id": deployment_id,
        "archive_id": str(uuid.uuid4()), "generation": generation,
        "recovery_epoch": recovery_epoch, "capture_started_at": capture_started_at,
        "consistency_point_at": consistency_point_at,
        "completed_at": completed_at, "image_digest": image_digest,
        "package_manifest_digest": package_manifest_digest,
        "volumes": members, "settings_revision": settings_revision,
        "settings_digest": settings_digest, "host_policy_revision": host_policy_revision,
        "host_policy_digest": host_policy_digest,
        "controller_instance_id": controller_instance_id,
        "controller_sequence": controller_sequence,
        "queue_inventory_digest": proof["queue_inventory_digest"], "outcome": "complete"}
    signature = _sign(canonical_json(manifest), signing_key)
    manifest["signature"] = {"algorithm": "Ed25519", "key_id": key_id,
        "value": base64.urlsafe_b64encode(signature).decode("ascii").rstrip("=")}
    result = archive_dir / "manifest.json"
    with result.open("xb") as stream:
        stream.write(canonical_json(manifest) + b"\n")
        stream.flush()
        os.fsync(stream.fileno())
    result.chmod(0o600)
    _fsync_path(archive_dir)
    return result


def create_archive(**kwargs) -> Path:
    """Publish only a fully signed archive directory; remove partial staging."""
    destination = kwargs["archive_dir"]
    staging = destination.with_name(destination.name + ".incomplete-" + uuid.uuid4().hex)
    if destination.exists():
        raise RecoveryError("archive destination already exists")
    kwargs["archive_dir"] = staging
    try:
        staged_manifest = _create_archive_staging(**kwargs)
        os.replace(staging, destination)
        _fsync_path(destination.parent)
        return destination / staged_manifest.name
    finally:
        if staging.exists():
            import shutil
            shutil.rmtree(staging)


def _sign(data: bytes, private_key: Path) -> bytes:
    from cryptography.hazmat.primitives import serialization
    with private_key.open("rb") as stream:
        key = serialization.load_pem_private_key(stream.read(), password=None)
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    if not isinstance(key, Ed25519PrivateKey):
        raise RecoveryError("archive signer must use Ed25519")
    return key.sign(data)


def verify_archive(*, archive_dir: Path, public_key: Path,
        deployment_id: str, image_digest: str,
        package_manifest_digest: str, expected_key_id: str) -> dict:
    manifest_path = archive_dir / "manifest.json"
    try:
        if archive_dir.is_symlink() or not archive_dir.is_dir():
            raise ValueError("archive path is not a private directory")
        if manifest_path.is_symlink() or not manifest_path.is_file():
            raise ValueError("archive manifest is not a regular file")
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"),
            object_pairs_hook=_unique_pairs, parse_float=_reject_float,
            parse_constant=_reject_constant)
    except Exception as exc:
        raise RecoveryError("archive manifest is malformed") from exc
    if (not isinstance(manifest, dict) or set(manifest) != MANIFEST_FIELDS
            or type(manifest.get("schema_version")) is not int
            or manifest.get("schema_version") != 1):
        raise RecoveryError("archive manifest has an unsupported exact shape")
    if (manifest["deployment_id"] != deployment_id or manifest["image_digest"] != image_digest
            or manifest["package_manifest_digest"] != package_manifest_digest
            or manifest["outcome"] != "complete"):
        raise RecoveryError("archive deployment, image, package or outcome does not match")
    try:
        if str(uuid.UUID(manifest["archive_id"])) != manifest["archive_id"]:
            raise ValueError
        if str(uuid.UUID(manifest["controller_instance_id"])) != manifest["controller_instance_id"]:
            raise ValueError
        started, consistency = parse_utc(manifest["capture_started_at"]), parse_utc(
            manifest["consistency_point_at"])
        completed = parse_utc(manifest["completed_at"])
        if started < consistency or completed != consistency:
            raise ValueError
    except (ValueError, TypeError, KeyError):
        raise RecoveryError("archive identity or consistency-point timestamps are invalid") from None
    if (type(manifest["generation"]) is not int or manifest["generation"] < 1
            or type(manifest["recovery_epoch"]) is not int or manifest["recovery_epoch"] < 0
            or type(manifest["settings_revision"]) is not int or manifest["settings_revision"] < 1
            or type(manifest["host_policy_revision"]) is not int or manifest["host_policy_revision"] < 1
            or type(manifest["controller_sequence"]) is not int or manifest["controller_sequence"] < 1
            or any(not isinstance(manifest[field], str) or not re.fullmatch(
                r"sha256:[0-9a-f]{64}", manifest[field]) for field in (
                    "image_digest", "package_manifest_digest", "settings_digest",
                    "host_policy_digest", "queue_inventory_digest"))):
        raise RecoveryError("archive revision, sequence or digest fields are invalid")
    unsigned = {key: value for key, value in manifest.items() if key != "signature"}
    try:
        raw, _ = verify_signature(manifest, str(public_key), expected_key_id)
    except Exception as exc:
        raise RecoveryError("archive manifest signature is invalid") from exc
    if raw != canonical_json(unsigned):
        raise RecoveryError("archive manifest canonical bytes are invalid")
    volumes = manifest["volumes"]
    if (not isinstance(volumes, list) or len(volumes) != 3
            or any(not isinstance(item, dict) for item in volumes)
            or any(not isinstance(item.get("name"), str) for item in volumes)
            or {item["name"] for item in volumes} != set(VOLUMES)):
        raise RecoveryError("archive must contain exactly the three declared volume members")
    volume_ids = [member.get("volume_id") for member in volumes]
    if any(not isinstance(value, str) for value in volume_ids) or len(set(volume_ids)) != 3:
        raise RecoveryError("archive contains duplicated or invalid volume identities")
    seen = set()
    for member in volumes:
        if set(member) != {"name", "volume_id", "member", "sha256", "byte_length"}:
            raise RecoveryError("archive member descriptor is malformed")
        if (not isinstance(member["name"], str) or member["name"] not in VOLUMES
                or not isinstance(member["member"], str)
                or member["member"] != f"{member['name']}.tar.gz"
                or not isinstance(member["volume_id"], str)
                or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", member["volume_id"])
                or not isinstance(member["sha256"], str)
                or not re.fullmatch(r"[0-9a-f]{64}", member["sha256"])
                or type(member["byte_length"]) is not int or member["byte_length"] < 1):
            raise RecoveryError("archive member descriptor is unsafe")
        if member["member"] in seen:
            raise RecoveryError("archive contains duplicate member names")
        seen.add(member["member"])
        path = archive_dir / member["member"]
        if path.is_symlink() or not path.is_file():
            raise RecoveryError("archive is missing a declared member")
        digest, size = _sha(path)
        if digest != member["sha256"] or size != member["byte_length"]:
            raise RecoveryError("archive member digest or length does not match")
        _validate_tar(path)
    extra = {path.name for path in archive_dir.iterdir()} - seen - {"manifest.json"}
    if extra:
        raise RecoveryError("archive directory contains undeclared member files")
    return manifest


def restore_new_volumes(*, archive_dir: Path, public_key: Path,
        deployment_id: str, image_digest: str, package_manifest_digest: str,
        expected_key_id: str, helper_image: str, name_prefix: str,
        host_journal: Path | None = None, recovery_epoch: int | None = None) -> dict[str, str]:
    if (not isinstance(name_prefix, str)
            or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,50}", name_prefix)):
        raise RecoveryError("replacement volume name prefix is invalid")
    manifest = verify_archive(archive_dir=archive_dir, public_key=public_key,
        deployment_id=deployment_id, image_digest=image_digest,
        package_manifest_digest=package_manifest_digest,
        expected_key_id=expected_key_id)
    if host_journal is not None:
        journal = json.loads(host_journal.read_text(encoding="utf-8"),
            object_pairs_hook=_unique_pairs, parse_float=_reject_float,
            parse_constant=_reject_constant)
        if (type(recovery_epoch) is not int or recovery_epoch < 1
                or not isinstance(journal, dict) or journal.get("deployment_id") != deployment_id
                or type(journal.get("recovery_epoch_floor")) is not int
                or recovery_epoch != journal["recovery_epoch_floor"] + 1):
            raise RecoveryError("external recovery epoch is not the next journaled epoch")
        journal["recovery_epoch_floor"] = recovery_epoch
        temporary = host_journal.with_name(host_journal.name + ".recovery-tmp")
        with temporary.open("xb") as stream:
            stream.write(canonical_json(journal) + b"\n")
            stream.flush(); os.fsync(stream.fileno())
        os.replace(temporary, host_journal)
        _fsync_path(host_journal.parent)
    helper_digest = _run(["docker", "image", "inspect", helper_image, "--format", "{{.Id}}"])
    if helper_digest != image_digest:
        raise RecoveryError("restore helper must use the exact archive image digest")
    created = {}
    try:
        for name, target in VOLUMES.items():
            volume = f"{name_prefix}-{name}-{uuid.uuid4().hex[:8]}"
            _run(["docker", "volume", "create", volume])
            created[name] = volume
        for name, target in VOLUMES.items():
            descriptor = next(member for member in manifest["volumes"] if member["name"] == name)
            _run(["docker", "run", "--rm", "--mount", f"type=volume,src={created[name]},dst=/member",
                "--mount", f"type=bind,src={archive_dir},dst=/archive,readonly", "--entrypoint", "/bin/bash",
                helper_image, "-lc", f"tar --numeric-owner --xattrs -xzf /archive/{descriptor['member']} -C /member"])
        return created
    except Exception:
        for volume in created.values():
            subprocess.run(["docker", "volume", "rm", "-f", volume], check=False,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        raise


def submit_restore_events(*, config_path: Path, manifest_path: Path,
        volume_ids_path: Path, recovery_epoch: int, connector_recovery_id: str,
        drain_proof_path: Path, public_key: Path) -> dict:
    from tools.g7_backup_controller import Controller, load_config
    controller = Controller(load_config(config_path))
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"), object_pairs_hook=_unique_pairs)
    volumes = json.loads(volume_ids_path.read_text(encoding="utf-8"), object_pairs_hook=_unique_pairs)
    if (recovery_epoch != controller.state["recovery_epoch_floor"]
            or str(uuid.UUID(connector_recovery_id)) != connector_recovery_id):
        raise RecoveryError("restore identity does not match the external journal")
    # The pre-capture database sequence is bound by the signed manifest; the
    # externally retained controller sequence can have advanced since capture.
    response = controller.resynchronize(database_epoch_seen=manifest["recovery_epoch"],
        database_sequence_seen=manifest["controller_sequence"],
        checkpoint_epoch_floor=controller.state["recovery_epoch_floor"])
    proof = _load_signed(drain_proof_path, public_key, controller.config["signing_key_id"])
    if proof["queue_inventory_digest"] != manifest["queue_inventory_digest"]:
        raise RecoveryError("restore inventory does not match the signed archive")
    held = proof["queue_inventory"]["intent_inventory"].get("held_intents", [])
    common = {"schema_version": 1, "deployment_id": controller.deployment,
        "recovery_epoch": recovery_epoch, "connector_recovery_id": connector_recovery_id,
        "archive_id": manifest["archive_id"],
        "manifest_digest": "sha256:" + _sha(manifest_path)[0],
        "source_image_digest": manifest["image_digest"],
        "target_image_digest": None, "new_volume_ids": None,
        "verification": {"uvm_public_api": "not_run", "ce_public_api": "not_run",
            "media_readback": "not_run", "queue_reconciliation": "not_run",
            "migration": "not_run", "details_digest": None},
        "queue_inventory_digest": manifest["queue_inventory_digest"],
        "public_readback_digest": None, "failure_code": None}
    responses = []
    # Reuse the exact event/ack pair after interruption. Controller journals
    # each signed request before I/O, including the event UUID and timestamp.
    for event_type in ("restore_started", "volumes_restored"):
        if event_type == "volumes_restored":
            for item in held:
                controller.submit_quarantine({"schema_version": 1,
                    "deployment_id": controller.deployment, "event_id": str(uuid.uuid4()),
                    "recovery_epoch": recovery_epoch, "connector_recovery_id": connector_recovery_id,
                    "connector_id": item["connector_id"], "intent_ids": [item["intent_id"]],
                    "reason_code": "restore_uncertain_effect",
                    "observed_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")})
        last = controller.state.get("last_recovery_event") or {}
        last_event = last.get("event") or {}
        if (last_event.get("recovery_epoch") == recovery_epoch and
                last_event.get("event_type") in ({"restore_started", "volumes_restored"}
                    if event_type == "restore_started" else {"volumes_restored"})):
            responses.append(last["response"])
            continue
        body = {**common, "event_id": str(uuid.uuid4()), "event_type": event_type,
            "previous_epoch": recovery_epoch - 1 if event_type == "restore_started" else recovery_epoch,
            "target_image_digest": manifest["image_digest"] if event_type == "volumes_restored" else None,
            "new_volume_ids": volumes if event_type == "volumes_restored" else None,
            "observed_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")}
        responses.append(controller.submit_recovery_event(body))

    return {"resync": response, "events": responses}


def main() -> None:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    capture = sub.add_parser("capture")
    capture.add_argument("--container", required=True)
    capture.add_argument("--deployment-id", required=True)
    capture.add_argument("--archive-dir", type=Path, required=True)
    capture.add_argument("--drain-proof", type=Path, required=True)
    capture.add_argument("--public-key", type=Path, required=True)
    capture.add_argument("--signing-key", type=Path, required=True)
    capture.add_argument("--key-id", required=True)
    capture.add_argument("--generation", type=int, required=True)
    capture.add_argument("--recovery-epoch", type=int, required=True)
    capture.add_argument("--settings-revision", type=int, required=True)
    capture.add_argument("--settings-digest", required=True)
    capture.add_argument("--host-policy-revision", type=int, required=True)
    capture.add_argument("--host-policy-digest", required=True)
    capture.add_argument("--controller-instance-id", required=True)
    capture.add_argument("--controller-sequence", type=int, required=True)
    capture.add_argument("--package-manifest-digest", required=True)
    capture.add_argument("--helper-image", required=True)
    capture.add_argument("--stop-timeout", type=int, default=120)
    capture.add_argument("--consumer-state", type=Path)
    observe = sub.add_parser("observe-queue")
    observe.add_argument("--container", required=True)
    observe.add_argument("--output", type=Path, required=True)
    observe.add_argument("--network-fenced", action="store_true")
    observe.add_argument("--writers-stopped", action="store_true")
    drain_sign = sub.add_parser("sign-drain-proof")
    drain_sign.add_argument("--container", required=True)
    drain_sign.add_argument("--deployment-id", required=True)
    drain_sign.add_argument("--key-id", required=True)
    drain_sign.add_argument("--signing-key", type=Path, required=True)
    drain_sign.add_argument("--queue-inventory", type=Path, required=True)
    drain_sign.add_argument("--network-fence", type=Path, required=True)
    drain_sign.add_argument("--supervisor-log", type=Path, required=True)
    drain_sign.add_argument("--output", type=Path, required=True)
    verify = sub.add_parser("verify")
    verify.add_argument("--archive-dir", type=Path, required=True)
    verify.add_argument("--public-key", type=Path, required=True)
    verify.add_argument("--deployment-id", required=True)
    verify.add_argument("--image-digest", required=True)
    verify.add_argument("--package-manifest-digest", required=True)
    verify.add_argument("--expected-key-id", required=True)
    restore = sub.add_parser("restore")
    restore.add_argument("--archive-dir", type=Path, required=True)
    restore.add_argument("--public-key", type=Path, required=True)
    restore.add_argument("--deployment-id", required=True)
    restore.add_argument("--image-digest", required=True)
    restore.add_argument("--package-manifest-digest", required=True)
    restore.add_argument("--expected-key-id", required=True)
    restore.add_argument("--helper-image", required=True)
    restore.add_argument("--name-prefix", required=True)
    restore.add_argument("--host-journal", type=Path)
    restore.add_argument("--recovery-epoch", type=int)
    admit = sub.add_parser("admit-restore")
    admit.add_argument("--config", type=Path, required=True)
    admit.add_argument("--manifest", type=Path, required=True)
    admit.add_argument("--volume-ids", type=Path, required=True)
    admit.add_argument("--recovery-epoch", type=int, required=True)
    admit.add_argument("--connector-recovery-id", required=True)
    admit.add_argument("--drain-proof", type=Path, required=True)
    admit.add_argument("--public-key", type=Path, required=True)
    token = sub.add_parser("startup-token")
    token.add_argument("--deployment-id", required=True)
    token.add_argument("--image-digest", required=True)
    token.add_argument("--volume-ids-json", type=Path, required=True)
    token.add_argument("--archive-digest", required=True)
    token.add_argument("--recovery-epoch", type=int, required=True)
    token.add_argument("--connector-recovery-id", required=True)
    token.add_argument("--key-id", required=True)
    token.add_argument("--signing-key", type=Path, required=True)
    token.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.command == "capture":
        manifest = create_archive(container=args.container, deployment_id=args.deployment_id,
            archive_dir=args.archive_dir, drain_proof=args.drain_proof,
            public_key=args.public_key, signing_key=args.signing_key, key_id=args.key_id,
            generation=args.generation, recovery_epoch=args.recovery_epoch,
            settings_revision=args.settings_revision, settings_digest=args.settings_digest,
            host_policy_revision=args.host_policy_revision, host_policy_digest=args.host_policy_digest,
            controller_instance_id=args.controller_instance_id,
            controller_sequence=args.controller_sequence,
            package_manifest_digest=args.package_manifest_digest,
            helper_image=args.helper_image, stop_timeout=args.stop_timeout,
            consumer_state=args.consumer_state)
        print(json.dumps({"archive_manifest": str(manifest), "outcome": "complete"}, separators=(",", ":")))
    elif args.command == "observe-queue":
        inventory = observe_queue_state(args.container,
            network_fenced=args.network_fenced, writers_stopped=args.writers_stopped)
        args.output.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        with args.output.open("xb") as stream:
            stream.write(canonical_json(inventory) + b"\n")
            stream.flush()
            os.fsync(stream.fileno())
        args.output.chmod(0o600)
        print(json.dumps({"observed": True, "drain_proof": False,
            "unresolved_count": len(inventory["unresolved"])}, separators=(",", ":")))
    elif args.command == "sign-drain-proof":
        result = sign_drain_proof(container=args.container,
            deployment_id=args.deployment_id, key_id=args.key_id,
            signing_key=args.signing_key, queue_path=args.queue_inventory,
            fence_path=args.network_fence, supervisor_log=args.supervisor_log,
            output=args.output)
        print(json.dumps(result, separators=(",", ":")))
    elif args.command == "verify":
        manifest = verify_archive(archive_dir=args.archive_dir, public_key=args.public_key,
            deployment_id=args.deployment_id, image_digest=args.image_digest,
            package_manifest_digest=args.package_manifest_digest,
            expected_key_id=args.expected_key_id)
        print(json.dumps({"verified": True, "archive_id": manifest["archive_id"],
            "recovery_epoch": manifest["recovery_epoch"], "member_count": len(manifest["volumes"])},
            separators=(",", ":")))
    elif args.command == "restore":
        volumes = restore_new_volumes(archive_dir=args.archive_dir,
            public_key=args.public_key, deployment_id=args.deployment_id,
            image_digest=args.image_digest, package_manifest_digest=args.package_manifest_digest,
            expected_key_id=args.expected_key_id, helper_image=args.helper_image,
            name_prefix=args.name_prefix, host_journal=args.host_journal,
            recovery_epoch=args.recovery_epoch)
        print(json.dumps({"replacement_volumes": volumes,
            "startup_fence_required": True}, separators=(",", ":")))
    elif args.command == "admit-restore":
        result = submit_restore_events(config_path=args.config,
            manifest_path=args.manifest, volume_ids_path=args.volume_ids,
            recovery_epoch=args.recovery_epoch,
            connector_recovery_id=args.connector_recovery_id,
            drain_proof_path=args.drain_proof, public_key=args.public_key)
        print(json.dumps(result, separators=(",", ":")))
    elif args.command == "startup-token":
        try:
            volumes = json.loads(args.volume_ids_json.read_text(encoding="utf-8"),
                object_pairs_hook=_unique_pairs, parse_float=_reject_float,
                parse_constant=_reject_constant)
            if (set(volumes) != set(VOLUMES) or any(not isinstance(value, str) or not value
                    or len(value) > 256 for value in volumes.values())
                    or not re.fullmatch(r"sha256:[0-9a-f]{64}", args.image_digest)
                    or not re.fullmatch(r"sha256:[0-9a-f]{64}", args.archive_digest)
                    or type(args.recovery_epoch) is not int or args.recovery_epoch < 1
                    or str(uuid.UUID(args.connector_recovery_id)) != args.connector_recovery_id):
                raise RecoveryError("startup-token binding fields are invalid")
            unsigned = {"schema_version": 1, "deployment_id": args.deployment_id,
                "target_image_digest": args.image_digest, "volume_ids": volumes,
                "archive_digest": args.archive_digest, "recovery_epoch": args.recovery_epoch,
                "connector_recovery_id": args.connector_recovery_id,
                "issued_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")}
            signature = _sign(canonical_json(unsigned), args.signing_key)
            document = {**unsigned, "signature": {"algorithm": "Ed25519",
                "key_id": args.key_id,
                "value": base64.urlsafe_b64encode(signature).decode("ascii").rstrip("=")}}
            args.output.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            with args.output.open("xb") as stream:
                stream.write(canonical_json(document) + b"\n")
                stream.flush()
                os.fsync(stream.fileno())
            args.output.chmod(0o600)
            print(json.dumps({"startup_token_written": True,
                "recovery_epoch": args.recovery_epoch}, separators=(",", ":")))
        except (ValueError, OSError, KeyError, TypeError) as exc:
            raise RecoveryError("startup token could not be created") from exc


if __name__ == "__main__":
    try:
        main()
    except urllib.error.HTTPError as exc:
        print(f"backup recovery failed closed: HTTP status={exc.code}", file=sys.stderr)
        raise SystemExit(2)
    except urllib.error.URLError as exc:
        print(f"backup recovery failed closed: transport={type(exc.reason).__name__}", file=sys.stderr)
        raise SystemExit(2)
    except (RecoveryError, OSError, subprocess.CalledProcessError, ValueError) as exc:
        print(f"backup recovery failed closed: {type(exc).__name__}", file=sys.stderr)
        raise SystemExit(2)
