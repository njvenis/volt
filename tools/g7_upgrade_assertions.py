"""Strict validators shared by the maintained G7 runner and regression tests."""
from __future__ import annotations
import hashlib, json
from pathlib import Path

def validate_epoch_two_readbacks(root: Path, readbacks: dict, context_binding: dict) -> str:
    required={"rollback-public-readback.json", "rollback-uvm-group.json",
        "rollback-uvm-audit.json", "rollback-ce-findings.json", "rollback-volume-ids.json",
        "epoch-2-rollback-readback.json", "restore-ce-media.txt", "restore-ce-engagement.json",
        "rollback-context-binding.json"}
    if not required.issubset(readbacks):
        raise ValueError("epoch-2 verification manifest omits required rollback results")
    for name, expected_hash in readbacks.items():
        path=root/name
        if not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest()!=expected_hash:
            raise ValueError("epoch-2 verification readback is missing or mismatched: "+name)
    if json.loads((root/"rollback-context-binding.json").read_text()) != context_binding:
        raise ValueError("epoch-2 rollback context binding changed")
    manifest=json.loads((root/"verification-readback-manifest.json").read_text())
    if manifest != readbacks:
        raise ValueError("epoch-2 verification manifest differs from checked readback hashes")
    payload={"readbacks":readbacks,"rollback_context":context_binding}
    digest=hashlib.sha256(json.dumps(payload,sort_keys=True,separators=(",",":")).encode()).hexdigest()
    return "sha256:"+digest

def classify_verification_queue(raw: dict, absence: dict) -> dict:
    """Only EX_UNAVAILABLE with Celery's exact no-node response means absence."""
    import copy
    result = copy.deepcopy(raw)
    if (absence.get("passed") is not True or absence.get("process_scan_exit") != 0
            or absence.get("worker_processes") != [] or absence.get("pid_files") != []):
        raise ValueError("worker absence was not independently demonstrated")
    for name in ("celery_active", "celery_reserved", "celery_scheduled"):
        found = [v for v in result.get("observations", []) if v.get("name") == name]
        if len(found) != 1 or not expected_absence(found[0]):
            raise ValueError("Celery read failed instead of reporting absent workers")
        found[0]["classification"] = "workers_absent"
    result["classified_raw_unresolved"] = result["unresolved"]
    result["unresolved"] = []
    result["verification_mode"] = True
    result["worker_pid_files_absent"] = True
    result["worker_absence_proof"] = absence
    return result


def expected_absence(observation: dict) -> bool:
    return (observation.get("exit_code") == 69
        and observation.get("expected_absent_worker_response") is True
        and observation.get("stdout_bytes") == 0
        and observation.get("stderr_sha256") == hashlib.sha256(
            b"Error: No nodes replied within time constraint\n").hexdigest()
        and observation.get("worker_ids") == []
        and "error_type" not in observation)


def validate_verification_queue(before: dict, after: dict) -> dict:
    if before.get("unresolved") != [] or before.get("tasks") != []:
        raise ValueError("signed pre-capture queue inventory was not drained")
    left, right=before.get("intent_inventory"), after.get("intent_inventory")
    if not isinstance(left,dict) or not isinstance(right,dict) or left != right:
        raise ValueError("post-upgrade durable effect-intent inventory changed")
    held = left.get("held_intents")
    if not isinstance(held, list) or any(not isinstance(item, dict)
            or item.get("state") != "uncertain" for item in held):
        raise ValueError("pre-capture uncertain effect intents are not explicitly retained as held")
    if right.get("unresolved_count") != 0 or right.get("missing_expected_tables") != []:
        raise ValueError("post-upgrade durable effect-intent inventory is unresolved or incomplete")
    tasks=after.get("tasks")
    if tasks != []: raise ValueError("verification runtime contains unknown queued tasks")
    if after.get("verification_mode") is not True or after.get("worker_pid_files_absent") is not True:
        raise ValueError("verification runtime mode or worker absence was not proved")
    absence=after.get("worker_absence_proof", {})
    if (absence.get("passed") is not True or absence.get("process_scan_exit") != 0
            or absence.get("worker_processes") != [] or absence.get("pid_files") != []):
        raise ValueError("independent worker absence proof is missing")
    expected_unresolved={"celery_active did not produce a verifiable response","celery_reserved did not produce a verifiable response","celery_scheduled did not produce a verifiable response","Celery task snapshots do not identify the same single expected worker","Valkey DB0 contains unknown queue state or unverified binding contents"}
    if set(after.get("classified_raw_unresolved",[])) != expected_unresolved:
        raise ValueError("verification runtime contains an unexplained or missing classified queue observation")
    observations=after.get("observations")
    if not isinstance(observations,list): raise ValueError("verification runtime observations are missing")
    for name in ("celery_active","celery_reserved","celery_scheduled"):
        found=[v for v in observations if isinstance(v,dict) and v.get("name")==name]
        if len(found)!=1: raise ValueError("verification runtime Celery observation missing or duplicated")
        v=found[0]
        if v.get("worker_ids") != []:
            raise ValueError("verification runtime Celery observation is unknown or active")
        if v.get("classification") != "workers_absent" or not expected_absence(v):
            raise ValueError("verification runtime Celery observation lacks explicit absent-worker classification")
    broker_observations=[v for v in observations if isinstance(v,dict) and v.get("name")=="valkey_db0_inventory"]
    if len(broker_observations)!=1: raise ValueError("verification runtime broker observation missing or duplicated")
    b=broker_observations[0]
    if b.get("exit_code")!=0 or b.get("cardinality_errors")!=0 or b.get("key_count")!=0 or b.get("keys_digest") != hashlib.sha256(b"[]").hexdigest():
        raise ValueError("verification runtime broker observation failed or is nonempty")
    if after.get("unresolved") != []: raise ValueError("verification runtime has unresolved task, broker, or read state")
    return {"passed":True,"workers_disabled":True,"broker_empty":True,
      "effect_inventory_sha256":"sha256:"+hashlib.sha256(json.dumps(right,sort_keys=True,separators=(",",":")).encode()).hexdigest(),
      "pre_capture_held_intent_count":len(held),
      "pre_capture_held_intent_sha256":"sha256:"+hashlib.sha256(json.dumps(held,sort_keys=True,separators=(",",":")).encode()).hexdigest(),
      "pre_capture_held_intents_retained":True,
      "new_unresolved_external_effect_count":right["unresolved_count"],
      "unresolved_external_effect_count":right["unresolved_count"]}
