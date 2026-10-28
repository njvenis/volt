#!/usr/bin/env python3
"""Independent local host controller for backup desired settings and acks."""
from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import ssl
import sys
import time
import urllib.error
import urllib.request
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tools.g7_backup_recovery import RecoveryError, _sign
from uvm.operations.backup_host import canonical_json, digest, parse_utc, validate_policy
from uvm.operations.observer_settings import validate_backup_values


def atomic_json(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temporary = path.with_name(path.name + ".tmp-" + uuid.uuid4().hex)
    data = canonical_json(value) + b"\n"
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        temporary.unlink(missing_ok=True)


def _last_intent_revision(value: dict) -> int:
    """Return the monotonic desired-revision floor for a nullable initial intent."""
    intent = value.get("last_intent")
    if intent is None:
        return 0
    if not isinstance(intent, dict):
        raise RecoveryError("external controller journal intent is invalid")
    revision = intent.get("revision", 0)
    if type(revision) is not int or revision < 0:
        raise RecoveryError("external controller journal intent revision is invalid")
    return revision


def load_config(path: Path) -> dict:
    try:
        config = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise RecoveryError("host controller configuration is unavailable") from exc
    required = {"schema_version", "deployment_id", "endpoint", "token_file",
        "client_cert_file", "client_key_file", "server_ca_file", "signing_key_file",
        "signing_key_id", "controller_instance_id", "host_policy", "journal_file",
        "active_settings_file", "scheduler_readback_file", "capture_request_file"}
    if (not isinstance(config, dict) or set(config) != required
            or type(config["schema_version"]) is not int or config["schema_version"] != 1
            or any(not isinstance(config[key], str) or not config[key]
                for key in required - {"schema_version", "host_policy"})
            or not isinstance(config["host_policy"], dict)):
        raise RecoveryError("host controller configuration has an invalid exact shape")
    if str(uuid.UUID(config["controller_instance_id"])) != config["controller_instance_id"]:
        raise RecoveryError("controller instance identity is invalid")
    endpoint = config["endpoint"]
    if not isinstance(endpoint, str) or not endpoint.startswith("https://"):
        raise RecoveryError("recovery-control endpoint must use mutually authenticated TLS")
    try:
        validate_policy(config["host_policy"])
    except ValueError as exc:
        raise RecoveryError("host controller's independent policy is invalid") from exc
    return config


class Controller:
    def __init__(self, config: dict):
        self.config = config
        self.deployment = config["deployment_id"]
        self.journal = Path(config["journal_file"])
        self.active_file = Path(config["active_settings_file"])
        self.token = Path(config["token_file"]).read_text(encoding="utf-8").strip()
        self.tls = ssl.create_default_context(cafile=config["server_ca_file"])
        self.tls.load_cert_chain(config["client_cert_file"], config["client_key_file"])
        self.state = self._read_journal()

    def _read_journal(self) -> dict:
        if not self.journal.exists():
            return {"schema_version": 1, "deployment_id": self.deployment,
                "controller_instance_id": self.config["controller_instance_id"],
                "last_sequence": 0, "recovery_epoch_floor": 0,
                "last_intent": None, "last_ack": None}
        value = json.loads(self.journal.read_text(encoding="utf-8"))
        required = {"schema_version", "deployment_id", "controller_instance_id",
            "last_sequence", "recovery_epoch_floor", "last_intent", "last_ack"}
        if (not isinstance(value, dict) or set(value) - required - {"pending_ack", "pending_resync",
                "last_resync", "pending_recovery_event", "last_recovery_event", "last_effective", "pending_quarantine", "quarantine_receipts", "pending_status", "last_status", "pending_policy", "last_policy", "desired_namespace", "namespace_history", "recovery_receipts", "schema_compatibility_admissions", "development_rollback_requests", "product_inventory_attestations", "submission_receipts", "inventory_delta_evidence"}
                or not required.issubset(value)
                or type(value.get("schema_version")) is not int or value.get("schema_version") != 1
                or value.get("deployment_id") != self.deployment
                or value.get("controller_instance_id") != self.config["controller_instance_id"]
                or type(value.get("last_sequence")) is not int
                or type(value.get("recovery_epoch_floor")) is not int):
            raise RecoveryError("external controller journal is invalid")
        return value

    def journal_schema_compatibility_admission(self, admission: dict) -> dict:
        """Durably journal the exact one-step image/schema transition before signing startup."""
        fields = {"admission_id", "recovery_epoch", "source_image_digest",
            "source_package_manifest_digest", "target_image_digest",
            "target_package_manifest_digest", "archive_digest", "from_schema",
            "to_schema", "volume_ids"}
        digests = ("source_image_digest", "source_package_manifest_digest", "target_image_digest",
            "target_package_manifest_digest", "archive_digest")
        if (not isinstance(admission, dict) or set(admission) != fields
                or str(uuid.UUID(admission["admission_id"])) != admission["admission_id"]
                or type(admission["recovery_epoch"]) is not int
                or admission["recovery_epoch"] != self.state["recovery_epoch_floor"]
                or admission["from_schema"] != "0058" or admission["to_schema"] != "0059"
                or not isinstance(admission["volume_ids"], dict)
                or set(admission["volume_ids"]) != {"postgres_cluster", "ce_media", "uvm_state"}
                or any(not isinstance(value, str) or not value for value in admission["volume_ids"].values())
                or len(set(admission["volume_ids"].values())) != 3
                or any(not isinstance(admission[name], str) or not re.fullmatch(
                    r"sha256:[0-9a-f]{64}", admission[name]) for name in digests)):
            raise RecoveryError("schema compatibility admission is invalid")
        retained = self.state.setdefault("schema_compatibility_admissions", {})
        epoch_key = str(admission["recovery_epoch"])
        existing = retained.get(epoch_key)
        context = {key: value for key, value in admission.items() if key != "admission_id"}
        if existing is not None:
            if {key: value for key, value in existing.items() if key != "admission_id"} != context:
                raise RecoveryError("same-epoch schema compatibility admission conflicts")
            return existing
        retained[epoch_key] = admission
        atomic_json(self.journal, self.state)
        return admission

    def journal_development_rollback_request(self, request: dict) -> dict:
        fields = {"request_id", "state", "recovery_epoch", "archive_id", "archive_digest",
            "source_image_digest", "source_package_manifest_digest", "upgraded_image_digest",
            "target_package_manifest_digest", "forward_volume_ids", "schema_head",
            "inventory_attestation_id", "inventory_attestation_digest", "product_write_count", "control_mutation_count", "unexpected_inventory_change_count",
            "unresolved_external_effect_count", "ingress_fenced", "egress_fenced",
            "public_readback_match", "requested_at"}
        digests = ("archive_digest", "source_image_digest", "source_package_manifest_digest",
            "upgraded_image_digest", "target_package_manifest_digest", "inventory_attestation_digest")
        if (not isinstance(request, dict) or set(request) != fields
                or str(uuid.UUID(request["request_id"])) != request["request_id"]
                or request["state"] != "development_rollback_requested"
                or type(request["recovery_epoch"]) is not int
                or request["recovery_epoch"] != self.state["recovery_epoch_floor"]
                or request["schema_head"] != "0059"
                or any(type(request[name]) is not int or request[name] < 0 for name in
                    ("product_write_count", "unexpected_inventory_change_count", "unresolved_external_effect_count"))
                or any(request[name] is not True for name in
                    ("ingress_fenced", "egress_fenced", "public_readback_match"))
                or not isinstance(request["forward_volume_ids"], dict)
                or set(request["forward_volume_ids"]) != {"postgres_cluster", "ce_media", "uvm_state"}
                or any(not isinstance(value, str) or not value for value in request["forward_volume_ids"].values())
                or len(set(request["forward_volume_ids"].values())) != 3
                or any(not isinstance(request[name], str) or not re.fullmatch(
                    r"sha256:[0-9a-f]{64}", request[name]) for name in digests)):
            raise RecoveryError("development rollback request lacks clean fenced evidence")
        attestation=(self.state.get("product_inventory_attestations") or {}).get(request["inventory_attestation_id"])
        attestation_digest=("sha256:"+hashlib.sha256(json.dumps({k:v for k,v in attestation.items() if k!="attestation_digest"},sort_keys=True,separators=(",",":")).encode()).hexdigest()) if isinstance(attestation,dict) else None
        if (not isinstance(attestation,dict) or attestation_digest != request["inventory_attestation_digest"]
                or request["unresolved_external_effect_count"] != 0
                or attestation.get("unresolved_external_effect_count") != request["unresolved_external_effect_count"]
                or attestation.get("recovery_epoch") != request["recovery_epoch"]
                or attestation.get("forward_volume_ids") != request["forward_volume_ids"]
                or attestation.get("product_mutation_count") != request["product_write_count"]
                or attestation.get("control_mutation_count") != request["control_mutation_count"]
                or attestation.get("unexpected_inventory_change_count") != request["unexpected_inventory_change_count"]
                or any(attestation.get(src)!=request[dst] for src,dst in (("archive_digest","archive_digest"),("source_image_digest","source_image_digest"),("source_package_manifest_digest","source_package_manifest_digest"),("upgraded_image_digest","upgraded_image_digest"),("target_package_manifest_digest","target_package_manifest_digest")))
                or attestation.get("unexpected_inventory_change_count") != 0):
            raise RecoveryError("development rollback request is not bound to a clean complete inventory attestation")
        retained = self.state.setdefault("development_rollback_requests", {})
        epoch_key = str(request["recovery_epoch"])
        existing = retained.get(epoch_key)
        if existing is not None:
            if existing != request:
                raise RecoveryError("same-epoch development rollback request conflicts")
            return existing
        retained[epoch_key] = request
        atomic_json(self.journal, self.state)
        return request

    def journal_product_inventory_attestation(self, attestation: dict) -> dict:
        required={"attestation_id","recovery_epoch","forward_volume_ids","source_digest","candidate_digest","delta_digest","archive_digest","source_image_digest","source_package_manifest_digest","upgraded_image_digest","target_package_manifest_digest","product_mutation_count","control_mutation_count","unexpected_inventory_change_count","unresolved_external_effect_count","controller_journal_pre_digest"}
        if (not isinstance(attestation,dict) or set(attestation)!=required
            or str(uuid.UUID(attestation["attestation_id"]))!=attestation["attestation_id"]
            or attestation["recovery_epoch"]!=self.state["recovery_epoch_floor"]
            or any(type(attestation[k]) is not int or attestation[k]<0 for k in ("product_mutation_count","control_mutation_count","unexpected_inventory_change_count","unresolved_external_effect_count"))
            or attestation["unexpected_inventory_change_count"]!=0 or attestation["unresolved_external_effect_count"]!=0
            or attestation["product_mutation_count"]!=0
            or not isinstance(attestation["forward_volume_ids"],dict)
            or set(attestation["forward_volume_ids"])!={"postgres_cluster","ce_media","uvm_state"}
            or any(not isinstance(attestation[k],str) or not re.fullmatch(r"sha256:[0-9a-f]{64}",attestation[k]) for k in ("source_digest","candidate_digest","delta_digest","archive_digest","source_image_digest","source_package_manifest_digest","upgraded_image_digest","target_package_manifest_digest","controller_journal_pre_digest"))):
            raise RecoveryError("complete product inventory attestation is invalid")
        retained=self.state.setdefault("product_inventory_attestations",{})
        key=attestation["attestation_id"]
        stored={**attestation,"attestation_digest":"sha256:"+hashlib.sha256(json.dumps(attestation,sort_keys=True,separators=(",",":")).encode()).hexdigest()}
        if key in retained and retained[key]!=stored: raise RecoveryError("product inventory attestation identity conflicts")
        retained[key]=stored; atomic_json(self.journal,self.state); return stored

    def resynchronize(self, *, database_epoch_seen: int, database_sequence_seen: int,
            checkpoint_epoch_floor: int, force: bool = False) -> dict:
        """Authenticate DB rollback recovery and journal the transport ack first."""
        for value in (database_epoch_seen, database_sequence_seen, checkpoint_epoch_floor):
            if type(value) is not int or value < 0:
                raise RecoveryError("sequence resync counters are invalid")
        last = self.state.get("last_resync") or {}
        previous = last.get("request") or {}
        if (not force and previous.get("database_epoch_seen") == database_epoch_seen and
                previous.get("database_sequence_seen") == database_sequence_seen and
                previous.get("checkpoint_epoch_floor") == checkpoint_epoch_floor):
            return last["response"]
        pending = self.state.get("pending_resync")
        if pending is None:
            if checkpoint_epoch_floor < self.state["recovery_epoch_floor"]:
                raise RecoveryError("external recovery epoch checkpoint regressed")
            request = {"schema_version": 1, "deployment_id": self.deployment,
                "resync_id": str(uuid.uuid4()),
                "controller_instance_id": self.config["controller_instance_id"],
                "database_epoch_seen": database_epoch_seen,
                "database_sequence_seen": database_sequence_seen,
                "checkpoint_epoch_floor": checkpoint_epoch_floor,
                "checkpoint_last_sequence": self.state["last_sequence"],
                "issued_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")}
            pending = {"request": request}
            self.state["pending_resync"] = pending
            atomic_json(self.journal, self.state)
        else:
            request = pending.get("request")
            if not isinstance(request, dict):
                raise RecoveryError("pending sequence-resync journal record is malformed")
        response = self._request("sequence-resync", request)
        if (response.get("accepted") is not True
                or response.get("resync_id") != request.get("resync_id")
                or response.get("recovery_epoch_floor") != request.get("checkpoint_epoch_floor")
                or response.get("next_sequence") != request.get("checkpoint_last_sequence", -1) + 1):
            raise RecoveryError("UVM sequence-resync acknowledgement does not match the journaled request")
        self.state["recovery_epoch_floor"] = response["recovery_epoch_floor"]
        self.state["last_sequence"] = request["checkpoint_last_sequence"]
        # Only a fresh authenticated newer epoch may open a restored revision
        # namespace. Preserve every superseded local record and last-good pair.
        namespace = self.state.get("desired_namespace", {"epoch": 0})
        if response["recovery_epoch_floor"] > namespace["epoch"]:
            self.state.setdefault("namespace_history", []).append({
                "namespace": namespace, **{key: self.state.get(key) for key in
                    ("last_intent", "last_ack", "last_effective", "pending_ack")}})
            self.state["desired_namespace"] = {"epoch": response["recovery_epoch_floor"],
                "configuration": response["revisions"]["configuration"]}
            self.state.pop("pending_ack", None)
        self.state["last_resync"] = {"request": request, "response": response}
        self.state.pop("pending_resync", None)
        atomic_json(self.journal, self.state)
        return response

    def renew_policy(self, config_path: Path, restored_revision: int) -> dict:
        """Journal a fresh signed policy after resync, before recovery events."""
        now = datetime.now(timezone.utc)
        last = self.state.get("last_policy") or {}
        if (last.get("epoch") == self.state["recovery_epoch_floor"] and
                last.get("request", {}).get("host_policy", {}).get("revision", 0) >= restored_revision and
                last["request"]["host_policy"] == self.config["host_policy"] and
                now <= parse_utc(last["request"]["fresh_until"])):
            self.config["host_policy"] = last["request"]["host_policy"]
            atomic_json(config_path, self.config)
            return last["response"]
        event = self.state.get("pending_policy")
        if event is None:
            policy = {**self.config["host_policy"]}
            policy["revision"] = max(policy["revision"], restored_revision) + 1
            policy["digest"] = "sha256:" + digest({k: v for k, v in policy.items() if k != "digest"})
            event = {"schema_version": 1, "deployment_id": self.deployment,
                "report_id": str(uuid.uuid4()), "sequence": self.state["last_sequence"] + 1,
                "controller_instance_id": self.config["controller_instance_id"],
                "report_kind": "policy", "host_policy": policy,
                **{k: None for k in ("desired", "settings_application", "completed_archive",
                    "freshness", "restore_verification", "recovery_epoch")},
                "observed_at": now.isoformat().replace("+00:00", "Z"),
                "fresh_until": (now + timedelta(seconds=policy["maximum_report_age_seconds"])).isoformat().replace("+00:00", "Z")}
            event["signature"] = {"algorithm": "Ed25519", "key_id": self.config["signing_key_id"],
                "value": __import__("base64").urlsafe_b64encode(_sign(canonical_json(event),
                    Path(self.config["signing_key_file"]))).decode().rstrip("=")}
            self.state["pending_policy"] = event
            atomic_json(self.journal, self.state)
        response = self._request("reports", event)
        if (response.get("accepted") is not True or response.get("report_id") != event["report_id"] or
                response.get("sequence") != event["sequence"] or
                response.get("host_policy_revision") != event["host_policy"]["revision"]):
            raise RecoveryError("policy acknowledgement differs from the journaled request")
        self.state["last_sequence"] = event["sequence"]
        self.state["last_policy"] = {"epoch": self.state["recovery_epoch_floor"], "request": event, "response": response}
        self.state.pop("pending_policy", None)
        atomic_json(self.journal, self.state)
        self.config["host_policy"] = event["host_policy"]
        atomic_json(config_path, self.config)
        return response

    @staticmethod
    def recovery_context(event: dict, *, replacement: bool = True) -> dict:
        keys = ("deployment_id", "recovery_epoch", "connector_recovery_id", "archive_id",
            "manifest_digest", "source_image_digest", "queue_inventory_digest")
        if replacement:
            keys += ("target_image_digest", "new_volume_ids")
        return {key: event.get(key) for key in keys}

    def retained_recovery_ack(self, requested: dict) -> dict | None:
        """Reuse a stage only after comparing its full immutable context."""
        records = list(self.state.get("recovery_receipts", {}).values())
        if self.state.get("last_recovery_event"):
            records.append(self.state["last_recovery_event"])
        for record in records:
            event = record["event"]
            if event["recovery_epoch"] != requested["recovery_epoch"]:
                continue
            replacement = requested["event_type"] != "restore_started"
            if self.recovery_context(event, replacement=replacement) != self.recovery_context(requested, replacement=replacement):
                # A restore_started record has not yet bound replacement IDs.
                if not (replacement and event["event_type"] == "restore_started" and
                        self.recovery_context(event, replacement=False) == self.recovery_context(requested, replacement=False)):
                    raise RecoveryError("same-epoch recovery context conflicts with durable receipt")
            if event["event_type"] == requested["event_type"]:
                stage_keys = ("previous_epoch", "verification", "public_readback_digest", "failure_code")
                if any(event.get(k) != requested.get(k) for k in stage_keys):
                    raise RecoveryError("cached recovery stage identity conflicts")
                return record["response"]
        return None

    def submit_recovery_event(self, unsigned_event: dict) -> dict:
        """Journal the exact signed event before its at-least-once submission."""
        required = {"schema_version", "deployment_id", "event_id", "recovery_epoch",
            "connector_recovery_id", "previous_epoch", "event_type", "archive_id",
            "manifest_digest", "source_image_digest", "target_image_digest",
            "new_volume_ids", "verification", "queue_inventory_digest",
            "public_readback_digest", "failure_code", "observed_at"}
        if not isinstance(unsigned_event, dict) or set(unsigned_event) != required:
            raise RecoveryError("recovery event fixture has an invalid exact shape")
        if unsigned_event.get("event_type") == "verification_passed":
            verification = unsigned_event.get("verification")
            expected_verification = {"uvm_public_api", "ce_public_api", "media_readback",
                "queue_reconciliation", "migration", "details_digest"}
            if (not isinstance(verification, dict) or set(verification) != expected_verification
                    or any(verification.get(key) != "passed" for key in expected_verification - {"details_digest"})
                    or not isinstance(verification.get("details_digest"), str)
                    or not re.fullmatch(r"sha256:[0-9a-f]{64}", verification["details_digest"])):
                raise RecoveryError("successful recovery verification lacks complete readback binding")
        retained = self.retained_recovery_ack(unsigned_event)
        if retained is not None:
            return retained
        pending = self.state.get("pending_recovery_event")
        if pending is None:
            event = {**unsigned_event, "sequence": self.state["last_sequence"] + 1,
                "controller_instance_id": self.config["controller_instance_id"]}
            event["signature"] = {"algorithm": "Ed25519",
                "key_id": self.config["signing_key_id"],
                "value": __import__("base64").urlsafe_b64encode(
                    _sign(canonical_json(event), Path(self.config["signing_key_file"]))
                    ).decode("ascii").rstrip("=")}
            self.state["pending_recovery_event"] = event
            atomic_json(self.journal, self.state)
        else:
            event = pending
            if (self.recovery_context(event) != self.recovery_context(unsigned_event) or
                    any(event.get(k) != unsigned_event.get(k) for k in
                        ("event_type", "previous_epoch", "verification", "public_readback_digest", "failure_code"))):
                raise RecoveryError("different recovery stage remains pending")
        response = self._request("recovery-events", event)
        if (response.get("accepted") is not True
                or response.get("event_id") != event.get("event_id")
                or response.get("sequence") != event.get("sequence")
                or response.get("recovery_epoch") != event.get("recovery_epoch")):
            raise RecoveryError("UVM recovery-event acknowledgement does not match the journaled event")
        self.state["last_sequence"] = event["sequence"]
        self.state["recovery_epoch_floor"] = event["recovery_epoch"]
        self.state["last_recovery_event"] = {"event": event, "response": response}
        self.state.setdefault("recovery_receipts", {})[str(event["recovery_epoch"]) + ":" + event["event_type"]] = self.state["last_recovery_event"]
        self.state.pop("pending_recovery_event", None)
        atomic_json(self.journal, self.state)
        return response

    def submit_status(self, unsigned: dict) -> dict:
        event = self.state.get("pending_status")
        if event is None:
            event = {**unsigned, "sequence": self.state["last_sequence"] + 1,
                "controller_instance_id": self.config["controller_instance_id"]}
            event["signature"] = {"algorithm": "Ed25519", "key_id": self.config["signing_key_id"],
                "value": __import__("base64").urlsafe_b64encode(_sign(canonical_json(event),
                    Path(self.config["signing_key_file"]))).decode().rstrip("=")}
            self.state["pending_status"] = event
            atomic_json(self.journal, self.state)
        response = self._request("reports", event)
        if (response.get("accepted") is not True or response.get("report_id") != event["report_id"]
                or response.get("sequence") != event["sequence"]):
            raise RecoveryError("status acknowledgement differs from the durable request")
        self.state["last_sequence"] = event["sequence"]
        self.state["last_status"] = {"request": event, "response": response}
        self.state.pop("pending_status", None)
        atomic_json(self.journal, self.state)
        return response

    def submit_quarantine(self, unsigned: dict) -> dict:
        identity = unsigned["connector_id"] + ":" + ",".join(unsigned["intent_ids"]) + ":" + str(unsigned["recovery_epoch"])
        receipts = self.state.setdefault("quarantine_receipts", {})
        stable = ("deployment_id", "recovery_epoch", "connector_recovery_id", "connector_id", "intent_ids", "reason_code")
        if identity in receipts:
            if any(receipts[identity]["request"].get(key) != unsigned.get(key) for key in stable):
                raise RecoveryError("cached quarantine acknowledgement conflicts with restore identity")
            return receipts[identity]["response"]
        event = self.state.get("pending_quarantine")
        if event is None:
            event = dict(unsigned)
            event["signature"] = {"algorithm": "Ed25519", "key_id": self.config["signing_key_id"],
                "value": __import__("base64").urlsafe_b64encode(_sign(canonical_json(unsigned),
                    Path(self.config["signing_key_file"]))).decode().rstrip("=")}
            self.state["pending_quarantine"] = event
            atomic_json(self.journal, self.state)
        if any(event.get(key) != unsigned.get(key) for key in stable):
            raise RecoveryError("a different quarantine acknowledgement remains pending")
        response = self._request("connector-quarantine", event)
        if (response.get("accepted") is not True or response.get("event_id") != event["event_id"]
                or response.get("recovery_epoch") != event["recovery_epoch"]):
            raise RecoveryError("quarantine acknowledgement differs from the durable request")
        receipts[identity] = {"request": event, "response": response}
        self.state.pop("pending_quarantine", None)
        atomic_json(self.journal, self.state)
        return response

    def _request(self, path: str, body: dict | None = None) -> dict:
        url = self.config["endpoint"].rstrip("/") + f"/recovery-control/v1/{self.deployment}/{path}"
        request = urllib.request.Request(url, data=canonical_json(body) if body is not None else None,
            headers={"Authorization": "Bearer " + self.token, "Accept": "application/json",
                **({"Content-Type": "application/json"} if body is not None else {})},
            method="POST" if body is not None else "GET")
        with urllib.request.urlopen(request, context=self.tls, timeout=15) as response:
            result = json.loads(response.read())
        if body is not None:
            self.state.setdefault("submission_receipts", []).append({"path": path, "request": body, "response": result})
            atomic_json(self.journal, self.state)
        return result

    def reconcile_desired(self) -> dict:
        # Complete the journaled at-least-once acknowledgement first. UVM may
        # already have retained it and admitted a newer desired revision after
        # the response was lost; fetching that revision must not strand replay.
        pending_ack = self.state.get("pending_ack")
        if pending_ack is not None:
            response = self._request("acks", pending_ack)
            if response.get("ack_id") != pending_ack["ack_id"] or response.get("accepted") is not True:
                raise RecoveryError("UVM did not return the retained pending acknowledgement")
            self.state["last_sequence"] = pending_ack["sequence"]
            self.state["last_ack"] = response
            self.state["last_intent"]["status"] = pending_ack["outcome"]
            if pending_ack["outcome"] == "applied":
                self.state["last_effective"] = {"revision": pending_ack["active_revision"],
                    "digest": pending_ack["active_digest"]}
            self.state.pop("pending_ack", None)
            atomic_json(self.journal, self.state)
            return {"state": pending_ack["outcome"], "revision": pending_ack["requested_revision"],
                "sequence": pending_ack["sequence"], "replayed": True}
        dto = self._request("desired")
        if (dto.get("schema_version") != 1 or dto.get("deployment_id") != self.deployment
                or not isinstance(dto.get("revisions"), dict)):
            raise RecoveryError("UVM desired-settings DTO is invalid")
        desired = dto.get("desired")
        if desired is None:
            return {"state": "unconfigured", "sequence": self.state["last_sequence"]}
        if not isinstance(desired, dict) or set(desired) != {
                "revision", "digest", "values", "command_id", "intent_id", "issued_at"}:
            raise RecoveryError("UVM desired settings have an invalid exact shape")
        if (not isinstance(desired["digest"], str) or not re.fullmatch(
                r"sha256:[0-9a-f]{64}", desired["digest"])):
            raise RecoveryError("UVM desired digest is malformed")
        try:
            if str(uuid.UUID(desired["command_id"])) != desired["command_id"]:
                raise ValueError
            if str(uuid.UUID(desired["intent_id"])) != desired["intent_id"]:
                raise ValueError
            parse_utc(desired["issued_at"])
        except (ValueError, TypeError, KeyError):
            raise RecoveryError("UVM desired identity or issue time is malformed") from None
        prior = self.state.get("last_intent") or {}
        namespace = self.state.get("desired_namespace", {"epoch": 0})
        prior_in_namespace = prior.get("recovery_epoch", 0) == namespace["epoch"]
        if (type(desired["revision"]) is not int or desired["revision"] < 1
                or digest(desired["values"]) != desired["digest"].removeprefix("sha256:")
                or desired["revision"] < namespace.get("configuration", 0)
                or (prior_in_namespace and desired["revision"] < _last_intent_revision(self.state))):
            raise RecoveryError("UVM desired revision is malformed or regressed")
        policy = self.config["host_policy"]
        if (dto["revisions"].get("host_policy") != policy.get("revision")
                or policy.get("digest") != "sha256:" + digest({key: value for key, value in policy.items()
                    if key != "digest"})):
            raise RecoveryError("UVM and independently configured host policy revisions differ")
        rejected = False
        try:
            values = validate_backup_values(desired["values"], policy)
        except ValueError:
            # This desired document was admitted under an earlier policy.
            # Report a bounded failure without replacing the running schedule.
            values, rejected = desired["values"], True
        if desired["digest"] != "sha256:" + digest(values):
            raise RecoveryError("UVM desired digest does not match canonical values")
        if prior_in_namespace and prior and prior.get("revision") == desired["revision"]:
            if prior.get("digest") != desired["digest"] or prior.get("intent_id") != desired["intent_id"]:
                raise RecoveryError("same settings revision changed its digest or intent")
        else:
            self.state["last_intent"] = {"revision": desired["revision"],
                "digest": desired["digest"], "intent_id": desired["intent_id"],
                "command_id": desired["command_id"], "status": "received", "recovery_epoch": namespace["epoch"]}
            atomic_json(self.journal, self.state)
        if not rejected and self.state["last_intent"].get("status") == "applied":
            try:
                readback = json.loads(Path(self.config["scheduler_readback_file"]).read_text())
                if (readback.get("revision") == desired["revision"] and
                        readback.get("digest") == desired["digest"] and
                        readback.get("intent_id") == desired["intent_id"] and
                        readback.get("values") == values and
                        0 <= (datetime.now(timezone.utc) - parse_utc(readback["observed_at"])).total_seconds() <= 5):
                    return {"state": "applied", "revision": desired["revision"],
                        "sequence": self.state["last_sequence"], "replayed": False}
            except (OSError, ValueError, KeyError):
                pass
        active = {"schema_version": 1, "deployment_id": self.deployment,
            "revision": desired["revision"], "digest": desired["digest"],
            "intent_id": desired["intent_id"], "values": values,
            "applied_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")}
        active["recovery_epoch"] = namespace["epoch"]
        if not rejected:
            atomic_json(self.active_file, active)
        outcome, failure_code, consumed = "uncertain", "consumer_readback_unavailable", None
        deadline = time.monotonic() + 5
        if rejected:
            outcome, failure_code = "failed", "host_policy_rejected"
        while not rejected and time.monotonic() < deadline:
            try:
                candidate = json.loads(Path(self.config["scheduler_readback_file"]).read_text())
                observed = parse_utc(candidate["observed_at"])
                if (candidate.get("deployment_id") == self.deployment and
                        candidate.get("revision") == desired["revision"] and
                        candidate.get("digest") == desired["digest"] and
                        candidate.get("intent_id") == desired["intent_id"] and
                        candidate.get("values") == values and
                        observed >= parse_utc(active["applied_at"]) and
                        0 <= (datetime.now(timezone.utc) - observed).total_seconds() <= 5):
                    consumed = candidate
                    outcome, failure_code = "applied", None
                    break
            except (OSError, ValueError, KeyError):
                pass
            try:
                failure = json.loads(Path(self.config["scheduler_readback_file"]).with_suffix(".failure.json").read_text())
                if (failure.get("revision") == desired["revision"] and
                        failure.get("digest") == desired["digest"] and failure.get("intent_id") == desired["intent_id"] and
                        failure.get("failure_code") == "consumer_rejected" and
                        parse_utc(failure["observed_at"]) >= parse_utc(active["applied_at"])):
                    outcome, failure_code = "failed", "consumer_rejected"
                    break
            except (OSError, ValueError, KeyError):
                pass
            time.sleep(0.1)
        last_good = self.state.get("last_effective") or {}
        active_revision = desired["revision"] if consumed else last_good.get("revision")
        active_digest = desired["digest"] if consumed else last_good.get("digest")
        ack_id = str(uuid.uuid4())
        sequence = self.state["last_sequence"] + 1
        now = datetime.now(timezone.utc).replace(microsecond=0)
        unsigned = {"schema_version": 1, "deployment_id": self.deployment,
            "ack_id": ack_id, "sequence": sequence,
            "controller_instance_id": self.config["controller_instance_id"],
            "intent_id": desired["intent_id"], "requested_revision": desired["revision"],
            "requested_digest": desired["digest"], "active_revision": active_revision,
            "active_digest": active_digest, "host_policy_revision": policy["revision"],
            "outcome": outcome, "failure_code": failure_code,
            "observed_at": now.isoformat().replace("+00:00", "Z")}
        signed = {**unsigned, "signature": {"algorithm": "Ed25519",
            "key_id": self.config["signing_key_id"],
            "value": __import__("base64").urlsafe_b64encode(
                _sign(canonical_json(unsigned), Path(self.config["signing_key_file"]))
                ).decode("ascii").rstrip("=")}}
        # Store the exact request before sending it so retries cannot skip a
        # consumed sequence or invent a new acknowledgement identity.
        self.state["pending_ack"] = signed
        atomic_json(self.journal, self.state)
        response = self._request("acks", signed)
        if response.get("ack_id") != ack_id or response.get("accepted") is not True:
            raise RecoveryError("UVM did not retain the exact application acknowledgement")
        self.state["last_sequence"] = sequence
        self.state["last_ack"] = response
        self.state["last_intent"]["status"] = outcome
        if outcome == "applied":
            self.state["last_effective"] = {"revision": active_revision, "digest": active_digest}
        self.state.pop("pending_ack", None)
        atomic_json(self.journal, self.state)
        return {"state": outcome, "revision": desired["revision"], "sequence": sequence}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--once", action="store_true")
    parser.add_argument("--poll-seconds", type=int, default=10)
    parser.add_argument("--resync-database-epoch", type=int)
    parser.add_argument("--resync-database-sequence", type=int)
    parser.add_argument("--resync-checkpoint-epoch", type=int)
    parser.add_argument("--force-resync", action="store_true")
    parser.add_argument("--recovery-event-json", type=Path)
    parser.add_argument("--schema-compatibility-admission-json", type=Path)
    parser.add_argument("--development-rollback-request-json", type=Path)
    parser.add_argument("--status-json", type=Path)
    args = parser.parse_args()
    if not 1 <= args.poll_seconds <= 3600:
        raise RecoveryError("poll interval is outside host-owned bounds")
    controller = Controller(load_config(args.config))
    if args.schema_compatibility_admission_json is not None:
        admission = json.loads(args.schema_compatibility_admission_json.read_text(encoding="utf-8"))
        print(json.dumps(controller.journal_schema_compatibility_admission(admission),
            sort_keys=True, separators=(",", ":")))
        return
    if args.development_rollback_request_json is not None:
        request = json.loads(args.development_rollback_request_json.read_text(encoding="utf-8"))
        print(json.dumps(controller.journal_development_rollback_request(request),
            sort_keys=True, separators=(",", ":")))
        return
    if args.status_json is not None:
        print(json.dumps(controller.submit_status(json.loads(args.status_json.read_text())), separators=(",", ":")))
        return
    if args.recovery_event_json is not None:
        try:
            event = json.loads(args.recovery_event_json.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise RecoveryError("recovery event input is unavailable") from exc
        print(json.dumps(controller.submit_recovery_event(event), separators=(",", ":")))
        return
    resync_args = (args.resync_database_epoch, args.resync_database_sequence,
        args.resync_checkpoint_epoch)
    if any(value is not None for value in resync_args):
        if any(value is None for value in resync_args):
            raise RecoveryError("all three sequence-resync counters are required together")
        print(json.dumps(controller.resynchronize(database_epoch_seen=args.resync_database_epoch,
            database_sequence_seen=args.resync_database_sequence,
            checkpoint_epoch_floor=args.resync_checkpoint_epoch, force=args.force_resync), separators=(",", ":")))
        return
    while True:
        result = controller.reconcile_desired()
        print(json.dumps(result, separators=(",", ":")), flush=True)
        if args.once:
            return
        time.sleep(args.poll_seconds)


if __name__ == "__main__":
    try:
        main()
    except (RecoveryError, OSError, ValueError, urllib.error.URLError) as exc:
        print(f"backup controller failed closed: {type(exc).__name__}", file=sys.stderr)
        raise SystemExit(2)
