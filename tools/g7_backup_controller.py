#!/usr/bin/env python3
"""Independent local host controller for backup desired settings and acks."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
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
        "active_settings_file"}
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
                "last_resync", "pending_recovery_event", "last_recovery_event"}
                or not required.issubset(value)
                or type(value.get("schema_version")) is not int or value.get("schema_version") != 1
                or value.get("deployment_id") != self.deployment
                or value.get("controller_instance_id") != self.config["controller_instance_id"]
                or type(value.get("last_sequence")) is not int
                or type(value.get("recovery_epoch_floor")) is not int):
            raise RecoveryError("external controller journal is invalid")
        return value

    def resynchronize(self, *, database_epoch_seen: int, database_sequence_seen: int,
            checkpoint_epoch_floor: int) -> dict:
        """Authenticate DB rollback recovery and journal the transport ack first."""
        for value in (database_epoch_seen, database_sequence_seen, checkpoint_epoch_floor):
            if type(value) is not int or value < 0:
                raise RecoveryError("sequence resync counters are invalid")
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
        self.state["last_resync"] = {"request": request, "response": response}
        self.state.pop("pending_resync", None)
        atomic_json(self.journal, self.state)
        return response

    def submit_recovery_event(self, unsigned_event: dict) -> dict:
        """Journal the exact signed event before its at-least-once submission."""
        required = {"schema_version", "deployment_id", "event_id", "recovery_epoch",
            "connector_recovery_id", "previous_epoch", "event_type", "archive_id",
            "manifest_digest", "source_image_digest", "target_image_digest",
            "new_volume_ids", "verification", "queue_inventory_digest",
            "public_readback_digest", "failure_code", "observed_at"}
        if not isinstance(unsigned_event, dict) or set(unsigned_event) != required:
            raise RecoveryError("recovery event fixture has an invalid exact shape")
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
        response = self._request("recovery-events", event)
        if (response.get("accepted") is not True
                or response.get("event_id") != event.get("event_id")
                or response.get("sequence") != event.get("sequence")
                or response.get("recovery_epoch") != event.get("recovery_epoch")):
            raise RecoveryError("UVM recovery-event acknowledgement does not match the journaled event")
        self.state["last_sequence"] = event["sequence"]
        self.state["recovery_epoch_floor"] = event["recovery_epoch"]
        self.state["last_recovery_event"] = {"event": event, "response": response}
        self.state.pop("pending_recovery_event", None)
        atomic_json(self.journal, self.state)
        return response

    def _request(self, path: str, body: dict | None = None) -> dict:
        url = self.config["endpoint"].rstrip("/") + f"/recovery-control/v1/{self.deployment}/{path}"
        request = urllib.request.Request(url, data=canonical_json(body) if body is not None else None,
            headers={"Authorization": "Bearer " + self.token, "Accept": "application/json",
                **({"Content-Type": "application/json"} if body is not None else {})},
            method="POST" if body is not None else "GET")
        with urllib.request.urlopen(request, context=self.tls, timeout=15) as response:
            return json.loads(response.read())

    def reconcile_desired(self) -> dict:
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
        if (type(desired["revision"]) is not int or desired["revision"] < 1
                or digest(desired["values"]) != desired["digest"].removeprefix("sha256:")
                or desired["revision"] < _last_intent_revision(self.state)):
            raise RecoveryError("UVM desired revision is malformed or regressed")
        policy = self.config["host_policy"]
        if (dto["revisions"].get("host_policy") != policy.get("revision")
                or policy.get("digest") != "sha256:" + digest({key: value for key, value in policy.items()
                    if key != "digest"})):
            raise RecoveryError("UVM and independently configured host policy revisions differ")
        values = validate_backup_values(desired["values"], policy)
        if desired["digest"] != "sha256:" + digest(values):
            raise RecoveryError("UVM desired digest does not match canonical values")
        if prior and prior.get("revision") == desired["revision"]:
            if prior.get("digest") != desired["digest"] or prior.get("intent_id") != desired["intent_id"]:
                raise RecoveryError("same settings revision changed its digest or intent")
        else:
            self.state["last_intent"] = {"revision": desired["revision"],
                "digest": desired["digest"], "intent_id": desired["intent_id"],
                "command_id": desired["command_id"], "status": "received"}
            atomic_json(self.journal, self.state)
        if (self.state.get("last_intent", {}).get("status") == "applied"
                and not self.state.get("pending_ack")):
            try:
                active = json.loads(self.active_file.read_text(encoding="utf-8"))
            except (OSError, ValueError) as exc:
                raise RecoveryError("last applied settings record is unavailable") from exc
            if active.get("revision") != desired["revision"] or active.get("digest") != desired["digest"]:
                raise RecoveryError("last applied settings record changed")
            return {"state": "applied", "revision": desired["revision"],
                "sequence": self.state["last_sequence"], "replayed": False}
        pending_ack = self.state.get("pending_ack")
        if pending_ack is not None:
            if (pending_ack.get("intent_id") != desired["intent_id"]
                    or pending_ack.get("requested_revision") != desired["revision"]
                    or pending_ack.get("requested_digest") != desired["digest"]):
                raise RecoveryError("pending acknowledgement belongs to a different desired intent")
            response = self._request("acks", pending_ack)
            if response.get("ack_id") != pending_ack["ack_id"] or response.get("accepted") is not True:
                raise RecoveryError("UVM did not return the retained pending acknowledgement")
            self.state["last_sequence"] = pending_ack["sequence"]
            self.state["last_ack"] = response
            self.state["last_intent"]["status"] = "applied"
            self.state.pop("pending_ack", None)
            atomic_json(self.journal, self.state)
            return {"state": "applied", "revision": desired["revision"],
                "sequence": pending_ack["sequence"], "replayed": True}
        active = {"schema_version": 1, "deployment_id": self.deployment,
            "revision": desired["revision"], "digest": desired["digest"],
            "intent_id": desired["intent_id"], "values": values,
            "applied_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")}
        atomic_json(self.active_file, active)
        ack_id = str(uuid.uuid4())
        sequence = self.state["last_sequence"] + 1
        now = datetime.now(timezone.utc).replace(microsecond=0)
        unsigned = {"schema_version": 1, "deployment_id": self.deployment,
            "ack_id": ack_id, "sequence": sequence,
            "controller_instance_id": self.config["controller_instance_id"],
            "intent_id": desired["intent_id"], "requested_revision": desired["revision"],
            "requested_digest": desired["digest"], "active_revision": desired["revision"],
            "active_digest": desired["digest"], "host_policy_revision": policy["revision"],
            "outcome": "applied", "failure_code": None,
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
        self.state["last_intent"]["status"] = "applied"
        self.state.pop("pending_ack", None)
        atomic_json(self.journal, self.state)
        return {"state": "applied", "revision": desired["revision"], "sequence": sequence}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--once", action="store_true")
    parser.add_argument("--poll-seconds", type=int, default=10)
    parser.add_argument("--resync-database-epoch", type=int)
    parser.add_argument("--resync-database-sequence", type=int)
    parser.add_argument("--resync-checkpoint-epoch", type=int)
    parser.add_argument("--recovery-event-json", type=Path)
    args = parser.parse_args()
    if not 1 <= args.poll_seconds <= 3600:
        raise RecoveryError("poll interval is outside host-owned bounds")
    controller = Controller(load_config(args.config))
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
            checkpoint_epoch_floor=args.resync_checkpoint_epoch), separators=(",", ":")))
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
