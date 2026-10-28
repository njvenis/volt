#!/usr/bin/env python3
"""Capture and independently sign one bounded G7 preservation readcheck."""
from __future__ import annotations

import argparse
import base64
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen
from uuid import uuid4
import fcntl

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from uvm.operations.preservation import (CLASSES, canonical_json, tuple_digest,
    unknown_class, utc_timestamp)

UTC = timezone.utc
MAX_EVIDENCE_BYTES = 16 * 1024 * 1024


def _private_bytes(path: Path, maximum: int) -> bytes:
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size > maximum or info.st_mode & 0o077:
            raise ValueError("unsafe private input")
        chunks = []
        remaining = maximum + 1
        while remaining:
            part = os.read(fd, min(65536, remaining))
            if not part:
                break
            chunks.append(part)
            remaining -= len(part)
        value = b"".join(chunks)
        if len(value) > maximum:
            raise ValueError("private input exceeds bound")
        return value
    finally:
        os.close(fd)


def _request(origin: str, path: str, token: str, *, body: dict | None = None,
             timeout: int = 30) -> tuple[int, bytes, dict]:
    encoded = None if body is None else canonical_json(body)
    request = Request(origin.rstrip("/") + path, data=encoded,
        headers={"Authorization": "Bearer " + token,
            "Accept": "application/json" if body is not None else "application/octet-stream",
            **({"Content-Type": "application/json"} if body is not None else {})},
        method="POST" if body is not None else "GET")
    try:
        with urlopen(request, timeout=timeout) as response:
            return response.status, response.read(MAX_EVIDENCE_BYTES + 1), {
                key.lower(): value for key, value in response.headers.items()}
    except HTTPError as exc:
        headers = dict(exc.headers)
        try:
            body = json.loads(exc.read(4096))
            detail = body.get("detail", body.get("error", body))
            code = detail.get("code") if isinstance(detail, dict) else None
            if code in {"evidence_missing", "evidence_changed", "evidence_unreadable"}:
                headers["evidence-code"] = code
        except (ValueError, AttributeError):
            pass
        return exc.code, b"", headers
    except URLError as exc:
        raise RuntimeError("source_api_unavailable") from None


def _dto(class_id: str, period: str, members: list[dict], checked_at: str) -> dict:
    count = len(members)
    dates = [item["retained_at"] for item in members]
    oldest = min(dates) if dates and all(dates) else None
    baseline = hashlib.sha256(canonical_json([
        [item["record_key"], item["record_kind"], item["record_sha256"], item["expected_sha256"]]
        for item in members])).hexdigest()
    return {"class_id": class_id, "minimum_period": period, "state": "verified",
        "reasons": [], "expected_records": count, "verified_records": count,
        "missing_records": 0, "changed_records": 0, "unreadable_records": 0,
        "unexpected_records": 0, "oldest_retained_at": oldest,
        "baseline_digest": "sha256:" + baseline, "audit_copy": None}


def _safe_members(source_class: dict, token: str, origin: str, expected_inventory=None) -> list[dict]:
    members = source_class.get("members")
    if not isinstance(members, list):
        raise ValueError("source_member_list_invalid")
    result = []
    expected_by_key = {item["member"]["record_key"]: item for item in (expected_inventory or {}).get("members", [])}
    observed_registrations = {item.get("evidence_id") for item in members
        if isinstance(item, dict) and item.get("record_kind") == "evidence_registration"}
    verified_bytes = {}
    byte_errors = {}
    for item in members:
        if not isinstance(item, dict):
            raise ValueError("source_member_invalid")
        kind, stable_key = item.get("record_kind"), item.get("stable_key")
        record_digest, raw_digest = item.get("record_sha256"), item.get("raw_sha256")
        byte_size, evidence_id = item.get("byte_size"), item.get("evidence_id")
        retained_at = item.get("observed_at")
        if (not isinstance(kind, str) or not isinstance(stable_key, str)
                or not isinstance(record_digest, str) or len(record_digest) != 64
                or (raw_digest is not None and (not isinstance(raw_digest, str) or len(raw_digest) != 64))
                or (retained_at is not None and not isinstance(retained_at, str))):
            raise ValueError("source_member_invalid")
        independent = expected_by_key.get(kind + ":" + stable_key)
        incomplete_link = evidence_id is None or byte_size is None
        if raw_digest is not None and incomplete_link and independent is not None:
            evidence_id = independent["member"]["evidence_id"]
            byte_size = independent["byte_size"]
            if evidence_id not in observed_registrations:
                verified_bytes[evidence_id] = (None, None)
                byte_errors[evidence_id] = "evidence_unreadable"
        byte_bearing = raw_digest is not None
        if byte_bearing:
            if (not isinstance(evidence_id, str) or type(byte_size) is not int
                    or not 0 <= byte_size <= MAX_EVIDENCE_BYTES):
                raise ValueError("source_byte_linkage_invalid")
            previous = verified_bytes.get(evidence_id)
            if previous is None:
                status, raw, headers = _request(origin,
                    "/api/v1/operations/preservation/evidence/" + evidence_id, token)
                if status >= 500 or status in {401, 403, 404}:
                    raise RuntimeError("evidence_readback_unavailable")
                if status == 409:
                    # Registration exists; absence/corruption is an established gap,
                    # not a failed dependency read. No partial body is retained.
                    verified_bytes[evidence_id] = (None, None)
                    byte_errors[evidence_id] = headers.get("evidence-code", "evidence_unreadable")
                elif status == 200 and len(raw) <= MAX_EVIDENCE_BYTES:
                    actual_digest, actual_size = hashlib.sha256(raw).hexdigest(), len(raw)
                    digest_header = headers.get("content-digest", "")
                    if digest_header != "sha-256=:" + base64.b64encode(bytes.fromhex(actual_digest)).decode("ascii") + ":":
                        raise RuntimeError("evidence_digest_header_mismatch")
                    verified_bytes[evidence_id] = (actual_digest, actual_size)
                else:
                    raise RuntimeError("evidence_readback_unavailable")
            actual_digest, actual_size = verified_bytes[evidence_id]
        elif evidence_id is not None or byte_size is not None:
            raise ValueError("metadata_byte_fields_conflict")
        result.append({"record_key": kind + ":" + stable_key,
            "record_kind": kind, "retained_at": retained_at,
            "state": ({"evidence_missing": "missing", "evidence_changed": "changed"}.get(
                byte_errors.get(evidence_id), "unreadable") if byte_bearing and actual_digest is None else
                "changed" if byte_bearing and (actual_digest != raw_digest or actual_size != byte_size) else "verified"),
            "reasons": ([byte_errors.get(evidence_id, "bytes_unreadable")] if byte_bearing and actual_digest is None else
                ["bytes_changed"] if byte_bearing and (actual_digest != raw_digest or actual_size != byte_size) else []),
            "expected_sha256": raw_digest, "actual_sha256": actual_digest if byte_bearing else None,
            "record_sha256": None if byte_errors.get(evidence_id) == "evidence_missing" else record_digest, "byte_bearing": byte_bearing,
            "evidence_id": evidence_id})
    result.sort(key=lambda item: (item["record_kind"].encode(), item["record_key"].encode()))
    keys = [(item["record_kind"], item["record_key"]) for item in result]
    if len(keys) != len(set(keys)):
        raise ValueError("source_member_identity_conflict")
    return result


def _publish_no_replace(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
    info = path.parent.stat(follow_symlinks=False)
    # The caller keeps the run root private. The mounted report directory and
    # signed report are readable by the unprivileged UVM process; neither is
    # writable by group/other and the report contains no raw evidence bytes.
    if not stat.S_ISDIR(info.st_mode) or info.st_mode & 0o022:
        raise ValueError("unsafe_report_directory")
    temp_name = None
    try:
        fd, temp_name = tempfile.mkstemp(prefix=".g7-report-", dir=path.parent)
        os.fchmod(fd, 0o644)
        with os.fdopen(fd, "wb", closefd=True) as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        # Hard-link publication is atomic and fails if an immutable report for
        # this exact tuple has already been published.
        os.link(temp_name, path, follow_symlinks=False)
        dir_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
    except FileExistsError:
        raise RuntimeError("report_publication_conflict") from None
    finally:
        if temp_name is not None:
            try:
                os.unlink(temp_name)
            except FileNotFoundError:
                pass


def _assert_preserved_inventory(previous_path: str | None, private_key,
                                classes: list[dict], scope: tuple[str, str, str],
                                deployment_id: str, storage_generation: str,
                                key_id: str) -> None:
    if previous_path is None:
        return
    previous = json.loads(_private_bytes(Path(previous_path), 32 * 1024 * 1024))
    if (not isinstance(previous, dict) or set(previous) != {"payload", "signature"}
            or not isinstance(previous["payload"], dict)
            or not isinstance(previous["signature"], dict)
            or previous["signature"].get("algorithm") != "Ed25519"
            or previous["signature"].get("key_id") != key_id):
        raise ValueError("previous_report_invalid")
    signature = previous["signature"].get("value")
    if not isinstance(signature, str):
        raise ValueError("previous_report_invalid")
    payload = previous["payload"]
    signed = b"VOLT-G7-PRESERVATION\0readcheck-report-v1\0" + canonical_json(payload)
    try:
        private_key.public_key().verify(base64.b64decode(signature, validate=True), signed)
    except Exception:
        raise ValueError("previous_report_untrusted") from None
    if (payload.get("contract_id") != "g7-data-preservation/v1"
            or payload.get("purpose") != "readcheck-report-v1"
            or payload.get("deployment_id") != deployment_id
            or tuple(payload.get("scope", ())) != scope
            or payload.get("storage_generation") == storage_generation
            or not isinstance(payload.get("classes"), list)):
        raise ValueError("previous_report_binding_invalid")
    old_classes = {item.get("class_id"): item for item in payload["classes"]
        if isinstance(item, dict)}
    new_classes = {item.get("class_id"): item for item in classes
        if isinstance(item, dict)}
    if set(old_classes) != set(new_classes) or len(old_classes) != len(payload["classes"]):
        raise ValueError("previous_report_class_set_invalid")
    for class_id, old in old_classes.items():
        new = new_classes[class_id]
        old_members, new_members = old.get("members"), new.get("members")
        if (old.get("dto", {}).get("state") != "verified"
                or not isinstance(old_members, list) or not isinstance(new_members, list)):
            raise ValueError("previous_report_inventory_incomplete")
        old_by_key = {(item.get("record_kind"), item.get("record_key")): item
            for item in old_members if isinstance(item, dict)}
        new_by_key = {(item.get("record_kind"), item.get("record_key")): item
            for item in new_members if isinstance(item, dict)}
        if (len(old_by_key) != len(old_members) or len(new_by_key) != len(new_members)
                or set(old_by_key) != set(new_by_key)):
            raise ValueError("preservation_inventory_continuity_mismatch")
        for key, before in old_by_key.items():
            after = new_by_key[key]
            stable_fields = ("record_kind", "record_key", "expected_sha256",
                "byte_bearing", "evidence_id")
            try:
                same_time = (before.get("retained_at") is None and after.get("retained_at") is None
                    or utc_timestamp(before["retained_at"]) == utc_timestamp(after["retained_at"]))
            except (KeyError, TypeError, ValueError):
                same_time = False
            if (any(before.get(field) != after.get(field) for field in stable_fields)
                    or not same_time):
                raise ValueError("preservation_inventory_continuity_mismatch")
            if before.get("record_sha256") != after.get("record_sha256"):
                if class_id != "product.audit_history" or any(
                    before.get(field) != after.get(field) for field in
                    ("state", "reasons", "legacy_payload_sha256", "canonicalization_version",
                     "representation_metadata")):
                    raise ValueError("preservation_inventory_continuity_mismatch")


from uvm.operations.preservation_streams import reconcile_members as _reconcile


def _counts(dto, members):
    dto = dict(dto)
    counts = {state: sum(item["state"] == state for item in members)
        for state in ("verified", "missing", "changed", "unreadable", "unexpected")}
    dto.update({state + "_records": count for state, count in counts.items()})
    dto["oldest_retained_at"] = min((item["retained_at"] for item in members
        if item["state"] == "verified" and item["retained_at"]), default=None) if all(
            item["retained_at"] for item in members if item["state"] != "unexpected") else None
    dto["expected_records"] = sum(counts[s] for s in ("verified", "missing", "changed", "unreadable"))
    if any(counts[s] for s in ("missing", "changed", "unreadable", "unexpected")):
        dto["state"] = "gap"
        dto["reasons"] = sorted(set(dto["reasons"]) | {reason for item in members for reason in item["reasons"]})
    return dto


def _read_controller_bytes(path):
    from uvm.operations.preservation import _read_regular
    return _read_regular(path, 65536)


def _controller(args, private_key):
    from uvm.operations.preservation_streams import CONTROLLER, sign
    return sign({"contract_id": "g7-data-preservation/v1", "purpose": CONTROLLER,
        "deployment_id": args.deployment_id, "recovery_epoch": args.recovery_epoch,
        "storage_generation": args.storage_generation, "volume_set_digest": args.volume_set_digest,
        "key_id": args.key_id, "schema_head_digest": args.schema_head_digest,
        "key_valid_from": args.key_valid_from, "key_valid_until": args.key_valid_until},
        private_key, args.key_id)


def _prepare_trust(args, private_key):
    root = Path(args.trust_dir)
    root.mkdir(parents=True, exist_ok=True, mode=0o755); root.chmod(0o755)
    public_path = root / "public.pem"
    public_bytes = private_key.public_key().public_bytes(serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo)
    if public_path.exists():
        if public_path.read_bytes() != public_bytes: raise ValueError("trust_key_conflict")
    else:
        public_path.write_bytes(public_bytes); public_path.chmod(0o644)
    return root, public_path


def _provision_controller(args, private_key):
    """Explicit host/controller operation precedes all generation-bound reads."""
    from uvm.operations.preservation_streams import immutable, digest, replace_head
    root, _ = _prepare_trust(args, private_key)
    lock_fd = os.open(root / ".publisher-lock", os.O_CREAT | os.O_RDWR, 0o600)
    try:
        fcntl.flock(lock_fd, fcntl.LOCK_EX)
        controller = _controller(args, private_key)
        immutable(root / "objects" / (digest(controller) + ".json"), controller)
        replace_head(root / "controller.json", controller)
    finally:
        os.close(lock_fd)


def _bind_streams(args, payload, private_key, byte_sizes):
    from uvm.operations.preservation_streams import (INVENTORY, REPORT,
        namespace, publish, read_stream, digest, snapshot_id)
    root, public_path = _prepare_trust(args, private_key)
    lock_fd = os.open(root / ".publisher-lock", os.O_CREAT | os.O_RDWR, 0o600)
    try:
        fcntl.flock(lock_fd, fcntl.LOCK_EX)
        controller = _controller(args, private_key)
        if json.loads(_read_controller_bytes(root / "controller.json")) != controller:
            raise ValueError("deployment_controller_mismatch")
        bindings = []
        for entry in payload["classes"]:
            class_id = entry["class_id"]
            ns = namespace(args.deployment_id, INVENTORY, payload["scope"], class_id)
            try:
                previous, previous_digest = read_stream(root, public_path, ns, key_id=args.key_id)
                baseline = previous.get("content")
            except FileNotFoundError:
                baseline = None
            observed = entry["members"]
            if baseline is None:
                if not args.admit_new_members or entry["dto"]["state"] not in {"verified", "gap"}:
                    raise ValueError("independent_baseline_missing")
                if any(item["state"] != "verified" for item in observed):
                    raise ValueError("initial_inventory_not_verified")
                baseline = {"schema_version": 1, "class_id": class_id, "complete": True,
                    "capture_id": payload["snapshot_id"], "captured_at": payload["class_checked_at"][class_id],
                    "source_watermark": payload["source_watermark"], "schema_head_digest": args.schema_head_digest,
                    "key_valid_from": args.key_valid_from, "key_valid_until": args.key_valid_until,
                    "members": [{"member": item, "byte_size": byte_sizes.get(item["record_key"])} for item in observed],
                    "audit_targets": entry.get("audit_targets")}
            elif args.admit_new_members:
                expected_keys = {item["member"]["record_key"] for item in baseline["members"]}
                additions = [{"member": item, "byte_size": byte_sizes.get(item["record_key"])}
                    for item in observed if item["record_key"] not in expected_keys and item["state"] == "verified"]
                if additions:
                    targets = baseline.get("audit_targets")
                    if class_id == "product.audit_history":
                        targets = [json.loads(item) for item in sorted({json.dumps(item, sort_keys=True)
                            for item in [*(targets or []), *entry.get("audit_targets", [])]})]
                    baseline = {**baseline, "members": baseline["members"] + additions,
                        "capture_id": payload["snapshot_id"], "captured_at": payload["class_checked_at"][class_id],
                        "source_watermark": payload["source_watermark"], "audit_targets": targets}
            if datetime.fromisoformat(baseline["captured_at"].replace("Z", "+00:00")) > datetime.fromisoformat(
                    payload["class_checked_at"][class_id].replace("Z", "+00:00")):
                raise ValueError("inventory_newer_than_observation")
            inventory_head = publish(root, private_key, args.key_id, ns, baseline)
            if class_id == "product.audit_history":
                entry["audit_targets"] = baseline["audit_targets"]
            if entry["dto"]["state"] in {"verified", "gap"} or entry["dto"].get("expected_records") is not None:
                entry["members"] = _reconcile(baseline["members"], observed)
                entry["dto"] = _counts(entry["dto"], entry["members"])
                entry["dto"]["baseline_digest"] = "sha256:" + inventory_head["digest"]
                if class_id == "product.audit_history":
                    entry["audit_targets"] = baseline["audit_targets"]
                    audit = dict(entry["dto"]["audit_copy"])
                    for kind, suffix in (("audit_event", "events"), ("audit_copy_receipt_established", "receipts")):
                        items = [m for m in entry["members"] if m["record_kind"] == kind]
                        audit["expected_"+suffix] = sum(m["state"] != "unexpected" for m in items)
                        for state, field in (("verified","matching"),("missing","missing"),("changed","changed"),("unexpected","unexpected")):
                            audit[field+"_"+suffix] = sum(m["state"] == state for m in items)
                    audit["state"], audit["reasons"] = entry["dto"]["state"], entry["dto"]["reasons"]
                    entry["dto"]["audit_copy"] = audit
            report_content = {"entry": entry, "inventory_digest": inventory_head["digest"],
                "controller_digest": digest(controller), "checked_at": payload["class_checked_at"][class_id],
                "valid_until": utc_timestamp(min(datetime.fromisoformat(args.key_valid_until.replace("Z", "+00:00")),
                    datetime.fromisoformat(payload["class_checked_at"][class_id].replace("Z", "+00:00")) + timedelta(seconds=args.freshness_seconds))), "source_watermark": payload["source_watermark"]}
            report_head = publish(root, private_key, args.key_id,
                namespace(args.deployment_id, REPORT, payload["scope"], class_id), report_content)
            bindings.append([class_id, inventory_head["digest"], report_head["sequence"], report_head["digest"]])
        payload["stream_bindings"] = bindings
        payload["controller_digest"] = digest(controller)
        payload["volume_set_digest"] = args.volume_set_digest
        payload["snapshot_id"] = snapshot_id(payload["scope"], args.storage_generation, bindings)
    finally:
        os.close(lock_fd)


def capture(args: argparse.Namespace) -> dict:
    token_raw = _private_bytes(Path(args.token_file), 4096).strip()
    key_raw = _private_bytes(Path(args.signing_key_file), 65536)
    token = token_raw.decode("ascii")
    try:
        private_key = serialization.load_pem_private_key(key_raw, password=None)
    except ValueError:
        private_key = Ed25519PrivateKey.from_private_bytes(key_raw)
    if not isinstance(private_key, Ed25519PrivateKey):
        raise ValueError("host_signing_key_invalid")
    valid_from = datetime.fromisoformat(args.key_valid_from.replace("Z", "+00:00"))
    valid_until = datetime.fromisoformat(args.key_valid_until.replace("Z", "+00:00"))
    if not valid_from <= datetime.now(UTC) < valid_until:
        raise ValueError("signing_key_outside_validity")
    if args.provision_controller:
        _provision_controller(args, private_key)
    if getattr(args, "provision_controller_only", False):
        if not args.provision_controller: raise ValueError("controller_provisioning_not_explicit")
        return {"controller_provisioned": True, "deployment_id": args.deployment_id,
            "recovery_epoch": args.recovery_epoch, "storage_generation": args.storage_generation,
            "source_reads": 0, "inventory_or_report_heads_changed": False}
    scope = (args.source_family, args.source_account_id, args.scope_key)
    request_body = {"schema_version": 1, "scope": dict(zip(
        ("source_family", "source_account_id", "scope_key"), scope)),
        "class_ids": [class_id for class_id, _ in CLASSES]}
    status, raw, _ = _request(args.origin, "/internal/g7/preservation/source-snapshot", token,
        body=request_body)
    if status != 200:
        raise RuntimeError("source_snapshot_unavailable")
    snapshot = json.loads(raw)
    if (type(snapshot.get("schema_version")) is not int or snapshot.get("schema_version") != 1 or snapshot.get("deployment_id") != args.deployment_id
            or tuple(snapshot.get("scope", {}).get(k) for k in
                ("source_family", "source_account_id", "scope_key")) != scope
            or snapshot.get("storage_generation") != args.storage_generation
            or snapshot.get("schema_head_digest") != args.schema_head_digest
            or snapshot.get("recovery_epoch") != args.recovery_epoch
            or snapshot.get("volume_set_digest") != args.volume_set_digest):
        raise ValueError("source_snapshot_binding_mismatch")
    by_class = {item["class_id"]: item for item in snapshot.get("classes", [])
        if isinstance(item, dict)}
    if set(by_class) != {class_id for class_id, _ in CLASSES}:
        raise ValueError("source_class_set_invalid")
    checked = datetime.now(UTC)
    source_checked = datetime.fromisoformat(snapshot["checked_at"].replace("Z", "+00:00"))
    if source_checked > checked or checked - source_checked > timedelta(seconds=args.freshness_seconds):
        raise ValueError("source_check_stale_or_future")
    checked = min(checked, source_checked)
    checked_at = utc_timestamp(checked)
    classes = []
    class_checked_at = {class_id: utc_timestamp(source_checked) for class_id, _ in CLASSES}
    byte_sizes: dict[str, int] = {}
    for class_id, period in CLASSES:
        source = by_class[class_id]
        if class_id == "product.audit_history":
            if not args.audit_state_file:
                dto = unknown_class(class_id, period, args.audit_state_failure_reason)
                if args.audit_state_failure_reason in {"source_unavailable", "sink_unavailable", "evidence_store_unavailable"}:
                    dto["state"] = "failed"
                    dto["audit_copy"]["state"] = "failed"
                classes.append({"class_id": class_id, "minimum_period": period,
                    "dto": dto, "members": [], "audit_targets": []})
                continue
            try:
                audit_state = json.loads(_private_bytes(Path(args.audit_state_file),
                    16 * 1024 * 1024))
                from uvm.operations.preservation import _valid_class_dto, _valid_members
                context = audit_state["context"]
                expected_context = {"deployment_id": args.deployment_id,
                    "storage_generation": args.storage_generation, "recovery_epoch": args.recovery_epoch,
                    "volume_set_digest": args.volume_set_digest, "scope": list(scope)}
                if any(context.get(k) != v for k, v in expected_context.items()):
                    raise ValueError("audit_context_mismatch")
                dto_check_time = audit_state["dto"]["audit_copy"]["checked_at"]
                context_check_time = context.get("checked_at")
                if (dto_check_time is not None and context_check_time is not None
                        and utc_timestamp(dto_check_time) != utc_timestamp(context_check_time)):
                    raise ValueError("audit_check_time_mismatch")
                audit_check_time = context_check_time or dto_check_time
                if not isinstance(audit_check_time, str): raise ValueError("audit_check_time_unavailable")
                audit_checked = datetime.fromisoformat(audit_check_time.replace("Z", "+00:00"))
                if audit_checked > checked or checked - audit_checked > timedelta(seconds=args.freshness_seconds):
                    raise ValueError("audit_check_stale_or_future")
                class_checked_at[class_id] = utc_timestamp(audit_checked)
                checked = min(checked, audit_checked)
                checked_at = utc_timestamp(checked)
                snapshot["source_watermark"]["audit_export"] = {name: context[name] for name in
                    ("source_watermark", "export_context_id", "sink_watermark", "anchor_watermark")}
                audit_members = audit_state["members"]
                audit_dto = audit_state["dto"]
                if (type(audit_state.get("schema_version")) is not int or audit_state.get("schema_version") != 1
                        or audit_state.get("class_id") != class_id
                        or not isinstance(audit_state.get("audit_targets"), list)
                        or not isinstance(audit_members, list)
                        or not isinstance(audit_dto, dict)
                        or not _valid_class_dto(audit_dto, class_id)
                        or not _valid_members(audit_members, class_id, audit_dto)):
                    raise ValueError("audit_reconciliation_invalid")
                classes.append({"class_id": class_id, "minimum_period": period,
                    "dto": audit_dto, "members": audit_members,
                    "audit_targets": audit_state["audit_targets"]})
            except (OSError, ValueError, TypeError, KeyError, json.JSONDecodeError):
                dto = unknown_class(class_id, period, "audit_scope_incomplete")
                classes.append({"class_id": class_id, "minimum_period": period,
                    "dto": dto, "members": [], "audit_targets": []})
            continue
        if source.get("complete") is not True:
            dto = unknown_class(class_id, period, source.get("coverage_reason") or "scope_incomplete")
            classes.append({"class_id": class_id, "minimum_period": period,
                "dto": dto, "members": []})
            continue
        try:
            for source_member in source.get("members", []):
                if (isinstance(source_member, dict) and source_member.get("raw_sha256") is not None
                        and type(source_member.get("byte_size")) is int):
                    byte_sizes[source_member["record_kind"] + ":" + source_member["stable_key"]] = source_member["byte_size"]
            from uvm.operations.preservation_streams import read_stream, namespace, INVENTORY
            expected_inventory = None
            try:
                previous_inventory, _ = read_stream(args.trust_dir, Path(args.trust_dir) / "public.pem",
                    namespace(args.deployment_id, INVENTORY, scope, class_id), key_id=args.key_id)
                expected_inventory = previous_inventory["content"]
            except FileNotFoundError:
                pass
            members = _safe_members(source, token, args.origin, expected_inventory)
        except RuntimeError:
            dto = unknown_class(class_id, period, "evidence_unreadable")
            dto["state"] = "failed"
            dto["reasons"] = ["evidence_unreadable"]
            classes.append({"class_id": class_id, "minimum_period": period,
                "dto": dto, "members": []})
            continue
        except ValueError:
            dto = unknown_class(class_id, period, "coverage_unsupported")
            classes.append({"class_id": class_id, "minimum_period": period,
                "dto": dto, "members": []})
            continue
        dto = _dto(class_id, period, members, checked_at)
        classes.append({"class_id": class_id, "minimum_period": period,
            "dto": dto, "members": members})
    payload = {"contract_id": "g7-data-preservation/v1", "purpose": "readcheck-report-v1",
        "schema_version": 1, "snapshot_id": str(uuid4()), "deployment_id": args.deployment_id,
        "recovery_epoch": args.recovery_epoch, "storage_generation": args.storage_generation,
        "scope": list(scope), "scope_object": dict(zip(
            ("source_family", "source_account_id", "scope_key"), scope)),
        "environment": args.environment, "checked_at": checked_at,
        "valid_until": (checked + timedelta(seconds=args.freshness_seconds)).isoformat().replace("+00:00", "Z"),
        "freshness_seconds": args.freshness_seconds, "source_watermark": snapshot["source_watermark"], "schema_head_digest": args.schema_head_digest,
        "class_checked_at": class_checked_at, "classes": classes}
    if not valid_from <= checked < valid_until:
        raise ValueError("signing_key_outside_validity")
    payload["valid_until"] = utc_timestamp(min(valid_until, checked + timedelta(seconds=args.freshness_seconds)))
    _bind_streams(args, payload, private_key, byte_sizes)
    signed = b"VOLT-G7-PRESERVATION\0readcheck-report-v1\0" + canonical_json(payload)
    signature = base64.b64encode(private_key.sign(signed)).decode("ascii")
    document = {"payload": payload, "signature": {
        "algorithm": "Ed25519", "key_id": args.key_id, "value": signature}}
    report = canonical_json(document) + b"\n"
    report_path = Path(args.report_dir) / (tuple_digest(scope) + ".json")
    report_path.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
    snapshots_root = Path(args.report_dir) / "snapshots"
    snapshots_root.mkdir(exist_ok=True, mode=0o755)
    snapshots_root.chmod(0o755)
    _publish_no_replace(snapshots_root / (payload["snapshot_id"] + ".json"), report)
    current_staging = report_path.with_name(".current-" + str(uuid4()))
    _publish_no_replace(current_staging, report)
    os.replace(current_staging, report_path)
    directory_fd = os.open(report_path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try: os.fsync(directory_fd)
    finally: os.close(directory_fd)
    if args.metadata_output:
        metadata_path = Path(args.metadata_output)
        metadata_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        fd = os.open(metadata_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
            getattr(os, "O_NOFOLLOW", 0), 0o600)
        with os.fdopen(fd, "wb") as handle:
            handle.write(canonical_json({"schema_version": 1, "byte_sizes": byte_sizes}) + b"\n")
            handle.flush(); os.fsync(handle.fileno())
    return {"snapshot_id": payload["snapshot_id"], "class_states": {
        item["class_id"]: item["dto"]["state"] for item in classes},
        "class_members": {item["class_id"]: item["dto"]["expected_records"] for item in classes},
        "verified_evidence_objects": len({m["evidence_id"] for x in classes
            for m in x["members"] if m.get("evidence_id")})}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--provision-controller", action="store_true")
    parser.add_argument("--provision-controller-only", action="store_true")
    parser.add_argument("--trust-dir", required=True)
    parser.add_argument("--volume-set-digest", required=True)
    parser.add_argument("--schema-head-digest", required=True)
    parser.add_argument("--key-valid-from", required=True)
    parser.add_argument("--key-valid-until", required=True)
    parser.add_argument("--admit-new-members", action="store_true")
    parser.add_argument("--origin", required=True)
    parser.add_argument("--token-file", required=True)
    parser.add_argument("--signing-key-file", required=True)
    parser.add_argument("--report-dir", required=True)
    parser.add_argument("--key-id", required=True)
    parser.add_argument("--deployment-id", required=True)
    parser.add_argument("--recovery-epoch", type=int, required=True)
    parser.add_argument("--storage-generation", required=True)
    parser.add_argument("--environment", required=True)
    parser.add_argument("--freshness-seconds", type=int, required=True)
    parser.add_argument("--metadata-output")
    parser.add_argument("--audit-state-file")
    parser.add_argument("--audit-state-failure-reason", choices=("audit_scope_incomplete",
        "source_unavailable", "sink_unavailable", "evidence_store_unavailable"),
        default="audit_scope_incomplete")
    parser.add_argument("--previous-report")
    parser.add_argument("--source-family", required=True)
    parser.add_argument("--source-account-id", required=True)
    parser.add_argument("--scope-key", required=True)
    args = parser.parse_args()
    if not 1 <= args.freshness_seconds <= 86400 or args.recovery_epoch < 0:
        raise SystemExit("invalid bounded report freshness or recovery epoch")
    result = capture(args)
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, HTTPError, RuntimeError, URLError, json.JSONDecodeError) as exc:
        code = str(exc) if str(exc).isidentifier() else "preservation_capture_failed"
        raise SystemExit(code)
