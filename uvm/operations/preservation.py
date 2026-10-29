"""Read-only verifier for independently published G7 preservation reports."""
from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import stat
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from uuid import UUID

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

CONTRACT = "g7-data-preservation/v1"
PURPOSE = "readcheck-report-v1"
CLASSES = (
    ("product.source_evidence", "P1Y"),
    ("product.audit_history", "P1Y"),
    ("operational.scanner_collection", "P3M"),
)
_HEX = re.compile(r"[0-9a-f]{64}\Z")
_REASONS = set("baseline_missing baseline_incomplete baseline_untrusted baseline_discontinuous baseline_replay baseline_expired legacy_preimage_unavailable coverage_unsupported scope_incomplete audit_scope_incomplete environment_unlabelled record_missing bytes_changed bytes_unreadable receipt_missing receipt_changed sink_record_missing sink_record_changed unexpected_member source_unavailable sink_unavailable evidence_store_unavailable evidence_missing evidence_changed evidence_unreadable source_checkpoint_missing report_expired cursor_expired snapshot_expired authority_changed trust_key_unavailable trust_config_mismatch schema_mismatch future_timestamp internal_check_failed".split())


def canonical_json(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
        separators=(",", ":"), allow_nan=False).encode("utf-8")


def utc_timestamp(value: datetime | str) -> str:
    """Normalize an aware datetime/string to contract UTC RFC3339 ending in Z."""
    if isinstance(value, str):
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None or parsed.utcoffset() is None:
            raise ValueError("timestamp must include a timezone")
        if parsed.utcoffset().total_seconds() == 0:
            return value[:-6] + "Z" if value.endswith("+00:00") else value
        fraction_match = re.search(r"\.(\d+)(?:[+-]\d{2}:\d{2})$", value)
        fraction_size = len(fraction_match.group(1)) if fraction_match else 0
        normalized = parsed.astimezone(timezone.utc)
        result = normalized.strftime("%Y-%m-%dT%H:%M:%S")
        if fraction_size:
            result += "." + f"{normalized.microsecond:06d}"[:fraction_size]
        return result + "Z"
    parsed = value
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("timestamp must include a timezone")
    return parsed.astimezone(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _canonical_timestamp(value: Any) -> bool:
    if not isinstance(value, str) or not value.endswith("Z"):
        return False
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
        return parsed.tzinfo is not None and parsed.utcoffset() == timezone.utc.utcoffset(parsed)
    except (ValueError, TypeError, OverflowError):
        return False


def tuple_digest(scope: tuple[str, str, str]) -> str:
    return hashlib.sha256(canonical_json(list(scope))).hexdigest()


def unknown_class(class_id: str, period: str, reason: str) -> dict[str, Any]:
    audit = None
    if class_id == "product.audit_history":
        audit = {"state": "unknown", "reasons": [reason],
            **{name: None for name in ("expected_events", "matching_events", "missing_events",
                "changed_events", "unexpected_events", "expected_receipts", "matching_receipts",
                "missing_receipts", "changed_receipts", "unexpected_receipts", "pending_receipts")},
            "checked_at": None}
    return {"class_id": class_id, "minimum_period": period, "state": "unknown",
        "reasons": [reason], **{name: None for name in ("expected_records", "verified_records",
            "missing_records", "changed_records", "unreadable_records", "unexpected_records",
            "oldest_retained_at", "baseline_digest")}, "audit_copy": audit}


def _read_regular(path: Path, maximum: int) -> bytes:
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size > maximum or info.st_mode & 0o022:
            raise ValueError("unsafe preservation object")
        chunks = []
        remaining = maximum + 1
        while remaining:
            part = os.read(fd, min(65536, remaining))
            if not part:
                break
            chunks.append(part)
            remaining -= len(part)
        raw = b"".join(chunks)
        if len(raw) > maximum:
            raise ValueError("oversized preservation object")
        return raw
    finally:
        os.close(fd)


def _verify(document: dict, key_path: Path, expected_purpose: str) -> dict:
    if not isinstance(document, dict) or set(document) != {"payload", "signature"}:
        raise ValueError("invalid signed preservation document")
    signature = document["signature"]
    if (not isinstance(signature, dict) or set(signature) != {"algorithm", "key_id", "value"}
            or signature["algorithm"] != "Ed25519" or not isinstance(signature["key_id"], str)):
        raise ValueError("invalid preservation signature metadata")
    key_bytes = _read_regular(key_path, 65536)
    try:
        key = serialization.load_pem_public_key(key_bytes)
    except ValueError:
        key = Ed25519PublicKey.from_public_bytes(key_bytes)
    if not isinstance(key, Ed25519PublicKey):
        raise ValueError("preservation verifier key must be Ed25519")
    signed = b"VOLT-G7-PRESERVATION\0" + expected_purpose.encode() + b"\0" + canonical_json(document["payload"])
    key.verify(base64.b64decode(signature["value"], validate=True), signed)
    return document["payload"]


def load_report(scope: tuple[str, str, str], *, allow_expired: bool = False, report_path: Path | None = None, allow_previous: bool = False) -> tuple[dict | None, str]:
    root = os.environ.get("UVM_G7_PRESERVATION_REPORT_DIR")
    public_key = os.environ.get("UVM_G7_PRESERVATION_PUBLIC_KEY_FILE")
    if not root or not public_key:
        return None, "baseline_missing"
    try:
        report_path = report_path or Path(root) / (tuple_digest(scope) + ".json")
        report = json.loads(_read_regular(report_path, 32 * 1024 * 1024))
        payload = _verify(report, Path(public_key), PURPOSE)
        expected_deployment = os.environ.get("UVM_G7_DEPLOYMENT_ID")
        expected_epoch = os.environ.get("UVM_G7_RECOVERY_EPOCH")
        expected_generation = os.environ.get("UVM_G7_STORAGE_GENERATION")
        expected_key_id = os.environ.get("UVM_G7_PRESERVATION_KEY_ID")
        if not expected_epoch or not expected_epoch.isdigit():
            raise ValueError("preservation recovery epoch is invalid")
        if (type(payload.get("schema_version")) is not int or payload.get("schema_version") != 1
                or payload.get("scope_object") != dict(zip(("source_family", "source_account_id", "scope_key"), scope))
                or not _canonical_timestamp(payload.get("checked_at"))
                or not _canonical_timestamp(payload.get("valid_until"))
                or payload.get("contract_id") != CONTRACT or payload.get("purpose") != PURPOSE
                or payload.get("scope") != list(scope) or not isinstance(payload.get("classes"), list)
                or len(payload["classes"]) != len(CLASSES)
                or {item.get("class_id") for item in payload["classes"] if isinstance(item, dict)}
                    != {class_id for class_id, _ in CLASSES}
                or not isinstance(payload.get("snapshot_id"), str)
                or not expected_deployment or payload.get("deployment_id") != expected_deployment
                or type(payload.get("recovery_epoch")) is not int
                or (not allow_previous and payload.get("recovery_epoch") != int(expected_epoch))
                or not expected_generation or (not allow_previous and payload.get("storage_generation") != expected_generation)
                or not expected_key_id or report["signature"].get("key_id") != expected_key_id):
            raise ValueError("preservation report binding mismatch")
        checked = datetime.fromisoformat(payload["checked_at"].replace("Z", "+00:00"))
        expiry = datetime.fromisoformat(payload["valid_until"].replace("Z", "+00:00"))
        now = datetime.now(timezone.utc)
        skew = int(os.environ.get("UVM_G7_PRESERVATION_MAX_FUTURE_SKEW_SECONDS", "0"))
        if (checked.tzinfo is None or expiry.tzinfo is None
                or checked > now + timedelta(seconds=skew)):
            raise ValueError("report time is invalid")
        if expiry <= now and not allow_expired:
            return None, "report_expired"
        freshness = payload.get("freshness_seconds")
        if (type(freshness) is not int or freshness <= 0
                or expiry > checked + timedelta(seconds=freshness)):
            raise ValueError("preservation freshness binding mismatch")
        trust_root = os.environ.get("UVM_G7_PRESERVATION_TRUST_DIR")
        if not trust_root:
            raise ValueError("independent trust store unavailable")
        from uvm.operations.preservation_streams import validate_bindings
        validate_bindings(payload, trust_root, public_key, expected_key_id, now=now, allow_previous=allow_previous)
        if payload.get("volume_set_digest") != os.environ.get("UVM_G7_VOLUME_SET_DIGEST"):
            raise ValueError("volume-set binding mismatch")
        return payload, ""
    except FileNotFoundError:
        return None, "baseline_missing"
    except (OSError, ValueError, TypeError, KeyError, json.JSONDecodeError, Exception) as exc:
        # No exception text or private path is returned to the caller.
        return None, "baseline_untrusted"


def class_map(payload: dict | None, scope: tuple[str, str, str],
              absent_reason: str = "baseline_missing") -> dict[str, dict]:
    if payload is None:
        return {class_id: unknown_class(class_id, period, absent_reason)
            for class_id, period in CLASSES}
    result = {}
    for class_id, period in CLASSES:
        entry = next((item for item in payload["classes"]
            if isinstance(item, dict) and item.get("class_id") == class_id), None)
        if not isinstance(entry, dict) or entry.get("minimum_period") != period:
            result[class_id] = unknown_class(class_id, period, "baseline_untrusted")
            continue
        # Validate and return a presentation copy with contract UTC timestamps.
        # The signed payload itself, including legacy anchor bytes/digests, is
        # never rewritten by this wire normalization.
        try:
            dto = _class_wire(entry.get("dto"))
            members = [_member_wire(member) for member in entry.get("members", [])]
            valid = (isinstance(dto, dict) and dto.get("minimum_period") == period
                and isinstance(members, list) and _valid_class_dto(dto, class_id)
                and _valid_members(members, class_id, dto))
        except (TypeError, ValueError, UnicodeError, KeyError):
            valid = False
        if not valid:
            result[class_id] = unknown_class(class_id, period, "baseline_untrusted")
            continue
        result[class_id] = dto
    return result


def _member_wire(member: Any) -> Any:
    if not isinstance(member, dict):
        return member
    projected = dict(member)
    if projected.get("retained_at") is not None:
        projected["retained_at"] = utc_timestamp(projected["retained_at"])
    return projected


def _class_wire(dto: Any) -> Any:
    if not isinstance(dto, dict):
        return dto
    projected = dict(dto)
    if projected.get("oldest_retained_at") is not None:
        projected["oldest_retained_at"] = utc_timestamp(projected["oldest_retained_at"])
    audit = projected.get("audit_copy")
    if isinstance(audit, dict):
        audit = dict(audit)
        if audit.get("checked_at") is not None:
            audit["checked_at"] = utc_timestamp(audit["checked_at"])
        projected["audit_copy"] = audit
    return projected


def _valid_members(members: list, class_id: str, dto: dict) -> bool:
    kinds = {
        "product.source_evidence": {"observation", "observation_linkage", "retention_receipt", "evidence_registration"},
        "product.audit_history": {"audit_event", "audit_attribution", "audit_copy_receipt_established", "audit_anchor"},
        "operational.scanner_collection": {"expected_run", "run_revision", "attempt", "page", "expected_transition", "evidence_registration"},
    }
    fields = {"record_key", "record_kind", "retained_at", "state", "reasons",
        "expected_sha256", "actual_sha256", "record_sha256", "byte_bearing", "evidence_id"}
    audit_fields = fields | {"legacy_payload_sha256", "canonicalization_version",
        "representation_metadata"}
    ordered = []
    counts = {state: 0 for state in ("verified", "missing", "changed", "unreadable", "unexpected")}
    for member in members:
        required_fields = audit_fields if class_id == "product.audit_history" else fields
        if not isinstance(member, dict) or set(member) != required_fields:
            return False
        key, kind = member["record_key"], member["record_kind"]
        if (not isinstance(key, str) or not key or not isinstance(kind, str)
                or len(key.encode("utf-8")) > 512 or any(ord(char) < 32 for char in key)
                or kind not in kinds[class_id]):
            return False
        ordered.append((kind.encode("utf-8"), key.encode("utf-8")))
        state, reasons = member["state"], member["reasons"]
        if (not isinstance(state, str) or state not in counts or not isinstance(reasons, list)
                or any(not isinstance(reason, str) for reason in reasons)
                or reasons != sorted(set(reasons))):
            return False
        if any(reason not in _REASONS for reason in reasons):
            return False
        counts[state] += 1
        if type(member["byte_bearing"]) is not bool:
            return False
        if class_id == "product.audit_history":
            legacy = member["legacy_payload_sha256"]
            version = member["canonicalization_version"]
            representation = member["representation_metadata"]
            if kind in {"audit_event", "audit_anchor"}:
                if (not isinstance(legacy, str) or not _HEX.fullmatch(legacy)
                        or version not in {"g7-audit-anchor/v1", "g7-audit-anchor/v2"}
                        or not isinstance(representation, dict)
                        or set(representation) != {"source_time_values", "sink_time_values"}):
                    return False
                for side in ("source_time_values", "sink_time_values"):
                    values = representation[side]
                    if (not isinstance(values, dict) or set(values) != {"occurred_at", "received_at"}
                            or any(value not in {"datetime", "string"} for value in values.values())):
                        return False
            elif legacy is not None or version is not None or representation is not None:
                return False
        hashes = [member[name] for name in ("expected_sha256", "actual_sha256", "record_sha256")]
        if any(value is not None and (not isinstance(value, str) or not _HEX.fullmatch(value))
                for value in hashes):
            return False
        expected, actual, record = hashes
        if not member["byte_bearing"] and (expected is not None or actual is not None):
            return False
        if state == "missing" and (actual is not None or record is not None
                or member["byte_bearing"] and expected is None):
            return False
        if state == "unexpected" and expected is not None:
            return False
        if state == "verified" and member["byte_bearing"] and (expected is None or actual != expected):
            return False
        if state == "unreadable" and member["byte_bearing"] and (expected is None or actual is not None):
            return False
        if state == "changed" and "bytes_changed" in reasons and member["byte_bearing"] and expected == actual:
            return False
        evidence_id = member["evidence_id"]
        if evidence_id is not None:
            try:
                if str(UUID(evidence_id)) != evidence_id or not member["byte_bearing"]:
                    return False
            except (ValueError, TypeError, AttributeError):
                return False
        if member["retained_at"] is not None:
            if not _canonical_timestamp(member["retained_at"]):
                return False
    if (ordered != sorted(ordered) or len(set(ordered)) != len(ordered)
            or len({item["record_key"] for item in members}) != len(members)):
        return False
    if dto["state"] == "failed":
        return not members
    if dto["state"] == "unknown" and dto["expected_records"] is None:
        return not members
    return (dto["expected_records"] == sum(counts[state] for state in
            ("verified", "missing", "changed", "unreadable"))
        and dto["verified_records"] == counts["verified"]
        and dto["missing_records"] == counts["missing"]
        and dto["changed_records"] == counts["changed"]
        and dto["unreadable_records"] == counts["unreadable"]
        and dto["unexpected_records"] == counts["unexpected"])


def _valid_class_dto(dto: dict, class_id: str) -> bool:
    fields = {"class_id", "minimum_period", "state", "reasons", "expected_records",
        "verified_records", "missing_records", "changed_records", "unreadable_records",
        "unexpected_records", "oldest_retained_at", "baseline_digest", "audit_copy"}
    if set(dto) != fields or dto.get("class_id") != class_id:
        return False
    if not isinstance(dto.get("state"), str) or dto.get("state") not in {"verified", "gap", "unknown", "failed"}:
        return False
    if (not isinstance(dto.get("reasons"), list)
            or any(not isinstance(reason, str) for reason in dto["reasons"])
            or dto["reasons"] != sorted(set(dto["reasons"]))
            or any(reason not in _REASONS for reason in dto["reasons"])):
        return False
    counts = [dto.get(key) for key in ("expected_records", "verified_records", "missing_records",
        "changed_records", "unreadable_records", "unexpected_records")]
    if any(value is not None and (type(value) is not int or value < 0) for value in counts):
        return False
    if dto["state"] == "failed" and any(value is not None for value in counts):
        return False
    if any(value is None for value in counts) and any(value is not None for value in counts):
        return False
    if dto["state"] in {"verified", "gap"} and any(value is None for value in counts):
        return False
    if all(value is not None for value in counts):
        if dto.get("baseline_digest") is None:
            return False
        if dto["expected_records"] == 0 and dto.get("oldest_retained_at") is not None:
            return False
        if dto["state"] == "unknown" and any(dto[key] for key in ("missing_records", "changed_records", "unreadable_records", "unexpected_records")):
            return False
        if dto["expected_records"] != sum(dto[key] for key in (
                "verified_records", "missing_records", "changed_records", "unreadable_records")):
            return False
    if (dto.get("baseline_digest") is not None
            and (not isinstance(dto["baseline_digest"], str)
                 or not dto["baseline_digest"].startswith("sha256:")
                 or not _HEX.fullmatch(dto["baseline_digest"][7:]))):
        return False
    if dto.get("oldest_retained_at") is not None and not _canonical_timestamp(dto["oldest_retained_at"]):
        return False
    if dto["state"] == "verified" and (any(dto[key] != 0 for key in
            ("missing_records", "changed_records", "unreadable_records", "unexpected_records"))
            or dto["reasons"]):
        return False
    if class_id != "product.audit_history":
        return dto["audit_copy"] is None
    audit = dto.get("audit_copy")
    if not isinstance(audit, dict) or set(audit) != {"state", "reasons", "expected_events",
            "matching_events", "missing_events", "changed_events", "unexpected_events",
            "expected_receipts", "matching_receipts", "missing_receipts", "changed_receipts",
            "unexpected_receipts", "pending_receipts", "checked_at"}:
        return False
    if not isinstance(audit["state"], str) or audit["state"] not in {"verified", "gap", "unknown", "failed"}:
        return False
    if audit["state"] != dto["state"]:
        return False
    if (not isinstance(audit["reasons"], list)
            or any(not isinstance(reason, str) for reason in audit["reasons"])
            or audit["reasons"] != sorted(set(audit["reasons"]))
            or any(reason not in _REASONS for reason in audit["reasons"])):
        return False
    if audit["checked_at"] is not None and not _canonical_timestamp(audit["checked_at"]):
        return False
    values = [audit[key] for key in ("expected_events", "matching_events", "missing_events",
        "changed_events", "unexpected_events", "expected_receipts", "matching_receipts",
        "missing_receipts", "changed_receipts", "unexpected_receipts", "pending_receipts")]
    if any(value is not None and (type(value) is not int or value < 0) for value in values):
        return False
    if audit["state"] == "failed" and any(value is not None for value in values):
        return False
    if any(value is None for value in values) and any(value is not None for value in values):
        return False
    if audit["state"] in {"verified", "gap"} and any(value is None for value in values):
        return False
    if all(value is not None for value in values):
        if audit["expected_events"] != sum(audit[key] for key in
                ("matching_events", "missing_events", "changed_events")):
            return False
        if audit["expected_receipts"] != sum(audit[key] for key in
                ("matching_receipts", "missing_receipts", "changed_receipts")):
            return False
    if audit["state"] == "verified" and (any(audit[key] != 0 for key in
            ("missing_events", "changed_events", "unexpected_events", "missing_receipts",
             "changed_receipts", "unexpected_receipts", "pending_receipts")) or audit["reasons"]):
        return False
    return True
