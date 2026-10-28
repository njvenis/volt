#!/usr/bin/env python3
"""Exercise public read failures against copied, signed report negatives."""
from __future__ import annotations

import argparse
import base64
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from uvm.operations.preservation import (canonical_json, unknown_class,
    _valid_class_dto, _valid_members)


def sign(payload: dict, key: Ed25519PrivateKey, key_id: str) -> dict:
    message = b"VOLT-G7-PRESERVATION\0readcheck-report-v1\0" + canonical_json(payload)
    return {"payload": payload, "signature": {"algorithm": "Ed25519", "key_id": key_id,
        "value": base64.b64encode(key.sign(message)).decode("ascii")}}


def set_counts(entry: dict) -> None:
    members = entry["members"]
    counts = {state: sum(item["state"] == state for item in members)
        for state in ("verified", "missing", "changed", "unreadable", "unexpected")}
    dto = entry["dto"]
    dto.update({"expected_records": sum(counts[s] for s in
        ("verified", "missing", "changed", "unreadable")),
        "verified_records": counts["verified"], "missing_records": counts["missing"],
        "changed_records": counts["changed"], "unreadable_records": counts["unreadable"],
        "unexpected_records": counts["unexpected"]})
    reasons = sorted({reason for member in members for reason in member["reasons"]})
    dto["reasons"] = reasons
    dto["state"] = "gap" if any(member["state"] in {"missing", "changed", "unreadable", "unexpected"}
        for member in members) else "verified"


def mutate(original: dict, case: str, key: Ed25519PrivateKey) -> tuple[dict, dict]:
    document = deepcopy(original)
    payload = document["payload"]
    source = next(item for item in payload["classes"] if item["class_id"] == "product.source_evidence")
    audit = next(item for item in payload["classes"] if item["class_id"] == "product.audit_history")
    expected = {"case": case}
    if case == "healthy_cursor_binding":
        expected.update(states={name: "verified" for name in
            ("product.source_evidence", "product.audit_history", "operational.scanner_collection")},
            cursorBinding={"sourceClass": "product.source_evidence",
                "otherClass": "operational.scanner_collection"})
        return document, expected
    if case == "untrusted_signature":
        value = bytearray(base64.b64decode(document["signature"]["value"]))
        value[0] ^= 1
        document["signature"]["value"] = base64.b64encode(value).decode("ascii")
        expected.update(states={name: "unknown" for name in
            ("product.source_evidence", "product.audit_history", "operational.scanner_collection")},
            nullCountClasses=["product.source_evidence", "product.audit_history", "operational.scanner_collection"],
            reasons={name: "baseline_untrusted" for name in
            ("product.source_evidence", "product.audit_history", "operational.scanner_collection")})
        return document, expected
    if case == "expired_report":
        payload["valid_until"] = "2000-01-01T00:00:00Z"
        expected.update(states={name: "unknown" for name in
            ("product.source_evidence", "product.audit_history", "operational.scanner_collection")},
            nullCountClasses=["product.source_evidence", "product.audit_history", "operational.scanner_collection"],
            reasons={name: "report_expired" for name in
            ("product.source_evidence", "product.audit_history", "operational.scanner_collection")})
    elif case == "wrong_generation":
        payload["storage_generation"] = "00000000-0000-4000-8000-000000000099"
        expected.update(states={name: "unknown" for name in
            ("product.source_evidence", "product.audit_history", "operational.scanner_collection")},
            nullCountClasses=["product.source_evidence", "product.audit_history", "operational.scanner_collection"],
            reasons={name: "baseline_untrusted" for name in
            ("product.source_evidence", "product.audit_history", "operational.scanner_collection")})
    elif case == "incomplete_source_inventory":
        source["dto"] = unknown_class("product.source_evidence", "P1Y", "scope_incomplete")
        source["members"] = []
        expected.update(states={"product.source_evidence": "unknown", "product.audit_history": "verified",
            "operational.scanner_collection": "verified"}, nullCountClasses=["product.source_evidence"],
            reasons={"product.source_evidence": "scope_incomplete"},
            counts={"product.audit_history": audit["dto"]["expected_records"]})
    elif case in {"source_all_expected_missing", "source_one_member_missing", "source_bytes_changed"}:
        selected = source["members"] if case == "source_all_expected_missing" else [next(
            item for item in source["members"] if item["byte_bearing"])]
        for member in selected:
            if case == "source_bytes_changed":
                member["state"] = "changed"; member["reasons"] = ["bytes_changed"]
                member["actual_sha256"] = ("0" if member["expected_sha256"][0] != "0" else "1") + member["expected_sha256"][1:]
            else:
                member["state"] = "missing"; member["reasons"] = ["record_missing"]
                member["actual_sha256"] = None; member["record_sha256"] = None
        set_counts(source)
        expected.update(states={"product.source_evidence": "gap", "product.audit_history": "verified",
            "operational.scanner_collection": "verified"}, counts={"product.source_evidence": len(source["members"])},
            reasons={"product.source_evidence": "bytes_changed" if case == "source_bytes_changed" else "record_missing"},
            recordClass="product.source_evidence")
        if case == "source_all_expected_missing": expected["allRecordsMissing"] = True
        elif case == "source_bytes_changed": expected.update(recordState="changed", recordReason="bytes_changed", rawHashesDiffer=True)
        else: expected.update(recordState="missing", recordReason="record_missing", recordDigestNull=True)
    elif case in {"audit_sink_event_missing", "audit_sink_event_changed",
            "audit_all_sink_events_missing", "audit_established_receipt_missing",
            "audit_established_receipt_changed", "audit_anchor_missing", "audit_anchor_changed"}:
        if case == "audit_sink_event_missing":
            member = next(item for item in audit["members"] if item["record_kind"] == "audit_event")
            member["state"] = "missing"; member["reasons"] = ["sink_record_missing"]
            audit["dto"]["audit_copy"].update(matching_events=3, missing_events=1)
            expected.update(recordKind="audit_event", recordReason="sink_record_missing")
        elif case == "audit_sink_event_changed":
            member = next(item for item in audit["members"] if item["record_kind"] == "audit_event")
            member["state"] = "changed"; member["reasons"] = ["sink_record_changed"]
            audit["dto"]["audit_copy"].update(matching_events=3, changed_events=1)
            expected.update(recordKind="audit_event", recordReason="sink_record_changed",
                recordState="changed")
        elif case == "audit_all_sink_events_missing":
            selected = [item for item in audit["members"] if item["record_kind"] == "audit_event"]
            for item in selected:
                item["state"] = "missing"; item["reasons"] = ["sink_record_missing"]
                item["record_sha256"] = None
            for item in audit["members"]:
                if item["record_kind"] == "audit_anchor":
                    item["state"] = "changed"; item["reasons"] = ["sink_record_changed"]
            audit["dto"]["audit_copy"].update(matching_events=0, missing_events=len(selected))
            member = selected[0]
            expected.update(recordKind="audit_event", recordReason="sink_record_missing",
                recordState="missing", recordDigestNull=True, allExpectedKindMissing="audit_event")
        else:
            if case.startswith("audit_established_receipt"):
                member = next(item for item in audit["members"] if item["record_kind"] == "audit_copy_receipt_established")
                if case.endswith("changed"):
                    member["state"] = "changed"; member["reasons"] = ["receipt_changed"]
                    audit["dto"]["audit_copy"].update(matching_receipts=3, changed_receipts=1)
                    expected.update(recordKind="audit_copy_receipt_established", recordReason="receipt_changed",
                        recordState="changed")
                else:
                    member["state"] = "missing"; member["reasons"] = ["receipt_missing"]
                    audit["dto"]["audit_copy"].update(matching_receipts=3, missing_receipts=1)
                    expected.update(recordKind="audit_copy_receipt_established", recordReason="receipt_missing")
            else:
                member = next(item for item in audit["members"] if item["record_kind"] == "audit_anchor")
                if case.endswith("changed"):
                    member["state"] = "changed"; member["reasons"] = ["sink_record_changed"]
                    expected.update(recordKind="audit_anchor", recordReason="sink_record_changed",
                        recordState="changed")
                else:
                    member["state"] = "missing"; member["reasons"] = ["sink_record_missing"]
                    expected.update(recordKind="audit_anchor", recordReason="sink_record_missing")
        if case != "audit_all_sink_events_missing" and member["state"] == "missing":
            member["record_sha256"] = None
        if case != "audit_all_sink_events_missing":
            expected.update(recordDigestNull=member["state"] == "missing")
        audit["dto"]["audit_copy"]["state"] = "gap"
        reasons = sorted({reason for item in audit["members"] for reason in item["reasons"]})
        audit["dto"]["audit_copy"]["reasons"] = reasons
        set_counts(audit)
        audit["dto"]["audit_copy"]["state"] = "gap"
        audit["dto"]["audit_copy"]["reasons"] = reasons
        audit["dto"]["reasons"] = reasons
        expected.update(states={"product.source_evidence": "verified", "product.audit_history": "gap",
            "operational.scanner_collection": "verified"}, recordClass="product.audit_history",
            counts={"product.audit_history": len(audit["members"])},
            reasons={"product.audit_history": reasons[0]})
        if case == "audit_all_sink_events_missing":
            expected["allExpectedKindsMissing"] = {"audit_event": len(selected)}
    else:
        raise ValueError("unknown_failure_case")
    for entry in payload["classes"]:
        if not _valid_class_dto(entry["dto"], entry["class_id"]) or not _valid_members(
                entry["members"], entry["class_id"], entry["dto"]):
            raise ValueError("negative_case_dto_invalid:" + case)
    key_id = document["signature"]["key_id"]
    return sign(payload, key, key_id), expected


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--report", required=True)
    parser.add_argument("--key", required=True)
    parser.add_argument("--origin", required=True)
    parser.add_argument("--storage-state", required=True)
    parser.add_argument("--evidence", required=True)
    parser.add_argument("--sink-unavailable-report")
    parser.add_argument("--evidence-unavailable-report")
    args = parser.parse_args()
    report_path, evidence = Path(args.report), Path(args.evidence)
    original_bytes = report_path.read_bytes()
    original = json.loads(original_bytes)
    key_data = Path(args.key).read_bytes()
    key = serialization.load_pem_private_key(key_data, password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError("invalid_fixture_signing_key")
    cases = ("healthy_cursor_binding", "untrusted_signature", "expired_report", "wrong_generation", "incomplete_source_inventory",
        "source_one_member_missing", "source_all_expected_missing", "source_bytes_changed",
        "audit_sink_event_missing", "audit_sink_event_changed", "audit_all_sink_events_missing",
        "audit_established_receipt_missing", "audit_established_receipt_changed",
        "audit_anchor_missing", "audit_anchor_changed")
    results = []
    backup = evidence / "preservation-report-original.json"
    backup.write_bytes(original_bytes); backup.chmod(0o600)
    try:
        for case in cases:
            negative, expected = mutate(original, case, key)
            expected_path = evidence / f"preservation-negative-{case}-expect.json"
            negative_path = evidence / f"preservation-negative-{case}-signed.json"
            output_path = evidence / f"preservation-negative-{case}-public.json"
            expected_path.write_bytes(canonical_json(expected) + b"\n"); expected_path.chmod(0o600)
            negative_bytes = canonical_json(negative) + b"\n"
            negative_path.write_bytes(negative_bytes); negative_path.chmod(0o600)
            swap = report_path.with_name(".g7-negative-report.json")
            swap.write_bytes(negative_bytes); swap.chmod(0o644); os.replace(swap, report_path)
            try:
                env = dict(os.environ)
                env["PLAYWRIGHT_BROWSERS_PATH"] = "/home/nicho/.cache/ms-playwright"
                env["CHROMIUM_EXECUTABLE_PATH"] = "/home/nicho/.cache/ms-playwright/chromium-1234/chrome-linux64/chrome"
                command = ["node", str(Path(__file__).with_suffix(".mjs")),
                    "--origin", args.origin, "--storage-state", args.storage_state,
                    "--expect", str(expected_path), "--output", str(output_path)]
                result = subprocess.run(command, capture_output=True, text=True, env=env, check=False)
                (evidence / f"preservation-negative-{case}.stdout").write_text(result.stdout)
                (evidence / f"preservation-negative-{case}.stderr").write_text(result.stderr)
                if result.returncode:
                    raise RuntimeError("public_negative_assertion_failed:" + case)
                results.append(json.loads(result.stdout))
            finally:
                restore = report_path.with_name(".g7-original-report.json")
                restore.write_bytes(original_bytes); restore.chmod(0o644); os.replace(restore, report_path)
        if args.evidence_unavailable_report:
            case = "observed_evidence_store_unavailable"
            negative_bytes = Path(args.evidence_unavailable_report).read_bytes()
            negative = json.loads(negative_bytes)
            negative_path = evidence / f"preservation-negative-{case}-signed.json"
            negative_path.write_bytes(negative_bytes); negative_path.chmod(0o600)
            expected = {"case": case,
                "states": {"product.source_evidence": "failed",
                    "product.audit_history": "verified", "operational.scanner_collection": "failed"},
                "nullCountClasses": ["product.source_evidence", "operational.scanner_collection"],
                "reasons": {"product.source_evidence": "evidence_unreadable",
                    "operational.scanner_collection": "evidence_unreadable"}}
            expected_path = evidence / f"preservation-negative-{case}-expect.json"
            output_path = evidence / f"preservation-negative-{case}-public.json"
            expected_path.write_bytes(canonical_json(expected) + b"\n"); expected_path.chmod(0o600)
            swap = report_path.with_name(".g7-negative-report.json")
            swap.write_bytes(negative_bytes); swap.chmod(0o644); os.replace(swap, report_path)
            try:
                env = dict(os.environ)
                env["PLAYWRIGHT_BROWSERS_PATH"] = "/home/nicho/.cache/ms-playwright"
                env["CHROMIUM_EXECUTABLE_PATH"] = "/home/nicho/.cache/ms-playwright/chromium-1234/chrome-linux64/chrome"
                command = ["node", str(Path(__file__).with_suffix(".mjs")),
                    "--origin", args.origin, "--storage-state", args.storage_state,
                    "--expect", str(expected_path), "--output", str(output_path)]
                result = subprocess.run(command, capture_output=True, text=True, env=env, check=False)
                (evidence / f"preservation-negative-{case}.stdout").write_text(result.stdout)
                (evidence / f"preservation-negative-{case}.stderr").write_text(result.stderr)
                if result.returncode:
                    raise RuntimeError("public_negative_assertion_failed:" + case)
                results.append(json.loads(result.stdout))
            finally:
                restore = report_path.with_name(".g7-original-report.json")
                restore.write_bytes(original_bytes); restore.chmod(0o644); os.replace(restore, report_path)
        if args.sink_unavailable_report:
            case = "observed_sink_unavailable"
            negative_bytes = Path(args.sink_unavailable_report).read_bytes()
            negative = json.loads(negative_bytes)
            negative_path = evidence / f"preservation-negative-{case}-signed.json"
            negative_path.write_bytes(negative_bytes); negative_path.chmod(0o600)
            expected = {"case": case,
                "states": {"product.source_evidence": "verified",
                    "product.audit_history": "unknown", "operational.scanner_collection": "verified"},
                "nullCountClasses": ["product.audit_history"],
                "reasons": {"product.audit_history": "sink_unavailable"},
                "auditCopy": {"state": "unknown", "expected_events": None,
                    "matching_events": None, "missing_events": None, "changed_events": None,
                    "unexpected_events": None, "expected_receipts": None,
                    "matching_receipts": None, "missing_receipts": None,
                    "changed_receipts": None, "unexpected_receipts": None,
                    "pending_receipts": None}}
            expected_path = evidence / f"preservation-negative-{case}-expect.json"
            output_path = evidence / f"preservation-negative-{case}-public.json"
            expected_path.write_bytes(canonical_json(expected) + b"\n"); expected_path.chmod(0o600)
            swap = report_path.with_name(".g7-negative-report.json")
            swap.write_bytes(negative_bytes); swap.chmod(0o644); os.replace(swap, report_path)
            try:
                env = dict(os.environ)
                env["PLAYWRIGHT_BROWSERS_PATH"] = "/home/nicho/.cache/ms-playwright"
                env["CHROMIUM_EXECUTABLE_PATH"] = "/home/nicho/.cache/ms-playwright/chromium-1234/chrome-linux64/chrome"
                command = ["node", str(Path(__file__).with_suffix(".mjs")),
                    "--origin", args.origin, "--storage-state", args.storage_state,
                    "--expect", str(expected_path), "--output", str(output_path)]
                result = subprocess.run(command, capture_output=True, text=True, env=env, check=False)
                (evidence / f"preservation-negative-{case}.stdout").write_text(result.stdout)
                (evidence / f"preservation-negative-{case}.stderr").write_text(result.stderr)
                if result.returncode:
                    raise RuntimeError("public_negative_assertion_failed:" + case)
                results.append(json.loads(result.stdout))
            finally:
                restore = report_path.with_name(".g7-original-report.json")
                restore.write_bytes(original_bytes); restore.chmod(0o644); os.replace(restore, report_path)
        if report_path.read_bytes() != original_bytes:
            raise RuntimeError("original_report_restore_mismatch")
        (evidence / "preservation-negative-matrix.json").write_bytes(
            canonical_json({"schema_version": 1, "cases": results,
                "original_report_sha256": hashlib.sha256(original_bytes).hexdigest(),
                "original_restored": True}) + b"\n")
        print(json.dumps({"cases": len(results), "original_restored": True}, sort_keys=True))
    finally:
        if report_path.read_bytes() != original_bytes:
            restore = report_path.with_name(".g7-emergency-restore.json")
            restore.write_bytes(original_bytes); restore.chmod(0o644); os.replace(restore, report_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
