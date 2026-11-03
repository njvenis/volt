#!/usr/bin/env python3
"""Run a full Trivy image scan and gate fixable High/Critical findings."""
from __future__ import annotations

import argparse
import datetime as dt
import json
import shutil
import subprocess
import sys
from pathlib import Path


def validate_report(report: dict, exceptions: list[dict], today: dt.date, expected_image_id: str) -> list[str]:
    if not isinstance(report, dict) or report.get("SchemaVersion") != 2 or report.get("ArtifactType") != "container_image":
        return ["scanner report is not a supported complete Trivy container image report"]
    metadata = report.get("Metadata")
    if not isinstance(metadata, dict) or not isinstance(metadata.get("OS"), dict):
        return ["scanner report has no image/OS metadata"]
    os_metadata = metadata["OS"]
    if not isinstance(os_metadata.get("Family"), str) or not os_metadata["Family"] or not isinstance(os_metadata.get("Name"), str):
        return ["scanner report OS metadata is incomplete"]
    if metadata.get("ImageID") != expected_image_id:
        return ["scanner report image ID differs from the requested immutable image"]
    results = report.get("Results")
    if not isinstance(results, list) or not results:
        return ["scanner report has no complete scan results"]
    for result in results:
        if not isinstance(result, dict) or not all(isinstance(result.get(k), str) and result[k] for k in ("Target", "Class", "Type")):
            return ["scanner result is incomplete or malformed"]
    vulnerabilities = []
    for result in results:
        vulns = result.get("Vulnerabilities")
        if vulns is None:
            continue
        if not isinstance(vulns, list):
            return ["scanner vulnerability result has invalid shape"]
        for vuln in vulns:
            if not isinstance(vuln, dict) or not all(isinstance(vuln.get(k), str) for k in ("VulnerabilityID", "PkgName", "InstalledVersion", "Severity")):
                return ["scanner vulnerability record has invalid shape"]
        vulnerabilities.extend(vulns)
    issues = []
    for vuln in vulnerabilities:
        severity = str(vuln.get("Severity", "")).upper()
        fixed = str(vuln.get("FixedVersion", "")).strip()
        if severity not in {"HIGH", "CRITICAL"} or not fixed:
            continue
        key = (str(vuln.get("VulnerabilityID", "")), str(vuln.get("PkgName", "")), str(vuln.get("InstalledVersion", "")))
        matched = False
        for item in exceptions:
            expected = (item["advisory"], item["package"], item["version"])
            if key != expected:
                continue
            expiry = dt.date.fromisoformat(item["expires"])
            if expiry < today or (expiry - today).days > 30:
                issues.append(f"exception for {key[0]} is expired or exceeds 30 days")
            elif not all(item.get(field, "").strip() for field in ("rationale", "owner", "approval")):
                issues.append(f"exception for {key[0]} is missing rationale, owner, or approval")
            else:
                matched = True
            break
        if not matched:
            issues.append(f"fixable {severity}: {key[0]} {key[1]} {key[2]} (fixed in {fixed})")
    return issues


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--image", required=True)
    ap.add_argument("--exceptions", required=True, type=Path)
    ap.add_argument("--expected-image-id", required=True)
    ap.add_argument("--diagnostics", type=Path)
    ap.add_argument("--output", required=True, type=Path)
    ap.add_argument("--at", help="UTC date for deterministic policy checks")
    args = ap.parse_args()
    binary = shutil.which("trivy")
    if not binary:
        ap.error("pinned Trivy binary is required; scanner absence fails this gate")
    lock = Path(__file__).with_name("tools.lock").read_text()
    version = next((line.split("=", 1)[1] for line in lock.splitlines() if line.startswith("trivy_version=")), None)
    if not version:
        ap.error("Trivy version pin missing")
    installed = subprocess.run([binary, "--version"], check=True, text=True, capture_output=True).stdout
    if version not in installed:
        ap.error(f"expected Trivy {version}, got {installed.strip()}")
    try:
        exceptions_doc = json.loads(args.exceptions.read_text())
        exceptions = exceptions_doc["exceptions"]
        if not isinstance(exceptions, list):
            raise ValueError("exceptions must be a list")
        required = ("advisory", "package", "version", "rationale", "owner", "approval", "expires")
        for item in exceptions:
            if not isinstance(item, dict) or any(not isinstance(item.get(k), str) or not item[k].strip() for k in required):
                raise ValueError("each exception must name advisory, package/version, rationale, owner, approval, expiry")
        today = dt.date.fromisoformat(args.at) if args.at else dt.datetime.now(dt.timezone.utc).date()
        for item in exceptions:
            expiry = dt.date.fromisoformat(item["expires"])
            if expiry < today or (expiry - today).days > 30:
                raise ValueError(f"exception {item['advisory']} must be unexpired and limited to 30 days")
    except (OSError, ValueError, KeyError, json.JSONDecodeError) as exc:
        ap.error(f"invalid exception policy: {exc}")
    if args.image != args.expected_image_id or not args.image.startswith("sha256:"):
        print("scan target must be the expected immutable image ID", file=sys.stderr)
        return 2
    proc = subprocess.run([binary, "image", "--scanners", "vuln", "--format", "json", "--output", str(args.output), args.image], text=True, capture_output=True)
    diagnostics = args.diagnostics or args.output.with_suffix(args.output.suffix + ".diagnostics.txt")
    diagnostics.write_text((proc.stdout + "\n" + proc.stderr)[-65536:])
    if proc.returncode:
        print(proc.stderr[-8192:], file=sys.stderr)
        return proc.returncode
    try:
        report = json.loads(args.output.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        print(f"scanner did not produce valid JSON: {exc}", file=sys.stderr)
        return 2
    errors = validate_report(report, exceptions, today, args.expected_image_id)
    if errors:
        for issue in errors:
            print(f"BLOCK: {issue}", file=sys.stderr)
        return 1
    print(f"PASS: full Trivy report retained at {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
