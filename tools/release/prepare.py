#!/usr/bin/env python3
"""Fail-closed local release candidate checks; this never publishes artifacts."""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path


def git(source: Path, *args: str) -> str:
    return subprocess.check_output(["git", "-C", str(source), *args], text=True).strip()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--version", required=True)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--notices", type=Path, required=True)
    parser.add_argument("--image-id", required=True)
    parser.add_argument("--docker", default="docker")
    parser.add_argument("--exception", type=Path)
    parser.add_argument("--at", help="UTC date for deterministic policy checks (YYYY-MM-DD)")
    args = parser.parse_args()

    if not re.fullmatch(r"0\.1\.0-rc\.2", args.version):
        parser.error("only the prepared version 0.1.0-rc.2 is configured")
    if args.exception:
        from datetime import date

        doc = json.loads(args.exception.read_text())
        today = date.fromisoformat(args.at) if args.at else dt.datetime.now(dt.timezone.utc).date()
        entries = doc.get("exceptions")
        if not isinstance(entries, list):
            parser.error("exception file must contain an exceptions list")
        for item in entries:
            required = {"advisory", "package", "version", "rationale", "owner", "approval", "expires"}
            if not isinstance(item, dict) or not required <= item.keys():
                parser.error("each exception needs advisory, package, version, rationale, owner, approval and expires")
            if not all(isinstance(item[key], str) and item[key].strip() for key in required):
                parser.error("exception fields must be non-empty strings")
            expiry = date.fromisoformat(item["expires"])
            if expiry < today or (expiry - today).days > 30:
                parser.error(f"exception {item['advisory']} must expire within 30 days and not be expired")

    source = args.source.resolve()
    notices = args.notices.resolve()
    if not source.is_dir() or not notices.is_dir():
        parser.error("source and verified notice directories are required")
    if not (args.notices / "sbom.syft.json").is_file() or not (args.notices / "sbom.spdx.json").is_file():
        parser.error("both Syft and SPDX SBOMs are required")
    verified = subprocess.run(
        [sys.executable, str(Path(__file__).parents[1] / "notices" / "verify.py"),
         "--directory", str(notices), "--image", args.image_id], text=True, capture_output=True
    )
    if verified.returncode:
        parser.error(f"generated notice inventory failed verification: {verified.stderr.strip()}")

    # A release candidate must be based on an immutable, clean main commit.
    source_root = Path(git(source, "rev-parse", "--show-toplevel")).resolve()
    if source_root != source:
        parser.error("--source must name the Git worktree root")
    branch = git(source, "branch", "--show-current")
    if branch != "main":
        parser.error(f"release source must be checked out on main (found {branch or 'detached HEAD'})")
    if git(source, "status", "--porcelain"):
        parser.error("release source worktree must be clean")
    commit = git(source, "rev-parse", "HEAD")
    source_archive = subprocess.check_output(["git", "-C", str(source), "archive", "--format=tar", "HEAD"])
    source_snapshot = "sha256:" + hashlib.sha256(source_archive).hexdigest()
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", args.image_id):
        parser.error("candidate image ID must be immutable sha256")
    inspected = subprocess.run([args.docker, "image", "inspect", args.image_id], text=True, capture_output=True)
    if inspected.returncode:
        parser.error(f"candidate image could not be inspected: {inspected.stderr.strip()}")
    try:
        image_info = json.loads(inspected.stdout)[0]
    except (json.JSONDecodeError, IndexError, TypeError):
        parser.error("candidate image inspect returned invalid JSON")
    labels = image_info.get("Config", {}).get("Labels") or {}
    if image_info.get("Id") != args.image_id or labels.get("org.opencontainers.image.revision") != commit or labels.get("org.opencontainers.image.version") != args.version:
        parser.error("candidate image source/version labels do not match --source")
    if (labels.get("org.volt.oidc-deployment-modes") != "demo,external"
            or labels.get("org.volt.compose-install.contract") != "1"
            or labels.get("org.volt.compose.source-snapshot") != source_snapshot):
        parser.error("candidate image lacks the required Compose contract or exact source snapshot label")
    if git(source, "tag", "--list", f"v{args.version}"):
        parser.error(f"version tag v{args.version} already exists")
    print(f"release preparation accepted source commit {commit}; publication is a separate approval gate")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except subprocess.CalledProcessError as exc:
        print(f"git precondition failed: {exc}", file=sys.stderr)
        raise SystemExit(exc.returncode)
