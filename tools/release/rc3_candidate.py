#!/usr/bin/env python3
"""Closed RC3 candidate admission using controller-owned code, before publication."""
from __future__ import annotations
import argparse
import datetime as dt
import json
import re
from pathlib import Path
import subprocess
import sys
import tempfile

import archive
from scan import validate_report

ROOT = Path(__file__).resolve().parents[2]
VERSION = "0.1.0-rc.3"
FILES = {"image.tar", "image-id.txt", "source.tar", "source.bundle", "source-snapshot.txt",
         "prepare-run-id.txt", "compose-qualification.tar.gz", "compose-qualification.tar.gz.sha256",
         "release-scan.json", "release-scan.json.diagnostics.txt"}
DIRECTORIES = {"notices", "compose-evidence"}
NOTICE_SOURCES = {"Dockerfile.g7", "docker/g7/versions.lock", "pyproject.toml", "uv.lock",
    "ui/package.json", "ui/package-lock.json", "THIRD-PARTY-NOTICES.md", "LICENSE",
    "tools/notices/collect.py", "tools/notices/verify.py", "tools/notices/tools.lock",
    "tests/notices/test_verify.py", "docs/third-party-notices.md"}

QUALIFICATION_PASSES = ("health", "audited_operation", "demo_mode", "loopback_binding",
    "private_peer_ingress_denial", "restart_readback", "image_binding_rejection",
    "corrupt_inventory_rejection", "restore_readback",
    "provider_group_removal_old_cookie_revocation",
    "provider_group_removal_fresh_login_no_role_or_scope_recovery")


def inventory(root: Path) -> dict[str, str]:
    result = {}
    for path in root.rglob("*"):
        if path.is_symlink() or not (path.is_file() or path.is_dir()):
            raise ValueError("candidate contains a symlink or special file")
        if path.is_file() and path.relative_to(root).as_posix() != "candidate.json":
            result[path.relative_to(root).as_posix()] = archive.sha(path)
    return result


def seal(root: Path) -> None:
    # This is a transport inventory, authenticated by the admitted Actions artifact.
    # It is never accepted instead of the semantic checks below.
    (root / "candidate.json").write_text(json.dumps({"schema": "volt-rc3-candidate/v1",
        "files": inventory(root)}, sort_keys=True, indent=2) + "\n")


def verify(root: Path, source: str, run_id: str, platform: str, *, controller: Path = ROOT) -> dict:
    if not re.fullmatch(r"[0-9a-f]{40}", source) or not re.fullmatch(r"[0-9]+", run_id):
        raise ValueError("candidate source/run identity is malformed")
    if platform not in archive.SUPPORTED_PLATFORMS:
        raise ValueError("unsupported candidate platform")
    if set(p.name for p in root.iterdir()) != FILES | DIRECTORIES | {"candidate.json"}:
        raise ValueError("candidate closed top-level inventory differs")
    if any(not (root / name).is_file() for name in FILES) or any(not (root / name).is_dir() for name in DIRECTORIES):
        raise ValueError("candidate member type differs")
    doc = json.loads((root / "candidate.json").read_text())
    if set(doc) != {"schema", "files"} or doc["schema"] != "volt-rc3-candidate/v1" or doc["files"] != inventory(root):
        raise ValueError("candidate closed file inventory/hash differs")
    if (root / "prepare-run-id.txt").read_text().strip() != run_id:
        raise ValueError("candidate run binding differs")
    image = (root / "image-id.txt").read_text().strip()
    snapshot = "sha256:" + archive.sha(root / "source.tar")
    if (root / "source-snapshot.txt").read_text().strip() != snapshot:
        raise ValueError("source snapshot hash differs")
    # First require the source to be the approved commit in the trusted controller.
    approved = subprocess.check_output(["git", "-C", str(controller), "archive", "--format=tar", source])
    if approved != (root / "source.tar").read_bytes():
        raise ValueError("source archive differs from approved controller commit")
    with tempfile.TemporaryDirectory(prefix="volt-rc3-admit-") as temporary:
        checkout = Path(temporary) / "source"
        subprocess.run(["git", "clone", "--quiet", "--no-checkout", str(root / "source.bundle"), str(checkout)],
                       check=True, capture_output=True)
        bundled = subprocess.check_output(["git", "-C", str(checkout), "archive", "--format=tar", source])
        if bundled != approved:
            raise ValueError("source bundle differs from approved executable source")
        subprocess.run(["git", "-C", str(checkout), "checkout", "--quiet", "--detach", source], check=True, capture_output=True)
        # Import the controller-owned verifier; never execute code from the candidate.
        sys.path.insert(0, str(ROOT / "tools"))
        import build_compose_bundle
        try:
            build_compose_bundle.verify(root / "compose-qualification.tar.gz", source_root=checkout)
        except SystemExit as exc:
            raise ValueError(str(exc)) from exc
        if (checkout / "deploy/compose/VERSION").read_text().strip() != VERSION:
            raise ValueError("qualification bundle version differs")
        with tempfile.TemporaryDirectory(prefix="volt-rc3-bundle-") as build_temp:
            expected = Path(build_temp) / "compose-qualification.tar.gz"
            build_compose_bundle.build(expected, source_root=checkout)
            if expected.read_bytes() != (root / expected.name).read_bytes():
                raise ValueError("qualification bundle bytes differ from approved source")
        bundle = root / "compose-qualification.tar.gz"
        if bundle.with_suffix(".gz.sha256").read_text() != f"{archive.sha(bundle)}  {bundle.name}\n":
            raise ValueError("qualification bundle sidecar differs")
        notice = json.loads((root / "notices/notice-manifest.json").read_text())
        if (notice.get("image_id"), notice.get("platform"), notice.get("source_revision")) != (image, platform, source):
            raise ValueError("notice image/platform/source binding differs")
        source_rows = notice.get("source_files", [])
        if not isinstance(source_rows, list) or not NOTICE_SOURCES <= {row["path"] for row in source_rows}:
            raise ValueError("notice source inventory is incomplete")
        if len({row["path"] for row in source_rows}) != len(source_rows):
            raise ValueError("notice source inventory contains duplicates")
        for row in source_rows:
            rel = Path(row["path"])
            if rel.is_absolute() or ".." in rel.parts or archive.sha(checkout / rel) != row["sha256"]:
                raise ValueError("notice source differs from approved commit")
        exceptions = json.loads((checkout / "tools/release/exceptions.example.json").read_text())["exceptions"]
        # No candidate-controlled policy expansion. A changed policy needs separate approval.
        if exceptions != json.loads((ROOT / "tools/release/exceptions.example.json").read_text())["exceptions"]:
            raise ValueError("candidate scan exception policy differs from controller")
        errors = validate_report(json.loads((root / "release-scan.json").read_text()), exceptions,
                                 dt.datetime.now(dt.timezone.utc).date(), image)
        if errors:
            raise ValueError("retained scan policy rejected: " + "; ".join(errors))
    identity = archive.validate_docker_archive(root / "image.tar", {"image_id": image,
        "source_commit": source, "source_snapshot": snapshot, "version": VERSION, "platform": platform})
    qualification = json.loads((root / "compose-evidence/qualification.json").read_text())
    expected = {"result": "passed", "qualification_scope": "hosted_rc3_release", "release_version": VERSION,
        "requested_image_version": VERSION, "bundle_version": VERSION, "image_version": VERSION,
        "image_id": image, "platform": platform, "source_revision": source, "source_snapshot": snapshot,
        "bundle_sha256": archive.sha(root / "compose-qualification.tar.gz"), "cold_backup_inventories": 3,
        **{key: "passed" for key in QUALIFICATION_PASSES}}
    if any(qualification.get(key) != value for key, value in expected.items()):
        raise ValueError("qualification receipt assertions or image/source/bundle binding differ")
    if qualification.get("execution_environment") != {"GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "github-hosted"}:
        raise ValueError("qualification execution environment differs")
    if (root / "compose-evidence/owned-cleanup.exit").read_text().strip() != "0":
        raise ValueError("qualification owned cleanup did not pass")
    for suffix in ("stdout", "stderr"):
        if not (root / f"compose-evidence/owned-cleanup.{suffix}").is_file():
            raise ValueError("qualification cleanup raw output missing")
    subprocess.run([sys.executable, str(ROOT / "tools/notices/verify.py"), "--directory", str(root / "notices"),
                    "--image", image, "--platform", platform], check=True)
    return {"source_commit": source, "source_snapshot": snapshot, "image_id": image,
            "platform": platform, "qualification_bundle_sha256": archive.sha(root / "compose-qualification.tar.gz"),
            **identity}


def verify_pair(amd64: Path, arm64: Path, source: str, run_id: str) -> None:
    records = [verify(root, source, run_id, f"linux/{arch}") for root, arch in ((amd64,"amd64"),(arm64,"arm64"))]
    for key in ("source_commit", "source_snapshot", "qualification_bundle_sha256"):
        if records[0][key] != records[1][key]:
            raise ValueError(f"cross-architecture {key} differs")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("seal", "verify-pair"))
    parser.add_argument("--directory", type=Path)
    parser.add_argument("--amd64", type=Path)
    parser.add_argument("--arm64", type=Path)
    parser.add_argument("--source")
    parser.add_argument("--prepare-run-id")
    args = parser.parse_args()
    try:
        if args.command == "seal":
            seal(args.directory)
        else:
            verify_pair(args.amd64, args.arm64, args.source, args.prepare_run_id)
        return 0
    except (OSError, ValueError, KeyError, TypeError, subprocess.CalledProcessError, SystemExit) as exc:
        print(f"RC3 admission rejected: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
