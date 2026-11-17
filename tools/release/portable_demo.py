#!/usr/bin/env python3
"""Build, verify, and load a checksum-bound local VOLT demo package.

This package is local-demo distribution material, not a signed release archive.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys
import tarfile
import tempfile

import archive

ROOT = Path(__file__).resolve().parents[2]
VERSION = "0.1.0-demo"
PLATFORM_CE_KEY = {
    "linux/amd64": "defectdojo_ce_amd64",
    "linux/arm64": "defectdojo_ce_arm64",
}
INTEGRITY = "checksum-only-local-demo"
PACKAGE_SCHEMA = "volt-portable-demo/v1"


def sha(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def command(argv: list[str], *, capture: bool = False) -> str:
    result = subprocess.run(argv, check=True, text=True,
                            stdout=subprocess.PIPE if capture else None,
                            stderr=subprocess.PIPE if capture else None)
    return result.stdout.strip() if capture else ""


def pins() -> dict[str, str]:
    values = {}
    for line in (ROOT / "docker/g7/versions.lock").read_text().splitlines():
        if "=" in line and not line.startswith("#"):
            key, value = line.split("=", 1)
            values[key] = value
    return values


def source_identity() -> tuple[str, Path]:
    commit = command(["git", "-C", str(ROOT), "rev-parse", "HEAD"], capture=True)
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise ValueError("source checkout does not have a full Git commit")
    dirty = command(["git", "-C", str(ROOT), "status", "--porcelain", "--untracked-files=all"], capture=True)
    if dirty:
        raise ValueError("portable demo builds require a clean tracked source checkout")
    return commit, ROOT


def _manifest_for_image(image_tar: Path, source_tar: Path, image_id: str, platform: str,
                        source_commit: str, source_snapshot: str, image_ref: str) -> dict:
    return {
        "schema": PACKAGE_SCHEMA,
        "integrity": INTEGRITY,
        "version": VERSION,
        "source_commit": source_commit,
        "source_snapshot": source_snapshot,
        "platform": platform,
        "image_id": image_id,
        "image_config_id": image_id,
        "image_ref": image_ref,
        "files": {
            "image.tar": sha(image_tar),
            "source.tar": sha(source_tar),
        },
    }


def _image_admission(image_tar: Path, manifest: dict) -> dict:
    if manifest.get("schema") != PACKAGE_SCHEMA or manifest.get("integrity") != INTEGRITY:
        raise ValueError("not a checksum-only VOLT local demo package")
    if manifest.get("platform") not in archive.SUPPORTED_PLATFORMS:
        raise ValueError("unsupported local demo platform")
    if manifest.get("version") != VERSION:
        raise ValueError("unsupported local demo image version")
    if not re.fullmatch(r"[0-9a-f]{40}", str(manifest.get("source_commit", ""))):
        raise ValueError("source commit is missing or malformed")
    for field in ("source_snapshot", "image_id", "image_config_id"):
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", str(manifest.get(field, ""))):
            raise ValueError(f"{field} is missing or malformed")
    if not isinstance(manifest.get("image_ref"), str) or not manifest["image_ref"]:
        raise ValueError("image import reference is missing")
    identity = archive.validate_docker_archive(image_tar, manifest)
    if identity.get("image_ref") != manifest["image_ref"]:
        raise ValueError("saved image import reference differs from package manifest")
    return identity


def _write_sums(directory: Path) -> None:
    rows = []
    for path in sorted(p for p in directory.iterdir() if p.is_file() and p.name != "SHA256SUMS"):
        rows.append(f"{sha(path)}  {path.name}")
    (directory / "SHA256SUMS").write_text("\n".join(rows) + "\n")


def _pack_directory(directory: Path, output: Path) -> None:
    root = f"volt-portable-demo-{VERSION}"
    output = output.resolve()
    with tarfile.open(output, "w:gz") as tf:
        for path in sorted(p for p in directory.iterdir() if p.is_file() and p.resolve() != output):
            info = tarfile.TarInfo(f"{root}/{path.name}")
            info.size = path.stat().st_size
            info.mode = 0o644
            with path.open("rb") as stream:
                tf.addfile(info, stream)


def build(output: Path, platform: str, docker: str) -> dict:
    if platform not in PLATFORM_CE_KEY:
        raise ValueError("platform must be linux/amd64 or linux/arm64")
    commit, source_root = source_identity()
    output = output.resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    lock = pins()
    ce = lock.get(PLATFORM_CE_KEY[platform], "")
    if not re.fullmatch(r"3\.5\.0@sha256:[0-9a-f]{64}", ce):
        raise ValueError(f"missing immutable DefectDojo CE pin for {platform}")
    arch = platform.split("/", 1)[1]
    image_ref = f"volt-portable-demo:{arch}"
    with tempfile.TemporaryDirectory(prefix="volt-portable-demo-") as work:
        package = Path(work)
        source_tar = package / "source.tar"
        image_tar = package / "image.tar"
        command(["git", "-C", str(source_root), "archive", "--format=tar", "--output", str(source_tar), commit])
        source_snapshot = "sha256:" + sha(source_tar)
        labels = [
            f"org.opencontainers.image.version={VERSION}",
            f"org.opencontainers.image.revision={commit}",
            "org.opencontainers.image.source=https://github.com/njvenis/volt",
            "org.opencontainers.image.licenses=Apache-2.0",
            "org.volt.oidc-deployment-modes=demo,external",
            f"org.volt.compose.source-snapshot={source_snapshot}",
            "org.volt.compose-install.contract=1",
        ]
        argv = [docker, "buildx", "build", "--load", "--platform", platform,
                "--build-arg", f"CE_IMAGE=defectdojo/defectdojo-django@sha256:{ce.split('@sha256:',1)[1]}",
                "--build-arg", f"VOLT_SOURCE_SNAPSHOT={source_snapshot}"]
        for label in labels:
            argv.extend(["--label", label])
        argv.extend(["-f", "Dockerfile.g7", "-t", image_ref, "."])
        command(argv)
        item = json.loads(command([docker, "image", "inspect", image_ref], capture=True))[0]
        if f"{item.get('Os')}/{item.get('Architecture')}" != platform:
            raise ValueError("built Docker image platform differs from selected package platform")
        image_id = item.get("Id", "")
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", image_id):
            raise ValueError("built Docker image ID is malformed")
        actual_labels = item.get("Config", {}).get("Labels") or {}
        if (actual_labels.get("org.opencontainers.image.revision") != commit
                or actual_labels.get("org.opencontainers.image.version") != VERSION
                or actual_labels.get("org.volt.compose.source-snapshot") != source_snapshot):
            raise ValueError("built image source/version labels disagree with captured source")
        command([docker, "image", "save", "--output", str(image_tar), image_ref])
        manifest = _manifest_for_image(image_tar, source_tar, image_id, platform, commit, source_snapshot, image_ref)
        _image_admission(image_tar, manifest)
        (package / "manifest.json").write_text(json.dumps(manifest, sort_keys=True, indent=2) + "\n")
        _write_sums(package)
        _pack_directory(package, output)
    return verify(output)


def verify(path: Path) -> dict:
    with tempfile.TemporaryDirectory(prefix="volt-portable-demo-verify-") as temp:
        root = Path(temp)
        archive.safe_extract(path.resolve(), root)
        expected_root = f"volt-portable-demo-{VERSION}"
        package = root / expected_root
        if not package.is_dir() or set(p.name for p in root.iterdir()) != {expected_root}:
            raise ValueError("portable demo archive has an unexpected root")
        expected_files = {"image.tar", "source.tar", "manifest.json", "SHA256SUMS"}
        if {p.name for p in package.iterdir()} != expected_files:
            raise ValueError("portable demo archive inventory is incomplete or contains unexpected files")
        manifest = json.loads((package / "manifest.json").read_text())
        if manifest.get("version") != VERSION or manifest.get("schema") != PACKAGE_SCHEMA:
            raise ValueError("unsupported portable demo package schema or version")
        expected_files = {"image.tar": sha(package / "image.tar"),
                          "source.tar": sha(package / "source.tar")}
        if manifest.get("files") != expected_files:
            raise ValueError("source or image archive checksum differs from package manifest")
        sum_rows = (package / "SHA256SUMS").read_text().splitlines()
        sums = {}
        for line in sum_rows:
            match = re.fullmatch(r"([0-9a-f]{64})  ([A-Za-z0-9._-]+)", line)
            if not match or match.group(2) in sums:
                raise ValueError("SHA256SUMS contains a malformed or duplicate entry")
            sums[match.group(2)] = match.group(1)
        actual = {p.name: sha(p) for p in package.iterdir() if p.is_file() and p.name != "SHA256SUMS"}
        if sums != actual:
            raise ValueError("SHA256SUMS does not cover the exact portable package payload")
        if "source.tar" not in actual or "sha256:" + actual["source.tar"] != manifest.get("source_snapshot"):
            raise ValueError("source archive digest differs from image source binding")
        identity = _image_admission(package / "image.tar", manifest)
        if identity.get("image_id") != manifest.get("image_id"):
            raise ValueError("saved image identity differs from package manifest")
        return manifest


def load(path: Path, docker: str) -> dict:
    manifest = verify(path)
    with tempfile.TemporaryDirectory(prefix="volt-portable-demo-load-") as temp:
        root = Path(temp)
        archive.safe_extract(path.resolve(), root)
        image_tar = root / f"volt-portable-demo-{VERSION}" / "image.tar"
        command([docker, "image", "load", "--input", str(image_tar)])
    item = json.loads(command([docker, "image", "inspect", manifest["image_ref"]], capture=True))[0]
    if (item.get("Id") != manifest["image_id"]
            or f"{item.get('Os')}/{item.get('Architecture')}" != manifest["platform"]):
        raise ValueError("loaded image ID or platform differs from verified package manifest")
    labels = item.get("Config", {}).get("Labels") or {}
    if (labels.get("org.opencontainers.image.revision") != manifest["source_commit"]
            or labels.get("org.opencontainers.image.version") != manifest["version"]
            or labels.get("org.volt.compose.source-snapshot") != manifest["source_snapshot"]):
        raise ValueError("loaded image source/version labels differ from verified package")
    return manifest


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    build_parser = sub.add_parser("build")
    build_parser.add_argument("--platform", required=True)
    build_parser.add_argument("--output", required=True, type=Path)
    build_parser.add_argument("--docker", default="docker")
    verify_parser = sub.add_parser("verify")
    verify_parser.add_argument("--archive", required=True, type=Path)
    load_parser = sub.add_parser("load")
    load_parser.add_argument("--archive", required=True, type=Path)
    load_parser.add_argument("--docker", default="docker")
    args = parser.parse_args()
    try:
        if args.command == "build":
            result = build(args.output, args.platform, args.docker)
        elif args.command == "verify":
            result = verify(args.archive)
        else:
            result = load(args.archive, args.docker)
        print(json.dumps({"result": "verified", "integrity": result["integrity"],
                          "platform": result["platform"], "image_id": result["image_id"],
                          "source_commit": result["source_commit"],
                          "source_snapshot": result["source_snapshot"]}, sort_keys=True))
        return 0
    except (OSError, ValueError, TypeError, KeyError, json.JSONDecodeError,
            tarfile.TarError, subprocess.CalledProcessError) as exc:
        print(f"portable demo package rejected: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
