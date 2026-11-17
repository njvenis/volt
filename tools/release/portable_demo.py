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
import shutil
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
COMPOSE_BUNDLE_FILES = {
    "VERSION", "README.md", "backup-restore.md", "compose.yaml", "demo.yaml",
    "compose.env.example", "oidc.example.json", "setup.py", "manifest.json",
}


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


def _install_instructions() -> str:
    return """# Install the portable VOLT local demo

This artifact is checksum-only local demo material, not a signed release. It supports a
synthetic local OIDC principal; it does not provide password login or verified Okta integration.

Requirements on the destination: Python 3.11+, Docker Engine/Desktop with Compose v2,
OpenSSL, and tar.
No VOLT checkout, Git, Node.js, npm, uv, source build, or network access is needed after transfer.

1. Extract the downloaded artifact, then verify its package:

   tar -xzf volt-portable-demo-*.tar.gz
   cd volt-portable-demo-0.1.0-demo
   python3 offline-tools/portable_demo.py verify --archive ../volt-portable-demo-*.tar.gz

2. Import the verified image; retain the printed image ID and platform:

   python3 offline-tools/portable_demo.py load --archive ../volt-portable-demo-*.tar.gz

3. Extract the bundled Compose installer:

   mkdir -p installer && tar -xzf installer.tar.gz -C installer
   cd installer/volt-compose-0.1.0-rc.2

4. Initialise and start a private local demo (replace IMAGE_ID and PLATFORM with verified values):

   python3 setup.py init "$HOME/.local/share/volt/demo" --mode demo --project volt-demo --image IMAGE_ID --platform PLATFORM --bootstrap-principal local-testing-admin --demo-subject local-testing-admin-subject
   python3 setup.py start "$HOME/.local/share/volt/demo"
   python3 setup.py status "$HOME/.local/share/volt/demo"

5. Link the configured synthetic subject to the local testing administrator:

   python3 setup.py link-admin "$HOME/.local/share/volt/demo"

6. In a browser, open http://127.0.0.1:8180, sign in with the synthetic local OIDC principal,
and complete an administrative action. This is synthetic OIDC; no local password is created.

7. Copy the uvm_session cookie from the browser storage inspector. Then initialise authority;
the command prompts for the cookie without echoing it:

   python3 setup.py initialize-authority "$HOME/.local/share/volt/demo"

Keep demo data disposable. Follow the bundled backup/restore and cleanup instructions for this
named instance.
"""


def _verify_compose_bundle(path: Path) -> None:
    """Validate the generated source-free installer without executing its contents."""
    expected_payload = COMPOSE_BUNDLE_FILES - {"manifest.json"}
    with tarfile.open(path, "r:gz") as tf:
        members = tf.getmembers()
        names = [member.name for member in members]
        if len(names) != len(set(names)) or any(not member.isfile() for member in members):
            raise ValueError("Compose installer contains duplicate or non-file entries")
        roots = set()
        payload: dict[str, bytes] = {}
        version = None
        for member in members:
            parts = PurePosixPath(member.name).parts
            if len(parts) != 2 or any(part in {"", ".", ".."} for part in parts):
                raise ValueError("Compose installer contains an unsafe member path")
            roots.add(parts[0])
            payload[parts[1]] = tf.extractfile(member).read()
        if len(roots) != 1 or set(payload) != COMPOSE_BUNDLE_FILES:
            raise ValueError("Compose installer file inventory is invalid")
        version = payload["VERSION"].decode().strip()
        if next(iter(roots)) != f"volt-compose-{version}":
            raise ValueError("Compose installer root and version disagree")
        metadata = json.loads(payload["manifest.json"])
        if metadata.get("format_version") != 1 or metadata.get("bundle_version") != version or metadata.get("release_image") is not None:
            raise ValueError("Compose installer manifest metadata is invalid")
        wanted = {name: hashlib.sha256(payload[name]).hexdigest() for name in expected_payload}
        if metadata.get("files") != wanted:
            raise ValueError("Compose installer manifest file digests disagree")
        if b"git clone" in payload["README.md"] or b"npm " in payload["README.md"]:
            raise ValueError("Compose installer instructions require source or npm")
    sidecar = path.with_suffix(path.suffix + ".sha256")
    if sidecar.read_text() != f"{sha(path)}  {path.name}\n":
        raise ValueError("Compose installer checksum sidecar is invalid")


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
    identity = archive.validate_docker_archive(image_tar, {"image_id": image_id,
        "platform": platform, "source_commit": source_commit, "source_snapshot": source_snapshot,
        "version": VERSION})
    return {
        "schema": PACKAGE_SCHEMA,
        "integrity": INTEGRITY,
        "version": VERSION,
        "source_commit": source_commit,
        "source_snapshot": source_snapshot,
        "platform": platform,
        "image_id": image_id,
        "image_config_id": identity["image_config_id"],
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
    for path in sorted(p for p in directory.rglob("*") if p.is_file() and p.name != "SHA256SUMS"):
        rows.append(f"{sha(path)}  {path.relative_to(directory).as_posix()}")
    (directory / "SHA256SUMS").write_text("\n".join(rows) + "\n")


def _pack_directory(directory: Path, output: Path) -> None:
    root = f"volt-portable-demo-{VERSION}"
    output = output.resolve()
    with tarfile.open(output, "w:gz") as tf:
        for path in sorted(p for p in directory.rglob("*") if p.is_file() and p.resolve() != output):
            info = tarfile.TarInfo(f"{root}/{path.relative_to(directory).as_posix()}")
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
        installer = package / "installer.tar.gz"
        command([sys.executable, str(ROOT / "tools/build_compose_bundle.py"), "build", "--output", str(installer)])
        (package / "offline-tools").mkdir()
        for helper in (ROOT / "tools/release/portable_demo.py", ROOT / "tools/release/archive.py",
                       ROOT / "tools/release/provenance.py", ROOT / "tools/build_compose_bundle.py"):
            shutil.copyfile(helper, package / "offline-tools" / helper.name)
        (package / "PORTABLE-INSTALL.md").write_text(_install_instructions())
        manifest["files"].update({
            "installer.tar.gz": sha(installer),
            "installer.tar.gz.sha256": sha(installer.with_suffix(installer.suffix + ".sha256")),
            "PORTABLE-INSTALL.md": sha(package / "PORTABLE-INSTALL.md"),
        })
        for helper in (package / "offline-tools").iterdir():
            manifest["files"][f"offline-tools/{helper.name}"] = sha(helper)
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
        expected_paths = {"image.tar", "source.tar", "installer.tar.gz", "installer.tar.gz.sha256", "PORTABLE-INSTALL.md",
                          "manifest.json", "SHA256SUMS", "offline-tools/portable_demo.py",
                          "offline-tools/archive.py", "offline-tools/provenance.py",
                          "offline-tools/build_compose_bundle.py"}
        actual_paths = {p.relative_to(package).as_posix() for p in package.rglob("*") if p.is_file()}
        if actual_paths != expected_paths:
            raise ValueError("portable demo archive inventory is incomplete or contains unexpected files")
        manifest = json.loads((package / "manifest.json").read_text())
        if manifest.get("version") != VERSION or manifest.get("schema") != PACKAGE_SCHEMA:
            raise ValueError("unsupported portable demo package schema or version")
        expected_files = {p.relative_to(package).as_posix(): sha(p) for p in package.rglob("*")
                          if p.is_file() and p.name not in {"manifest.json", "SHA256SUMS"}}
        if manifest.get("files") != expected_files:
            raise ValueError("source or image archive checksum differs from package manifest")
        sum_rows = (package / "SHA256SUMS").read_text().splitlines()
        sums = {}
        for line in sum_rows:
            match = re.fullmatch(r"([0-9a-f]{64})  ([A-Za-z0-9._/-]+)", line)
            if not match or match.group(2) in sums:
                raise ValueError("SHA256SUMS contains a malformed or duplicate entry")
            sums[match.group(2)] = match.group(1)
        actual = {p.relative_to(package).as_posix(): sha(p) for p in package.rglob("*")
                  if p.is_file() and p.name != "SHA256SUMS"}
        if sums != actual:
            raise ValueError("SHA256SUMS does not cover the exact portable package payload")
        if "source.tar" not in actual or "sha256:" + actual["source.tar"] != manifest.get("source_snapshot"):
            raise ValueError("source archive digest differs from image source binding")
        identity = _image_admission(package / "image.tar", manifest)
        if identity.get("image_id") != manifest.get("image_id"):
            raise ValueError("saved image identity differs from package manifest")
        _verify_compose_bundle(package / "installer.tar.gz")
        return manifest


def load(path: Path, docker: str) -> dict:
    manifest = verify(path)
    with tempfile.TemporaryDirectory(prefix="volt-portable-demo-load-") as temp:
        root = Path(temp)
        archive.safe_extract(path.resolve(), root)
        image_tar = root / f"volt-portable-demo-{VERSION}" / "image.tar"
        command([docker, "image", "load", "--input", str(image_tar)])
    item = json.loads(command([docker, "image", "inspect", manifest["image_ref"]], capture=True))[0]
    if (item.get("Id") not in {manifest["image_id"], manifest["image_config_id"], manifest.get("image_index_id")}
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
    ce_parser = sub.add_parser("ce-image")
    ce_parser.add_argument("--platform", required=True, choices=sorted(PLATFORM_CE_KEY))
    args = parser.parse_args()
    try:
        if args.command == "build":
            result = build(args.output, args.platform, args.docker)
        elif args.command == "verify":
            result = verify(args.archive)
        elif args.command == "ce-image":
            value = pins().get(PLATFORM_CE_KEY[args.platform], "")
            if not re.fullmatch(r"3\.5\.0@sha256:[0-9a-f]{64}", value):
                raise ValueError(f"missing immutable DefectDojo CE pin for {args.platform}")
            print("defectdojo/defectdojo-django@" + value.split("@", 1)[1])
            return 0
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
