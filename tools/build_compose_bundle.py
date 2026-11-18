#!/usr/bin/env python3
"""Build and verify the versioned source-free Compose installation archive."""
from __future__ import annotations

import argparse
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import tarfile
import re
import gzip

RC2_FILES = ("VERSION", "README.md", "backup-restore.md", "compose.yaml", "demo.yaml", "compose.env.example", "oidc.example.json", "setup.py")
RC3_FILES = (*RC2_FILES, "okta-publisher.yaml", "okta-publisher.example.json")
RC4_FILES = (*RC3_FILES, "local.yaml", "local-restore.yaml", "launcher.sh", "release-image.ref")
FILES = RC3_FILES  # Current source tree; historical source roots are selected by VERSION.


def files_for_version(version: str) -> tuple[str, ...]:
    if version == "0.1.0-rc.2":
        return RC2_FILES
    if version == "0.1.0-rc.3":
        return RC3_FILES
    if version == "0.1.0-rc.4":
        return RC4_FILES
    raise SystemExit("unsupported Compose bundle release version")


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def valid_image_reference(value: str, *, local_fixture: bool = False) -> bool:
    if re.fullmatch(r"ghcr\.io/njvenis/volt@sha256:[0-9a-f]{64}", value):
        return True
    return local_fixture and re.fullmatch(r"127\.0\.0\.1:46150/volt@sha256:[0-9a-f]{64}", value) is not None


def build(output: Path, image_reference: str | None = None, source_root: Path | None = None,
          *, local_admission_fixture: bool = False, verifier_reference: str | None = None) -> None:
    source = (source_root or Path(__file__).resolve().parents[1]) / "deploy" / "compose"
    version = (source / "VERSION").read_text().strip()
    names = files_for_version(version)
    if version == "0.1.0-rc.4" and image_reference is None:
        raise SystemExit("future RC4 installer bundles require an exact immutable runtime image reference")
    if version == "0.1.0-rc.4" and verifier_reference is None:
        raise SystemExit("future RC4 installer bundles require an exact independent verifier image digest")
    payload = {name: (source / ("README.rc4.md" if version == "0.1.0-rc.4" and name == "README.md" else name)).read_bytes()
               for name in names}
    if image_reference is not None and not valid_image_reference(image_reference,
            local_fixture=local_admission_fixture):
        raise SystemExit("release image reference must be the exact VOLT GHCR sha256 digest")
    if verifier_reference is not None:
        accepted_verifier = (r"127\.0\.0\.1:46150/volt-installer-verifier@sha256:[0-9a-f]{64}"
                             if local_admission_fixture else
                             r"ghcr\.io/njvenis/volt-installer-verifier@sha256:[0-9a-f]{64}")
        if not re.fullmatch(accepted_verifier, verifier_reference):
            raise SystemExit("verifier reference must be an exact official or explicitly local fixture digest")
    if image_reference:
        payload = {name: content.replace(b"VOLT_RELEASE_IMAGE_REFERENCE", image_reference.encode())
                   for name, content in payload.items()}
        if version == "0.1.0-rc.4" and payload["release-image.ref"].decode().strip() != image_reference:
            raise SystemExit("future RC4 runtime reference must match the exact signed immutable image digest")
    if verifier_reference:
        payload["launcher.sh"] = payload["launcher.sh"].replace(
            b"VOLT_VERIFIER_IMAGE_REFERENCE", verifier_reference.encode())
    manifest = {"format_version": 1, "bundle_version": version,
                "release_image": image_reference,
                "files": {name: digest(payload[name]) for name in names}}
    if verifier_reference and local_admission_fixture:
        manifest["verifier_reference"] = verifier_reference
    entries = {**payload, "manifest.json": (json.dumps(manifest, sort_keys=True, indent=2) + "\n").encode()}
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("wb") as raw, gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as compressed, tarfile.open(fileobj=compressed, mode="w", format=tarfile.PAX_FORMAT) as archive:
        for name, data in sorted(entries.items()):
            info = tarfile.TarInfo(name=f"volt-compose-{version}/{name}")
            info.size = len(data)
            info.mtime = 0
            info.uid = info.gid = 0
            info.uname = info.gname = ""
            info.mode = 0o755 if name == "setup.py" else 0o644
            archive.addfile(info, io.BytesIO(data))
    checksum = digest(output.read_bytes())
    output.with_suffix(output.suffix + ".sha256").write_text(f"{checksum}  {output.name}\n")
    print(f"bundle_version={version}\narchive={output}\nsha256={checksum}")


def verify(archive_path: Path, source_root: Path | None = None,
           *, local_admission_fixture: bool = False, verifier_reference: str | None = None) -> None:
    with tarfile.open(archive_path, "r:gz") as archive:
        members = archive.getmembers()
        names = [member.name for member in members]
        if len(names) != len(set(names)):
            raise SystemExit("bundle contains duplicate member names")
        for name in names:
            path = PurePosixPath(name)
            if path.is_absolute() or any(part in ("", ".", "..") for part in path.parts):
                raise SystemExit("bundle contains an unsafe member path")
        if any(not member.isfile() for member in members):
            raise SystemExit("bundle contains a non-file member")
        roots = {PurePosixPath(member.name).parts[0] for member in members}
        if len(roots) != 1:
            raise SystemExit("bundle must contain exactly one root directory")
        if any(len(PurePosixPath(member.name).parts) != 2 for member in members):
            raise SystemExit("bundle members must be one level below the root directory")
        files = {PurePosixPath(member.name).name: archive.extractfile(member).read() for member in members}
    manifest = json.loads(files.get("manifest.json", b"{}"))
    if not isinstance(manifest, dict):
        raise SystemExit("bundle file manifest is malformed")
    version = manifest.get("bundle_version")
    names_expected = files_for_version(version)
    if set(files) != {*names_expected, "manifest.json"}:
        raise SystemExit("bundle file inventory does not match the maintained source-free manifest")
    if manifest.get("format_version") != 1 or manifest.get("bundle_version") != files["VERSION"].decode().strip():
        raise SystemExit("bundle version metadata is invalid")
    image_reference = manifest.get("release_image")
    if image_reference is not None and not valid_image_reference(image_reference,
            local_fixture=local_admission_fixture):
        raise SystemExit("bundle release image reference is malformed")
    if version == "0.1.0-rc.4" and (image_reference is None
            or files["release-image.ref"].decode("ascii").strip() != image_reference):
        raise SystemExit("future RC4 installer runtime reference differs from its signed bundle manifest")
    selected_verifier_reference = None
    if version == "0.1.0-rc.4":
        selected_verifier_reference = (manifest.get("verifier_reference") if local_admission_fixture
                                       else verifier_reference)
        verifier_pattern = (r"127\.0\.0\.1:46150/volt-installer-verifier@sha256:[0-9a-f]{64}"
                            if local_admission_fixture else
                            r"ghcr\.io/njvenis/volt-installer-verifier@sha256:[0-9a-f]{64}")
        if (not isinstance(selected_verifier_reference, str)
                or not re.fullmatch(verifier_pattern, selected_verifier_reference)
                or selected_verifier_reference.encode() not in files["launcher.sh"]):
            raise SystemExit("RC4 launcher does not bind the exact independently pinned verifier image")
    if image_reference and image_reference.encode() not in files["README.md"]:
        raise SystemExit("bundle instructions do not bind the declared release image")
    expected = {name: digest(files[name]) for name in names_expected}
    if manifest.get("files") != expected:
        raise SystemExit("bundle file digest mismatch")
    if source_root is not None:
        source = source_root / "deploy" / "compose"
        for name in names_expected:
            source_name = "README.rc4.md" if version == "0.1.0-rc.4" and name == "README.md" else name
            original = (source / source_name).read_bytes()
            wanted = original.replace(b"VOLT_RELEASE_IMAGE_REFERENCE", image_reference.encode()) if image_reference else original
            if name == "launcher.sh" and selected_verifier_reference:
                wanted = wanted.replace(b"VOLT_VERIFIER_IMAGE_REFERENCE", selected_verifier_reference.encode())
            if files[name] != wanted:
                raise SystemExit(f"bundle source differs from the selected VOLT source commit: {name}")
    if b"git clone" in files["README.md"] or b"npm " in files["README.md"]:
        raise SystemExit("ordinary installation instructions must not require source or npm")
    print(f"verified_version={manifest['bundle_version']} files={len(names_expected)} sha256={digest(archive_path.read_bytes())}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(required=True)
    build_cmd = sub.add_parser("build"); build_cmd.add_argument("--output", type=Path, required=True)
    build_cmd.add_argument("--image-reference")
    build_cmd.add_argument("--source-root", type=Path)
    build_cmd.add_argument("--local-admission-fixture", action="store_true",
                           help="allow only the owned loopback registry runtime reference for local qualification")
    build_cmd.add_argument("--verifier-reference",
                           help="independently provisioned local fixture verifier digest (local fixture only)")
    build_cmd.set_defaults(func=lambda args: build(args.output, args.image_reference, args.source_root,
        local_admission_fixture=args.local_admission_fixture, verifier_reference=args.verifier_reference))
    verify_cmd = sub.add_parser("verify"); verify_cmd.add_argument("--archive", type=Path, required=True)
    verify_cmd.add_argument("--source-root", type=Path)
    verify_cmd.add_argument("--local-admission-fixture", action="store_true",
                            help="allow only the owned loopback registry runtime reference for local qualification")
    verify_cmd.add_argument("--verifier-reference",
                            help="exact official verifier digest used to render production bundle source")
    verify_cmd.set_defaults(func=lambda args: verify(args.archive, args.source_root,
        local_admission_fixture=args.local_admission_fixture, verifier_reference=args.verifier_reference))
    args = parser.parse_args(); args.func(args)


if __name__ == "__main__":
    main()
