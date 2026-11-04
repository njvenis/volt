#!/usr/bin/env python3
"""Build and verify the versioned source-free Compose installation archive."""
from __future__ import annotations

import argparse
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import tarfile

FILES = ("VERSION", "README.md", "backup-restore.md", "compose.yaml", "demo.yaml",
         "compose.env.example", "oidc.example.json", "setup.py")


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def build(output: Path) -> None:
    source = Path(__file__).resolve().parents[1] / "deploy" / "compose"
    payload = {name: (source / name).read_bytes() for name in FILES}
    version = payload["VERSION"].decode().strip()
    manifest = {"format_version": 1, "bundle_version": version,
                "files": {name: digest(payload[name]) for name in FILES}}
    entries = {**payload, "manifest.json": (json.dumps(manifest, sort_keys=True, indent=2) + "\n").encode()}
    output.parent.mkdir(parents=True, exist_ok=True)
    with tarfile.open(output, "w:gz", format=tarfile.PAX_FORMAT) as archive:
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


def verify(archive_path: Path) -> None:
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
    if set(files) != {*FILES, "manifest.json"}:
        raise SystemExit("bundle file inventory does not match the maintained source-free manifest")
    manifest = json.loads(files["manifest.json"])
    if manifest.get("format_version") != 1 or manifest.get("bundle_version") != files["VERSION"].decode().strip():
        raise SystemExit("bundle version metadata is invalid")
    expected = {name: digest(files[name]) for name in FILES}
    if manifest.get("files") != expected:
        raise SystemExit("bundle file digest mismatch")
    if b"git clone" in files["README.md"] or b"npm " in files["README.md"]:
        raise SystemExit("ordinary installation instructions must not require source or npm")
    print(f"verified_version={manifest['bundle_version']} files={len(FILES)} sha256={digest(archive_path.read_bytes())}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(required=True)
    build_cmd = sub.add_parser("build"); build_cmd.add_argument("--output", type=Path, required=True)
    build_cmd.set_defaults(func=lambda args: build(args.output))
    verify_cmd = sub.add_parser("verify"); verify_cmd.add_argument("--archive", type=Path, required=True)
    verify_cmd.set_defaults(func=lambda args: verify(args.archive))
    args = parser.parse_args(); args.func(args)


if __name__ == "__main__":
    main()
