#!/usr/bin/env python3
"""Assemble the already-signed RC4 launcher and Compose bundle without changing release assets."""
from __future__ import annotations

import argparse
import gzip
import io
from pathlib import Path, PurePosixPath
import re
import sys
import tarfile

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.build_compose_bundle import verify
from tools.release.easy_bootstrap import VERIFIER_IMAGE_PATTERN
FILES = ("launcher.sh", "launcher.sigstore.json", "installer.bundle.tar.gz",
         "installer.bundle.sigstore.json")


def build(output: Path, *, bundle: Path, launcher_signature: Path, bundle_signature: Path,
          verifier_reference: str, source_root: Path | None = None) -> None:
    if output.exists() or output.is_symlink():
        raise SystemExit("refusing an existing installer package output")
    if not re.fullmatch(VERIFIER_IMAGE_PATTERN, verifier_reference):
        raise SystemExit("easy installer requires the exact externally pinned official verifier digest")
    for path in (bundle, launcher_signature, bundle_signature):
        if path.is_symlink() or not path.is_file():
            raise SystemExit("signed installer inputs must be regular non-symlink files")
    verify(bundle, source_root=source_root, verifier_reference=verifier_reference)
    with tarfile.open(bundle, "r:gz") as archive:
        version_member = next((m for m in archive.getmembers() if PurePosixPath(m.name).name == "VERSION"), None)
        if version_member is None or archive.extractfile(version_member).read().decode().strip() != "0.1.0-rc.4":
            raise SystemExit("easy installer packages require the future RC4 bundle")
        launchers = [m for m in archive.getmembers() if PurePosixPath(m.name).name == "launcher.sh"]
        if len(launchers) != 1 or not launchers[0].isfile():
            raise SystemExit("signed RC4 bundle must contain one regular launcher")
        launcher = archive.extractfile(launchers[0]).read()
    try:
        launcher_text = launcher.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise SystemExit("packaged launcher is not UTF-8 text") from exc
    if (f"VERIFIER_IMAGE='{verifier_reference}'" not in launcher_text
            or "VOLT_VERIFIER_IMAGE_REFERENCE" in launcher_text):
        raise SystemExit("packaged launcher does not bind the independently pinned verifier digest")
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("wb") as raw, gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as compressed, \
            tarfile.open(fileobj=compressed, mode="w", format=tarfile.PAX_FORMAT) as outer:
        inputs = {"launcher.sh": None,
            "launcher.sigstore.json": launcher_signature,
            "installer.bundle.tar.gz": bundle,
            "installer.bundle.sigstore.json": bundle_signature}
        for name in FILES:
            data = launcher if name == "launcher.sh" else inputs[name].read_bytes()
            info = tarfile.TarInfo(name=name)
            info.size = len(data)
            info.mtime = 0
            info.uid = info.gid = 0
            info.uname = info.gname = ""
            info.mode = 0o755 if name == "launcher.sh" else 0o644
            outer.addfile(info, io.BytesIO(data))
    print(f"package={output}\nfiles={len(FILES)}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--bundle", type=Path, required=True)
    parser.add_argument("--launcher-signature", type=Path, required=True)
    parser.add_argument("--bundle-signature", type=Path, required=True)
    parser.add_argument("--verifier-reference", required=True,
                        help="official verifier OCI digest pinned by the independently trusted release page")
    parser.add_argument("--source-root", type=Path,
                        help="exact extracted source tree used to verify the closed bundle")
    args = parser.parse_args()
    build(args.output, bundle=args.bundle, launcher_signature=args.launcher_signature,
          bundle_signature=args.bundle_signature, verifier_reference=args.verifier_reference,
          source_root=args.source_root)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
