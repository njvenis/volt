#!/usr/bin/env python3
"""Revalidate retained candidate contents before any registry write."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys


def sha(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--directory", type=Path, required=True)
    p.add_argument("--source", required=True)
    p.add_argument("--prepare-run-id", required=True)
    args = p.parse_args()
    root = args.directory.resolve()
    try:
        if not re.fullmatch(r"[0-9a-f]{40}", args.source):
            raise ValueError("source commit is malformed")
        if not re.fullmatch(r"[0-9]+", args.prepare_run_id):
            raise ValueError("candidate preparation run ID is malformed")
        if (root/"prepare-run-id.txt").read_text().strip() != args.prepare_run_id:
            raise ValueError("retained candidate artifact is not bound to the named preparation run")
        image_id = (root/"image-id.txt").read_text().strip()
        snapshot = (root/"source-snapshot.txt").read_text().strip()
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", image_id) or not re.fullmatch(r"sha256:[0-9a-f]{64}", snapshot):
            raise ValueError("candidate image or source snapshot identity is malformed")
        if "sha256:" + sha(root/"source.tar") != snapshot:
            raise ValueError("candidate source archive digest differs from the image label binding")
        sys.path.insert(0,str(Path(__file__).parent))
        from archive import validate_docker_archive
        validate_docker_archive(root/"image.tar", {"image_id":image_id,"source_commit":args.source,
            "source_snapshot":snapshot,"version":"0.1.0-rc.2","platform":"linux/amd64"})
        report=json.loads((root/"release-scan.json").read_text())
        if report.get("Metadata",{}).get("ImageID") != image_id:
            raise ValueError("retained full scan is not bound to the candidate image ID")
        verified=subprocess.run([sys.executable,str(Path(__file__).parents[1]/"notices/verify.py"),
            "--directory",str(root/"notices"),"--image",image_id],capture_output=True,text=True)
        if verified.returncode:
            raise ValueError("retained image-bound notice inventory failed verification")
        bundle=root/"compose-qualification.tar.gz"
        bundle_check=subprocess.run([sys.executable,str(Path(__file__).parents[1]/"build_compose_bundle.py"),
            "verify","--archive",str(bundle)],capture_output=True,text=True)
        if bundle_check.returncode:
            raise ValueError("retained source-free qualification bundle failed verification")
        print(json.dumps({"source_commit":args.source,"image_id":image_id,"source_snapshot":snapshot,
            "image_archive":"verified","notice_manifest":"verified","scan_image_id":"verified",
            "qualification_bundle_sha256":sha(bundle)},sort_keys=True))
        return 0
    except (OSError,ValueError,json.JSONDecodeError,KeyError,IndexError) as exc:
        print(f"candidate artifact rejected: {exc}",file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
