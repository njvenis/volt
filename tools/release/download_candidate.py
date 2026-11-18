#!/usr/bin/env python3
"""Download one admitted Actions ZIP and enforce its API digest before extraction."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import zipfile


def extract(archive: Path, expected_digest: str, destination: Path, name: str) -> None:
    with archive.open("rb") as source:
        digest = hashlib.file_digest(source, "sha256").hexdigest()
    if expected_digest != "sha256:" + digest:
        raise ValueError("Actions artifact API digest differs from downloaded ZIP")
    with zipfile.ZipFile(archive) as bundle:
        rows = bundle.infolist()
        if len(rows) != 1 or rows[0].filename != name or rows[0].is_dir():
            raise ValueError("Actions ZIP must contain exactly the expected candidate archive")
        destination.mkdir(parents=True, exist_ok=False)
        with bundle.open(rows[0]) as source, (destination / name).open("wb") as output:
            import shutil
            shutil.copyfileobj(source, output)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--identity", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--arch", choices=("amd64", "arm64"), required=True)
    args = parser.parse_args()
    identity = json.loads(args.identity.read_text())
    if identity["repository"] != "njvenis/volt" or not re.fullmatch(r"[0-9]+", str(identity["artifact_id"])):
        raise ValueError("invalid admitted Actions identity")
    archive = args.output.with_suffix(".zip")
    with archive.open("wb") as output:
        subprocess.run(["gh", "api", f"repos/njvenis/volt/actions/artifacts/{identity['artifact_id']}/zip"], stdout=output, check=True)
    extract(archive, identity["artifact_digest"], args.output, f"volt-rc3-candidate-{args.arch}.tar.gz")


if __name__ == "__main__":
    main()
