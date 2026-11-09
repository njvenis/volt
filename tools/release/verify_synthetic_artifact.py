"""Validate the exact synthetic directory and checksum produced by CI."""

from __future__ import annotations

import argparse
import hashlib
import re
from pathlib import Path

EXPECTED_FILES = {"SHA256SUMS", "payload/deep/synthetic.txt"}
EXPECTED_PAYLOAD = b"VOLT synthetic GitHub Actions artifact compatibility fixture\n"


def verify_artifact(root: Path) -> None:
    """Reject missing, extra, unsafe, or corrupted downloaded artifact files."""
    if not root.is_dir() or root.is_symlink():
        raise ValueError("artifact root must be a real directory")

    paths = list(root.rglob("*"))
    if any(path.is_symlink() for path in paths):
        raise ValueError("artifact must not contain symbolic links")
    actual = {path.relative_to(root).as_posix() for path in paths if path.is_file()}
    if actual != EXPECTED_FILES:
        raise ValueError(f"artifact file set differs: expected {sorted(EXPECTED_FILES)}, got {sorted(actual)}")

    payload = root / "payload/deep/synthetic.txt"
    if payload.read_bytes() != EXPECTED_PAYLOAD:
        raise ValueError("synthetic payload bytes differ")

    lines = (root / "SHA256SUMS").read_text(encoding="ascii").splitlines()
    if len(lines) != 1:
        raise ValueError("checksum manifest must contain exactly one entry")
    match = re.fullmatch(r"([0-9a-f]{64})  payload/deep/synthetic\.txt", lines[0])
    if match is None:
        raise ValueError("checksum manifest entry is malformed")
    actual_hash = hashlib.sha256(payload.read_bytes()).hexdigest()
    if match.group(1) != actual_hash:
        raise ValueError("synthetic payload SHA-256 differs from manifest")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", type=Path, help="downloaded artifact directory")
    args = parser.parse_args()
    verify_artifact(args.root)
    print("synthetic artifact paths and SHA-256 verified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
