#!/usr/bin/env python3
"""Fetch the exact Syft release asset only after its repository SHA-256 matches."""
import hashlib
import re
import shutil
import subprocess
import tarfile
import tempfile
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
LOCK = ROOT / "tools/notices/tools.lock"
DEST = Path("/tmp/volt-release-tools")


def pin(name: str) -> str:
    for line in LOCK.read_text().splitlines():
        if line.startswith(name + "="):
            return line.split("=", 1)[1]
    raise ValueError(f"missing {name} in tools/notices/tools.lock")


def main() -> None:
    version = pin("syft_version")
    expected = pin("syft_linux_amd64_sha256")
    url = pin("syft_release")
    if not re.fullmatch(r"[0-9a-f]{64}", expected) or f"v{version}/syft_{version}_linux_amd64.tar.gz" not in url:
        raise SystemExit("invalid Syft version, URL, or SHA-256 pin")
    DEST.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=DEST) as temp:
        archive = Path(temp) / "syft.tar.gz"
        urllib.request.urlretrieve(url, archive)
        actual = hashlib.sha256(archive.read_bytes()).hexdigest()
        if actual != expected:
            raise SystemExit(f"Syft archive SHA-256 mismatch: {actual}")
        with tarfile.open(archive, "r:gz") as tar:
            member = next((m for m in tar.getmembers() if Path(m.name).name == "syft" and m.isfile()), None)
            if member is None:
                raise SystemExit("pinned Syft archive does not contain binary")
            stream = tar.extractfile(member)
            assert stream is not None
            target = DEST / "syft"
            target.write_bytes(stream.read())
            target.chmod(0o755)
    result = subprocess.run([str(DEST / "syft"), "version"], check=True, text=True, capture_output=True)
    if version not in result.stdout:
        raise SystemExit("Syft binary version differs from pinned version")
    print(result.stdout.strip())


if __name__ == "__main__":
    main()
