#!/usr/bin/env python3
"""Download the pinned Trivy release asset and check its SHA-256."""
import hashlib
import re
import subprocess
import tarfile
import tempfile
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
LOCK = ROOT / "tools/release/tools.lock"
DEST = Path("/tmp/volt-release-tools")


def pin(name: str) -> str:
    for line in LOCK.read_text().splitlines():
        if line.startswith(name + "="):
            return line.split("=", 1)[1]
    raise ValueError(f"missing {name} pin")


def main() -> None:
    version, expected, url = (pin(x) for x in ("trivy_version", "trivy_linux_amd64_sha256", "trivy_release"))
    if not re.fullmatch(r"[0-9a-f]{64}", expected) or f"v{version}/trivy_{version}_Linux-64bit.tar.gz" not in url:
        raise SystemExit("invalid Trivy version, URL, or SHA-256 pin")
    DEST.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=DEST) as temporary:
        archive = Path(temporary) / "trivy.tar.gz"
        urllib.request.urlretrieve(url, archive)
        actual = hashlib.sha256(archive.read_bytes()).hexdigest()
        if actual != expected:
            raise SystemExit(f"Trivy archive SHA-256 mismatch: {actual}")
        with tarfile.open(archive, "r:gz") as tar:
            member = next((m for m in tar.getmembers() if Path(m.name).name == "trivy" and m.isfile()), None)
            if member is None:
                raise SystemExit("pinned Trivy archive has no binary")
            stream = tar.extractfile(member)
            assert stream is not None
            target = DEST / "trivy"
            target.write_bytes(stream.read())
            target.chmod(0o755)
    version_output = subprocess.run([str(DEST / "trivy"), "--version"], check=True, text=True, capture_output=True).stdout
    if version not in version_output:
        raise SystemExit("Trivy version differs from lock")
    print(version_output.strip())


if __name__ == "__main__":
    main()
