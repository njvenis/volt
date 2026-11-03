#!/usr/bin/env python3
"""Download actionlint from its pinned GitHub release and verify SHA-256."""
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


def pin(key: str) -> str:
    for line in LOCK.read_text().splitlines():
        if line.startswith(key + "="):
            return line.split("=", 1)[1]
    raise ValueError(f"missing tool pin {key}")


def main() -> None:
    version, url, expected = (pin(k) for k in ("actionlint_version", "actionlint_release", "actionlint_linux_amd64_sha256"))
    if not re.fullmatch(r"[0-9a-f]{64}", expected) or f"/v{version}/actionlint_{version}_linux_amd64.tar.gz" not in url:
        raise SystemExit("invalid actionlint version, URL, or SHA-256 pin")
    DEST.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=DEST) as temporary:
        archive = Path(temporary) / "actionlint.tar.gz"
        urllib.request.urlretrieve(url, archive)
        actual = hashlib.sha256(archive.read_bytes()).hexdigest()
        if actual != expected:
            raise SystemExit(f"actionlint SHA-256 mismatch: {actual}")
        with tarfile.open(archive, "r:gz") as tar:
            member = next((m for m in tar.getmembers() if Path(m.name).name == "actionlint" and m.isfile()), None)
            if member is None:
                raise SystemExit("pinned actionlint archive has no binary")
            stream = tar.extractfile(member)
            assert stream is not None
            binary = DEST / "actionlint"
            binary.write_bytes(stream.read())
            binary.chmod(0o755)
    output = subprocess.run([str(DEST / "actionlint"), "-version"], check=True, text=True, capture_output=True).stdout
    if version not in output:
        raise SystemExit("actionlint binary version differs from lock")
    print(output.splitlines()[0])


if __name__ == "__main__":
    main()
