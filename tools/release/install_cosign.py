#!/usr/bin/env python3
"""Download the pinned Cosign binary and verify the upstream release checksum."""
import hashlib
import re
import subprocess
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
    version, url, expected = (pin(k) for k in ("cosign_version", "cosign_release", "cosign_linux_amd64_sha256"))
    if not re.fullmatch(r"[0-9a-f]{64}", expected) or f"/v{version}/cosign-linux-amd64" not in url:
        raise SystemExit("invalid Cosign version, URL, or SHA-256 pin")
    DEST.mkdir(parents=True, exist_ok=True)
    binary = DEST / "cosign"
    urllib.request.urlretrieve(url, binary)
    actual = hashlib.sha256(binary.read_bytes()).hexdigest()
    if actual != expected:
        binary.unlink(missing_ok=True)
        raise SystemExit(f"Cosign SHA-256 mismatch: {actual}")
    binary.chmod(0o755)
    output = subprocess.run([str(binary), "version"], check=True, text=True, capture_output=True).stdout
    if f"v{version}" not in output:
        raise SystemExit("Cosign binary version differs from lock")
    print(output.splitlines()[-5].strip())


if __name__ == "__main__":
    main()
