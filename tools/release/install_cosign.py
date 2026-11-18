#!/usr/bin/env python3
"""Download the pinned Cosign binary and verify the upstream release checksum."""
import hashlib
import platform
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


def target_platform(system: str | None = None, machine: str | None = None) -> str:
    os_name = (system or platform.system()).lower()
    cpu = (machine or platform.machine()).lower()
    os_map = {"linux": "linux", "darwin": "darwin"}
    arch_map = {"x86_64": "amd64", "amd64": "amd64", "aarch64": "arm64", "arm64": "arm64"}
    if os_name not in os_map or cpu not in arch_map:
        raise SystemExit("pinned Cosign installer supports only Linux/macOS amd64/arm64 hosts")
    return f"{os_map[os_name]}_{arch_map[cpu]}"


def main() -> None:
    version = pin("cosign_version")
    target = target_platform()
    os_name, arch = target.split("_", 1)
    url = pin("cosign_release_template").format(version=version, platform=f"{os_name}-{arch}")
    expected = pin(f"cosign_{os_name}_{arch}_sha256")
    if (not re.fullmatch(r"[0-9a-f]{64}", expected)
            or url != f"https://github.com/sigstore/cosign/releases/download/v{version}/cosign-{os_name}-{arch}"):
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
