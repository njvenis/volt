#!/usr/bin/env python3
"""Exact immutable release/tag preflight; only structured HTTP 404 means absent."""
import argparse
import json
import subprocess
import sys


def require_absent(endpoint: str) -> None:
    result = subprocess.run(["gh", "api", "--include", endpoint], text=True, capture_output=True)
    # --include exposes authoritative status rather than conflating CLI/network failure with absence.
    statuses = [line.split()[1] for line in result.stdout.splitlines()
                if line.startswith("HTTP/") and len(line.split()) >= 2]
    if result.returncode and statuses == ["404"]:
        body = result.stdout.split("\n\n", 1)[-1]
        if json.loads(body).get("message") == "Not Found":
            return
    raise ValueError(f"immutable identity exists or lookup failed: {endpoint}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository", choices=("njvenis/volt",), required=True)
    args = parser.parse_args()
    try:
        for suffix in ("git/ref/tags/v0.1.0-rc.3", "releases/tags/v0.1.0-rc.3"):
            require_absent(f"repos/{args.repository}/{suffix}")
        return 0
    except (OSError, ValueError) as exc:
        print(f"release preflight rejected: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
