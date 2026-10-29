"""Fail-closed classification of a container-local TCP listener probe."""
from __future__ import annotations

import argparse
import json
import subprocess


def classify_listener_result(returncode: int, stdout: str, stderr: str = "") -> dict:
    if returncode != 0:
        raise RuntimeError(f"listener probe process failed with exit {returncode}: {stderr.strip()}")
    try:
        value = json.loads(stdout)
    except (TypeError, json.JSONDecodeError) as exc:
        raise RuntimeError("listener probe returned invalid JSON") from exc
    if value not in ({"listener": "closed", "connect_errno": 111},
                     {"listener": "open", "connect_errno": 0}):
        raise RuntimeError("listener probe did not return an exact successful socket result")
    return value


def probe_listener(container: str, port: int, timeout: float = 10.0) -> dict:
    code = ("import errno,json,socket,sys; s=socket.socket(); s.settimeout(1); "
            f"r=s.connect_ex(('127.0.0.1',{port})); s.close(); "
            "state='open' if r==0 else ('closed' if r==errno.ECONNREFUSED else None); "
            "print(json.dumps({'listener':state,'connect_errno':r},sort_keys=True)); "
            "sys.exit(0 if state else 3)")
    command = ["docker", "exec", container, "/opt/uvm/venv/bin/python", "-c", code]
    try:
        result = subprocess.run(command, capture_output=True, text=True,
                                timeout=timeout, check=False)
    except (OSError, subprocess.SubprocessError) as exc:
        raise RuntimeError(f"listener probe could not execute: {exc}") from exc
    return classify_listener_result(result.returncode, result.stdout, result.stderr)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("container")
    parser.add_argument("port", type=int)
    args = parser.parse_args()
    print(json.dumps(probe_listener(args.container, args.port), sort_keys=True,
                     separators=(",", ":")))


if __name__ == "__main__":
    main()
