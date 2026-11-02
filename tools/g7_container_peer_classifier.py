#!/usr/bin/env python3
"""Validate the unauthorized bridge-peer observations retained by the G7 journey."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any


def validate_peer_result(result: dict[str, Any], bridge_gateway: str) -> dict[str, Any]:
    """Raise ValueError unless every expected peer boundary observation holds."""
    recovery_denied = (
        result.get("8002_unauthorized_route_status") == 401
        or result.get("8002_unauthorized_route_error")
        in ("ConnectionResetError", "SSLError")
    )
    if (
        result.get("8000") is not True
        or result.get("9000") is not True
        or result.get("5432") is not False
        or result.get("6379") is not False
        or result.get("8081") is not False
        or result.get("peer_http_status") != 403
        or result.get("peer_error_code") != "ingress_peer_forbidden"
        or result.get("peer_source_ip") in {"127.0.0.1", bridge_gateway}
        or result.get("8002_tcp_listener") is not True
        or not recovery_denied
    ):
        raise ValueError(
            "bridge peer did not receive exact private-peer denial while listeners were present"
        )
    return {
        "accepted": True,
        "peer_source_ip": result["peer_source_ip"],
        "recovery_denial": (
            "http_401"
            if result.get("8002_unauthorized_route_status") == 401
            else result["8002_unauthorized_route_error"]
        ),
    }


def main() -> int:
    if len(sys.argv) != 3:
        print("usage: g7_container_peer_classifier.py PROBES.json BRIDGE_GATEWAY", file=sys.stderr)
        return 64
    try:
        result = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
        validated = validate_peer_result(result, sys.argv[2])
    except (OSError, json.JSONDecodeError, ValueError, KeyError) as exc:
        print(f"peer boundary classifier rejected evidence: {exc}", file=sys.stderr)
        return 70
    print(json.dumps(validated, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
