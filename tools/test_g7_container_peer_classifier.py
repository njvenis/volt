#!/usr/bin/env python3
"""Focused controls for the exact peer classifier used by the maintained runner."""

from __future__ import annotations

import copy
import json
import sys
from pathlib import Path

from g7_container_peer_classifier import validate_peer_result


def main() -> int:
    if len(sys.argv) != 3:
        print("usage: test_g7_container_peer_classifier.py RUN15_PROBES.json OUTPUT.json", file=sys.stderr)
        return 64
    baseline = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
    cases = [
        ("retained_reset", None, "ConnectionResetError", True),
        ("http_401", 401, None, True),
        ("timeout", None, "TimeoutError", False),
        ("connection_refused", None, "ConnectionRefusedError", False),
        ("http_200", 200, None, False),
        ("unrelated_error", None, "ValueError", False),
    ]
    results = []
    for name, status, error, expected_accept in cases:
        candidate = copy.deepcopy(baseline)
        candidate.pop("8002_unauthorized_route_status", None)
        candidate.pop("8002_unauthorized_route_error", None)
        if status is not None:
            candidate["8002_unauthorized_route_status"] = status
        if error is not None:
            candidate["8002_unauthorized_route_error"] = error
        try:
            decision = validate_peer_result(candidate, "172.17.0.1")
            accepted, failure = True, None
        except ValueError as exc:
            accepted, failure, decision = False, str(exc), None
        if accepted is not expected_accept:
            raise SystemExit(f"{name}: expected accepted={expected_accept}, got {accepted}")
        results.append({
            "case": name,
            "input_status": status,
            "input_error": error,
            "accepted": accepted,
            "failure": failure,
            "decision": decision,
        })
    Path(sys.argv[2]).write_text(json.dumps(results, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"cases": len(results), "accepted": sum(row["accepted"] for row in results),
                      "rejected": sum(not row["accepted"] for row in results), "result": "PASS"}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
