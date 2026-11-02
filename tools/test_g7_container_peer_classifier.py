#!/usr/bin/env python3
"""Focused controls for the exact peer classifier used by the maintained runner."""

from __future__ import annotations

import copy
import contextlib
import http.client
import io
import json
import re
import socket
import ssl
import sys
from pathlib import Path

from g7_container_peer_classifier import validate_peer_result


def run_exact_probe(status, error_name):
    """Run the runner's actual embedded Python probe with mocked I/O only."""
    runner = Path(__file__).with_name("g7_container_journey.sh").read_text(encoding="utf-8")
    match = re.search(
        r'--entrypoint python3 "\$IMAGE" -c \'(.*?)\' "\$BOUNDARY_PEER_IP"',
        runner,
        re.DOTALL,
    )
    if match is None:
        raise RuntimeError("could not extract maintained runner peer probe")
    probe = match.group(1)
    error_types = {
        "ConnectionResetError": ConnectionResetError,
        "SSLError": ssl.SSLError,
        "TimeoutError": TimeoutError,
        "ConnectionRefusedError": ConnectionRefusedError,
    }
    error_type = error_types.get(error_name)

    class UdpSocket:
        def connect(self, address):
            pass

        def getsockname(self):
            return ("172.17.0.4", 45000)

        def close(self):
            pass

    class Response:
        def __init__(self, response_status, body=b"{}", read_error=None):
            self.status = response_status
            self.body = body
            self.read_error = read_error

        def read(self):
            if self.read_error is not None:
                raise self.read_error("mock response read")
            return self.body

    class ApiConnection:
        def __init__(self, *args, **kwargs):
            pass

        def request(self, *args, **kwargs):
            pass

        def getresponse(self):
            return Response(403, b'{"error":{"code":"ingress_peer_forbidden"}}')

        def close(self):
            pass

    class RecoveryConnection:
        def __init__(self, *args, **kwargs):
            pass

        def request(self, *args, **kwargs):
            pass

        def getresponse(self):
            if status is None:
                if error_type is None:
                    raise RuntimeError("mock requires an error when no status is observed")
                raise error_type("mock before response status")
            read_error = error_type if error_name is not None else None
            return Response(status, b"", read_error)

        def close(self):
            pass

    original_socket = socket.socket
    original_create_connection = socket.create_connection
    original_http = http.client.HTTPConnection
    original_https = http.client.HTTPSConnection
    old_argv = sys.argv
    output = io.StringIO()
    try:
        socket.socket = lambda *args, **kwargs: UdpSocket()

        def create_connection(address, timeout=None):
            if address[1] in (8000, 9000, 8002):
                return UdpSocket()
            raise ConnectionRefusedError("mock private listener refusal")

        socket.create_connection = create_connection
        http.client.HTTPConnection = ApiConnection
        http.client.HTTPSConnection = RecoveryConnection
        sys.argv = ["peer-probe", "10.77.0.5"]
        with contextlib.redirect_stdout(output):
            exec(compile(probe, "<maintained-peer-probe>", "exec"), {})
    finally:
        socket.socket = original_socket
        socket.create_connection = original_create_connection
        http.client.HTTPConnection = original_http
        http.client.HTTPSConnection = original_https
        sys.argv = old_argv
    return json.loads(output.getvalue())


def main() -> int:
    if len(sys.argv) != 3:
        print("usage: test_g7_container_peer_classifier.py RUN15_PROBES.json OUTPUT.json", file=sys.stderr)
        return 64
    baseline = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
    cases = [
        ("no_status_reset", None, "ConnectionResetError", True),
        ("no_status_tls_error", None, "SSLError", True),
        ("http_401", 401, None, True),
        ("timeout", None, "TimeoutError", False),
        ("connection_refused", None, "ConnectionRefusedError", False),
        ("http_200", 200, None, False),
        ("http_200_then_reset", 200, "ConnectionResetError", False),
        ("http_200_then_tls_error", 200, "SSLError", False),
        ("http_403_then_reset", 403, "ConnectionResetError", False),
        ("http_500_then_reset", 500, "ConnectionResetError", False),
    ]
    results = []
    for name, status, error, expected_accept in cases:
        candidate = run_exact_probe(status, error)
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
            "producer_result": candidate,
            "accepted": accepted,
            "failure": failure,
            "decision": decision,
        })
    malformed = []
    for name, status in (("status_zero", 0), ("status_false", False),
                         ("status_null", None), ("status_string_401", "401")):
        candidate = copy.deepcopy(baseline)
        candidate["8002_unauthorized_route_status"] = status
        try:
            validate_peer_result(candidate, "172.17.0.1")
            accepted, failure = True, None
        except ValueError as exc:
            accepted, failure = False, str(exc)
        if accepted:
            raise SystemExit(f"{name}: malformed observed status was accepted")
        malformed.append({"case": name, "status": status, "accepted": False, "failure": failure})
    unrelated = copy.deepcopy(baseline)
    unrelated.pop("8002_unauthorized_route_status", None)
    unrelated["8002_unauthorized_route_error"] = "ValueError"
    try:
        validate_peer_result(unrelated, "172.17.0.1")
        raise SystemExit("unrelated_error: missing-status error was accepted")
    except ValueError as exc:
        malformed.append({"case": "unrelated_error", "status": None,
                           "accepted": False, "failure": str(exc)})
    payload = {"probe_consumer_cases": results, "strict_status_controls": malformed}
    Path(sys.argv[2]).write_text(json.dumps(payload, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"probe_cases": len(results), "accepted": sum(row["accepted"] for row in results),
                      "rejected": sum(not row["accepted"] for row in results),
                      "strict_status_controls": len(malformed), "result": "PASS"}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
