#!/usr/bin/env python3
"""Small client-side assertions for the disposable G7 network journey."""
from __future__ import annotations

import argparse
import base64
import hashlib
import http.client
import json
import socket
import ssl
import sys
import time
from urllib.parse import urlsplit


def request(args):
    if args.request_file:
        spec = json.load(open(args.request_file, encoding="utf-8"))
        url = spec["url"]
    else:
        spec = {}
        url = args.url
    parsed = urlsplit(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("url must be an absolute HTTP(S) URL")
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    cls = http.client.HTTPSConnection if parsed.scheme == "https" else http.client.HTTPConnection
    options = {"timeout": args.timeout}
    if parsed.scheme == "https":
        options["context"] = ssl.create_default_context()
    connection = cls(parsed.hostname, port, **options)
    headers = {str(k): str(v) for k, v in spec.get("headers", {}).items()}
    headers.update(dict(item.split(":", 1) for item in args.header))
    if args.host or spec.get("host"):
        headers["Host"] = args.host or spec["host"]
    if "body_base64" in spec:
        body = base64.b64decode(spec["body_base64"], validate=True)
    elif spec.get("body_file"):
        body = open(spec["body_file"], "rb").read()
    elif args.body_file:
        body = open(args.body_file, "rb").read()
    else:
        body = None
    method = spec.get("method", args.method)
    started = time.monotonic()
    connection.request(method, parsed.path or "/", body=body, headers=headers)
    response = connection.getresponse()
    peer = connection.sock.getpeername()[0] if connection.sock else None
    local = connection.sock.getsockname()[0] if connection.sock else None
    payload = response.read()
    result = {"status": response.status, "remote_address": peer, "client_address": local,
        "elapsed_ms": round((time.monotonic() - started) * 1000, 3),
        "response_bytes": len(payload), "response_sha256": hashlib.sha256(payload).hexdigest()}
    try:
        result["response"] = json.loads(payload)
    except (ValueError, UnicodeDecodeError):
        pass
    if args.response_file:
        with open(args.response_file, "wb") as stream:
            stream.write(payload)
    connection.close()
    print(json.dumps(result, sort_keys=True))
    allowed = {int(value) for value in args.expect.split(",")}
    if response.status not in allowed:
        raise AssertionError(f"unexpected HTTP status {response.status}; expected {sorted(allowed)}")
    if args.expected_peer and local != args.expected_peer:
        raise AssertionError(f"unexpected selected client address {local!r}; expected {args.expected_peer!r}")


def ports(args):
    results = []
    for port in args.ports:
        try:
            with socket.create_connection((args.host, port), timeout=args.timeout):
                reachable = True
        except OSError:
            reachable = False
        results.append({"port": port, "reachable": reachable})
    print(json.dumps({"host": args.host, "ports": results}, sort_keys=True))
    unexpected = [item["port"] for item in results if item["reachable"] != args.expect_reachable]
    if unexpected:
        raise AssertionError(f"ports with unexpected reachability: {unexpected}")


def main():
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="command", required=True)
    http = commands.add_parser("http")
    http.add_argument("url")
    http.add_argument("--request-file")
    http.add_argument("--method", default="GET")
    http.add_argument("--host")
    http.add_argument("--header", action="append", default=[])
    http.add_argument("--body-file")
    http.add_argument("--expect", default="200")
    http.add_argument("--expected-peer")
    http.add_argument("--timeout", type=float, default=5)
    http.add_argument("--response-file")
    http.set_defaults(run=request)
    port_parser = commands.add_parser("ports")
    port_parser.add_argument("host")
    port_parser.add_argument("ports", nargs="+", type=int)
    port_parser.add_argument("--expect-reachable", action="store_true")
    port_parser.add_argument("--timeout", type=float, default=1)
    port_parser.set_defaults(run=ports)
    args = parser.parse_args()
    try:
        args.run(args)
    except (OSError, ValueError, AssertionError) as exc:
        print(f"g7_network_assert: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
