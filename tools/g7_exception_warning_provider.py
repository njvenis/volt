"""Loopback Slack HTTP fixture for the disposable G7 warning journey."""
from __future__ import annotations

import argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import threading


class Provider(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address, output: Path, token: str):
        super().__init__(address, Handler)
        self.output = output
        self.token = token
        self.lock = threading.Lock()
        self.rows: list[dict] = []

    def retain(self, row):
        with self.lock:
            self.rows.append(row)
            temporary = self.output.with_suffix(".tmp")
            temporary.write_text(json.dumps(self.rows, sort_keys=True, separators=(",", ":")) + "\n")
            temporary.replace(self.output)


class Handler(BaseHTTPRequestHandler):
    server: Provider

    def log_message(self, _format, *_args):
        return

    def do_GET(self):
        if self.path != "/healthz":
            self.send_error(404)
            return
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"ready\n")

    def do_POST(self):
        if self.path != "/api/chat.postMessage":
            self.send_error(404)
            return
        try:
            size = int(self.headers.get("Content-Length", "0"))
            if not 0 < size <= 65536:
                raise ValueError
            raw = self.rfile.read(size)
            payload = json.loads(raw)
            if (self.headers.get("Authorization") != "Bearer " + self.server.token
                    or not isinstance(payload, dict)
                    or not isinstance(payload.get("channel"), str)
                    or not isinstance(payload.get("blocks"), list)):
                raise ValueError
        except (ValueError, json.JSONDecodeError):
            self.send_error(400)
            return
        channel = payload["channel"]
        response = {"channel": channel, "ts": "1720000000.000001", "ok": True}
        self.server.retain({"channel": channel, "authorization_verified": True,
            "idempotency_key": self.headers.get("Idempotency-Key"), "payload": payload})
        if channel == "C_FIXTURE_FAILED":
            self.send_response(429)
            self.send_header("Retry-After", "60")
            self.end_headers()
            return
        if channel == "C_FIXTURE_UNCERTAIN":
            # The provider captures the request, then drops the connection. The
            # caller cannot distinguish a post-acceptance disconnect from loss.
            self.close_connection = True
            self.connection.shutdown(2)
            self.connection.close()
            return
        encoded = json.dumps(response, separators=(",", ":")).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", required=True)
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--token", required=True)
    args = parser.parse_args()
    args.output.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    server = Provider((args.host, args.port), args.output, args.token)
    print(json.dumps({"ready": True, "host": args.host, "port": args.port}), flush=True)
    try:
        server.serve_forever(poll_interval=0.2)
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
