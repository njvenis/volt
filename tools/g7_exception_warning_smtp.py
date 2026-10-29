"""Loopback implicit-TLS SMTP fixture for the disposable G7 journey."""
from __future__ import annotations

import argparse
from email.parser import BytesParser
from email.policy import default
import hashlib
import json
from pathlib import Path
import re
import socketserver
import ssl
import threading


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, address, cert: Path, key: Path, output: Path):
        super().__init__(address, Handler)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert, key)
        self.context = context
        self.output = output
        self.lock = threading.Lock()
        self.rows: list[dict] = []
        self.recipient_counts: dict[str, int] = {}

    def get_request(self):
        connection, address = super().get_request()
        try:
            return self.context.wrap_socket(connection, server_side=True), address
        except Exception:
            connection.close()
            raise

    def retain(self, row):
        with self.lock:
            self.rows.append(row)
            tmp = self.output.with_suffix(".tmp")
            tmp.write_text(json.dumps(self.rows, sort_keys=True, separators=(",", ":")) + "\n")
            tmp.replace(self.output)


class Handler(socketserver.StreamRequestHandler):
    def line(self, value: str):
        self.wfile.write((value + "\r\n").encode("ascii"))
        self.wfile.flush()

    def handle(self):
        self.line("220 g7-warning-fixture ESMTP ready")
        self.sender = None
        self.recipient = None
        self.authenticated = False
        auth_state = None
        while True:
            raw = self.rfile.readline(65538)
            if not raw:
                return
            command = raw.decode("utf-8", "replace").rstrip("\r\n")
            verb, _, argument = command.partition(" ")
            verb = verb.upper()
            if verb in {"EHLO", "HELO"}:
                self.wfile.write(b"250-g7-warning-fixture\r\n250 AUTH PLAIN LOGIN\r\n")
                self.wfile.flush()
            elif verb == "AUTH":
                if argument.upper().startswith("PLAIN "):
                    import base64
                    token = base64.b64decode(argument.split(" ", 1)[1])
                    self.authenticated = token.rsplit(b"\0", 1)[-1] == b"fixture-secret"
                    self.line("235 2.7.0 authenticated" if self.authenticated else "535 5.7.8 denied")
                elif argument.upper() == "LOGIN":
                    auth_state = "username"
                    self.line("334 VXNlcm5hbWU6")
                else:
                    self.line("504 5.5.4 unsupported auth")
            elif auth_state == "username":
                auth_state = "password"
                self.line("334 UGFzc3dvcmQ6")
            elif auth_state == "password":
                import base64
                self.authenticated = base64.b64decode(command).decode() == "fixture-secret"
                auth_state = None
                self.line("235 2.7.0 authenticated" if self.authenticated else "535 5.7.8 denied")
            elif verb == "MAIL":
                self.sender = argument
                self.line("250 2.1.0 sender ok" if self.authenticated else "530 5.7.0 authenticate first")
            elif verb == "RCPT":
                match = re.search(r"<([^>]+)>", argument)
                self.recipient = match.group(1) if match else None
                with self.server.lock:
                    count = self.server.recipient_counts.get(self.recipient or "", 0) + 1
                    self.server.recipient_counts[self.recipient or ""] = count
                self.count = count
                if self.recipient == "predatadisconnect@fixture.invalid" and count == 1:
                    self.server.retain({"recipient": self.recipient, "sender": self.sender,
                        "result": "connection_lost_before_data", "authenticated": self.authenticated,
                        "exchange_number": count})
                    self.request.shutdown(2)
                    self.request.close()
                    return
                if self.recipient == "retry@fixture.invalid" and count == 1:
                    self.line("451 4.3.0 temporary fixture rejection")
                    self.server.retain({"recipient": self.recipient, "sender": self.sender,
                        "result": "temporary_rcpt_rejection", "authenticated": self.authenticated,
                        "exchange_number": count})
                elif self.recipient in {"accepted@fixture.invalid", "retry@fixture.invalid", "uncertain@fixture.invalid", "predatadisconnect@fixture.invalid"}:
                    self.line("250 2.1.5 recipient ok")
                else:
                    self.line("550 5.1.1 unknown fixture recipient")
            elif verb == "DATA":
                if self.recipient is None:
                    self.line("503 5.5.1 recipient required")
                    continue
                self.line("354 end with <CRLF>.<CRLF>")
                chunks = []
                while True:
                    data_line = self.rfile.readline(65538)
                    if not data_line:
                        return
                    if data_line == b".\r\n":
                        break
                    if data_line.startswith(b".."):
                        data_line = data_line[1:]
                    chunks.append(data_line)
                message = b"".join(chunks)
                parsed = BytesParser(policy=default).parsebytes(message)
                row = {"recipient": self.recipient, "sender": self.sender,
                    "result": "accepted", "authenticated": self.authenticated,
                    "exchange_number": self.count, "message_id": parsed.get("Message-ID"),
                    "data_sha256": hashlib.sha256(message).hexdigest(), "byte_count": len(message)}
                if self.recipient == "uncertain@fixture.invalid":
                    row["result"] = "connection_lost_after_data"
                    self.server.retain(row)
                    self.request.shutdown(2)
                    self.request.close()
                    return
                self.server.retain(row)
                self.line("250 2.0.0 queued by local fixture")
            elif verb == "RSET":
                self.sender = self.recipient = None
                self.line("250 2.0.0 reset")
            elif verb == "NOOP":
                self.line("250 2.0.0 ok")
            elif verb == "QUIT":
                self.line("221 2.0.0 bye")
                return
            else:
                self.line("502 5.5.1 unsupported command")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", required=True)
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--cert", type=Path, required=True)
    parser.add_argument("--key", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    server = Server((args.host, args.port), args.cert, args.key, args.output)
    print(json.dumps({"ready": True, "host": args.host, "port": args.port}), flush=True)
    try:
        server.serve_forever(poll_interval=0.2)
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
