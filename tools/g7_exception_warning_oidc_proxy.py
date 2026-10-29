"""Private TCP relay for the disposable warning-mode synthetic OIDC issuer."""
from __future__ import annotations

import argparse
import select
import socket
import socketserver


class Relay(socketserver.BaseRequestHandler):
    def handle(self):
        upstream = socket.create_connection(("127.0.0.1", self.server.upstream_port), timeout=5)
        upstream.settimeout(None)
        sockets = [self.request, upstream]
        try:
            while sockets:
                readable, _, exceptional = select.select(sockets, [], sockets, 30)
                if exceptional:
                    return
                if not readable:
                    continue
                for source in readable:
                    data = source.recv(65536)
                    if not data:
                        destination = upstream if source is self.request else self.request
                        try:
                            destination.shutdown(socket.SHUT_WR)
                        except OSError:
                            pass
                        sockets.remove(source)
                        continue
                    destination = upstream if source is self.request else self.request
                    destination.sendall(data)
        finally:
            upstream.close()


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, address, upstream_port):
        super().__init__(address, Relay)
        self.upstream_port = upstream_port


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--upstream-port", type=int, default=9000)
    args = parser.parse_args()
    server = Server((args.host, args.port), args.upstream_port)
    print(f"ready host={args.host} port={args.port} upstream=127.0.0.1:{args.upstream_port}", flush=True)
    try:
        server.serve_forever(poll_interval=0.2)
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
