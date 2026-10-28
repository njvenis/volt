#!/usr/bin/env python3
"""Fence external IPv4 egress before recovery startup; retain local control."""
from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
import socket
import struct
from pathlib import Path


def routes() -> list[list[str]]:
    return [line.split() for line in Path("/proc/net/route").read_text().splitlines()[1:]]


def remove_default_route() -> dict:
    defaults = [route for route in routes() if route[1] == "00000000"]
    if not defaults:
        connected = [r for r in routes() if r[1] != "00000000"]
        if not connected: raise RuntimeError("local control route is absent")
        return {"default_route_removed":True,"connected_route_retained":True,"already_fenced":True}
    if len(defaults) != 1:
        raise RuntimeError(f"expected one default route, found {len(defaults)}")
    route = defaults[0]
    interface = route[0]
    gateway = socket.inet_ntoa(struct.pack("<I", int(route[2], 16)))
    interface_index = socket.if_nametoindex(interface)
    attrs = (struct.pack("=HH", 8, 5) + socket.inet_aton(gateway)
        + struct.pack("=HH", 8, 4) + struct.pack("=I", interface_index))
    route_message = struct.pack("=BBBBBBBBI", socket.AF_INET, 0, 0, 0,
        254, 3, 0, 1, 0)
    sequence = 1
    header = struct.pack("=IHHII", 16 + len(route_message) + len(attrs),
        25, 5, sequence, 0)
    sock = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, socket.NETLINK_ROUTE)
    try:
        sock.bind((0, 0))
        sock.send(header + route_message + attrs)
        response = sock.recv(4096)
    finally:
        sock.close()
    _, _, _, response_sequence, _ = struct.unpack_from("=IHHII", response)
    error = struct.unpack_from("=i", response, 16)[0]
    if response_sequence != sequence or error:
        raise OSError(-error if error else 71, "RTM_DELROUTE acknowledgement failed")
    remaining = routes()
    if any(item[1] == "00000000" for item in remaining):
        raise RuntimeError("default route remains after deletion")
    if not any(item[0] == interface and item[1] != "00000000" for item in remaining):
        raise RuntimeError("connected control-network route disappeared")
    return {"interface": interface, "gateway": gateway,
        "default_route_removed": True, "connected_route_retained": True}


if __name__ == "__main__":
    if "--verify" in sys.argv:
        if any(r[1] == "00000000" for r in routes()):
            raise RuntimeError("external IPv4 default route exists")
        result={"default_route_absent":True}
    else:
        result=remove_default_route()
    ipv6=Path("/proc/net/ipv6_route").read_text().splitlines()
    if any(r.split()[0] == "0"*32 and r.split()[1] == "00" and r.split()[-1] != "lo" for r in ipv6):
        raise RuntimeError("external IPv6 default route exists")
    probe=socket.socket(); probe.settimeout(2)
    try: status=probe.connect_ex(("203.0.113.1",443))
    finally: probe.close()
    if status != 101: raise RuntimeError("external probe is not ENETUNREACH")
    result.update(external_probe_errno=status,ipv6_default_absent=True,
        observed_at=datetime.now(timezone.utc).isoformat(),namespace=str(Path("/proc/self/ns/net").readlink()))
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
