"""Outer socket-peer and Host authority guard for the G7 local ingress."""
from __future__ import annotations

import ipaddress
import json
import logging
import os

_LOG = logging.getLogger("uvm.api.private_ingress")


def _networks(raw: str) -> tuple:
    values = [item.strip() for item in raw.split(",") if item.strip()]
    if not values:
        raise RuntimeError("UVM_INGRESS_ALLOWED_PEER_CIDRS must not be empty")
    networks = tuple(ipaddress.ip_network(item, strict=False) for item in values)
    private_networks = tuple(map(ipaddress.ip_network,
        ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7")))
    loopback_networks = tuple(map(ipaddress.ip_network, ("127.0.0.0/8", "::1/128")))
    if any(not any(network.version == allowed.version and network.subnet_of(allowed)
            for allowed in (*private_networks, *loopback_networks)) for network in networks):
        raise RuntimeError("UVM ingress peer networks must be loopback or private")
    return networks


def _hosts(raw: str) -> frozenset[str]:
    values = frozenset(item.strip().lower().rstrip(".") for item in raw.split(",") if item.strip())
    if not values or any("/" in item or "*" in item for item in values):
        raise RuntimeError("UVM_INGRESS_ALLOWED_HOSTS must contain exact host names")
    return values


def configured_ingress_guard():
    peers = os.getenv("UVM_INGRESS_ALLOWED_PEER_CIDRS")
    hosts = os.getenv("UVM_INGRESS_ALLOWED_HOSTS")
    if bool(peers) != bool(hosts):
        raise RuntimeError("both UVM ingress peer and Host allowlists must be configured together")
    if not peers:
        return None
    return PrivateIngressGuard(_networks(peers), _hosts(hosts))


class PrivateIngressGuard:
    """Reject untrusted socket peers and Host authorities without proxy headers."""

    def __init__(self, networks, hosts):
        self.networks = networks
        self.hosts = hosts

    async def __call__(self, scope, receive, send):
        if scope["type"] not in {"http", "websocket"}:
            await self.app(scope, receive, send)
            return
        peer_text = (scope.get("client") or ("", 0))[0]
        try:
            peer = ipaddress.ip_address(peer_text.split("%", 1)[0])
        except ValueError:
            peer = None
        allowed_peer = peer is not None and any(
            peer.version == network.version and peer in network for network in self.networks)
        headers = {key.lower(): value for key, value in scope.get("headers", ())}
        authority = headers.get(b"host", b"").decode("latin-1").strip()
        # Parse the authority only; X-Forwarded-Host/Forwarded never participate.
        if authority.startswith("["):
            host = authority[1:].split("]", 1)[0].lower()
        else:
            host = authority.rsplit(":", 1)[0] if authority.count(":") == 1 else authority
            host = host.lower().rstrip(".")
        allowed_host = host in self.hosts
        if allowed_peer and allowed_host:
            _LOG.warning("private_ingress_decision peer=%s host=%s status=allow", peer, host)
            await self.app(scope, receive, send)
            return
        if scope["type"] == "websocket":
            await send({"type": "websocket.close", "code": 1008})
            return
        code = "ingress_peer_forbidden" if not allowed_peer else "ingress_host_forbidden"
        status = 403 if not allowed_peer else 421
        _LOG.warning("private_ingress_decision peer=%s host=%s status=deny code=%s",
            peer_text, host, code)
        payload = json.dumps({"schema_version": 1, "error": {"code": code,
            "message": "Request is outside the configured private ingress"}},
            separators=(",", ":")).encode()
        await send({"type": "http.response.start", "status": status,
            "headers": [(b"content-type", b"application/json"),
                (b"content-length", str(len(payload)).encode())]})
        await send({"type": "http.response.body", "body": payload})


def install(app):
    guard = configured_ingress_guard()
    if guard is not None:
        guard.app = app
        app.add_middleware(_GuardMiddleware, guard=guard)


class _GuardMiddleware:
    def __init__(self, app, guard):
        self.app = app
        guard.app = app
        self.guard = guard

    async def __call__(self, scope, receive, send):
        await self.guard(scope, receive, send)
