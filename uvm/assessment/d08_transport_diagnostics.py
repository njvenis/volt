"""Clock-free, opt-in API transport events for the D-08 dry-run diagnosis."""

from __future__ import annotations

import asyncio
import hashlib
import itertools
import json
import logging
import threading
import uuid
import os


_LOG = logging.getLogger("uvm.assessment.d08_transport")
_PATH = "/api/v1/assessment/groups"
_SEQUENCE = itertools.count()
_SEQUENCE_LOCK = threading.Lock()


def _next_sequence() -> int:
    with _SEQUENCE_LOCK:
        return next(_SEQUENCE)


class D08ListTransportMiddleware:
    """Record list-response delivery stages without clocks or query contents."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if (scope.get("type") != "http" or scope.get("method") != "GET"
                or scope.get("path") != _PATH):
            return await self.app(scope, receive, send)

        action_id = None
        for key, value in scope.get("headers", []):
            if key == b"x-uvm-d08-action":
                try:
                    action_id = str(uuid.UUID(value.decode("ascii")))
                except (ValueError, UnicodeError):
                    pass
        query = scope.get("query_string", b"")
        request_id = str(uuid.uuid4())
        endpoint = scope.get("client")
        total_body_bytes = 0
        response_status = None

        def emit(stage: str, **fields) -> None:
            _LOG.warning("D08_API_TRANSPORT %s", json.dumps({
                "sequence": _next_sequence(), "request_id": request_id,
                "action_id": action_id, "method": "GET", "path": _PATH,
                "query_sha256": hashlib.sha256(query).hexdigest(),
                "client_endpoint": endpoint, "stage": stage, **fields,
            }, separators=(",", ":")))

        emit("ingress")

        async def traced_receive():
            message = await receive()
            if message.get("type") == "http.disconnect":
                emit("client_disconnected", body_bytes=total_body_bytes)
            return message

        async def traced_send(message):
            nonlocal total_body_bytes, response_status
            if message.get("type") == "http.response.start":
                response_status = message.get("status")
                emit("response_start", status=response_status)
            elif message.get("type") == "http.response.body":
                chunk = message.get("body", b"")
                total_body_bytes += len(chunk)
                more = bool(message.get("more_body", False))
                if chunk:
                    emit("response_chunk", chunk_bytes=len(chunk),
                         body_bytes=total_body_bytes)
                if not more:
                    emit("body_complete", status=response_status,
                         body_bytes=total_body_bytes)
            await send(message)

        try:
            await self.app(scope, traced_receive, traced_send)
        except asyncio.CancelledError:
            emit("request_cancelled", status=response_status,
                 body_bytes=total_body_bytes)
            raise


def install(app) -> None:
    """Install only when the maintained D-08 runner explicitly opts in."""
    if os.environ.get("UVM_D08_TRANSPORT_TRACE") == "1":
        app.add_middleware(D08ListTransportMiddleware)
