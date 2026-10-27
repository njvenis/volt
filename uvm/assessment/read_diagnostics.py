"""Opt-in, credential-free stage traces for the maintained G3 group read."""

from contextvars import ContextVar
from datetime import datetime, timezone
import json
import logging
import os
import re
import time
import uuid

from sqlalchemy import event

_CURRENT = ContextVar("g3_group_read_trace", default=None)
_LOG = logging.getLogger("uvm.assessment.read_diagnostics")
_PATH = re.compile(r"^/api/v1/assessment/groups/[0-9a-f-]{36}$")


def stage(name, **safe_fields):
    trace = _CURRENT.get()
    if trace is None:
        return
    now = time.monotonic_ns()
    _LOG.warning("G3_READ_TRACE %s", json.dumps({
        "request_id": trace["request_id"], "client_correlation_id": trace["correlation"],
        "path": trace["path"], "client_endpoint": trace["client"],
        "utc": datetime.now(timezone.utc).isoformat(), "monotonic_ns": now,
        "elapsed_ms": (now - trace["start"]) / 1_000_000,
        "stage": name, **safe_fields}, separators=(",", ":")))


class GroupReadTraceMiddleware:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or scope.get("method") != "GET" or not _PATH.fullmatch(scope.get("path", "")):
            return await self.app(scope, receive, send)
        correlation = None
        # Retain only canonical UUID correlation, never headers or credentials.
        for key, value in scope.get("headers", []):
            if key == b"x-correlation-id":
                try:
                    correlation = str(uuid.UUID(value.decode("ascii")))
                except (ValueError, UnicodeError):
                    pass
        token = _CURRENT.set({"request_id": str(uuid.uuid4()), "correlation": correlation,
            "path": scope["path"], "client": scope.get("client"), "start": time.monotonic_ns()})
        status = None
        stage("ingress")

        async def traced_receive():
            message = await receive()
            if message["type"] == "http.disconnect":
                stage("disconnect")
            return message

        async def traced_send(message):
            nonlocal status
            if message["type"] == "http.response.start":
                status = message["status"]
                stage("serialization_complete_response_start", status=status)
            await send(message)
            if message["type"] == "http.response.body" and not message.get("more_body", False):
                stage("response_body_complete", status=status)

        try:
            await self.app(scope, traced_receive, traced_send)
        finally:
            stage("request_complete", status=status)
            _CURRENT.reset(token)


def install(app, engine):
    if os.environ.get("UVM_G3_READ_DIAGNOSTICS") != "1":
        return
    app.add_middleware(GroupReadTraceMiddleware)

    @event.listens_for(engine, "checkout")
    def acquired(_dbapi_connection, _record, _proxy):
        stage("connection_acquired")

    @event.listens_for(engine, "before_cursor_execute")
    def before(_connection, _cursor, _statement, _parameters, _context, _many):
        stage("repository_query_start")

    @event.listens_for(engine, "after_cursor_execute")
    def after(_connection, _cursor, _statement, _parameters, _context, _many):
        stage("repository_query_complete")
