"""Opt-in report stages; logs digests/IDs/timings, never bodies or credentials."""
from __future__ import annotations
import contextvars
import hashlib
import json
import logging
import os
import time
import uuid
from datetime import datetime, timezone

from sqlalchemy import event

_LOG = logging.getLogger(__name__)
_CONTEXT = contextvars.ContextVar('g5_report_trace', default=None)


def stage(name, command_id=None, **details):
    trace = _CONTEXT.get()
    if trace is None:
        return
    if command_id is not None:
        try:
            trace['command_id'] = str(uuid.UUID(str(command_id)))
        except (ValueError, TypeError, AttributeError):
            pass
    if name == 'request_end':
        query_totals = trace.get('query_totals', {})
        details['sql_query_count'] = trace.get('sql_query_count', 0)
        details['sql_elapsed_ms'] = round(trace.get('sql_elapsed_ns', 0) / 1e6, 3)
        details['sql_templates'] = [
            {'fingerprint': key, 'count': value['count'],
                'elapsed_ms': round(value['elapsed_ns'] / 1e6, 3),
                'max_ms': round(value['max_ns'] / 1e6, 3)}
            for key, value in sorted(query_totals.items(),
                key=lambda item: item[1]['elapsed_ns'], reverse=True)[:12]
        ]
    _LOG.warning('G5_REPORT_TRACE %s', json.dumps({
        'request_id': trace['request_id'], 'command_id': trace.get('command_id'),
        'client_endpoint': trace['client_endpoint'],
        'utc': datetime.now(timezone.utc).isoformat(),
        'elapsed_ms': (time.monotonic_ns() - trace['started']) / 1e6,
        'stage': name, **details}, separators=(',', ':')))


class ReportTraceMiddleware:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope['type'] != 'http' or scope.get('method') != 'POST' or scope.get('path') != '/api/v1/reports':
            await self.app(scope, receive, send)
            return
        trace = {'request_id': str(uuid.uuid4()), 'started': time.monotonic_ns(),
            'client_endpoint': scope.get('client')}
        token = _CONTEXT.set(trace)
        digest, size, body = hashlib.sha256(), 0, bytearray()
        stage('ingress')

        async def traced_receive():
            nonlocal size
            message = await receive()
            if message['type'] == 'http.request':
                chunk = message.get('body', b'')
                digest.update(chunk)
                size += len(chunk)
                if size <= 65536:
                    body.extend(chunk)
                if not message.get('more_body', False):
                    try:
                        command = json.loads(body).get('command_id') if size <= 65536 else None
                    except (ValueError, AttributeError, TypeError):
                        command = None
                    stage('body_complete', command, body_bytes=size, body_sha256=digest.hexdigest())
            elif message['type'] == 'http.disconnect':
                stage('client_disconnect', body_bytes=size)
            return message

        async def traced_send(message):
            if message['type'] == 'http.response.start':
                stage('response_start', status=message['status'])
            elif message['type'] == 'http.response.body' and not message.get('more_body', False):
                stage('response_complete')
            await send(message)

        try:
            await self.app(scope, traced_receive, traced_send)
        finally:
            stage('request_end')
            _CONTEXT.reset(token)


def install(app):
    if os.environ.get('UVM_G3_READ_DIAGNOSTICS') == '1':
        app.add_middleware(ReportTraceMiddleware)

        engine = app.state.engine

        @event.listens_for(engine, 'before_cursor_execute')
        def report_query_start(_connection, _cursor, statement, _parameters, context, _many):
            trace = _CONTEXT.get()
            if trace is None:
                return
            fingerprint = hashlib.sha256(statement.encode('utf-8')).hexdigest()[:16]
            context._g5_report_query = (time.monotonic_ns(), fingerprint)

        @event.listens_for(engine, 'after_cursor_execute')
        def report_query_end(_connection, _cursor, _statement, _parameters, context, _many):
            trace = _CONTEXT.get()
            timing = getattr(context, '_g5_report_query', None)
            if trace is None or timing is None:
                return
            elapsed = time.monotonic_ns() - timing[0]
            trace['sql_query_count'] = trace.get('sql_query_count', 0) + 1
            trace['sql_elapsed_ns'] = trace.get('sql_elapsed_ns', 0) + elapsed
            totals = trace.setdefault('query_totals', {})
            item = totals.setdefault(timing[1], {'count': 0, 'elapsed_ns': 0, 'max_ns': 0})
            item['count'] += 1
            item['elapsed_ns'] += elapsed
            item['max_ns'] = max(item['max_ns'], elapsed)
