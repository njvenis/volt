"""Bounded private transport readers; none grants clean-stop authority.

Real input descriptors are read through select with the fixed deadline, including
EOF. BytesIO is only an explicit in-memory component/test input. Public offline
exchange wiring is not yet implemented here.
"""
from __future__ import annotations

import io
import json
import os
import select
import time

from uvm.installer import route_check
from uvm.installer.offline_artifacts import pairs

MAX_TAR = 128 * 1024
MAX_ENVELOPE = 2048
MAX_LOG_BYTES = 1024 * 1024
MAX_LOG_LINES = 1024
MAX_LOG_SECONDS = 10
MAX_WAIT_SECONDS = 0.5
MAX_TAR_SECONDS = 1
READ_SIZE = 65536


def _before(deadline):
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError('private stopped acquisition deadline exceeded')
    return remaining


def _bounded_bytes(stream, limit: int, deadline) -> bytes:
    result = bytearray()
    while True:
        remaining = _before(deadline)
        size = min(READ_SIZE, limit + 1 - len(result))
        if isinstance(stream, io.BytesIO):
            block = stream.read(size)
        else:
            descriptor = stream.fileno()
            ready, _, _ = select.select([descriptor], [], [], remaining)
            if not ready:
                raise TimeoutError('private stopped acquisition deadline exceeded')
            block = os.read(descriptor, size)
        _before(deadline)
        if type(block) is not bytes:
            raise ValueError('private stopped acquisition is not a byte stream')
        if not block:
            return bytes(result)
        result.extend(block)
        if len(result) > limit:
            raise ValueError('private stopped acquisition exceeded its byte bound')


def docker_wait_output(stream) -> bytes:
    raw = _bounded_bytes(stream, 2, time.monotonic() + MAX_WAIT_SECONDS)
    if raw != b'0\n':
        raise ValueError('current Docker wait output is not exact zero')
    return raw


def routing_tar(stream) -> bytes:
    deadline = time.monotonic() + MAX_TAR_SECONDS
    raw = _bounded_bytes(stream, MAX_TAR, deadline)
    route_check.stopped_tar_records(raw)
    _before(deadline)
    return raw


def _json_constant(_value):
    raise ValueError('private completion JSON constant is invalid')


def completion_line(stream) -> bytes:
    """Keep exactly one whole canonical candidate, not a clean-stop proof.

    Every JSON object line is decoded before profile recognition, including
    escaped strings and duplicate-key rejection. Raw marker matching only adds
    conservative rejection; it never determines which record grants success.
    """
    deadline = time.monotonic() + MAX_LOG_SECONDS
    raw_logs = _bounded_bytes(stream, MAX_LOG_BYTES, deadline)
    # Decode before classification. json.loads(bytes) accepts encoding BOMs;
    # allowing those to hide an escaped-profile second record is ambiguous.
    try:
        raw_logs.decode('utf-8', errors='strict')
    except UnicodeError:
        raise ValueError('private completion encoding is unsupported') from None
    if b'\xef\xbb\xbf' in raw_logs or b'\x00' in raw_logs:
        raise ValueError('private completion encoding is unsupported')
    if raw_logs and not raw_logs.endswith(b'\n'):
        raise ValueError('private completion line is truncated')
    lines = raw_logs.split(b'\n')[:-1]
    if len(lines) > MAX_LOG_LINES:
        raise ValueError('private completion acquisition exceeded its line bound')
    shared = route_check._shared()
    marker = shared.COMPLETION_PROFILE.encode('ascii')
    candidate = None
    for raw in lines:
        _before(deadline)
        if len(raw) > MAX_ENVELOPE:
            raise ValueError('private completion acquisition exceeded its record bound')
        value = None
        # JSON object records can encode the profile with Unicode escapes or
        # surround it with whitespace. Decode BEFORE deciding they are unknown.
        if b'{' in raw or marker in raw:
            try:
                value = json.loads(raw, object_pairs_hook=pairs, parse_constant=_json_constant)
            except (ValueError, UnicodeError, RecursionError):
                raise ValueError('private completion candidate is malformed') from None
        if isinstance(value, dict) and value.get('profile') == shared.COMPLETION_PROFILE:
            if candidate is not None:
                raise ValueError('private completion candidate is duplicated')
            try:
                value = shared.validate_record('completion', raw)
            except shared.RouteCheckError:
                raise ValueError('private completion candidate is malformed') from None
            if shared.canonical(value) != raw:
                raise ValueError('private completion candidate is not canonical')
            candidate = raw
        elif marker in raw:
            raise ValueError('private completion candidate is malformed')
    _before(deadline)
    if candidate is None:
        raise ValueError('private completion candidate is missing')
    return candidate
