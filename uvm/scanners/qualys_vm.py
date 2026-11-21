"""Bounded Qualys VM/VMDR Host Detection List v2 HTTP and XML adapter."""
from __future__ import annotations

import re
import ssl
import time
import errno
import selectors
import socket
import queue
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit
from urllib.request import Request
import xml.etree.ElementTree as ET
from collections.abc import Callable, Iterator
from contextlib import AbstractContextManager
import json
import uuid

import h11

from uvm.identity.observations import (MISSING_NOT_SUPPLIED, MISSING_UNVERIFIED,
    MissingField, SourceObservationV1)
from uvm.scanners.contracts import QualysBasicCredential

ENDPOINT_PATH = "/api/2.0/fo/asset/host/vm/detection/"
PLATFORM_ORIGINS = {
    "us1": "https://qualysapi.qualys.com",
    "us2": "https://qualysapi.qg2.apps.qualys.com",
    "us3": "https://qualysapi.qg3.apps.qualys.com",
    "eu1": "https://qualysapi.qualys.eu",
    "eu2": "https://qualysapi.qg2.apps.qualys.eu",
    "in1": "https://qualysapi.qg1.apps.qualys.in",
}
MAX_PAGE_BYTES = 10 * 1024 * 1024
MAX_PAGES = 10
MAX_TOTAL_BYTES = 50 * 1024 * 1024
MAX_ROWS = 100_000
TOTAL_DEADLINE_SECONDS = 120
REQUEST_TIMEOUT_SECONDS = 30
MAX_PAGE_ATTEMPTS = 3
SOURCE_STATUSES = "New,Active,Re-Opened,Fixed"


class QualysError(Exception):
    """Safe, typed provider failure; messages never contain response bodies."""

    def __init__(self, code: str, *, retry_after: float | None = None):
        self.code, self.retry_after = code, retry_after
        super().__init__(code)


@dataclass(frozen=True)
class Detection:
    host_id: str
    qid: str
    detection_type: str | None
    severity: str | None
    status: str | None
    port: str | None
    protocol: str | None
    ssl: str | None
    unique_vuln_id: str | None
    source_times: tuple[tuple[str, str], ...]
    ordinal: int


@dataclass(frozen=True)
class ParsedPage:
    detections: tuple[Detection, ...]
    host_count: int
    host_ids: tuple[str, ...]
    continuation: str | None


@dataclass(frozen=True)
class QualysPage:
    ordinal: int
    request_url: str
    raw_bytes: bytes
    parsed: ParsedPage


def observations_for_page(page: QualysPage, *, source_account_id: str,
                          account_authority_id: str, run_id: str,
                          collected_at: datetime, evidence_ref: str,
                          evidence_sha256: str, first_ordinal: int = 1
                          ) -> tuple[SourceObservationV1, ...]:
    """Map detections to retained source facts without inventing workload identity."""
    if collected_at.tzinfo is None or collected_at.utcoffset() is None:
        raise ValueError("collected_at must be timezone-aware")
    if first_ordinal < 1:
        raise ValueError("first_ordinal must be positive")
    collected_at = collected_at.astimezone(timezone.utc)
    output = []
    for offset, detection in enumerate(page.parsed.detections):
        vendor_times = dict(detection.source_times)
        observed_at = _parse_vendor_time(vendor_times.get("LAST_FOUND_DATETIME"))
        first_seen = _parse_vendor_time(vendor_times.get("FIRST_FOUND_DATETIME"))
        locator = {"host_id": detection.host_id, "qid": detection.qid,
            "type": detection.detection_type, "severity": detection.severity,
            "status": detection.status, "port": detection.port,
            "protocol": detection.protocol, "ssl": detection.ssl,
            "unique_vuln_id": detection.unique_vuln_id,
            "vendor_times": vendor_times, "page_ordinal": page.ordinal,
            "page_detection_ordinal": detection.ordinal,
            "evidence_ref": evidence_ref, "evidence_sha256": evidence_sha256}
        missing = [MissingField("component_locator", MISSING_UNVERIFIED),
            MissingField("vulnerability_refs", MISSING_NOT_SUPPLIED),
            MissingField("report_id", MISSING_NOT_SUPPLIED)]
        if observed_at is None:
            missing.append(MissingField("observed_at", MISSING_NOT_SUPPLIED))
        if first_seen is None:
            missing.append(MissingField("source_first_seen_at", MISSING_NOT_SUPPLIED))
        if detection.severity is None:
            missing.append(MissingField("source_rating", MISSING_NOT_SUPPLIED))
        source_ordinal = first_ordinal + offset
        try:
            namespace = uuid.UUID(run_id)
        except (ValueError, TypeError, AttributeError):
            raise ValueError("run_id must be a UUID") from None
        observation_id = str(uuid.uuid5(namespace,
            f"qualys:{source_account_id}:{source_ordinal}"))
        output.append(SourceObservationV1(schema_version=1,
            observation_id=observation_id, revision=1, source_family="qualys",
            source_account_id=source_account_id, run_id=run_id,
            source_record_ordinal=source_ordinal, collection_status="success",
            collected_at=collected_at, raw_evidence_ref=evidence_ref,
            raw_evidence_sha256=evidence_sha256, missing_fields=tuple(missing),
            observed_at=observed_at, native_id_scheme="qualys_vm_qid_v1",
            native_id_authority=account_authority_id, native_id_value=detection.qid,
            asset_locator=detection.host_id, component_locator=None,
            source_record_locator=json.dumps(locator, sort_keys=True,
                separators=(",", ":"), ensure_ascii=True),
            source_rating=detection.severity, vulnerability_refs=None,
            source_first_seen_at=first_seen, report_id=None,
            coverage_scope="account_visible"))
    return tuple(output)


def _parse_vendor_time(value: str | None) -> datetime | None:
    if value is None:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        return None
    return parsed.astimezone(timezone.utc)


def _tag(element: ET.Element) -> str:
    return element.tag.rsplit("}", 1)[-1].upper()


def _child_text(parent: ET.Element, name: str) -> str | None:
    child = next((item for item in parent if _tag(item) == name), None)
    if child is None or child.text is None:
        return None
    value = child.text.strip()
    return value or None


def _decode_xml(data: bytes) -> str:
    if (data.startswith((b"\xff\xfe", b"\xfe\xff", b"\x00\x00\xfe\xff", b"\xff\xfe\x00\x00"))
            or b"\x00" in data):
        raise QualysError("unsupported_xml_encoding")
    try:
        text = data.decode("utf-8-sig", errors="strict")
    except UnicodeDecodeError:
        raise QualysError("unsupported_xml_encoding") from None
    declaration = re.match(r"\s*<\?xml\s+[^?]*encoding\s*=\s*['\"]([^'\"]+)", text,
        re.IGNORECASE)
    if declaration and declaration.group(1).lower().replace("_", "-") not in {"utf-8", "utf8"}:
        raise QualysError("unsupported_xml_encoding")
    if re.search(r"<!ENTITY\b", text, re.IGNORECASE):
        raise QualysError("unsafe_xml")
    return _strip_doctype_text(text)


def _strip_doctype_text(data: str) -> str:
    """Remove one declaration without interpreting or fetching its external ID."""
    start = re.search(r"<!DOCTYPE\b", data, re.IGNORECASE)
    if not start:
        return data
    quote = None
    subset = 0
    i = start.end()
    while i < len(data):
        ch = data[i]
        if quote:
            if ch == quote:
                quote = None
        elif ch in ('"', "'"):
            quote = ch
        elif ch == "[":
            subset += 1
        elif ch == "]" and subset:
            subset -= 1
        elif ch == ">" and not subset:
            return data[:start.start()] + data[i + 1:]
        i += 1
    raise QualysError("malformed_xml")


class _DepthBoundTree:
    """TreeBuilder target enforcing nesting while Expat parses input chunks."""
    def __init__(self, max_depth: int):
        self.builder = ET.TreeBuilder()
        self.max_depth = max_depth
        self.depth = 0

    def start(self, tag, attributes):
        self.depth += 1
        if self.depth > self.max_depth:
            raise QualysError("xml_depth_exceeded")
        return self.builder.start(tag, attributes)

    def end(self, tag):
        element = self.builder.end(tag)
        self.depth -= 1
        return element

    def data(self, value):
        self.builder.data(value)

    def close(self):
        return self.builder.close()


def parse_page(data: bytes, *, max_bytes: int = MAX_PAGE_BYTES,
               max_depth: int = 64) -> ParsedPage:
    if not isinstance(data, bytes) or len(data) > max_bytes:
        raise QualysError("response_too_large")
    try:
        safe_text = _decode_xml(data)
        target = _DepthBoundTree(max_depth)
        parser = ET.XMLParser(target=target)
        for start in range(0, len(safe_text), 4096):
            parser.feed(safe_text[start:start + 4096])
        root = parser.close()
    except QualysError:
        raise
    except (ET.ParseError, ValueError):
        raise QualysError("malformed_xml") from None
    if _tag(root) != "HOST_LIST_VM_DETECTION_OUTPUT":
        raise QualysError("unexpected_xml_root")
    response = next((node for node in root if _tag(node) == "RESPONSE"), None)
    if response is None:
        raise QualysError("unexpected_xml_root")
    error = next((node for node in response if _tag(node) == "ERROR"), None)
    if error is not None:
        code = _child_text(error, "CODE")
        raise QualysError("provider_rejected" if code else "provider_error")
    host_list = next((node for node in response if _tag(node) == "HOST_LIST"), None)
    if host_list is None:
        raise QualysError("unexpected_xml_root")
    detections: list[Detection] = []
    hosts = [node for node in host_list if _tag(node) == "HOST"]
    host_ids = []
    for host in hosts:
        host_id = _child_text(host, "ID")
        if not host_id or not host_id.isdigit():
            raise QualysError("missing_host_id")
        if host_id in host_ids:
            raise QualysError("duplicate_host_id")
        host_ids.append(host_id)
        detection_list = next((node for node in host if _tag(node) == "DETECTION_LIST"), None)
        if detection_list is None:
            continue
        for item in detection_list:
            if _tag(item) != "DETECTION":
                continue
            qid = _child_text(item, "QID")
            if not qid:
                raise QualysError("missing_qid")
            fields = {name: _child_text(item, name) for name in (
                "TYPE", "SEVERITY", "STATUS", "PORT", "PROTOCOL", "SSL",
                "UNIQUE_VULN_ID", "FIRST_FOUND_DATETIME", "LAST_FOUND_DATETIME",
                "LAST_TEST_DATETIME", "LAST_UPDATE_DATETIME", "LAST_PROCESSED_DATETIME")}
            times = tuple((key, value) for key, value in fields.items()
                          if key.endswith("_DATETIME") and value is not None)
            detections.append(Detection(host_id, qid, fields["TYPE"], fields["SEVERITY"],
                fields["STATUS"], fields["PORT"], fields["PROTOCOL"], fields["SSL"],
                fields["UNIQUE_VULN_ID"], times, len(detections) + 1))
            if len(detections) > MAX_ROWS:
                raise QualysError("row_limit_exceeded")
    continuation = None
    warnings = [node for node in response if _tag(node) == "WARNING"]
    for warning in warnings:
        if _child_text(warning, "CODE") != "1980":
            raise QualysError("provider_warning")
        if continuation is not None:
            raise QualysError("multiple_continuations")
        continuation = _child_text(warning, "URL")
        if not continuation:
            raise QualysError("missing_continuation")
    return ParsedPage(tuple(detections), len(hosts), tuple(host_ids), continuation)


def _query_params(id_min: str | None = None) -> list[tuple[str, str]]:
    params = [("action", "list"), ("show_igs", "1"),
        ("status", SOURCE_STATUSES), ("truncation_limit", "10000")]
    if id_min is not None:
        params.append(("id_min", id_min))
    return sorted(params)


def _page_url(origin: str, id_min: str | None = None) -> str:
    return origin + ENDPOINT_PATH + "?" + urlencode(_query_params(id_min))


def validate_continuation(value: str, *, origin: str,
                          previous_id_min: str | None,
                          returned_host_ids: tuple[str, ...] | None) -> str:
    base = urlsplit(origin)
    candidate = urlsplit(value)
    if (candidate.scheme != "https" or candidate.netloc.lower() != base.netloc.lower()
            or candidate.path != ENDPOINT_PATH or candidate.username or candidate.password
            or candidate.fragment):
        raise QualysError("unsafe_continuation")
    try:
        pairs = parse_qsl(candidate.query, keep_blank_values=True, strict_parsing=True)
    except ValueError:
        raise QualysError("unsafe_continuation") from None
    keys = [key for key, _ in pairs]
    if len(keys) != len(set(keys)):
        raise QualysError("unsafe_continuation")
    params = dict(pairs)
    expected = dict(_query_params())
    if any(params.get(key) != val for key, val in expected.items()):
        raise QualysError("unsafe_continuation")
    id_min = params.get("id_min")
    if (set(params) != set(expected) | {"id_min"} or not id_min
            or not id_min.isdigit()):
        raise QualysError("unsafe_continuation")
    if returned_host_ids is not None:
        if not returned_host_ids:
            raise QualysError("pagination_progress_invalid")
        host_numbers = [int(host_id) for host_id in returned_host_ids]
        if int(id_min) <= max(host_numbers):
            raise QualysError("pagination_progress_invalid")
    if previous_id_min is not None and int(id_min) <= int(previous_id_min):
        raise QualysError("pagination_progress_invalid")
    return urlunsplit(("https", base.netloc, ENDPOINT_PATH,
                       urlencode(_query_params(id_min)), ""))


def _remaining(deadline: float) -> float:
    value = deadline - time.monotonic()
    if value <= 0:
        raise QualysError("deadline_exceeded")
    return value


def _wait(sock, event: int, deadline: float) -> None:
    with selectors.DefaultSelector() as selector:
        selector.register(sock, event)
        if not selector.select(_remaining(deadline)):
            raise QualysError("deadline_exceeded")


_DNS_SLOT = threading.BoundedSemaphore(1)


def _getaddrinfo_deadline(host: str, port: int, deadline: float):
    if not _DNS_SLOT.acquire(timeout=_remaining(deadline)):
        raise QualysError("deadline_exceeded")
    result_queue: queue.Queue = queue.Queue(maxsize=1)
    def resolve():
        try:
            result_queue.put((True, socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)))
        except BaseException as exc:
            result_queue.put((False, exc))
        finally:
            _DNS_SLOT.release()
    threading.Thread(target=resolve, name="qualys-dns", daemon=True).start()
    try:
        ok, result = result_queue.get(timeout=_remaining(deadline))
    except queue.Empty:
        raise QualysError("deadline_exceeded") from None
    if not ok:
        raise QualysError("network_error") from None
    return result


def _connect_deadline(host: str, port: int, deadline: float) -> socket.socket:
    try:
        addresses = _getaddrinfo_deadline(host, port, deadline)
    except (OSError, RuntimeError):
        raise QualysError("network_error") from None
    _remaining(deadline)
    for family, socktype, proto, _canonname, address in addresses:
        sock = socket.socket(family, socktype, proto)
        sock.setblocking(False)
        try:
            result = sock.connect_ex(address)
            pending = {errno.EINPROGRESS, errno.EWOULDBLOCK, errno.EALREADY}
            if result not in ({0} | pending):
                sock.close()
                continue
            if result:
                _wait(sock, selectors.EVENT_WRITE, deadline)
                if sock.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR):
                    sock.close()
                    continue
            return sock
        except BaseException:
            sock.close()
            raise
    raise QualysError("network_error")


def _tls_handshake(raw_socket, host: str, context: ssl.SSLContext, deadline: float):
    tls = context.wrap_socket(raw_socket, server_hostname=host, do_handshake_on_connect=False)
    tls.setblocking(False)
    while True:
        try:
            tls.do_handshake()
            return tls
        except ssl.SSLWantReadError:
            _wait(tls, selectors.EVENT_READ, deadline)
        except ssl.SSLWantWriteError:
            _wait(tls, selectors.EVENT_WRITE, deadline)


def _send_tls(tls, payload: bytes, deadline: float) -> None:
    offset = 0
    while offset < len(payload):
        _remaining(deadline)
        try:
            offset += tls.send(payload[offset:])
        except ssl.SSLWantReadError:
            _wait(tls, selectors.EVENT_READ, deadline)
        except ssl.SSLWantWriteError:
            _wait(tls, selectors.EVENT_WRITE, deadline)
        except (BlockingIOError, InterruptedError):
            _wait(tls, selectors.EVENT_WRITE, deadline)


def _recv_tls(tls, deadline: float) -> bytes:
    while True:
        _remaining(deadline)
        try:
            return tls.recv(65536)
        except ssl.SSLWantReadError:
            _wait(tls, selectors.EVENT_READ, deadline)
        except ssl.SSLWantWriteError:
            _wait(tls, selectors.EVENT_WRITE, deadline)
        except (BlockingIOError, InterruptedError):
            _wait(tls, selectors.EVENT_READ, deadline)


def _read_response(tls, protocol: h11.Connection, deadline: float
                   ) -> tuple[int, bytes, dict[str, str]]:
    """Use h11 framing, with bounded decoded bytes and header/trailer events."""
    status = None
    headers: dict[str, str] = {}
    body = bytearray()
    while True:
        _remaining(deadline)
        event = protocol.next_event()
        if event is h11.NEED_DATA:
            protocol.receive_data(_recv_tls(tls, deadline))
        elif isinstance(event, h11.InformationalResponse):
            if event.status_code == 101:
                raise QualysError("malformed_http_response")
        elif isinstance(event, h11.Response):
            status = event.status_code
            headers = {key.decode("ascii").lower(): value.decode("latin-1")
                       for key, value in event.headers}
            if "transfer-encoding" in headers and "content-length" in headers:
                raise QualysError("malformed_http_response")
            declared = headers.get("content-length")
            if declared is not None and int(declared) > MAX_PAGE_BYTES:
                raise QualysError("response_too_large")
        elif isinstance(event, h11.Data):
            if len(body) + len(event.data) > MAX_PAGE_BYTES:
                raise QualysError("response_too_large")
            body.extend(event.data)
        elif isinstance(event, h11.EndOfMessage):
            if status is None:
                raise QualysError("malformed_http_response")
            return status, bytes(body), headers
        elif event is h11.PAUSED or isinstance(event, h11.ConnectionClosed):
            raise QualysError("truncated_http_body")


def _production_transport(request: Request, timeout: float, deadline: float, *,
                          _ssl_context: ssl.SSLContext | None = None
                          ) -> tuple[int, bytes, dict[str, str]]:
    """Verified HTTPS with an absolute deadline through connection and body.

    `_ssl_context` is test-composition-only for trusting the local fixture CA;
    production uses the default verified trust store. Redirects are never followed.
    """
    parsed = urlsplit(request.full_url)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
        raise QualysError("unsafe_request_url")
    host, port = parsed.hostname, parsed.port or 443
    target = parsed.path or "/"
    if parsed.query:
        target += "?" + parsed.query
    raw_socket = tls = None
    attempt_deadline = min(deadline, time.monotonic() + timeout)
    try:
        _remaining(attempt_deadline)
        raw_socket = _connect_deadline(host, port, attempt_deadline)
        tls = _tls_handshake(raw_socket, host, _ssl_context or ssl.create_default_context(), attempt_deadline)
        raw_socket = None
        headers = dict(request.header_items())
        headers["Host"] = parsed.netloc
        headers["Connection"] = "close"
        protocol = h11.Connection(h11.CLIENT, max_incomplete_event_size=65536)
        payload = protocol.send(h11.Request(method=request.get_method(), target=target,
            headers=list(headers.items())))
        payload += protocol.send(h11.EndOfMessage())
        _send_tls(tls, payload, attempt_deadline)
        return _read_response(tls, protocol, attempt_deadline)
    except h11.RemoteProtocolError:
        raise QualysError("malformed_http_response") from None
    except ssl.SSLCertVerificationError:
        raise QualysError("tls_verification_failed") from None
    except ssl.SSLError:
        raise QualysError("tls_error") from None
    except (OSError, TimeoutError):
        if time.monotonic() >= deadline:
            raise QualysError("deadline_exceeded") from None
        if time.monotonic() >= attempt_deadline:
            raise QualysError("request_timeout") from None
        raise QualysError("network_error") from None
    except QualysError as exc:
        if exc.code == "deadline_exceeded" and time.monotonic() >= deadline:
            raise
        if exc.code == "deadline_exceeded" and time.monotonic() >= attempt_deadline:
            raise QualysError("request_timeout") from None
        raise
    finally:
        if tls is not None:
            tls.close()
        elif raw_socket is not None:
            raw_socket.close()


class QualysVMClient:
    """Client for fixed origins; each HTTP attempt gets a scoped credential lease."""
    def __init__(self, platform_id: str, *, _transport=None, _sleep=time.sleep):
        if platform_id not in PLATFORM_ORIGINS:
            raise ValueError("unsupported_platform")
        self.origin = PLATFORM_ORIGINS[platform_id]
        self._transport, self._sleep = _transport or _production_transport, _sleep

    def fetch_page(self, continuation: str | None = None, *, deadline: float | None = None,
                   credential_scope: Callable[[], AbstractContextManager[QualysBasicCredential]],
                   before_request: Callable[[], None] | None = None):
        url = (validate_continuation(continuation, origin=self.origin,
                previous_id_min=None,
                returned_host_ids=None) if continuation else
               _page_url(self.origin))
        if deadline is None:
            deadline = time.monotonic() + TOTAL_DEADLINE_SECONDS
        if credential_scope is None:
            raise ValueError("credential_attempt_scope_required")
        for attempt in range(MAX_PAGE_ATTEMPTS):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise QualysError("deadline_exceeded")
            if before_request is not None:
                before_request()
            if time.monotonic() >= deadline:
                raise QualysError("deadline_exceeded")
            try:
                with credential_scope() as credential:
                    request = Request(url, headers={
                        "Authorization": credential.authorization_header(),
                        "X-Requested-With": "VOLT", "Accept": "application/xml"})
                    try:
                        remaining = deadline - time.monotonic()
                        if remaining <= 0:
                            raise QualysError("deadline_exceeded")
                        status, body, headers = self._transport(
                            request, min(REQUEST_TIMEOUT_SECONDS, remaining), deadline)
                    finally:
                        request.remove_header("Authorization")
            except QualysError as exc:
                if exc.code != "network_error" or attempt + 1 == MAX_PAGE_ATTEMPTS:
                    raise
                continue
            if len(body) > MAX_PAGE_BYTES:
                raise QualysError("response_too_large")
            if status in (401, 403):
                raise QualysError("authentication_rejected")
            if status in (301, 302, 303, 307, 308):
                raise QualysError("redirect_rejected")
            if status == 429 or status >= 500:
                if attempt + 1 == MAX_PAGE_ATTEMPTS:
                    raise QualysError("throttled" if status == 429 else "provider_unavailable")
                retry = 0.0
                raw = next((value for key, value in headers.items()
                    if key.lower() == "retry-after"), None) if headers else None
                if raw:
                    try:
                        retry = max(0.0, float(raw))
                    except ValueError:
                        try:
                            retry_at = parsedate_to_datetime(raw)
                            if retry_at.tzinfo is None:
                                retry_at = retry_at.replace(tzinfo=timezone.utc)
                            retry = max(0.0, (retry_at - datetime.now(timezone.utc)).total_seconds())
                        except (TypeError, ValueError, OverflowError):
                            retry = 0.0
                remaining = deadline - time.monotonic()
                if retry > remaining:
                    raise QualysError("deadline_exceeded")
                self._sleep(retry)
                continue
            if status < 200 or status >= 300:
                raise QualysError("provider_rejected")
            return body, headers
        raise QualysError("provider_unavailable")

    def iter_pages(self, *, credential_scope: Callable[[], AbstractContextManager[QualysBasicCredential]],
                   before_request: Callable[[], None] | None = None,
                   deadline: float | None = None) -> Iterator[QualysPage]:
        """Yield exact pages after bounded parse; the fence runs before each HTTP try."""
        if deadline is None:
            deadline = time.monotonic() + TOTAL_DEADLINE_SECONDS
        seen: set[str] = set()
        total_bytes = total_rows = page_count = 0
        continuation = None
        current_id_min = None
        stream_seen_hosts: set[str] = set()
        while True:
            if page_count >= MAX_PAGES:
                raise QualysError("operation_page_limit")
            request_url = continuation or _page_url(self.origin)
            if request_url in seen:
                raise QualysError("pagination_cycle")
            seen.add(request_url)
            body, _headers = self.fetch_page(continuation, deadline=deadline,
                credential_scope=credential_scope, before_request=before_request)
            total_bytes += len(body)
            if total_bytes > MAX_TOTAL_BYTES:
                raise QualysError("operation_byte_limit")
            parsed = parse_page(body)
            numeric_hosts = [int(host_id) for host_id in parsed.host_ids]
            if (numeric_hosts != sorted(numeric_hosts)
                    or len(set(numeric_hosts)) != len(numeric_hosts)):
                raise QualysError("pagination_progress_invalid")
            # id_min is inclusive: each host must meet THIS request's bound.
            if current_id_min is not None and any(
                    host_id < int(current_id_min) for host_id in numeric_hosts):
                raise QualysError("pagination_progress_invalid")
            if stream_seen_hosts.intersection(parsed.host_ids):
                raise QualysError("duplicate_host_across_pages")
            stream_seen_hosts.update(parsed.host_ids)
            total_rows += len(parsed.detections)
            if total_rows > MAX_ROWS:
                raise QualysError("operation_row_limit")
            page_count += 1
            # Validate the continuation before publishing the page as valid.
            continuation = parsed.continuation
            if continuation is not None:
                continuation = validate_continuation(continuation, origin=self.origin,
                    previous_id_min=current_id_min, returned_host_ids=parsed.host_ids)
                current_id_min = dict(parse_qsl(urlsplit(continuation).query))["id_min"]
            yield QualysPage(page_count, request_url, body, parsed)
            if continuation is None:
                break
