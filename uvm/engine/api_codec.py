"""Bounded supported-API request codec for DefectDojo CE import/reimport.

G1 CR-01/CR-04, EXPLICITLY EXPERIMENTAL baseline for the local CE 3.3.100
pair-readback evidence set. This module does NOT claim a D-03 engine pin
and is not CR-04 proof: it only builds the deterministic request bytes a
future adapter would POST, from the approved G1 design and the retained
live 3.3.100 field baselines
(``evidence/G1/ce-33100-pair-readback/artifacts/import-scan-fields.txt``
and ``reimport-scan-fields.txt``, captured by
``run-phase2-33100.sh`` against the live OpenAPI schema).

Transport-independent and pure: no HTTP, no token handling, no POST
issuance, no ledger/OperationStore mutation, no CE integration. The
caller owns the OperationStore; this module only turns an
``EngineImportOperationV1`` plus the exact retained payload bytes into a
typed request value, and parses the two documented response fields
(``test_id``, ``deduplication_complete``) from a response body.

Guarantees:

- ``close_old_findings`` is always sent explicitly as ``false``; it is
  never omitted and never true (the tagged reimport serializer defaults
  it to ``true`` — absence is not a safe default).
- Every emitted multipart field name is a member of the retained live
  3.3.100 field baseline for that route; no fabricated fields. There is
  no ``import_scan_results``, ``reimport_scan_results`` or ``test_type``
  request field — the fields are exactly ``file``, ``scan_type``,
  ``test`` (reimport only) and the documented context/setting fields.
- The payload SHA-256 is verified against
  ``EngineImportOperationV1.payload_sha256`` before any bytes are
  encoded; a mismatch, a wrong request kind, or a reimport without its
  registered Test ID is rejected.
- Multipart construction is deterministic (a payload-derived boundary
  that provably cannot occur as a MIME delimiter in the file bytes, fixed
  part order, CRLF line endings); text values are kept safe against CR/LF
  header splitting and the report filename is restricted to safe ASCII
  with a typed error for unsafe values.
- The first-import request sends the documented ``auto_create_context=true``
  field; a reimport reuses the registered Test and does not send it.
- The first-import Product target is bound to the operation's immutable
  ``context_key``: a single canonical context key is derived from the
  ``ScanContextV1`` fields and must equal ``operation.context_key``
  before anything is encoded, so one operation/payload can never produce
  two different Product bodies. A reimport requires its
  ``operation.context_key`` to be canonical. Migration of legacy
  arbitrary context keys is a codec boundary: ``OperationStore`` is
  unchanged and still accepts arbitrary keys on registration; only this
  codec refuses to encode a request for a non-canonical key.
- A reimport requires the operation's registered Test ID to be a canonical
  positive numeric identifier (CE requires a positive integer Test ID); a
  non-numeric ID such as ``test-42`` is rejected.

A response body parsed here yields only ``test_id`` and
``deduplication_complete``. ``test_id`` is the canonical positive numeric
Test ID as a ``str`` (matching ``OperationStore.record_response``'s str
field; zero and non-positive values are rejected) and
``deduplication_complete`` is a strict JSON boolean or null. Duplicate
JSON keys are rejected as ambiguous (the stdlib parser otherwise keeps
the last value, which could flip the deduplication flag). The parser
does not classify network failures, does not settle operations, and does
not advance any revision; that is the OperationStore's job.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
from dataclasses import dataclass
from typing import Optional, Tuple
from urllib.parse import quote, unquote

from uvm.engine.operation import (
    REQUEST_IMPORT,
    REQUEST_REIMPORT,
    EngineImportOperationV1,
)

# Routes and retained live field baselines (CE 3.3.100 OpenAPI, retained
# bytes in evidence/G1/ce-33100-pair-readback/artifacts/). Experimental
# baseline only — not a pinned API contract.
IMPORT_SCAN_PATH = "/api/v2/import-scan/"
REIMPORT_SCAN_PATH = "/api/v2/reimport-scan/"

#: Retained live 3.3.100 multipart field names for POST /api/v2/import-scan/.
IMPORT_SCAN_FIELDS = frozenset(
    {
        "active",
        "api_scan_configuration",
        "apply_tags_to_endpoints",
        "apply_tags_to_findings",
        "auto_create_context",
        "branch_tag",
        "build_id",
        "close_old_findings",
        "close_old_findings_product_scope",
        "commit_hash",
        "create_finding_groups_for_all_findings",
        "deduplication_execution_mode",
        "deduplication_on_engagement",
        "endpoint_to_add",
        "engagement",
        "engagement_end_date",
        "engagement_name",
        "environment",
        "file",
        "group_by",
        "lead",
        "minimum_severity",
        "product_name",
        "product_type_name",
        "push_to_jira",
        "scan_date",
        "scan_type",
        "service",
        "source_code_management_uri",
        "tags",
        "test_title",
        "verified",
        "version",
    }
)

#: Retained live 3.3.100 multipart field names for POST /api/v2/reimport-scan/.
REIMPORT_SCAN_FIELDS = frozenset(
    {
        "active",
        "api_scan_configuration",
        "apply_tags_to_endpoints",
        "apply_tags_to_findings",
        "auto_create_context",
        "branch_tag",
        "build_id",
        "close_old_findings",
        "close_old_findings_product_scope",
        "commit_hash",
        "create_finding_groups_for_all_findings",
        "deduplication_execution_mode",
        "deduplication_on_engagement",
        "do_not_reactivate",
        "endpoint_to_add",
        "engagement_end_date",
        "engagement_name",
        "environment",
        "file",
        "group_by",
        "lead",
        "minimum_severity",
        "product_name",
        "product_type_name",
        "push_to_jira",
        "scan_date",
        "scan_type",
        "service",
        "source_code_management_uri",
        "tags",
        "test",
        "test_title",
        "verified",
        "version",
    }
)

# Deterministic, transport-independent multipart boundary. The boundary
# value is derived from the verified payload SHA-256 (see
# ``derive_boundary``) so it can never occur as a MIME delimiter inside
# the file bytes; a fixed string boundary can be present in arbitrary
# report bytes and would let a standard multipart parser truncate the
# file part. The boundary is 48 hex chars of the digest (192 bits),
# keeping the total at 69 characters — inside RFC 2046's 70-character
# maximum for the boundary parameter.
_BOUNDARY_PREFIX = "uvm-engine-multipart-"
_BOUNDARY_DIGEST_HEX = 48
_CRLF = b"\r\n"

#: Prefix of the single canonical context key derived from the
#: ScanContextV1 fields. Every slot is percent-quoted with ``safe=""`` so
#: field values can never introduce a slot separator or collide across
#: field splits (``a/b`` + ``c`` != ``a`` + ``b/c``); an empty first slot
#: is the only encoding of ``product_type_name=None`` and the other slots
#: are always non-empty, so the key is unambiguous.
CONTEXT_KEY_PREFIX = "uvm-ctx/1/"
_QUOTED_SLOT_RE = re.compile(r"^(?:[A-Za-z0-9._~-]|%[0-9A-F]{2})*$")


def _is_canonical_slot(slot: str) -> bool:
    """True when ``slot`` is the exact ``quote(value, safe="")`` output
    for a valid UTF-8 field value.

    The round-trip (strict-UTF-8 decode, then re-quote and compare) means
    a slot that decodes to a value but is not ``quote``'s own encoding —
    an alias of the same field value, e.g. ``%41`` where ``quote`` emits
    the always-safe ``A`` — is not canonical, and an invalid-UTF-8
    sequence such as ``%FF`` can never match, because no UTF-8 field
    value decodes to it.
    """
    if not _QUOTED_SLOT_RE.fullmatch(slot):
        return False
    try:
        decoded = unquote(slot, encoding="utf-8", errors="strict")
    except UnicodeDecodeError:
        return False
    return quote(decoded, safe="") == slot


class CodecError(ValueError):
    """Base error for codec rejections (digest, kind, shape, safety)."""


class PayloadDigestMismatch(CodecError):
    """Retained payload bytes do not match the operation's SHA-256."""


class UnsupportedField(CodecError):
    """A field name is not in the retained live CE 3.3.100 baseline."""


class MalformedResponseError(CodecError):
    """A response body is not the documented JSON response shape."""


class UnsafeFilenameError(CodecError):
    """A report filename is unsafe for a multipart Content-Disposition."""


class InvalidTestIdError(CodecError):
    """A reimport Test ID is not a canonical positive numeric identifier."""


class InvalidContextKeyError(CodecError):
    """A context key is not in the canonical form this codec encodes.

    Legacy arbitrary ``operation.context_key`` values are a codec
    boundary: they must be migrated to canonical keys before encoding.
    OperationStore is unchanged and still accepts them on registration.
    """


class ContextKeyMismatchError(CodecError):
    """The first-import Product target differs from the operation's
    immutable ``context_key``; two differing Product targets for one
    operation are rejected."""


def _verify_digest(operation: EngineImportOperationV1, payload: bytes) -> None:
    if not isinstance(payload, (bytes, bytearray)):
        raise CodecError("payload must be exact bytes")
    expected = operation.payload_sha256.strip().lower()
    if not expected:
        raise CodecError("operation carries no payload_sha256")
    actual = hashlib.sha256(bytes(payload)).hexdigest()
    if actual != expected:
        raise PayloadDigestMismatch(
            f"payload SHA-256 {actual} does not match the operation's "
            f"retained digest {expected}; nothing was encoded"
        )


def _require_kind(
    operation: EngineImportOperationV1, kind: str, builder: str
) -> None:
    if not isinstance(operation, EngineImportOperationV1):
        raise CodecError("an EngineImportOperationV1 is required")
    if operation.request_kind != kind:
        raise CodecError(
            f"{builder} requires request_kind={kind!r}; "
            f"got {operation.request_kind!r}"
        )
    if not operation.scan_type:
        raise CodecError("operation.scan_type is required")


def _clean_field_value(name: str, value: str) -> bytes:
    if not isinstance(value, str) or value == "":
        raise CodecError(f"field {name!r} must be a non-empty string")
    if "\r" in value or "\n" in value:
        raise CodecError(
            f"field {name!r} must not contain CR/LF; that would split "
            "multipart part headers"
        )
    return value.encode("utf-8")


def sanitize_filename(filename: str) -> str:
    """Reduce a caller-supplied report filename to a safe multipart
    filename: basename only, no path separators, and printable ASCII
    only. Empty result falls back to a fixed name. Deterministic: same
    input always yields the same output.

    Values that would break the Content-Disposition header — a double
    quote, a semicolon (the directive separator), any C0 control
    character (0x00-0x1f, including NUL and CR/LF), ASCII DEL (0x7f), or
    any non-ASCII byte — are rejected with :class:`UnsafeFilenameError`
    (never silently stripped) rather than emitting a broken header or
    raising a raw ``UnicodeEncodeError``.
    """
    if not isinstance(filename, str):
        raise CodecError("filename must be a string")
    name = filename.replace("\\", "/").rsplit("/", 1)[-1]
    if name == "":
        return "scan-report"
    for ch in name:
        if ch in ('"', ";") or ord(ch) < 0x20 or ord(ch) >= 0x7F:
            raise UnsafeFilenameError(
                f"filename {name!r} is unsafe for a multipart "
                "Content-Disposition header (double-quote, semicolon, "
                "C0 control character, non-printable ASCII such as DEL, "
                "or non-ASCII); restrict the report filename to "
                "printable ASCII without double-quote or semicolon"
            )
    return name


@dataclass(frozen=True)
class ScanContextV1:
    """Explicit first-import context (auto-created Product/Engagement).

    Every field maps one-to-one to a documented import-scan multipart
    field; nothing here invents a CE field. ``product_type_name`` may be
    omitted, in which case the field is not sent.
    """

    product_name: str
    engagement_name: str
    environment: str
    product_type_name: Optional[str] = None

    def __post_init__(self) -> None:
        for attr in ("product_name", "engagement_name", "environment"):
            value = getattr(self, attr)
            if not isinstance(value, str) or value == "":
                raise ValueError(f"{attr} is required and must be non-empty")
        if self.product_type_name is not None:
            if not isinstance(self.product_type_name, str):
                raise ValueError("product_type_name must be a string or None")
            if self.product_type_name == "":
                raise ValueError("product_type_name must be non-empty or None")


def canonical_context_key(context: ScanContextV1) -> str:
    """The single canonical, unambiguous context key for a Product target.

    Derived from the ScanContextV1 fields (product_type_name, product,
    engagement, environment — the same order the import-scan request
    sends them) so the first-import Product body is bound to the
    operation's immutable ``context_key``: one operation/payload can
    never produce two different Product bodies. Each field is
    percent-quoted with ``safe=""``; ``product_type_name=None`` is the
    empty first slot. Deterministic: same fields always yield the same
    key.
    """
    if not isinstance(context, ScanContextV1):
        raise CodecError("a ScanContextV1 is required")
    slots = [
        quote(context.product_type_name, safe="")
        if context.product_type_name is not None
        else "",
        quote(context.product_name, safe=""),
        quote(context.engagement_name, safe=""),
        quote(context.environment, safe=""),
    ]
    return CONTEXT_KEY_PREFIX + "/".join(slots)


def is_canonical_context_key(key: object) -> bool:
    """True when ``key`` is a well-formed canonical context key (the form
    :func:`canonical_context_key` produces). Legacy arbitrary keys such
    as ``"prod:acct-1/eng-prod"`` are not canonical and are refused at
    the codec boundary."""
    if not isinstance(key, str) or not key.startswith(CONTEXT_KEY_PREFIX):
        return False
    slots = key[len(CONTEXT_KEY_PREFIX) :].split("/")
    if len(slots) != 4 or any(slot == "" for slot in slots[1:]):
        return False
    return all(_is_canonical_slot(slot) for slot in slots)


def _require_context_binding(
    operation: EngineImportOperationV1, context: Optional[ScanContextV1] = None
) -> None:
    """Bind the request to the operation's immutable context key.

    For a first import the canonical key of the supplied ScanContextV1
    must equal ``operation.context_key`` (two differing Product targets
    for one operation are rejected); for a reimport the operation's key
    must at least be canonical. A non-canonical (legacy arbitrary) key
    is the codec migration boundary, not a store change.
    """
    if not is_canonical_context_key(operation.context_key):
        raise InvalidContextKeyError(
            f"operation.context_key {operation.context_key!r} is not a "
            "canonical context key; legacy arbitrary context keys must be "
            "migrated to canonical keys before encoding (codec boundary; "
            "OperationStore is unchanged)"
        )
    if context is not None and canonical_context_key(context) != operation.context_key:
        raise ContextKeyMismatchError(
            "first-import Product target (canonical key "
            f"{canonical_context_key(context)!r}) does not equal the "
            f"operation's immutable context_key "
            f"{operation.context_key!r}; one operation must never produce "
            "two different Product bodies"
        )


@dataclass(frozen=True)
class EngineRequestV1:
    """Typed, transport-independent request value.

    ``method``/``path`` target the engine's supported API; ``headers``
    is an ordered tuple of (name, value) pairs; ``body`` is the exact
    request body. No credentials, no base URL, no socket: the adapter
    (not this module) owns transport, token handling and POST issuance.
    """

    method: str
    path: str
    headers: Tuple[Tuple[str, str], ...]
    body: bytes

    def header(self, name: str) -> Optional[str]:
        for key, value in self.headers:
            if key.lower() == name.lower():
                return value
        return None


def derive_boundary(payload: bytes) -> bytes:
    """Deterministic multipart boundary that cannot occur in the file bytes.

    Derived from the payload's SHA-256 digest (the same digest the codec
    verifies before encoding): 48 hex chars (192 bits) of the digest, so
    the boundary total stays at 69 characters, inside RFC 2046's
    70-character maximum for the boundary parameter. If that exact token
    ever appeared in the payload bytes a standard multipart parser would
    truncate the file part, so we refuse to encode in that (astronomically
    unlikely) case rather than emit a body that silently drops trailing
    bytes.
    """
    if not isinstance(payload, (bytes, bytearray)):
        raise CodecError("payload must be exact bytes")
    digest = hashlib.sha256(bytes(payload)).hexdigest()
    boundary = f"{_BOUNDARY_PREFIX}{digest[:_BOUNDARY_DIGEST_HEX]}"
    boundary_bytes = boundary.encode("ascii")
    if boundary_bytes in bytes(payload):
        raise CodecError(
            "derived multipart boundary occurs in the payload bytes; "
            "refusing to encode a body a MIME parser would truncate"
        )
    return boundary_bytes


def _encode_part(boundary: bytes, name: str, value: bytes) -> bytes:
    header = 'Content-Disposition: form-data; name="' + name + '"\r\n\r\n'
    return b"--" + boundary + _CRLF + header.encode("ascii") + value + _CRLF


def _encode_file_part(boundary: bytes, name: str, filename: str, value: bytes) -> bytes:
    header = (
        'Content-Disposition: form-data; name="' + name
        + '"; filename="' + filename + '"\r\n'
        + "Content-Type: application/octet-stream\r\n\r\n"
    )
    return b"--" + boundary + _CRLF + header.encode("ascii") + value + _CRLF


def _build_body(boundary: bytes, fields: list[tuple[str, bytes]], file_part: bytes) -> bytes:
    body = b"".join(_encode_part(boundary, name, value) for name, value in fields)
    return body + file_part + b"--" + boundary + b"--\r\n"


def _check_fields(names, baseline: frozenset) -> None:
    for name in names:
        if name not in baseline:
            raise UnsupportedField(
                f"field {name!r} is not in the retained live CE 3.3.100 "
                f"baseline for this route; no fabricated fields are sent"
            )


def _close_old_findings_field(operation: EngineImportOperationV1) -> bytes:
    # The DTO already enforces close_old_findings is explicitly False;
    # send it explicitly so the tagged reimport serializer's True
    # default can never apply.
    if operation.close_old_findings is not False:
        raise CodecError(
            "close_old_findings must be explicitly False; absence of "
            "legacy findings is not remediation"
        )
    return b"false"


def _canonical_positive_int(value: str, field: str = "test_id") -> str:
    """Return ``value`` if it is a canonical positive numeric Test ID.

    CE requires a positive integer Test ID: all digits, no sign, no
    leading zero, strictly greater than zero. ``"42"`` is valid; ``"0"``,
    ``"-5"``, ``"042"`` and ``"test-42"`` are not.
    """
    if not isinstance(value, str) or not re.fullmatch(r"[1-9][0-9]*", value):
        raise InvalidTestIdError(
            f"{field} must be a canonical positive numeric Test ID (a "
            f"positive integer with no sign or leading zeros); got {value!r}"
        )
    return value


def build_import_request(
    operation: EngineImportOperationV1,
    payload: bytes,
    context: ScanContextV1,
    *,
    filename: str,
    minimum_severity: Optional[str] = None,
    deduplication_execution_mode: Optional[str] = None,
) -> EngineRequestV1:
    """Deterministic multipart POST body for /api/v2/import-scan/.

    First auto-create only (request_kind=import). Fields sent, in fixed
    order: the documented ``auto_create_context=true`` first-import
    context flag, the other documented context fields, ``scan_type``, the
    optional documented settings (only when explicitly supplied), the
    explicit ``close_old_findings=false``, and finally the retained report
    ``file``. Every field name is checked against the retained live
    3.3.100 import-scan baseline; the payload digest is verified and the
    multipart boundary derived from the payload (so it cannot occur in the
    file bytes) before anything is encoded. The Product target must bind to
    the operation's immutable canonical ``context_key`` (see
    :func:`canonical_context_key`).
    """
    _require_kind(operation, REQUEST_IMPORT, "build_import_request")
    _require_context_binding(operation, context)
    _verify_digest(operation, payload)
    boundary = derive_boundary(payload)
    clean_filename = sanitize_filename(filename)

    # Documented first-import context path: the retained 3.3.100 command
    # sends auto_create_context=true so the engine auto-creates the
    # Product/Engagement. A reimport reuses the registered Test and never
    # sends this field.
    fields = [("auto_create_context", b"true")]
    if context.product_type_name is not None:
        fields.append(
            ("product_type_name", _clean_field_value("product_type_name",
                                                     context.product_type_name))
        )
    fields.append(("product_name", _clean_field_value("product_name",
                                                      context.product_name)))
    fields.append(
        ("engagement_name", _clean_field_value("engagement_name",
                                               context.engagement_name))
    )
    fields.append(
        ("environment", _clean_field_value("environment", context.environment))
    )
    fields.append(
        ("scan_type", _clean_field_value("scan_type", operation.scan_type))
    )
    if minimum_severity is not None:
        fields.append(
            ("minimum_severity",
             _clean_field_value("minimum_severity", minimum_severity))
        )
    if deduplication_execution_mode is not None:
        fields.append(
            ("deduplication_execution_mode",
             _clean_field_value("deduplication_execution_mode",
                                deduplication_execution_mode))
        )
    fields.append(("close_old_findings", _close_old_findings_field(operation)))
    file_part = _encode_file_part(boundary, "file", clean_filename, bytes(payload))
    _check_fields([name for name, _ in fields], IMPORT_SCAN_FIELDS)

    return EngineRequestV1(
        method="POST",
        path=IMPORT_SCAN_PATH,
        headers=(
            (
                "Content-Type",
                f"multipart/form-data; boundary={boundary.decode('ascii')}",
            ),
        ),
        body=_build_body(boundary, fields, file_part),
    )


def build_reimport_request(
    operation: EngineImportOperationV1,
    payload: bytes,
    *,
    filename: str,
    minimum_severity: Optional[str] = None,
    deduplication_execution_mode: Optional[str] = None,
    do_not_reactivate: Optional[bool] = None,
) -> EngineRequestV1:
    """Deterministic multipart POST body for /api/v2/reimport-scan/.

    Recurring reimport against the operation's registered Test: the
    documented ``test`` field is bound exactly to ``operation.test_id``,
    which must be a canonical positive numeric Test ID (CE requires a
    positive integer; a reimport without a valid registered Test is
    rejected). Fields sent, in fixed order: ``test``, ``scan_type``, the
    optional documented settings (only when explicitly supplied), the
    explicit ``close_old_findings=false``, and the retained report
    ``file``. ``auto_create_context`` is not sent: a reimport reuses the
    registered Test. The operation's ``context_key`` must be a canonical
    context key (codec boundary for legacy arbitrary keys).
    """
    _require_kind(operation, REQUEST_REIMPORT, "build_reimport_request")
    _require_context_binding(operation)
    if not operation.test_id:
        raise CodecError(
            "reimport requires the operation's registered test_id; the "
            "request is never issued without the Test binding"
        )
    # CE requires a positive-integer Test ID; a non-numeric identifier
    # (e.g. "test-42") is not a valid reimport target and is rejected.
    test_id = _canonical_positive_int(operation.test_id)
    _verify_digest(operation, payload)
    boundary = derive_boundary(payload)
    clean_filename = sanitize_filename(filename)

    fields = [
        ("test", _clean_field_value("test", test_id)),
        ("scan_type", _clean_field_value("scan_type", operation.scan_type)),
    ]
    if minimum_severity is not None:
        fields.append(
            ("minimum_severity",
             _clean_field_value("minimum_severity", minimum_severity))
        )
    if deduplication_execution_mode is not None:
        fields.append(
            ("deduplication_execution_mode",
             _clean_field_value("deduplication_execution_mode",
                                deduplication_execution_mode))
        )
    if do_not_reactivate is not None:
        if not isinstance(do_not_reactivate, bool):
            raise CodecError("do_not_reactivate must be an explicit bool")
        fields.append(("do_not_reactivate", b"true" if do_not_reactivate else b"false"))
    fields.append(("close_old_findings", _close_old_findings_field(operation)))
    file_part = _encode_file_part(boundary, "file", clean_filename, bytes(payload))
    _check_fields([name for name, _ in fields], REIMPORT_SCAN_FIELDS)

    return EngineRequestV1(
        method="POST",
        path=REIMPORT_SCAN_PATH,
        headers=(
            (
                "Content-Type",
                f"multipart/form-data; boundary={boundary.decode('ascii')}",
            ),
        ),
        body=_build_body(boundary, fields, file_part),
    )


@dataclass(frozen=True)
class EngineResponseV1:
    """The two documented response fields, extracted from a supported-API
    response body. ``test_id`` is the registered Test ID as its canonical
    positive numeric identifier string (matching
    ``OperationStore.record_response``'s str field; ``None`` when
    absent); ``deduplication_complete`` is the captured completion flag
    (``None`` when absent — absence is not completion). This value is
    evidence input for the OperationStore; it classifies nothing.
    """

    test_id: Optional[str]
    deduplication_complete: Optional[bool]


def _object_pairs_hook(pairs):
    """Reject duplicate JSON keys anywhere in the body.

    The stdlib parser silently keeps the last value on a duplicate key,
    which could flip ``deduplication_complete`` false→true or change the
    Test ID; duplicate keys are ambiguous and malformed for this
    parser.
    """
    data = {}
    for key, value in pairs:
        if key in data:
            raise MalformedResponseError(
                "duplicate JSON key is ambiguous; refusing to parse a "
                "response whose deduplication flag or Test ID could be "
                "silently rewritten"
            )
        data[key] = value
    return data


def _reject_non_strict_constant(name: str) -> None:
    """Reject the non-strict JSON constants ``NaN``/``Infinity``/``-Infinity``.

    The documented response is strict JSON; the stdlib parser otherwise
    accepts these non-JSON literals (even in ignored fields) and silently
    turns them into floats.
    """
    raise MalformedResponseError(
        f"response body contains the non-strict JSON constant {name!r}; "
        "the documented response is strict JSON"
    )


def _reject_non_finite_float(value: str) -> float:
    """Reject JSON numbers whose Python float conversion overflows.

    ``json.loads`` otherwise turns an exponent overflow such as ``1e999``
    into positive infinity.  The response contract is strict JSON, so every
    numeric value—including values in ignored fields—must remain finite.
    """
    parsed = float(value)
    if not math.isfinite(parsed):
        raise MalformedResponseError(
            f"response body contains a non-finite JSON number {value!r}"
        )
    return parsed


def parse_response(body: bytes) -> EngineResponseV1:
    """Bounded parser for the documented import/reimport response.

    Extracts only ``test_id`` and ``deduplication_complete`` and rejects
    malformed shapes: non-JSON bodies (including the non-strict JSON
    constants ``NaN``/``Infinity`` anywhere in the body), non-object top
    levels, duplicate JSON keys, a ``test_id`` that is not a positive
    integer (booleans are
    rejected: ``bool`` is an ``int`` subclass but not a Test ID; zero is
    not a positive CE Test ID), and a ``deduplication_complete`` that is
    present but neither a strict bool nor null. ``test_id`` is returned
    as its canonical positive numeric string. It does not classify
    network failures and does not settle anything.
    """
    if not isinstance(body, (bytes, bytearray)):
        raise MalformedResponseError("response body must be bytes")
    try:
        data = json.loads(
            bytes(body),
            object_pairs_hook=_object_pairs_hook,
            parse_constant=_reject_non_strict_constant,
            parse_float=_reject_non_finite_float,
        )
    except MalformedResponseError:
        raise
    except (ValueError, UnicodeDecodeError):
        raise MalformedResponseError(
            "response body is not valid JSON"
        ) from None
    if not isinstance(data, dict):
        raise MalformedResponseError(
            "response body must be a JSON object"
        )

    test_id: Optional[str] = None
    if "test_id" in data:
        raw = data["test_id"]
        if isinstance(raw, bool) or not isinstance(raw, int):
            raise MalformedResponseError(
                f"test_id must be a JSON integer, got {raw!r}"
            )
        if raw <= 0:
            raise MalformedResponseError(
                f"test_id must be a positive integer, got {raw}"
            )
        test_id = str(raw)

    deduplication_complete: Optional[bool] = None
    if "deduplication_complete" in data:
        raw = data["deduplication_complete"]
        if raw is not None and not isinstance(raw, bool):
            raise MalformedResponseError(
                "deduplication_complete must be a strict JSON boolean or null, "
                f"got {raw!r}"
            )
        deduplication_complete = raw

    return EngineResponseV1(
        test_id=test_id, deduplication_complete=deduplication_complete
    )
