"""Focused behavioural tests for the G1 supported-API request codec.

Synthetic fixtures only: no HTTP, no network, no live CE, no
OperationStore mutation, no token handling. Covers exact multipart field
names and exact payload bytes, deterministic construction, digest/kind
rejection, reimport Test binding, explicit ``close_old_findings=false``,
filename/CRLF safety, and malformed response rejection. The CE 3.3.100
field baselines and routes are explicitly experimental — these tests pin
the retained evidence bytes, they do not claim a D-03 engine pin or
CR-04 proof.

Regressions pinning the four Reviewer material defects:

1. a fixed multipart boundary can occur in the file bytes and truncate
   them under MIME parsing — the boundary is now derived from the
   verified payload SHA-256 and verified against a standard multipart
   parser on adversarial payloads;
2. the first-import request omitted the documented
   ``auto_create_context=true`` field sent by the retained CE 3.3.100
   command — import sends it, reimport does not;
3. a filename quote broke Content-Disposition and a non-ASCII filename
   raised a raw ``UnicodeEncodeError`` — the filename is restricted to
   safe ASCII with a typed ``UnsafeFilenameError``;
4. the reimport fixture used an invalid CE Test ID ``test-42`` where CE
   requires a positive integer — a canonical positive numeric Test ID is
   now required and the fixture uses a CE-valid integer.

Second-pass reviewer regressions:

5. the first-import Product target (ScanContextV1) was independent of the
   immutable ``operation.context_key`` — one operation/payload could
   produce different Product bodies. A canonical context key derived from
   the ScanContextV1 fields is now required to equal
   ``operation.context_key`` before encoding a first import, and a
   reimport requires its ``operation.context_key`` to be canonical; two
   differing Product targets for one operation are rejected. Migration of
   legacy arbitrary context keys is a codec boundary (OperationStore is
   unchanged); existing request context semantics are preserved.
6. the payload-derived multipart boundary was 85 characters, above the
   RFC 2046 70-character maximum — it is now 48 hex chars of the payload
   SHA-256 (69 chars total), retaining digest derivation and the
   collision-in-payload rejection.
7. ``parse_response`` accepted ``test_id=0``, let duplicate JSON keys flip
   ``deduplication_complete`` false→true, and returned ``test_id`` as an
   int where ``OperationStore.record_response`` takes a str — duplicate
   JSON keys are now rejected, ``test_id`` must be a positive integer and
   is returned as its canonical str, and the deduplication flag stays a
   strict bool. The retained CE 3.3.100 response examples must still
   parse.

Third-pass reviewer regressions (pure input validation):

8. ``is_canonical_context_key`` accepted a percent-escaped alias of a
   canonical key (``%41`` where ``quote(safe="")`` emits ``A``) and an
   invalid-UTF-8 slot (``%FF``) — a slot is canonical only when it
   round-trips through strict-UTF-8 decode and re-quoting;
9. ``parse_response`` accepted non-strict JSON constants (``NaN``,
   ``Infinity``) in ignored fields — strict JSON only;
10. ``sanitize_filename`` allowed the non-printable ASCII DEL byte
    (0x7f) into a Content-Disposition filename — all non-printable
    filename bytes are rejected with a typed error;
11. ``sanitize_filename`` silently stripped C0 control characters
    (0x00-0x1f, including NUL) from the filename — like DEL, all C0
    control characters are rejected with a typed error.
"""

from __future__ import annotations

import email
import email.policy
import hashlib
import re
import unittest
import uuid
from datetime import datetime, timezone
from email.parser import BytesParser
from pathlib import Path

from uvm.engine.api_codec import (
    IMPORT_SCAN_FIELDS,
    IMPORT_SCAN_PATH,
    REIMPORT_SCAN_FIELDS,
    REIMPORT_SCAN_PATH,
    CodecError,
    ContextKeyMismatchError,
    EngineResponseV1,
    InvalidContextKeyError,
    InvalidTestIdError,
    MalformedResponseError,
    PayloadDigestMismatch,
    ScanContextV1,
    UnsafeFilenameError,
    build_import_request,
    build_reimport_request,
    canonical_context_key,
    derive_boundary,
    is_canonical_context_key,
    parse_response,
    sanitize_filename,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
from uvm.engine.operation import (
    REQUEST_IMPORT,
    REQUEST_REIMPORT,
    STATUS_PENDING,
    EngineImportOperationV1,
)

T0 = datetime(2026, 7, 6, 9, 0, 0, tzinfo=timezone.utc)
FIXTURE_CONTEXT = ScanContextV1(
    product_name="UVM G1 synthetic product",
    engagement_name="UVM G1 synthetic engagement",
    environment="Development",
)
# Regression 5: the operation's immutable context key is the canonical
# key of the Product target, not an arbitrary string.
CTX = canonical_context_key(FIXTURE_CONTEXT)
LEGACY_CTX = "prod:acct-1/eng-prod"  # pre-migration arbitrary key
PAYLOAD = b"<qualys-report>\r\n<finding qid='71101'/>\r\n</qualys-report>\r\n"
DIGEST = hashlib.sha256(PAYLOAD).hexdigest()
FIELD_RE = re.compile(rb'name="([A-Za-z0-9_]+)"(?:;\s*filename="([^"]*)")?', re.S)


# A payload deliberately hostile to a multipart parser: it embeds the OLD
# fixed boundary string as a line (with the leading ``--``), a decoy
# part-header line, bare ``--`` runs and CRLF sequences. Under a fixed
# boundary these bytes would truncate the file part; under a
# payload-derived boundary a standard parser must return the exact bytes.
ADVERSARIAL_PAYLOAD = (
    b"<r>\r\n"
    b"--uvm-engine-multipart-33100\r\n"
    b'Content-Disposition: form-data; name="evil"\r\n\r\n'
    b"decoy value --\r\n"
    b"----\r\n\r\n"
    b"trailing bytes </r>\r\n"
)
ADVERSARIAL_DIGEST = hashlib.sha256(ADVERSARIAL_PAYLOAD).hexdigest()


def _op(
    request_kind: str,
    test_id: str | None = None,
    digest: str = DIGEST,
    scan_type: str = "Qualys Scan",
    context_key: str | None = None,
) -> EngineImportOperationV1:
    return EngineImportOperationV1(
        schema_version=1,
        operation_id=str(uuid.uuid4()),
        revision=1,
        context_key=context_key if context_key is not None else CTX,
        source_run_id="run-1",
        scan_type=scan_type,
        payload_sha256=digest,
        parser_config_version="g1-ce-3.3.100-pair-readback-v1",
        engine_release="3.3.100",
        request_kind=request_kind,
        requested_at=T0,
        close_old_findings=False,
        status=STATUS_PENDING,
        test_id=test_id,
    )


def _boundary_of(body: bytes) -> bytes:
    first, _, _ = body.partition(b"\r\n")
    assert first.startswith(b"--"), f"body must start with a boundary: {first!r}"
    return first[2:]


def _parts(body: bytes) -> dict[str, bytes]:
    """Extract multipart part name -> content bytes using the body's own
    (payload-derived) boundary."""
    boundary = _boundary_of(body)
    sep = b"--" + boundary + b"\r\n"
    end = b"--" + boundary + b"--\r\n"
    assert body.startswith(sep)
    assert body.endswith(end)
    parts: dict[str, bytes] = {}
    for block in body[len(sep) : -len(end)].split(sep):
        if not block:
            continue
        header, _, content = block.partition(b"\r\n\r\n")
        assert content.endswith(b"\r\n")
        content = content[:-2]
        match = FIELD_RE.search(header)
        assert match is not None, f"no field name in header: {header!r}"
        parts[match.group(1).decode("ascii")] = content
    return parts


def _mime_parse(req) -> dict[str, bytes]:
    """Parse the request body with the stdlib MIME multipart parser and
    return {part_name: raw content bytes}. This is the independent
    parser used to prove the file bytes survive round-trip."""
    content_type = req.header("Content-Type").encode("ascii")
    full = b"Content-Type: " + content_type + b"\r\n\r\n" + req.body
    msg = BytesParser(policy=email.policy.default).parsebytes(full)
    assert msg.is_multipart(), "request body must parse as a multipart message"
    parts: dict[str, bytes] = {}
    for part in msg.iter_parts():
        cd = part.get("Content-Disposition", "")
        match = re.search(r'name="([^"]*)"', cd)
        assert match is not None, f"no field name in {cd!r}"
        parts[match.group(1)] = part.get_payload(decode=True)
    return parts


class ImportRequestConstructionTest(unittest.TestCase):
    def setUp(self) -> None:
        self.op = _op(REQUEST_IMPORT)
        self.context = FIXTURE_CONTEXT
        self.req = build_import_request(
            self.op, PAYLOAD, self.context, filename="qualys_qid_overlap.xml"
        )

    def test_exact_route_and_method(self) -> None:
        self.assertEqual(self.req.method, "POST")
        self.assertEqual(self.req.path, IMPORT_SCAN_PATH)
        self.assertEqual(
            self.req.header("Content-Type"),
            f"multipart/form-data; boundary={derive_boundary(PAYLOAD).decode('ascii')}",
        )

    def test_exact_field_names_and_values(self) -> None:
        parts = _parts(self.req.body)
        # Exactly the documented fields: no fabricated fields, and no
        # import_scan_results / reimport_scan_results / test_type field.
        # auto_create_context=true is the documented first-import flag.
        self.assertEqual(
            set(parts),
            {
                "auto_create_context",
                "product_name",
                "engagement_name",
                "environment",
                "scan_type",
                "close_old_findings",
                "file",
            },
        )
        self.assertNotIn("test", parts)
        self.assertNotIn("import_scan_results", parts)
        self.assertNotIn("reimport_scan_results", parts)
        self.assertNotIn("test_type", parts)
        self.assertEqual(parts["auto_create_context"], b"true")
        self.assertEqual(parts["scan_type"], b"Qualys Scan")
        self.assertEqual(parts["product_name"], b"UVM G1 synthetic product")
        self.assertEqual(
            parts["engagement_name"], b"UVM G1 synthetic engagement"
        )
        self.assertEqual(parts["environment"], b"Development")

    def test_exact_payload_bytes_and_filename(self) -> None:
        parts = _parts(self.req.body)
        self.assertEqual(parts["file"], PAYLOAD)
        file_header_start = self.req.body.find(b'name="file"')
        header = self.req.body[file_header_start : self.req.body.find(
            b"\r\n\r\n", file_header_start
        )]
        self.assertIn(b'filename="qualys_qid_overlap.xml"', header)
        self.assertIn(b"Content-Type: application/octet-stream", header)

    def test_close_old_findings_is_explicitly_false(self) -> None:
        # No absence closure: the field is always present, never true.
        parts = _parts(self.req.body)
        self.assertEqual(parts["close_old_findings"], b"false")

    def test_all_field_names_within_retained_baseline(self) -> None:
        parts = _parts(self.req.body)
        self.assertTrue(set(parts) <= IMPORT_SCAN_FIELDS)
        self.assertTrue(
            "import_scan_results" not in IMPORT_SCAN_FIELDS
            and "reimport_scan_results" not in IMPORT_SCAN_FIELDS
            and "test_type" not in IMPORT_SCAN_FIELDS
        )

    def test_construction_is_deterministic(self) -> None:
        again = build_import_request(
            self.op, PAYLOAD, self.context, filename="qualys_qid_overlap.xml"
        )
        self.assertEqual(again.body, self.req.body)
        self.assertEqual(again.headers, self.req.headers)

    def test_optional_context_field_omitted_when_none(self) -> None:
        full = ScanContextV1(
            product_name="p",
            engagement_name="e",
            environment="Development",
            product_type_name="UVM G1 synthetic",
        )
        req = build_import_request(
            _op(REQUEST_IMPORT, context_key=canonical_context_key(full)),
            PAYLOAD,
            full,
            filename="r.xml",
        )
        parts = _parts(req.body)
        self.assertEqual(parts["product_type_name"], b"UVM G1 synthetic")
        self.assertNotIn("product_type_name", _parts(self.req.body))

    def test_optional_settings_omitted_when_none(self) -> None:
        parts = _parts(self.req.body)
        self.assertNotIn("minimum_severity", parts)
        self.assertNotIn("deduplication_execution_mode", parts)
        req = build_import_request(
            self.op,
            PAYLOAD,
            self.context,
            filename="r.xml",
            minimum_severity="Info",
            deduplication_execution_mode="sync",
        )
        parts = _parts(req.body)
        self.assertEqual(parts["minimum_severity"], b"Info")
        self.assertEqual(parts["deduplication_execution_mode"], b"sync")
        self.assertTrue(set(parts) <= IMPORT_SCAN_FIELDS)


class BoundarySafetyTest(unittest.TestCase):
    """Defect 1: the boundary must never occur in the file bytes, verified
    with a standard multipart parser on adversarial payloads."""

    def test_boundary_is_payload_derived_and_deterministic(self) -> None:
        self.assertEqual(derive_boundary(PAYLOAD), derive_boundary(PAYLOAD))
        # 48 hex chars of the payload SHA-256 (regression 6).
        self.assertEqual(
            derive_boundary(PAYLOAD),
            ("uvm-engine-multipart-" + DIGEST[:48]).encode("ascii"),
        )
        # A different payload yields a different boundary.
        self.assertNotEqual(derive_boundary(PAYLOAD), derive_boundary(ADVERSARIAL_PAYLOAD))

    def test_boundary_within_rfc2046_seventy_char_maximum(self) -> None:
        # RFC 2046: the multipart boundary parameter is at most 70 chars.
        for payload in (PAYLOAD, ADVERSARIAL_PAYLOAD):
            self.assertLessEqual(len(derive_boundary(payload)), 70)

    def test_derived_boundary_is_absent_from_file_bytes(self) -> None:
        for payload in (PAYLOAD, ADVERSARIAL_PAYLOAD):
            self.assertNotIn(derive_boundary(payload), payload)

    def test_adversarial_payload_round_trips_through_stdlib_parser(self) -> None:
        # The payload contains the OLD fixed boundary as a line, a decoy
        # form-data header, bare ``--`` runs and CRLF. The standard
        # multipart parser must still return the exact file bytes and the
        # exact field values — no truncation, no decoy part.
        ctx = ScanContextV1(
            product_name="p", engagement_name="e", environment="Development"
        )
        op = _op(
            REQUEST_IMPORT,
            digest=ADVERSARIAL_DIGEST,
            context_key=canonical_context_key(ctx),
        )
        req = build_import_request(
            op, ADVERSARIAL_PAYLOAD, ctx, filename="adversarial.xml"
        )
        parts = _mime_parse(req)
        # No stray "evil"/decoy part is introduced by the embedded header.
        self.assertNotIn("evil", parts)
        self.assertEqual(parts["file"], ADVERSARIAL_PAYLOAD)
        self.assertEqual(parts["scan_type"], b"Qualys Scan")
        self.assertEqual(parts["auto_create_context"], b"true")

    def test_adversarial_payload_round_trips_reimport(self) -> None:
        op = _op(REQUEST_REIMPORT, test_id="7", digest=ADVERSARIAL_DIGEST)
        req = build_reimport_request(
            op, ADVERSARIAL_PAYLOAD, filename="adversarial_repeat.xml"
        )
        parts = _mime_parse(req)
        self.assertEqual(parts["file"], ADVERSARIAL_PAYLOAD)
        self.assertEqual(parts["test"], b"7")


class AutoCreateContextTest(unittest.TestCase):
    """Defect 2: first-import sends auto_create_context=true; reimport does
    not (it reuses the registered Test)."""

    def test_import_sends_auto_create_context_true(self) -> None:
        ctx = ScanContextV1(
            product_name="p", engagement_name="e", environment="Development"
        )
        req = build_import_request(
            _op(REQUEST_IMPORT, context_key=canonical_context_key(ctx)),
            PAYLOAD,
            ctx,
            filename="r.xml",
        )
        parts = _parts(req.body)
        self.assertEqual(parts["auto_create_context"], b"true")
        self.assertIn("auto_create_context", IMPORT_SCAN_FIELDS)

    def test_reimport_does_not_send_auto_create_context(self) -> None:
        req = build_reimport_request(
            _op(REQUEST_REIMPORT, test_id="42"), PAYLOAD, filename="r.xml"
        )
        self.assertNotIn("auto_create_context", _parts(req.body))


class ReimportRequestConstructionTest(unittest.TestCase):
    def setUp(self) -> None:
        # CE-valid positive integer Test ID (defect 4: "test-42" is not a
        # valid CE Test ID).
        self.op = _op(REQUEST_REIMPORT, test_id="42")
        self.req = build_reimport_request(
            self.op, PAYLOAD, filename="qualys_qid_overlap_repeat.xml"
        )

    def test_exact_route_and_test_binding(self) -> None:
        self.assertEqual(self.req.method, "POST")
        self.assertEqual(self.req.path, REIMPORT_SCAN_PATH)
        parts = _parts(self.req.body)
        # The documented `test` field binds exactly the registered CE Test.
        self.assertEqual(parts["test"], b"42")
        self.assertEqual(parts["scan_type"], b"Qualys Scan")
        self.assertEqual(parts["file"], PAYLOAD)
        self.assertEqual(parts["close_old_findings"], b"false")
        self.assertTrue(set(parts) <= REIMPORT_SCAN_FIELDS)
        self.assertNotIn("product_name", parts)
        self.assertNotIn("engagement_name", parts)
        self.assertNotIn("do_not_reactivate", parts)
        self.assertNotIn("auto_create_context", parts)

    def test_construction_is_deterministic(self) -> None:
        again = build_reimport_request(
            self.op, PAYLOAD, filename="qualys_qid_overlap_repeat.xml"
        )
        self.assertEqual(again.body, self.req.body)

    def test_file_bytes_survive_stdlib_parser(self) -> None:
        self.assertEqual(_mime_parse(self.req)["file"], PAYLOAD)

    def test_missing_test_id_rejected(self) -> None:
        # The DTO refuses to construct a reimport without its Test, so the
        # unbound case can never reach the codec through the normal
        # constructor; the codec double-checks the binding before
        # encoding anything (tested via a bypass-constructed instance).
        bad_kwargs = dict(
            schema_version=1,
            operation_id=str(uuid.uuid4()),
            revision=1,
            context_key=CTX,
            source_run_id="run-1",
            scan_type="Qualys Scan",
            payload_sha256=DIGEST,
            parser_config_version="v1",
            engine_release="3.3.100",
            request_kind=REQUEST_REIMPORT,
            requested_at=T0,
            close_old_findings=False,
            status=STATUS_PENDING,
        )
        with self.assertRaises(ValueError):
            EngineImportOperationV1(**bad_kwargs)
        unbound = object.__new__(EngineImportOperationV1)
        for attr, value in self.op.__dict__.items():
            object.__setattr__(unbound, attr, value)
        object.__setattr__(unbound, "test_id", None)
        with self.assertRaises(CodecError):
            build_reimport_request(unbound, PAYLOAD, filename="r.xml")


class ReimportTestIdTest(unittest.TestCase):
    """Defect 4: the reimport `test` field must be a canonical positive
    numeric Test ID (CE requires a positive integer)."""

    def test_valid_positive_integer_accepted(self) -> None:
        for tid in ("42", "1", "999999"):
            req = build_reimport_request(
                _op(REQUEST_REIMPORT, test_id=tid), PAYLOAD, filename="r.xml"
            )
            self.assertEqual(_parts(req.body)["test"], tid.encode("ascii"))

    def test_non_numeric_and_non_canonical_ids_rejected(self) -> None:
        for tid in ("test-42", "0", "-5", "042", "42 ", "4.2"):
            with self.assertRaises(InvalidTestIdError, msg=f"accepted {tid!r}"):
                build_reimport_request(
                    _op(REQUEST_REIMPORT, test_id=tid), PAYLOAD, filename="r.xml"
                )


class CodecRejectionTest(unittest.TestCase):
    def test_wrong_payload_digest_rejected_before_encoding(self) -> None:
        ctx = ScanContextV1(
            product_name="p",
            engagement_name="e",
            environment="Development",
        )
        op = _op(
            REQUEST_IMPORT,
            digest="0" * 64,
            context_key=canonical_context_key(ctx),
        )
        with self.assertRaises(PayloadDigestMismatch):
            build_import_request(op, PAYLOAD, ctx, filename="r.xml")

    def test_digest_comparison_is_case_insensitive_hex(self) -> None:
        ctx = ScanContextV1(
            product_name="p",
            engagement_name="e",
            environment="Development",
        )
        op = _op(
            REQUEST_IMPORT,
            digest=DIGEST.upper(),
            context_key=canonical_context_key(ctx),
        )
        req = build_import_request(op, PAYLOAD, ctx, filename="r.xml")
        self.assertEqual(_parts(req.body)["file"], PAYLOAD)

    def test_wrong_request_kind_rejected(self) -> None:
        reimport_op = _op(REQUEST_REIMPORT, test_id="42")
        ctx = ScanContextV1(
            product_name="p",
            engagement_name="e",
            environment="Development",
        )
        with self.assertRaises(CodecError):
            build_import_request(reimport_op, PAYLOAD, ctx, filename="r.xml")
        with self.assertRaises(CodecError):
            build_reimport_request(_op(REQUEST_IMPORT), PAYLOAD, filename="r.xml")

    def test_crlf_in_field_value_rejected(self) -> None:
        ctx = ScanContextV1(
            product_name="evil\r\nX-Injection: yes",
            engagement_name="e",
            environment="Development",
        )
        with self.assertRaises(CodecError):
            build_import_request(
                _op(REQUEST_IMPORT, context_key=canonical_context_key(ctx)),
                PAYLOAD,
                ctx,
                filename="r.xml",
            )

    def test_filename_sanitized_against_path(self) -> None:
        self.assertEqual(sanitize_filename("../../etc/name.xml"),
                         "name.xml")
        # Control characters in the path component are removed by the
        # basename step and never reach the filename; only CR/LF inside
        # the basename itself is rejected (see the sibling test).
        self.assertEqual(
            sanitize_filename("\r\n../../etc/name.xml"), "name.xml"
        )
        self.assertEqual(sanitize_filename("/srv/reports/a report.xml"),
                         "a report.xml")

    def test_filename_crlf_is_rejected_not_stripped(self) -> None:
        # CR/LF inside the basename are C0 control characters: rejected
        # with a typed error, not silently stripped from the filename.
        for filename in ("\r\n", "report\r.xml", "report\n.xml",
                         "../..\\C:\\report\r\n.xml"):
            with self.assertRaises(UnsafeFilenameError, msg=filename):
                sanitize_filename(filename)
        with self.assertRaises(UnsafeFilenameError):
            build_reimport_request(
                _op(REQUEST_REIMPORT, test_id="42"),
                PAYLOAD,
                filename="../..\\C:\\report\r\n.xml",
            )


class FilenameSafetyTest(unittest.TestCase):
    """Defect 3: a filename quote must not break Content-Disposition and a
    non-ASCII filename must not raise a raw UnicodeEncodeError — both are
    rejected with a typed UnsafeFilenameError."""

    def test_quote_breaks_header_only_via_typed_error(self) -> None:
        with self.assertRaises(UnsafeFilenameError):
            sanitize_filename('bad"name.xml')
        ctx = ScanContextV1(
            product_name="p", engagement_name="e",
            environment="Development",
        )
        with self.assertRaises(UnsafeFilenameError):
            build_import_request(
                _op(REQUEST_IMPORT, context_key=canonical_context_key(ctx)),
                PAYLOAD,
                ctx,
                filename='bad"name.xml',
            )

    def test_non_ascii_raises_typed_error_not_unicodeencodeerror(self) -> None:
        for filename in ("réport.xml", "report-ünicode.xml"):
            with self.assertRaises(UnsafeFilenameError, msg=filename):
                sanitize_filename(filename)
        # The typed error is a CodecError, and the codec must not leak a
        # raw UnicodeEncodeError for a non-ASCII filename.
        try:
            build_reimport_request(
                _op(REQUEST_REIMPORT, test_id="42"),
                PAYLOAD,
                filename="réport.xml",
            )
        except UnicodeEncodeError:  # pragma: no cover - regression guard
            self.fail("raw UnicodeEncodeError leaked for non-ASCII filename")
        except UnsafeFilenameError:
            pass
        self.assertTrue(
            issubclass(UnsafeFilenameError, CodecError),
            "UnsafeFilenameError must be a typed CodecError",
        )

    def test_semicolon_is_unsafe(self) -> None:
        with self.assertRaises(UnsafeFilenameError):
            sanitize_filename("a;b.xml")

    def test_ascii_del_is_rejected_not_emitted(self) -> None:
        # Reviewer finding: ASCII DEL (0x7f) is not a printable filename
        # byte and must not reach a Content-Disposition header.
        for filename in ("re\x7fport.xml", "report.xml\x7f"):
            with self.assertRaises(UnsafeFilenameError, msg=filename):
                sanitize_filename(filename)
        ctx = ScanContextV1(
            product_name="p", engagement_name="e",
            environment="Development",
        )
        with self.assertRaises(UnsafeFilenameError):
            build_reimport_request(
                _op(REQUEST_REIMPORT, test_id="42"),
                PAYLOAD,
                filename="re\x7fport.xml",
            )

    def test_c0_control_chars_raise_typed_error(self) -> None:
        # Reviewer finding: every C0 control character (0x00-0x1f),
        # including NUL, must be rejected with a typed error exactly as
        # DEL already is — never silently stripped from the filename.
        for code in range(0x20):
            with self.assertRaises(UnsafeFilenameError, msg=repr(chr(code))):
                sanitize_filename("report" + chr(code) + ".xml")
        ctx = ScanContextV1(
            product_name="p", engagement_name="e",
            environment="Development",
        )
        with self.assertRaises(UnsafeFilenameError):
            build_import_request(
                _op(REQUEST_IMPORT, context_key=canonical_context_key(ctx)),
                PAYLOAD,
                ctx,
                filename="report\x00.xml",
            )
        with self.assertRaises(UnsafeFilenameError):
            build_reimport_request(
                _op(REQUEST_REIMPORT, test_id="42"),
                PAYLOAD,
                filename="report\x1b[.xml",
            )

    def test_safe_ascii_filename_is_preserved(self) -> None:
        self.assertEqual(sanitize_filename("qualys_qid_overlap.xml"),
                         "qualys_qid_overlap.xml")
        req = build_reimport_request(
            _op(REQUEST_REIMPORT, test_id="42"),
            PAYLOAD,
            filename="a safe report.xml",
        )
        # The header round-trips through the stdlib parser with the exact
        # (safe) filename intact.
        self.assertIn(b'filename="a safe report.xml"', req.body)


class ResponseParserTest(unittest.TestCase):
    def test_documented_fields_extracted(self) -> None:
        # Regression 7: test_id is the canonical positive numeric Test ID
        # as a str, matching OperationStore.record_response's str field.
        resp = parse_response(
            b'{"test_id": 7, "deduplication_complete": true, '
            b'"statistics": {"total": 1}}'
        )
        self.assertEqual(resp, EngineResponseV1(test_id="7",
                                                deduplication_complete=True))
        self.assertIsInstance(resp.test_id, str)

    def test_absent_fields_are_explicit_none_not_completion(self) -> None:
        resp = parse_response(b'{"product_id": 1}')
        self.assertIsNone(resp.test_id)
        self.assertIsNone(resp.deduplication_complete)

    def test_false_completion_is_not_absence(self) -> None:
        resp = parse_response(b'{"test_id": 3, "deduplication_complete": false}')
        self.assertFalse(resp.deduplication_complete)
        self.assertEqual(resp.test_id, "3")

    def test_malformed_shapes_rejected(self) -> None:
        bad_bodies = [
            b"not json at all",
            b"[1, 2, 3]",
            b'"an object-less string"',
            b"null",
            b'{"test_id": "seven"}',
            b'{"test_id": true}',
            b'{"test_id": 7.5}',
            b'{"test_id": 0}',
            b'{"test_id": -1}',
            b'{"deduplication_complete": 1}',
            b'{"deduplication_complete": "true"}',
            b"42",
            # Strict JSON only: NaN/Infinity/-Infinity are not JSON, even
            # in ignored fields.
            b'{"ignored": NaN}',
            b'{"test_id": 7, "ignored": Infinity}',
            b'{"deduplication_complete": -Infinity}',
            b'{"ignored": NaN, "test_id": 3}',
            # Exponent overflow must be rejected even when nested in an
            # ignored response field; json.loads otherwise returns inf.
            b'{"ignored": {"nested": [1e999]}}',
        ]
        for body in bad_bodies:
            with self.assertRaises(MalformedResponseError,
                                   msg=f"accepted malformed body {body!r}"):
                parse_response(body)

    def test_finite_exponent_in_ignored_field_is_preserved(self) -> None:
        # A large but finite JSON number remains valid, including at depth.
        resp = parse_response(
            b'{"test_id": 7, "ignored": {"nested": [1e308]}}'
        )
        self.assertEqual(
            resp,
            EngineResponseV1(test_id="7", deduplication_complete=None),
        )

    def test_null_deduplication_complete_is_absent(self) -> None:
        resp = parse_response(b'{"test_id": 2, "deduplication_complete": null}')
        self.assertEqual(resp.test_id, "2")
        self.assertIsNone(resp.deduplication_complete)

    def test_duplicate_json_keys_rejected(self) -> None:
        # Regression 7: a duplicate key previously let the parser keep the
        # last value, flipping deduplication_complete false→true or
        # changing the Test ID. Duplicate keys are ambiguous and rejected.
        bad_bodies = [
            b'{"deduplication_complete": false, "deduplication_complete": true}',
            b'{"test_id": 1, "test_id": 2}',
            b'{"test_id": 1, "test_id": 1}',
            b'{"a": 1, "a": 2}',
        ]
        for body in bad_bodies:
            with self.assertRaises(MalformedResponseError,
                                   msg=f"accepted duplicate-key body {body!r}"):
                parse_response(body)

    def test_synthetic_ce_response_fixtures_still_parse(self) -> None:
        # Minimal synthetic CE response shapes keep parsing after the
        # strict-duplicate/positive-Test-ID changes.
        for name in ("qualys-import.json", "qualys-reimport.json"):
            path = (
                REPO_ROOT / "tests/fixtures/g1/ce-response" / name
            )
            resp = parse_response(path.read_bytes())
            self.assertEqual(
                resp,
                EngineResponseV1(test_id="1", deduplication_complete=True),
                msg=name,
            )


class CanonicalContextKeyTest(unittest.TestCase):
    """Regression 5: one canonical, unambiguous context key derived from
    the ScanContextV1 fields."""

    def test_key_is_deterministic(self) -> None:
        ctx = ScanContextV1(product_name="p", engagement_name="e",
                            environment="Development")
        self.assertEqual(canonical_context_key(ctx), canonical_context_key(ctx))
        self.assertTrue(is_canonical_context_key(canonical_context_key(ctx)))

    def test_key_is_unambiguous_across_field_splits(self) -> None:
        # Separator-bearing values must not let two different Product
        # targets produce the same key.
        self.assertNotEqual(
            canonical_context_key(ScanContextV1("a/b", "c", "e")),
            canonical_context_key(ScanContextV1("a", "b/c", "e")),
        )
        self.assertNotEqual(
            canonical_context_key(ScanContextV1("a", "e", "b")),
            canonical_context_key(ScanContextV1("a", "b", "e")),
        )

    def test_product_type_name_participates(self) -> None:
        base = ScanContextV1(product_name="p", engagement_name="e",
                             environment="Development")
        typed = ScanContextV1(product_name="p", engagement_name="e",
                              environment="Development",
                              product_type_name="UVM G1 synthetic")
        self.assertNotEqual(
            canonical_context_key(base), canonical_context_key(typed)
        )

    def test_legacy_arbitrary_keys_are_not_canonical(self) -> None:
        self.assertFalse(is_canonical_context_key(LEGACY_CTX))
        self.assertFalse(is_canonical_context_key(""))
        self.assertFalse(is_canonical_context_key(None))
        self.assertFalse(is_canonical_context_key("uvm-ctx/1/p/e/Development"))
        # A well-formed key round-trips as canonical.
        self.assertTrue(
            is_canonical_context_key(
                canonical_context_key(
                    ScanContextV1("p with space", "e:1", "Development")
                )
            )
        )

    def test_alias_encoding_and_invalid_utf8_keys_are_not_canonical(self) -> None:
        # Reviewer finding: ``uvm-ctx/1//%41/e/Development`` is an alias of
        # the canonical key for product "A" (``quote(safe="")`` never
        # emits ``%41`` for the always-safe character "A") and must be
        # rejected; the canonical form round-trips.
        self.assertFalse(
            is_canonical_context_key("uvm-ctx/1//%41/e/Development")
        )
        self.assertTrue(
            is_canonical_context_key("uvm-ctx/1//A/e/Development")
        )
        self.assertTrue(
            is_canonical_context_key(
                canonical_context_key(ScanContextV1("A", "e", "Development"))
            )
        )
        # ``%FF`` is invalid UTF-8: no UTF-8 field value can decode to it.
        self.assertFalse(
            is_canonical_context_key("uvm-ctx/1//%FF/e/Development")
        )
        self.assertFalse(
            is_canonical_context_key("uvm-ctx/1/%FF/p/e/Development")
        )


class ContextBindingTest(unittest.TestCase):
    """Regression 5: the immutable operation.context_key binds the Product
    target; two differing targets for one operation are rejected. Legacy
    arbitrary context keys are a codec boundary — OperationStore is
    unchanged and keeps accepting them on registration."""

    def test_import_requires_context_key_equality(self) -> None:
        ctx = ScanContextV1(product_name="p", engagement_name="e",
                            environment="Development")
        op = _op(REQUEST_IMPORT, context_key=canonical_context_key(ctx))
        req = build_import_request(op, PAYLOAD, ctx, filename="r.xml")
        self.assertEqual(_parts(req.body)["product_name"], b"p")

    def test_two_different_product_targets_for_one_operation_rejected(self) -> None:
        ctx = ScanContextV1(product_name="p", engagement_name="e",
                            environment="Development")
        op = _op(REQUEST_IMPORT, context_key=canonical_context_key(ctx))
        other = ScanContextV1(product_name="other-product", engagement_name="e",
                              environment="Development")
        with self.assertRaises(ContextKeyMismatchError):
            build_import_request(op, PAYLOAD, other, filename="r.xml")

    def test_import_with_legacy_arbitrary_key_is_codec_boundary(self) -> None:
        op = _op(REQUEST_IMPORT, context_key=LEGACY_CTX)
        ctx = ScanContextV1(product_name="p", engagement_name="e",
                            environment="Development")
        with self.assertRaises(InvalidContextKeyError):
            build_import_request(op, PAYLOAD, ctx, filename="r.xml")

    def test_reimport_requires_canonical_context_key(self) -> None:
        op = _op(REQUEST_REIMPORT, test_id="42", context_key=LEGACY_CTX)
        with self.assertRaises(InvalidContextKeyError):
            build_reimport_request(op, PAYLOAD, filename="r.xml")
        # A canonical key encodes as before (existing request semantics
        # preserved).
        req = build_reimport_request(
            _op(REQUEST_REIMPORT, test_id="42"), PAYLOAD, filename="r.xml"
        )
        self.assertEqual(_parts(req.body)["test"], b"42")


if __name__ == "__main__":
    unittest.main()
