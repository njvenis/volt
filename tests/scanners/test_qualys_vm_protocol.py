from __future__ import annotations

import unittest
import datetime
import http.client
import ssl
import subprocess
import tempfile
import threading
import time
import uuid
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
import hashlib
from urllib.parse import parse_qsl, urlsplit
from urllib.request import Request


from uvm.scanners.qualys_vm import (ENDPOINT_PATH, PLATFORM_ORIGINS, QualysError,
    QualysPage, QualysVMClient, observations_for_page, parse_page,
    validate_continuation)
from uvm.scanners.evidence import PrivateEvidenceStore
from uvm.scanners.contracts import (ExpectedRevisions, QualysBasicCredential,
    required_scanner_grant)
from uvm.scanners.qualys_vm import _production_transport


PAGE = b'''<?xml version="1.0"?>
<!DOCTYPE HOST_LIST_VM_DETECTION_OUTPUT SYSTEM "https://never-fetch.invalid/out.dtd">
<HOST_LIST_VM_DETECTION_OUTPUT><RESPONSE><HOST_LIST><HOST><ID>42</ID>
<DETECTION_LIST><DETECTION><QID>1001</QID><TYPE>Confirmed</TYPE><SEVERITY>5</SEVERITY>
<STATUS>Active</STATUS><PORT>443</PORT><PROTOCOL>tcp</PROTOCOL><SSL>1</SSL>
<UNIQUE_VULN_ID>instance-a</UNIQUE_VULN_ID><LAST_FOUND_DATETIME>2026-01-01T01:00:00Z</LAST_FOUND_DATETIME>
</DETECTION><DETECTION><QID>1001</QID><TYPE>Confirmed</TYPE><PORT>53</PORT>
<PROTOCOL>udp</PROTOCOL></DETECTION></DETECTION_LIST></HOST></HOST_LIST>
<WARNING><CODE>1980</CODE><URL>https://qualysapi.qualys.com/api/2.0/fo/asset/host/vm/detection/?action=list&amp;show_igs=1&amp;status=New%2CActive%2CRe-Opened%2CFixed&amp;truncation_limit=10000&amp;id_min=43</URL></WARNING>
</RESPONSE></HOST_LIST_VM_DETECTION_OUTPUT>'''
LAST_PAGE = b'''<HOST_LIST_VM_DETECTION_OUTPUT><RESPONSE><HOST_LIST><HOST><ID>43</ID>
<DETECTION_LIST><DETECTION><QID>1001</QID><TYPE>Confirmed</TYPE><PORT>443</PORT>
<PROTOCOL>tcp</PROTOCOL></DETECTION></DETECTION_LIST></HOST></HOST_LIST></RESPONSE>
</HOST_LIST_VM_DETECTION_OUTPUT>'''


def credential_scope_factory(leases=None):
    @contextmanager
    def scope():
        lease = QualysBasicCredential("user", b"pass")
        if leases is not None:
            leases.append(lease)
        try:
            yield lease
        finally:
            lease.close()
    return scope


@contextmanager
def local_https_server(handler):
    with tempfile.TemporaryDirectory() as directory:
        cert_path, key_path = Path(directory) / "cert.pem", Path(directory) / "key.pem"
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
            "-keyout", str(key_path), "-out", str(cert_path), "-days", "1",
            "-subj", "/CN=127.0.0.1", "-addext", "subjectAltName=IP:127.0.0.1"],
            check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        server = HTTPServer(("127.0.0.1", 0), handler)
        server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        server_context.load_cert_chain(cert_path, key_path)
        server.socket = server_context.wrap_socket(server.socket, server_side=True)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        client_context = ssl.create_default_context(cafile=str(cert_path))
        try:
            yield server, client_context
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)


class QualysProtocolTests(unittest.TestCase):
    def test_shared_contract_allows_null_secret_fence_and_maps_fixed_grants(self):
        revisions = ExpectedRevisions(1, 2, 3, 4, 5, 6, 7, 8, None)
        self.assertIsNone(revisions.secret)
        self.assertEqual(required_scanner_grant("scanner.collection.start"),
            "connector.configure")
        self.assertEqual(required_scanner_grant("connector.read"), "connector.read")
        self.assertEqual(required_scanner_grant("assessment.read"), "assessment.read")
        with self.assertRaises(ValueError):
            required_scanner_grant("scanner.arbitrary")
        with self.assertRaises(ValueError):
            ExpectedRevisions(1, 2, 3, 4, 5, 6, 7, 8, -1)

    def test_parser_keeps_port_protocol_occurrences_and_vendor_times(self):
        page = parse_page(PAGE)
        self.assertEqual(page.host_count, 1)
        self.assertEqual([row.ordinal for row in page.detections], [1, 2])
        self.assertEqual([(row.port, row.protocol) for row in page.detections],
                         [("443", "tcp"), ("53", "udp")])
        self.assertEqual(page.detections[0].source_times[0][1], "2026-01-01T01:00:00Z")
        self.assertIsNotNone(page.continuation)

    def test_observation_mapping_groups_by_qid_and_keeps_occurrence_unverified(self):
        parsed = parse_page(PAGE)
        page = QualysPage(1, "https://qualysapi.qualys.com/api/2.0/fo/asset/host/vm/detection/?action=list",
            PAGE, parsed)
        run_id = str(uuid.uuid4())
        observations = observations_for_page(page, source_account_id="account-id",
            account_authority_id="generated-authority-id", run_id=run_id,
            collected_at=datetime.datetime(2026, 11, 18,
                tzinfo=datetime.timezone.utc), evidence_ref="qualys-page-v1/" + "a" * 32,
            evidence_sha256="b" * 64)
        self.assertEqual([item.native_id_value for item in observations], ["1001", "1001"])
        self.assertEqual([item.source_record_ordinal for item in observations], [1, 2])
        self.assertEqual([(item.asset_locator, item.component_locator) for item in observations],
            [("42", None), ("42", None)])
        self.assertEqual([item.source_rating for item in observations], ["5", None])
        self.assertEqual(observations[0].observed_at.isoformat(), "2026-01-01T01:00:00+00:00")
        self.assertEqual(observations[1].observed_at, None)
        self.assertIn(("component_locator", "unverified"),
            [(field.field, field.reason) for field in observations[0].missing_fields])
        self.assertIn('"port":"443"', observations[0].source_record_locator)
        self.assertIn('"protocol":"udp"', observations[1].source_record_locator)
        replay = observations_for_page(page, source_account_id="account-id",
            account_authority_id="generated-authority-id", run_id=run_id,
            collected_at=datetime.datetime(2026, 11, 18,
                tzinfo=datetime.timezone.utc), evidence_ref="qualys-page-v1/" + "a" * 32,
            evidence_sha256="b" * 64)
        self.assertEqual([item.observation_id for item in observations],
            [item.observation_id for item in replay])

    def test_doctype_is_not_fetched_and_entities_are_rejected(self):
        self.assertEqual(parse_page(PAGE).host_count, 1)
        with self.assertRaises(QualysError) as raised:
            parse_page(PAGE.replace(b"<!DOCTYPE", b"<!ENTITY x SYSTEM \"file:///etc/passwd\">\n<!DOCTYPE"))
        self.assertEqual(raised.exception.code, "unsafe_xml")
        utf16 = PAGE.replace(b"<!DOCTYPE", b"<!ENTITY x SYSTEM \"file:///etc/passwd\">\n<!DOCTYPE").decode().encode("utf-16")
        with self.assertRaises(QualysError) as raised:
            parse_page(utf16)
        self.assertEqual(raised.exception.code, "unsupported_xml_encoding")
        with self.assertRaises(QualysError) as raised:
            parse_page(PAGE.replace(b"</RESPONSE>", b"<WARNING><CODE>9999</CODE></WARNING></RESPONSE>"))
        self.assertEqual(raised.exception.code, "provider_warning")

    def test_parser_rejects_duplicate_host_ids_within_page(self):
        duplicate = PAGE.replace(b"</HOST_LIST>",
            b"<HOST><ID>42</ID></HOST></HOST_LIST>")
        with self.assertRaises(QualysError) as raised:
            parse_page(duplicate)
        self.assertEqual(raised.exception.code, "duplicate_host_id")

    def test_depth_size_and_wrong_root_fail_closed(self):
        with self.assertRaises(QualysError):
            parse_page(PAGE, max_bytes=20)
        with self.assertRaises(QualysError):
            parse_page(PAGE.replace(b"<HOST_LIST_VM_DETECTION_OUTPUT>", b"<OTHER>", 1))
        deep = b"<HOST_LIST_VM_DETECTION_OUTPUT><RESPONSE>" + b"<X>" * 66
        deep += b"</X>" * 66 + b"</RESPONSE></HOST_LIST_VM_DETECTION_OUTPUT>"
        with self.assertRaises(QualysError) as raised:
            parse_page(deep)
        self.assertEqual(raised.exception.code, "xml_depth_exceeded")

    def test_continuation_is_exact_origin_path_and_query_allowlist(self):
        origin = PLATFORM_ORIGINS["us1"]
        good = (origin + ENDPOINT_PATH + "?action=list&show_igs=1"
            "&status=New%2CActive%2CRe-Opened%2CFixed&truncation_limit=10000&id_min=43")
        canonical = validate_continuation(good, origin=origin,
            previous_id_min=None, returned_host_ids=("42",))
        self.assertEqual(dict(parse_qsl(urlsplit(canonical).query)),
            dict(parse_qsl(urlsplit(good).query)))
        for bad in (
            good.replace("qualysapi.qualys.com", "evil.example"),
            good.replace(ENDPOINT_PATH, "/other/"),
            good + "&username=stolen",
            good.replace("id_min=43", "id_min=oops"),
            good.replace("https://", "http://"),
            good.replace("show_igs=1", "show_igs=0"),
            good.replace("id_min=43", "id_min=41"),
            good.replace("id_min=43", "id_min=42"),
            good + "&action=list",
        ):
            with self.subTest(bad=bad), self.assertRaises(QualysError):
                validate_continuation(bad, origin=origin,
                    previous_id_min=None, returned_host_ids=("42",))

    def test_client_sends_pinned_basic_auth_and_types_401_without_retry(self):
        calls = []
        leases = []
        def transport(request, timeout, deadline):
            calls.append((request, timeout))
            return 401, b"private vendor body", {}
        client = QualysVMClient("us1", _transport=transport)
        with self.assertRaises(QualysError) as raised:
            client.fetch_page(
                credential_scope=credential_scope_factory(leases))
        self.assertEqual(raised.exception.code, "authentication_rejected")
        self.assertEqual(len(calls), 1)
        request, timeout = calls[0]
        self.assertEqual(parse_qsl(urlsplit(request.full_url).query),
            [("action", "list"), ("show_igs", "1"),
             ("status", "New,Active,Re-Opened,Fixed"), ("truncation_limit", "10000")])
        self.assertEqual(request.get_header("X-requested-with"), "VOLT")
        self.assertEqual(timeout, 30)
        self.assertEqual(leases[0]._password, bytearray(b"\0\0\0\0"))
        self.assertEqual(repr(leases[0]), "QualysBasicCredential(<redacted>)")

    def test_unsupported_origin_is_rejected(self):
        with self.assertRaises(ValueError):
            QualysVMClient("custom")

    def test_private_evidence_store_keeps_exact_bytes_and_bounds(self):
        with tempfile.TemporaryDirectory() as directory:
            store = PrivateEvidenceStore(directory, max_page_bytes=4096, max_total_bytes=8192)
            receipt = store.write(PAGE, operation_bytes=100)
            self.assertEqual(store.read(receipt.ref), PAGE)
            self.assertEqual(receipt.sha256, hashlib.sha256(PAGE).hexdigest())
            self.assertEqual(receipt.size, len(PAGE))
            filename = Path(directory) / (receipt.ref.split("/")[1] + ".xml")
            self.assertEqual(filename.stat().st_mode & 0o777, 0o600)
            with self.assertRaises(ValueError):
                store.write(b"x" * 4097)
            with self.assertRaises(ValueError):
                store.write(b"x", operation_bytes=8192)
            with self.assertRaises(ValueError):
                store.read("qualys-page-v1/../secrets")

    def test_private_evidence_store_rejects_symlinked_directory_ancestor(self):
        with tempfile.TemporaryDirectory() as directory:
            real = Path(directory) / "real"
            (real / "private").mkdir(parents=True)
            alias = Path(directory) / "alias"
            alias.symlink_to(real, target_is_directory=True)
            store = PrivateEvidenceStore(alias / "private")
            with self.assertRaises(OSError):
                store.write(b"private")

    def test_two_page_walk_preserves_order_and_fences_each_request(self):
        responses = [PAGE, LAST_PAGE]
        requests, fences = [], []
        def transport(request, timeout, deadline):
            requests.append(request.full_url)
            return 200, responses.pop(0), {}
        client = QualysVMClient("us1", _transport=transport)
        pages = list(client.iter_pages(credential_scope=credential_scope_factory(),
            before_request=lambda: fences.append("checked")))
        self.assertEqual([page.parsed.host_count for page in pages], [1, 1])
        self.assertEqual([page.parsed.detections[0].host_id for page in pages], ["42", "43"])
        self.assertEqual(len(fences), 2)
        self.assertEqual(parse_qsl(urlsplit(requests[0]).query),
                         [("action", "list"), ("show_igs", "1"),
                          ("status", "New,Active,Re-Opened,Fixed"),
                          ("truncation_limit", "10000")])
        self.assertIn("id_min=43", requests[1])
        self.assertEqual(len(requests), 2)
        self.assertNotIn("password", requests[0])

    def test_real_https_fixture_observes_v2_request_and_returns_xml(self):
        observed = []
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                observed.append((self.path, self.headers.get("Authorization"),
                                 self.headers.get("X-Requested-With")))
                self.send_response(200)
                self.send_header("Content-Type", "application/xml")
                self.send_header("Content-Length", str(len(PAGE)))
                self.end_headers()
                self.wfile.write(PAGE)
            def log_message(self, *_args):
                pass
        with local_https_server(Handler) as (server, context):
            request = Request(f"https://127.0.0.1:{server.server_port}{ENDPOINT_PATH}?action=list",
                headers={"Authorization": "Basic dXNlcjpwYXNz", "X-Requested-With": "VOLT"})
            status, body, _headers = _production_transport(request, 3,
                time.monotonic() + 3, _ssl_context=context)
        self.assertEqual(status, 200)
        self.assertEqual(parse_page(body).detections[0].qid, "1001")
        self.assertEqual(observed[0][0], ENDPOINT_PATH + "?action=list")
        self.assertEqual(observed[0][1], "Basic dXNlcjpwYXNz")
        self.assertEqual(observed[0][2], "VOLT")

    def test_production_transport_never_follows_redirect(self):
        requests = []
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                requests.append(self.path)
                self.send_response(302)
                self.send_header("Location", "http://127.0.0.1/redirect-target")
                self.send_header("Content-Length", "0")
                self.end_headers()
            def log_message(self, *_args):
                pass
        with local_https_server(Handler) as (server, context):
            request = Request(f"https://127.0.0.1:{server.server_port}/redirect")
            status, _body, _headers = _production_transport(request, 2,
                time.monotonic() + 2, _ssl_context=context)
        self.assertEqual(status, 302)
        self.assertEqual(requests, ["/redirect"])

    def test_production_transport_enforces_absolute_slow_body_deadline(self):
        class SlowHandler(BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.send_header("Content-Length", "20")
                self.end_headers()
                try:
                    for _ in range(20):
                        self.wfile.write(b"x")
                        self.wfile.flush()
                        time.sleep(0.05)
                except OSError:
                    pass
            def log_message(self, *_args):
                pass
        with local_https_server(SlowHandler) as (server, context):
            request = Request(f"https://127.0.0.1:{server.server_port}/slow")
            started = time.monotonic()
            with self.assertRaises(QualysError) as raised:
                _production_transport(request, 2, started + 0.25, _ssl_context=context)
            elapsed = time.monotonic() - started
        self.assertEqual(raised.exception.code, "deadline_exceeded")
        self.assertLess(elapsed, 1.0)


if __name__ == "__main__":
    unittest.main()
