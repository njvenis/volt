"""Review regressions exercise the actual TLS transport, without replacing it."""
from __future__ import annotations

from http.server import BaseHTTPRequestHandler
import time
import unittest
from urllib.request import Request
from urllib.parse import parse_qsl, urlsplit

from test_qualys_vm_protocol import (PAGE, LAST_PAGE, credential_scope_factory,
    local_https_server)
from uvm.scanners.qualys_vm import (ENDPOINT_PATH, MAX_PAGE_BYTES, PLATFORM_ORIGINS,
    QualysError, QualysVMClient, _production_transport, validate_continuation)


class QualysReviewRegressions(unittest.TestCase):
    def test_inclusive_minimum_can_advance_above_last_host(self):
        value = (PLATFORM_ORIGINS['us1'] + ENDPOINT_PATH +
            '?action=list&show_igs=1&status=New%2CActive%2CRe-Opened%2CFixed'
            '&truncation_limit=10000&id_min=50')
        self.assertIn('id_min=50', validate_continuation(value,
            origin=PLATFORM_ORIGINS['us1'], previous_id_min='40',
            returned_host_ids=('42',)))

    def test_host_equal_to_current_minimum_is_included(self):
        responses = [PAGE.replace(b'id_min=43', b'id_min=50'),
            LAST_PAGE.replace(b'<ID>43</ID>', b'<ID>50</ID>')]
        client = QualysVMClient('us1', _transport=lambda *_: (200, responses.pop(0), {}))
        pages = list(client.iter_pages(credential_scope=credential_scope_factory()))
        self.assertEqual(pages[1].parsed.host_ids, ('50',))

    def test_every_host_must_meet_current_request_minimum(self):
        first = PAGE.replace(b'id_min=43', b'id_min=50')
        responses = [first, LAST_PAGE]  # host 43 violates current bound 50
        client = QualysVMClient('us1', _transport=lambda *_: (200, responses.pop(0), {}))
        with self.assertRaisesRegex(QualysError, 'pagination_progress_invalid'):
            list(client.iter_pages(credential_scope=credential_scope_factory()))

    def test_all_types_share_one_traversal(self):
        calls = []
        body = LAST_PAGE.replace(b'</DETECTION_LIST>',
            b'<DETECTION><QID>2002</QID><TYPE>Potential</TYPE></DETECTION>'
            b'<DETECTION><QID>45097</QID><TYPE>Information Gathered</TYPE></DETECTION>'
            b'</DETECTION_LIST>')
        def transport(request, *_):
            calls.append(request.full_url)
            return 200, body, {}
        pages = list(QualysVMClient('us1', _transport=transport).iter_pages(
            credential_scope=credential_scope_factory()))
        self.assertEqual(len(calls), 1)
        self.assertEqual(len(pages[0].parsed.detections), 3)
        params = dict(parse_qsl(urlsplit(calls[0]).query))
        self.assertEqual(params['show_igs'], '1')
        self.assertNotIn('include_vuln_type', params)

    def exchange(self, reply, *, deadline=2):
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                try:
                    reply(self)
                except OSError:
                    pass
            def log_message(self, *_args):
                pass
        with local_https_server(Handler) as (server, context):
            request = Request(f'https://127.0.0.1:{server.server_port}/fixture')
            return _production_transport(request, 3, time.monotonic() + deadline,
                _ssl_context=context)

    def test_declared_oversize_fails_even_when_prefix_is_valid_xml(self):
        def reply(handler):
            handler.send_response(200)
            handler.send_header('Content-Length', str(MAX_PAGE_BYTES + 1))
            handler.end_headers()
            handler.wfile.write(LAST_PAGE)
        with self.assertRaisesRegex(QualysError, 'response_too_large'):
            self.exchange(reply)

    def test_chunked_body_is_decoded_and_trailers_are_not_evidence(self):
        def reply(handler):
            handler.protocol_version = 'HTTP/1.1'
            handler.send_response(200)
            handler.send_header('Transfer-Encoding', 'chunked')
            handler.end_headers()
            for chunk in (LAST_PAGE[:25], LAST_PAGE[25:]):
                handler.wfile.write(f'{len(chunk):x};vendor=extension\r\n'.encode()
                    + chunk + b'\r\n')
            handler.wfile.write(b'0\r\nX-Page-End: yes\r\n\r\n')
        status, body, _ = self.exchange(reply)
        self.assertEqual(status, 200)
        self.assertEqual(body, LAST_PAGE)

    def test_chunked_decoded_size_is_bounded(self):
        def reply(handler):
            handler.send_response(200)
            handler.send_header('Transfer-Encoding', 'chunked')
            handler.end_headers()
            chunk = b'x' * 65536
            for _ in range(MAX_PAGE_BYTES // len(chunk) + 1):
                handler.wfile.write(b'10000\r\n' + chunk + b'\r\n')
            handler.wfile.write(b'0\r\n\r\n')
        with self.assertRaisesRegex(QualysError, 'response_too_large'):
            self.exchange(reply)

    def test_chunked_dribble_obeys_absolute_deadline(self):
        def reply(handler):
            handler.send_response(200)
            handler.send_header('Transfer-Encoding', 'chunked')
            handler.end_headers()
            for _ in range(40):
                handler.wfile.write(b'1\r\nx\r\n')
                handler.wfile.flush()
                time.sleep(.03)
        with self.assertRaisesRegex(QualysError, 'deadline_exceeded'):
            self.exchange(reply, deadline=.2)

    def test_conflicting_lengths_and_incomplete_chunks_fail_closed(self):
        for framing in (b'Content-Length: 1\r\nContent-Length: 2\r\n\r\nx',
                        b'Transfer-Encoding: chunked\r\n\r\n5\r\nxx'):
            with self.subTest(framing=framing):
                def reply(handler):
                    handler.wfile.write(b'HTTP/1.1 200 OK\r\n' + framing)
                with self.assertRaises(QualysError):
                    self.exchange(reply)
