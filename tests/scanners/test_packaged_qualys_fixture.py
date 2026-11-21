"""Real loopback TLS proof for the external server, not packaged acceptance.

Only127.0.0.1:47180 is contacted. SNI/certificate verification retain the fixed
Qualys hostname; socket creation is explicit and never performs public DNS.
"""
from contextlib import contextmanager
import hashlib
import http.client
import json
import os
from pathlib import Path
import socket
import select
import signal
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import uuid
from urllib.parse import quote

import packaged_qualys_fixture as fixture
from uvm.scanners.qualys_vm import parse_page, validate_continuation, QualysError


class PackagedQualysFixtureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix='volt-easy-qualys-https-')
        cls.root = Path(cls.temp.name)
        cls.root.chmod(0o700)
        cls.cert, cls.key = cls.root/'server.crt', cls.root/'server.key'
        cls.wrong_cert, cls.wrong_key = cls.root/'wrong.crt', cls.root/'wrong.key'
        for cert, key, name in ((cls.cert, cls.key, fixture.HOST),
                (cls.wrong_cert, cls.wrong_key, 'wrong.invalid')):
            result = subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
                '-keyout', str(key), '-out', str(cert), '-days', '1', '-subj', '/CN='+name,
                '-addext', 'subjectAltName=DNS:'+name], capture_output=True, timeout=15)
            if result.returncode:
                raise RuntimeError('fixture_test_certificate_creation_failed')
            key.chmod(0o600)
        cls.credentials = cls.root/'credentials.json'
        cls.password = 'Synthetic server fixture only 7!'
        cls.credentials.write_text(json.dumps({'username': 'synthetic-reader', 'password': cls.password}))
        cls.credentials.chmod(0o600)
        cls.authorization = fixture.load_credentials(cls.credentials)
        cls.trust = ssl.create_default_context(cafile=str(cls.cert))
        assert cls.trust.check_hostname and cls.trust.verify_mode == ssl.CERT_REQUIRED

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    @contextmanager
    def running(self, case='positive', *, wrong_leaf=False):
        events = self.root/(str(uuid.uuid4())+'.jsonl')
        server = fixture.FixtureServer(('127.0.0.1', 47180),
            cert_file=self.wrong_cert if wrong_leaf else self.cert,
            key_file=self.wrong_key if wrong_leaf else self.key,
            credentials_file=self.credentials, events_file=events, case=case)
        worker = threading.Thread(target=server.serve_forever, kwargs={'poll_interval': 0.02}, daemon=True)
        worker.start()
        try:
            yield server, events
        finally:
            server.shutdown()
            worker.join(3)
            server.server_close()
            self.assertFalse(worker.is_alive())
            self.assertFalse(server.failed)

    def connection(self, *, context=None, sni=fixture.HOST):
        raw = socket.create_connection(('127.0.0.1', 47180), timeout=2)
        try:
            tls = (context or self.trust).wrap_socket(raw, server_hostname=sni)
        except BaseException:
            raw.close()
            raise
        connection = http.client.HTTPConnection(fixture.HOST, 47180, timeout=2)
        connection.auto_open = 0  # No reconnect/public DNS, even on failed fixture input.
        connection.sock = tls
        self.addCleanup(connection.close)
        return connection

    def request(self, *, query=fixture.QUERY, path=fixture.PATH, headers=None, timeout=2):
        connection = self.connection()
        connection.sock.settimeout(timeout)
        values = {'Host': fixture.HOST, 'X-Requested-With': 'VOLT', 'Authorization': self.authorization}
        values.update(headers or {})
        connection.request('GET', path+'?'+query, headers=values)
        return connection, connection.getresponse()

    def events(self, path):
        return [json.loads(line) for line in path.read_text().splitlines()]

    def assert_safe(self, path):
        raw = path.read_text()
        for value in (self.password, 'synthetic-reader', self.authorization, 'Authorization', 'file:///'):
            self.assertNotIn(value, raw)
        for row in self.events(path):
            self.assertEqual(set(row), {'case', 'path', 'query', 'status', 'page_digest', 'auth_match'})
            self.assertIs(type(row['auth_match']), bool)
            self.assertIn(row['query'], ('', fixture.QUERY, fixture.NEXT_QUERY))
            self.assertIn(row['path'], ('', fixture.PATH))
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_positive_probe_and_two_pages_have_exact_counts_identity_and_digests(self):
        with self.running() as (server, events):
            self.assertEqual(self.events(events), [])
            _, probe = self.request()
            self.assertEqual(probe.status, 200)
            self.assertEqual(probe.read(), fixture.PAGE)
            self.assertEqual(len(self.events(events)), 1)
            bodies = []
            for query in (fixture.QUERY, fixture.NEXT_QUERY):
                _, response = self.request(query=query)
                self.assertEqual(response.status, 200)
                bodies.append(response.read())
            self.assertEqual(len(self.events(events)), 3)
            pages = [parse_page(body) for body in bodies]
            rows = [row for page in pages for row in page.detections]
            self.assertEqual(len(rows), 3)
            self.assertEqual({row.qid for row in rows}, {'1001'})
            self.assertEqual([page.host_ids for page in pages], [('42',), ('43',)])
            self.assertEqual([row['page_digest'] for row in self.events(events)],
                [hashlib.sha256(body).hexdigest() for body in (fixture.PAGE, *bodies)])
            self.assert_safe(events)

    def test_auth_host_query_headers_and_unknown_paths_reject_without_secret_echo(self):
        with self.running() as (_, events):
            for options, expected in (({'headers': {'Authorization': 'Basic invalid'}}, 401),
                    ({'headers': {'Host': 'wrong.invalid'}}, 400),
                    ({'headers': {'X-Requested-With': 'wrong'}}, 400),
                    ({'query': fixture.QUERY+'&password='+quote(self.password, safe='')}, 400),
                    ({'query': fixture.QUERY+'&action=list'}, 400),
                    ({'path': '/'+self.password.replace(' ', '-')}, 400)):
                _, response = self.request(**options)
                self.assertEqual(response.status, expected)
                self.assertEqual(response.read(), b'')
            self.assertFalse(self.events(events)[0]['auth_match'])
            self.assert_safe(events)

    def test_normal_tls_verification_rejects_untrusted_wrong_leaf_and_wrong_sni(self):
        with self.running() as (_, events):
            with self.assertRaises(ssl.SSLError):
                self.connection(context=ssl.create_default_context())
            with self.assertRaises(ssl.SSLError):
                self.connection(sni='wrong.invalid')
            self.assertEqual(self.events(events), [])
        trusted_wrong = ssl.create_default_context(cafile=str(self.wrong_cert))
        with self.running(wrong_leaf=True) as (_, events):
            with self.assertRaises(ssl.SSLCertVerificationError):
                self.connection(context=trusted_wrong)
            self.assertEqual(self.events(events), [])

    def test_status_redirect_and_page_two_failure_are_fixed_and_counted(self):
        for case, status in (('unauthorized', 401), ('forbidden', 403), ('throttled', 429), ('redirect', 302)):
            with self.subTest(case=case), self.running(case) as (_, events):
                _, response = self.request()
                self.assertEqual(response.status, status)
                if case == 'throttled':
                    self.assertEqual(response.getheader('Retry-After'), '1')
                if case == 'redirect':
                    self.assertEqual(response.getheader('Location'), 'https://foreign.invalid/forbidden')
                self.assertEqual(response.read(), b'')
                self.assertEqual(len(self.events(events)), 1)
                self.assert_safe(events)
        with self.running('page2_failure') as (_, events):
            _, first = self.request()
            self.assertEqual(first.read(), fixture.PAGE)
            _, second = self.request(query=fixture.NEXT_QUERY)
            self.assertEqual(second.status, 503)
            self.assertEqual(second.read(), b'')
            self.assertEqual(len(self.events(events)), 2)

    def test_xml_and_continuation_negative_bytes_reach_real_parser(self):
        for case in ('malformed', 'entity', 'deep'):
            with self.subTest(case=case), self.running(case) as (_, events):
                _, response = self.request()
                with self.assertRaises(QualysError):
                    parse_page(response.read())
                self.assert_safe(events)
        for case in ('cyclic', 'regressive'):
            with self.subTest(case=case), self.running(case):
                _, response = self.request(query=fixture.NEXT_QUERY if case == 'cyclic' else fixture.QUERY)
                page = parse_page(response.read())
                with self.assertRaises(QualysError):
                    validate_continuation(page.continuation, origin='https://'+fixture.HOST,
                        previous_id_min='43' if case == 'cyclic' else None, returned_host_ids=page.host_ids)

    def test_chunked_truncated_oversize_and_slow_body_use_real_tls(self):
        with self.running('chunked') as (_, events):
            _, response = self.request()
            self.assertEqual(response.getheader('Transfer-Encoding'), 'chunked')
            self.assertEqual(response.read(), fixture.PAGE)
            self.assert_safe(events)
        for case in ('truncated', 'oversize'):
            with self.subTest(case=case), self.running(case):
                _, response = self.request()
                if case == 'oversize':
                    self.assertEqual(int(response.getheader('Content-Length')), 10*1024*1024+1)
                with self.assertRaises(http.client.IncompleteRead):
                    response.read()
        with self.running('slow_body'):
            connection, response = self.request(timeout=0.08)
            began = time.monotonic()
            try:
                with self.assertRaises((TimeoutError, OSError)):
                    response.read(2)
                self.assertLess(time.monotonic()-began, 1)
            finally:
                response.close()
                connection.close()

    def test_private_inputs_safe_cli_errors_and_exclusive_threadsafe_events(self):
        bad = self.root/'bad.json'
        bad.write_text(json.dumps({'username': 'synthetic-reader', 'password': self.password, 'extra': True}))
        bad.chmod(0o600)
        with self.assertRaisesRegex(fixture.FixtureInputError, '^fixture_input_invalid$'):
            fixture.load_credentials(bad)
        bad.write_text('{"username":"a","username":"b","password":"secret"}')
        with self.assertRaises(fixture.FixtureInputError):
            fixture.load_credentials(bad)
        bad.chmod(0o644)
        with self.assertRaises(fixture.FixtureInputError):
            fixture.load_credentials(bad)
        link = self.root/'link.json'
        link.symlink_to(self.credentials)
        with self.assertRaises(fixture.FixtureInputError):
            fixture.load_credentials(link)
        result = subprocess.run([sys.executable, str(Path(fixture.__file__).resolve()), '--case', self.password],
            capture_output=True, text=True, timeout=3)
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stderr, 'qualys_fixture_arguments_invalid\n')
        self.assertNotIn(self.password, result.stdout+result.stderr)
        path = self.root/(str(uuid.uuid4())+'.jsonl')
        log = fixture.EventLog(path)
        def append():
            for _ in range(8):
                log.append(case='positive', path=fixture.PATH, query=fixture.QUERY,
                    status=200, page_digest=None, auth_match=True)
        workers = [threading.Thread(target=append) for _ in range(4)]
        for worker in workers: worker.start()
        for worker in workers: worker.join(2)
        self.assertEqual(log.count, 32)
        log.close()
        self.assertEqual(len(self.events(path)), 32)
        with self.assertRaises(FileExistsError):
            fixture.EventLog(path)
        self.assert_safe(path)

    def test_exact_cli_serves_verified_https_and_exits_without_secret_output(self):
        events = self.root/(str(uuid.uuid4())+'.jsonl')
        command = [sys.executable, str(Path(fixture.__file__).resolve()), '--bind', '127.0.0.1',
            '--port', '47180', '--cert-file', str(self.cert), '--key-file', str(self.key),
            '--credentials-file', str(self.credentials), '--events-file', str(events), '--case', 'positive']
        child = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            self.assertTrue(select.select([child.stdout], [], [], 3)[0])
            self.assertEqual(child.stdout.readline(), 'qualys_fixture_ready\n')
            _, response = self.request()
            self.assertEqual(response.status, 200)
            self.assertEqual(response.read(), fixture.PAGE)
            child.send_signal(signal.SIGINT)
            out, err = child.communicate(timeout=3)
            self.assertEqual(child.returncode, 0)
            self.assertEqual((out, err), ('', ''))
            self.assertEqual(len(self.events(events)), 1)
            self.assert_safe(events)
        finally:
            if child.poll() is None:
                child.terminate()
                child.communicate(timeout=3)

    def test_header_input_is_bounded_and_unsupported_method_has_safe_record(self):
        with self.running() as (_, events):
            connection = self.connection()
            connection.request('GET', fixture.PATH+'?'+fixture.QUERY,
                headers={'Host': fixture.HOST, 'X-Large': 'x'*9000})
            try:
                response = connection.getresponse()
                self.assertIn(response.status, (400, 431))
            except (http.client.RemoteDisconnected, ConnectionResetError):
                pass
            connection = self.connection()
            connection.request('POST', '/private-marker', body='private-body-marker')
            response = connection.getresponse()
            self.assertEqual(response.status, 501)
            self.assertEqual(response.read(), b'')
            self.assertNotIn('private-marker', events.read_text())
            self.assertNotIn('private-body-marker', events.read_text())
            self.assert_safe(events)
