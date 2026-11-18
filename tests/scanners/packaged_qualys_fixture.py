"""External qualification-only HTTPS server. No VOLT imports or control routes.

Read-only TLS/input directories: server-euid-owned0700, key/credentials0400 or
0600. A separate writable0700 directory receives NEW0600 JSONL events. Nonroot
container mappings must preserve these owners; only the server receives its leaf
key. Delivery owns CA signing, image admission, internal DNS/network and egress.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import http.client
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import os
from pathlib import Path
import socket
import ssl
import stat
import sys
import threading
import time
from urllib.parse import parse_qsl, urlencode, urlsplit

HOST = 'qualysapi.qualys.com'
PATH = '/api/2.0/fo/asset/host/vm/detection/'
PARAMS = {'action': 'list', 'show_igs': '1', 'status': 'New,Active,Re-Opened,Fixed', 'truncation_limit': '10000'}
QUERY = urlencode(sorted(PARAMS.items()))
NEXT_QUERY = urlencode(sorted(dict(PARAMS, id_min='43').items()))
NEXT_URL = f'https://{HOST}{PATH}?{NEXT_QUERY}'.replace('&', '&amp;')
PAGE = ('''<?xml version="1.0"?>
<!DOCTYPE HOST_LIST_VM_DETECTION_OUTPUT SYSTEM "https://never-fetch.invalid/out.dtd">
<HOST_LIST_VM_DETECTION_OUTPUT><RESPONSE><HOST_LIST><HOST><ID>42</ID>
<DETECTION_LIST><DETECTION><QID>1001</QID><TYPE>Confirmed</TYPE><SEVERITY>5</SEVERITY>
<STATUS>Active</STATUS><PORT>443</PORT><PROTOCOL>tcp</PROTOCOL><SSL>1</SSL>
<UNIQUE_VULN_ID>instance-a</UNIQUE_VULN_ID><LAST_FOUND_DATETIME>2026-01-01T01:00:00Z</LAST_FOUND_DATETIME>
</DETECTION><DETECTION><QID>1001</QID><TYPE>Confirmed</TYPE><PORT>53</PORT>
<PROTOCOL>udp</PROTOCOL></DETECTION></DETECTION_LIST></HOST></HOST_LIST>
<WARNING><CODE>1980</CODE><URL>''' + NEXT_URL + '''</URL></WARNING>
</RESPONSE></HOST_LIST_VM_DETECTION_OUTPUT>''').encode()
LAST_PAGE = b'''<HOST_LIST_VM_DETECTION_OUTPUT><RESPONSE><HOST_LIST><HOST><ID>43</ID>
<DETECTION_LIST><DETECTION><QID>1001</QID><TYPE>Confirmed</TYPE><PORT>443</PORT>
<PROTOCOL>tcp</PROTOCOL></DETECTION></DETECTION_LIST></HOST></HOST_LIST></RESPONSE>
</HOST_LIST_VM_DETECTION_OUTPUT>'''
CASES = ('positive', 'unauthorized', 'forbidden', 'throttled', 'redirect', 'malformed',
    'entity', 'deep', 'cyclic', 'regressive', 'oversize', 'chunked', 'truncated', 'slow_body', 'page2_failure')
MAX_REQUESTS = 256


class FixtureInputError(ValueError):
    """Fixed safe exception; private file contents never enter messages."""


def _safe_path(path, *, private=False, parent_private=False):
    path = Path(path).absolute()
    if any(part.is_symlink() for part in (path, *path.parents)):
        raise FixtureInputError('fixture_input_invalid')
    if parent_private:
        parent = path.parent.stat()
        if parent.st_uid != os.geteuid() or stat.S_IMODE(parent.st_mode) != 0o700:
            raise FixtureInputError('fixture_input_invalid')
    if private:
        value = path.stat()
        if (not stat.S_ISREG(value.st_mode) or value.st_uid != os.geteuid()
                or stat.S_IMODE(value.st_mode) not in (0o400, 0o600)):
            raise FixtureInputError('fixture_input_invalid')
    return path


def _open_input(path, *, private=False):
    path = _safe_path(path, private=private, parent_private=private)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        value = os.fstat(fd)
        if (not stat.S_ISREG(value.st_mode) or value.st_size > 16384
                or private and (value.st_uid != os.geteuid() or stat.S_IMODE(value.st_mode) not in (0o400, 0o600))):
            raise FixtureInputError('fixture_input_invalid')
        return fd
    except BaseException:
        os.close(fd)
        raise


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise FixtureInputError('fixture_input_invalid')
        result[key] = value
    return result


def load_credentials(path):
    fd = _open_input(path, private=True)
    try:
        body = os.read(fd, 16385)
        value = json.loads(body, object_pairs_hook=_unique)
        if not isinstance(value, dict) or set(value) != {'username', 'password'}:
            raise FixtureInputError('fixture_input_invalid')
        username, password = value['username'], value['password']
        if (type(username) is not str or type(password) is not str
                or not 1 <= len(username.encode()) <= 256 or ':' in username
                or not 1 <= len(password.encode()) <= 1024
                or any(ord(c) < 32 or ord(c) == 127 for c in username + password)):
            raise FixtureInputError('fixture_input_invalid')
        return 'Basic ' + base64.b64encode((username + ':' + password).encode()).decode('ascii')
    except (ValueError, UnicodeError):
        raise FixtureInputError('fixture_input_invalid') from None
    finally:
        os.close(fd)


class EventLog:
    def __init__(self, path):
        path = _safe_path(path, parent_private=True)
        self.fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        os.fchmod(self.fd, 0o600)
        self.lock = threading.Lock()
        self.count = 0

    def append(self, *, case, path, query, status, page_digest, auth_match):
        with self.lock:
            if self.count >= MAX_REQUESTS:
                raise FixtureInputError('fixture_request_limit')
            body = (json.dumps(dict(case=case, path=path, query=query, status=status,
                page_digest=page_digest, auth_match=auth_match), separators=(',', ':')) + '\n').encode()
            while body:
                written = os.write(self.fd, body)
                if written <= 0:
                    raise OSError('fixture_io_failure')
                body = body[written:]
            os.fsync(self.fd)
            self.count += 1

    def close(self):
        with self.lock:
            if self.fd is not None:
                os.close(self.fd)
                self.fd = None


class _HeaderReader:
    def __init__(self, raw):
        self.raw, self.remaining = raw, 16384

    def readline(self, size=-1):
        line = self.raw.readline(min(8193, self.remaining + 1, size if size >= 0 else 8193))
        self.remaining -= len(line)
        if self.remaining < 0 or len(line) > 8192:
            raise http.client.LineTooLong('fixture_header_limit')
        return line

    def __getattr__(self, name):
        return getattr(self.raw, name)


class FixtureServer(HTTPServer):
    allow_reuse_address = True
    request_queue_size = 8

    def __init__(self, address, *, cert_file, key_file, credentials_file, events_file, case='positive'):
        if address[0] not in ('127.0.0.1', '0.0.0.0') or address[1] not in (443, 47180) or case not in CASES:
            raise FixtureInputError('fixture_input_invalid')
        self.case = case
        self.authorization = load_credentials(credentials_file)
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.context.minimum_version = ssl.TLSVersion.TLSv1_2
        cert_fd = key_fd = None
        try:
            cert_fd = _open_input(cert_file)
            key_fd = _open_input(key_file, private=True)
            # Fixed open descriptors avoid reopening replaceable input paths.
            self.context.load_cert_chain(f'/proc/self/fd/{cert_fd}', f'/proc/self/fd/{key_fd}', password='')
        finally:
            if cert_fd is not None:
                os.close(cert_fd)
            if key_fd is not None:
                os.close(key_fd)
        self.context.set_servername_callback(self._sni)
        self.events = EventLog(events_file)
        self.failed = False
        try:
            super().__init__(address, _Handler)
        except BaseException:
            self.events.close()
            raise

    @staticmethod
    def _sni(sock, name, context):
        # Returning a TLS alert avoids Python callback exception diagnostics.
        if name != HOST:
            return ssl.ALERT_DESCRIPTION_UNRECOGNIZED_NAME

    def get_request(self):
        raw, address = super().get_request()
        try:
            if self.events.count >= MAX_REQUESTS:
                raise OSError('fixture_request_limit')
            raw.settimeout(2)
            return self.context.wrap_socket(raw, server_side=True), address
        except BaseException:
            raw.close()
            raise

    def handle_error(self, request, client_address):
        # Never emit request headers, credentials, client data or raw exceptions.
        pass

    def server_close(self):
        super().server_close()
        if hasattr(self, 'events'):
            self.events.close()


class _Handler(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'

    def log_message(self, *args):
        pass

    def handle_one_request(self):
        self.rfile = _HeaderReader(self.rfile)
        try:
            super().handle_one_request()
        finally:
            self.close_connection = True

    def send_error(self, code, message=None, explain=None):
        self._respond(code, b'', path='', query='', authenticated=False)

    def _respond(self, status, body, *, path, query, authenticated, headers=None, mode=None):
        try:
            self.server.events.append(case=self.server.case, path=path, query=query,
                status=status, page_digest=hashlib.sha256(body).hexdigest() if body else None,
                auth_match=authenticated)
        except (OSError, FixtureInputError):
            self.server.failed = True
            threading.Thread(target=self.server.shutdown, daemon=True).start()
            return
        self.send_response_only(status)
        self.send_header('Connection', 'close')
        self.send_header('Content-Type', 'application/xml')
        for name, value in (headers or {}).items():
            self.send_header(name, value)
        if mode == 'chunked':
            self.send_header('Transfer-Encoding', 'chunked')
        else:
            self.send_header('Content-Length', str(10 * 1024 * 1024 + 1 if mode == 'oversize'
                else len(body) + 40 if mode == 'truncated' else len(body)))
        self.end_headers()
        if mode == 'oversize':
            return
        if mode == 'chunked':
            for chunk in (body[:31], body[31:]):
                self.wfile.write(f'{len(chunk):X}\r\n'.encode() + chunk + b'\r\n')
            self.wfile.write(b'0\r\n\r\n')
        elif mode == 'slow_body':
            for octet in body[:175]:  # At most35s; production attempt deadline is30s.
                self.wfile.write(bytes((octet,)))
                self.wfile.flush()
                time.sleep(0.2)
        else:
            self.wfile.write(body)
        self.wfile.flush()

    def do_GET(self):
        authenticated = (len(self.headers.get_all('Authorization', [])) == 1
            and hmac.compare_digest(self.headers.get('Authorization', '').encode(), self.server.authorization.encode()))
        try:
            parsed = urlsplit(self.path)
            pairs = parse_qsl(parsed.query, keep_blank_values=True, strict_parsing=True, max_num_fields=5)
            params = dict(pairs)
            valid = (not parsed.scheme and not parsed.netloc and not parsed.fragment and parsed.path == PATH
                and len(pairs) == len(params) and params in (PARAMS, dict(PARAMS, id_min='43')))
        except ValueError:
            valid = False
        if not valid:
            return self._respond(400, b'', path='', query='', authenticated=authenticated)
        query = NEXT_QUERY if 'id_min' in params else QUERY
        hosts = self.headers.get_all('Host', [])
        if (hosts != [HOST] or self.headers.get_all('X-Requested-With', []) != ['VOLT']
                or self.headers.get('Content-Length', '0') != '0' or self.headers.get('Transfer-Encoding') is not None):
            return self._respond(400, b'', path=PATH, query=query, authenticated=authenticated)
        if not authenticated:
            return self._respond(401, b'', path=PATH, query=query, authenticated=False)
        case, second = self.server.case, 'id_min' in params
        status, body, headers, mode = 200, LAST_PAGE if second else PAGE, {}, None
        if case in ('unauthorized', 'forbidden', 'throttled'):
            status, body = {'unauthorized': 401, 'forbidden': 403, 'throttled': 429}[case], b''
            if case == 'throttled':
                headers = {'Retry-After': '1'}
        elif case == 'redirect':
            status, body, headers = 302, b'', {'Location': 'https://foreign.invalid/forbidden'}
        elif case == 'page2_failure' and second:
            status, body = 503, b''
        elif case == 'malformed':
            body = b'<HOST_LIST_VM_DETECTION_OUTPUT><broken>'
        elif case == 'entity':
            body = b'<!DOCTYPE HOST_LIST_VM_DETECTION_OUTPUT [<!ENTITY x SYSTEM "file:///never-read">]><HOST_LIST_VM_DETECTION_OUTPUT>&x;</HOST_LIST_VM_DETECTION_OUTPUT>'
        elif case == 'deep':
            body = b'<HOST_LIST_VM_DETECTION_OUTPUT>' + b'<X>' * 80 + b'</X>' * 80 + b'</HOST_LIST_VM_DETECTION_OUTPUT>'
        elif case == 'regressive':
            body = PAGE.replace(b'id_min=43', b'id_min=41')
        elif case == 'cyclic' and second:
            warning = ('<WARNING><CODE>1980</CODE><URL>' + NEXT_URL + '</URL></WARNING>').encode()
            body = LAST_PAGE.replace(b'</RESPONSE>', warning + b'</RESPONSE>')
        elif case in ('oversize', 'chunked', 'truncated', 'slow_body'):
            mode = case
        self._respond(status, body, path=PATH, query=query, authenticated=True, headers=headers, mode=mode)


class _SafeParser(argparse.ArgumentParser):
    def error(self, message):
        self.exit(2, 'qualys_fixture_arguments_invalid\n')


def main(argv=None):
    parser = _SafeParser(description=__doc__)
    parser.add_argument('--bind', choices=('127.0.0.1', '0.0.0.0'), default='127.0.0.1')
    parser.add_argument('--port', type=int, choices=(443, 47180), default=47180)
    for name in ('cert-file', 'key-file', 'credentials-file', 'events-file'):
        parser.add_argument('--' + name, required=True)
    parser.add_argument('--case', choices=CASES, default='positive')
    args = parser.parse_args(argv)
    try:
        with FixtureServer((args.bind, args.port), cert_file=args.cert_file, key_file=args.key_file,
                credentials_file=args.credentials_file, events_file=args.events_file, case=args.case) as server:
            print('qualys_fixture_ready', flush=True)
            server.serve_forever(poll_interval=0.1)
            return 1 if server.failed else 0
    except (OSError, ValueError):
        print('qualys_fixture_startup_failed', file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 0


if __name__ == '__main__':
    raise SystemExit(main())
