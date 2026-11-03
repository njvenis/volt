import base64
import contextlib
import email.message
import io
import json
import os
import sys
import urllib.error
import urllib.request
import urllib.response
from pathlib import Path
from unittest.mock import patch
import unittest

sys.path.insert(0, str(Path(__file__).parents[2] / "tools" / "release"))
import registry


class Response:
    def __init__(self, data=b'{"token":"fixture"}', headers=None):
        self.data = data
        self.headers = headers or {}
    def __enter__(self): return self
    def __exit__(self, *args): return False
    def read(self): return self.data


class RegistryCollisionTests(unittest.TestCase):
    def test_authenticated_token_exchange_and_manifest_request(self):
        calls = []
        def opener(request, timeout):
            calls.append(request)
            if len(calls) == 1:
                expected = "Basic " + base64.b64encode(b"actor:secret-token").decode()
                self.assertEqual(request.headers["Authorization"], expected)
                self.assertEqual(request.full_url.split("?")[0], "https://ghcr.io/token")
                return Response()
            self.assertEqual(request.headers["Authorization"], "Bearer fixture")
            return Response(b"", {"Docker-Content-Digest": "sha256:" + "f" * 64})
        self.assertEqual(registry.tag_digest("0.1.0-rc.1", opener, username="actor", password="secret-token"), "sha256:" + "f" * 64)
        self.assertEqual(len(calls), 2)

    def test_only_authoritative_manifest_404_is_absent(self):
        calls = 0
        def opener(request, timeout):
            nonlocal calls
            calls += 1
            if calls == 1: return Response()
            raise urllib.error.HTTPError(request.full_url, 404, "absent", {}, None)
        self.assertTrue(registry.unused_tag("0.1.0-rc.1", opener, username="actor", password="secret"))
        for code in (401, 403, 500):
            calls = 0
            def denied(request, timeout):
                nonlocal calls
                calls += 1
                if calls == 1: return Response()
                raise urllib.error.HTTPError(request.full_url, code, "denied", {}, None)
            with self.assertRaisesRegex(RuntimeError, f"HTTP {code}"):
                registry.unused_tag("0.1.0-rc.1", denied, username="actor", password="secret")

    def test_token_denial_does_not_leak_credential(self):
        def denied(request, timeout):
            raise urllib.error.HTTPError(request.full_url, 403, "denied", {}, None)
        with self.assertRaises(RuntimeError) as caught:
            registry.unused_tag("0.1.0-rc.1", denied, username="actor", password="secret-token")
        self.assertNotIn("secret-token", str(caught.exception))
        self.assertIn("HTTP 403", str(caught.exception))

    def test_network_and_ambiguous_token_responses_fail_closed(self):
        calls = 0
        def offline(request, timeout):
            nonlocal calls
            calls += 1
            if calls == 1: return Response()
            raise urllib.error.URLError("temporary DNS failure")
        with self.assertRaisesRegex(RuntimeError, "network error"):
            registry.unused_tag("0.1.0-rc.1", offline, username="actor", password="secret")
        for data in (b"not-json", b"{}"):
            def ambiguous(request, timeout): return Response(data)
            with self.assertRaises(RuntimeError):
                registry.unused_tag("0.1.0-rc.1", ambiguous, username="actor", password="secret")

    def test_redirect_handler_refuses_redirect(self):
        handler = registry.NoRedirect()
        req = type("Request", (), {"full_url": "https://ghcr.io/token"})()
        with self.assertRaises(urllib.error.HTTPError) as caught:
            handler.redirect_request(req, None, 302, "Found", {}, "https://example.invalid/token")
        self.assertIn("redirect refused", str(caught.exception))

    def test_anonymous_path_is_distinct_and_sends_no_basic_credentials(self):
        calls = []
        def opener(request, timeout):
            calls.append(request)
            if len(calls) == 1:
                self.assertNotIn("Authorization", request.headers)
                return Response()
            self.assertEqual(request.headers["Authorization"], "Bearer fixture")
            return Response(b"")
        self.assertFalse(registry.unused_tag("0.1.0-rc.1", opener, anonymous=True))
        self.assertEqual(len(calls), 2)

    def test_cli_requires_credentials_for_authenticated_preflight(self):
        env = {key: os.environ.get(key) for key in ("GITHUB_ACTOR", "GH_TOKEN")}
        try:
            os.environ.pop("GITHUB_ACTOR", None); os.environ.pop("GH_TOKEN", None)
            argv = ["registry.py", "--version-tag", "0.1.0-rc.1", "--sha-tag", "sha-" + "a" * 40]
            with patch.object(sys, "argv", argv):
                self.assertEqual(registry.main(), 2)
        finally:
            for key, value in env.items():
                if value is None: os.environ.pop(key, None)
                else: os.environ[key] = value

    def test_expected_digest_check_reads_both_tags_and_rejects_mismatch(self):
        expected = "sha256:" + "f" * 64; observed = []
        def digest(tag, **kwargs): observed.append(tag); return expected
        argv = ["registry.py", "--version-tag", "0.1.0-rc.1", "--sha-tag", "sha-" + "a" * 40, "--expected-digest", expected]
        with patch.dict(os.environ, {"GITHUB_ACTOR": "actor", "GH_TOKEN": "secret"}), patch.object(registry, "tag_digest", side_effect=digest), patch.object(sys, "argv", argv):
            self.assertEqual(registry.main(), 0)
        self.assertEqual(observed, ["0.1.0-rc.1", "sha-" + "a" * 40])
        argv[-1] = "sha256:" + "e" * 64
        with patch.dict(os.environ, {"GITHUB_ACTOR": "actor", "GH_TOKEN": "secret"}), patch.object(registry, "tag_digest", return_value=expected), patch.object(sys, "argv", argv):
            self.assertEqual(registry.main(), 2)

    def test_workflow_authenticates_before_registry_reads_and_keeps_public_check_explicit(self):
        workflow = (Path(__file__).parents[2] / ".github/workflows/release.yml").read_text()
        step = workflow.split("- name: Recheck exact source and immutable destination tags", 1)[1].split("\n      - name:", 1)[0]
        self.assertIn("GH_TOKEN: ${{ github.token }}", step)
        self.assertLess(step.index("env:"), step.index("python3 tools/release/registry.py"))
        self.assertIn("packages: write", workflow)
        self.assertIn("--anonymous", (Path(__file__).parents[2] / "tools/release/registry.py").read_text())
        self.assertNotIn("--anonymous", step)

    def run_default_cli(self, responses, *, anonymous=False, expected_digest=None):
        calls = []
        remaining = list(responses)

        class OfflineHTTPS(urllib.request.HTTPSHandler):
            def https_open(self, request):
                calls.append(request)
                status, payload, header_values = remaining.pop(0)
                headers = email.message.Message()
                for name, value in header_values.items():
                    headers[name] = value
                response = urllib.response.addinfourl(io.BytesIO(payload), headers, request.full_url, status)
                response.msg = "fixture response"
                return response

        argv = ["registry.py", "--version-tag", "0.1.0-rc.1", "--sha-tag", "sha-" + "a" * 40]
        if anonymous:
            argv.append("--anonymous")
        if expected_digest:
            argv.extend(["--expected-digest", expected_digest])
        stdout, stderr = io.StringIO(), io.StringIO()
        with patch.dict(os.environ, {"GITHUB_ACTOR": "actor", "GH_TOKEN": "fixture"}, clear=True), \
             patch.object(sys, "argv", argv), \
             patch.object(urllib.request, "HTTPSHandler", OfflineHTTPS), \
             patch("http.client.HTTPSConnection.connect", side_effect=AssertionError("unexpected network")), \
             contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            result = registry.main()
        return result, calls, stdout.getvalue(), stderr.getvalue()

    def test_real_default_opener_runs_authenticated_and_anonymous_cli(self):
        token = (200, b'{"token":"fixture"}', {})
        absent = (404, b"", {})
        for anonymous in (False, True):
            with self.subTest(anonymous=anonymous):
                result, calls, _, stderr = self.run_default_cli([token, absent, token, absent], anonymous=anonymous)
                self.assertEqual(result, 0, stderr)
                self.assertEqual(len(calls), 4)
                for request in calls[::2]:
                    expected = None if anonymous else "Basic " + base64.b64encode(b"actor:fixture").decode()
                    self.assertEqual(request.get_header("Authorization"), expected)
                self.assertTrue(all(request.full_url.startswith("https://ghcr.io/") for request in calls))

    def test_real_default_opener_checks_digest_and_refuses_denials_or_redirects(self):
        token = (200, b'{"token":"fixture"}', {})
        digest = "sha256:" + "f" * 64
        present = (200, b"", {"Docker-Content-Digest": digest})
        result, _, _, stderr = self.run_default_cli([token, present, token, present], expected_digest=digest)
        self.assertEqual(result, 0, stderr)
        for status in (401, 403, 500, 301, 302, 303, 307, 308):
            for endpoint in ("token", "manifest"):
                with self.subTest(status=status, endpoint=endpoint):
                    rejected = (status, b"", {"Location": "https://example.invalid/credential-target"})
                    responses = [rejected] if endpoint == "token" else [token, rejected]
                    result, calls, stdout, stderr = self.run_default_cli(responses)
                    self.assertEqual(result, 2)
                    self.assertTrue(all(request.full_url.startswith("https://ghcr.io/") for request in calls))
                    self.assertNotIn("Traceback", stdout + stderr)

    def test_malformed_bearer_is_rejected_without_credential_diagnostics(self):
        sentinel = "credential-sentinel"
        for token in (sentinel + "\r\nbad", sentinel + "\x00", sentinel + "\u2603", ""):
            with self.subTest(kind=repr(token[-4:])):
                payload = json.dumps({"token": token}).encode()
                result, calls, stdout, stderr = self.run_default_cli([(200, payload, {})])
                self.assertEqual(result, 2)
                self.assertEqual(len(calls), 1)
                self.assertNotIn(sentinel, stdout + stderr)
                self.assertNotIn(base64.b64encode(b"actor:fixture").decode(), stdout + stderr)
                self.assertNotIn("Traceback", stdout + stderr)


if __name__ == "__main__":
    unittest.main()
