import sys
from unittest.mock import patch
import unittest
import urllib.error
from pathlib import Path

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
    def test_authoritative_404_means_unused(self):
        calls = 0
        def opener(request, timeout):
            nonlocal calls
            calls += 1
            if calls == 1: return Response()
            raise urllib.error.HTTPError("https://ghcr.io", 404, "absent", {}, None)
        self.assertTrue(registry.unused_tag("0.1.0-rc.1", opener))

    def test_existing_tag_and_network_errors_fail_closed(self):
        calls = 0
        def existing(request, timeout):
            nonlocal calls
            calls += 1
            if calls == 1: return Response()
            return Response(b"")
        self.assertFalse(registry.unused_tag("0.1.0-rc.1", existing))
        def denied(request, timeout):
            raise urllib.error.HTTPError("https://ghcr.io/token", 404, "denied", {}, None)
        with self.assertRaisesRegex(RuntimeError, "token request"):
            registry.unused_tag("0.1.0-rc.1", denied)

    def test_tag_digest_reads_distribution_digest_header(self):
        calls=[]
        def opener(request, timeout):
            calls.append(request)
            if len(calls)==1: return Response()
            return Response(b"", {"Docker-Content-Digest":"sha256:"+"f"*64})
        self.assertEqual(registry.tag_digest("0.1.0-rc.1",opener),"sha256:"+"f"*64)
        self.assertEqual(len(calls),2)
        self.assertIn("Bearer fixture",calls[1].headers["Authorization"])

    def test_cli_requires_both_tags_to_resolve_to_expected_digest(self):
        expected="sha256:"+"f"*64; observed=[]
        def digest(tag): observed.append(tag); return expected
        with patch.object(registry,"tag_digest",side_effect=digest), patch.object(sys,"argv",["registry.py","--version-tag","0.1.0-rc.1","--sha-tag","sha-"+"a"*40,"--expected-digest",expected]):
            self.assertEqual(registry.main(),0)
        self.assertEqual(observed,["0.1.0-rc.1","sha-"+"a"*40])

    def test_tag_digest_mismatch_fails_closed(self):
        with patch.object(registry,"tag_digest",return_value="sha256:"+"e"*64), patch.object(sys,"argv",["registry.py","--version-tag","0.1.0-rc.1","--sha-tag","sha-"+"a"*40,"--expected-digest","sha256:"+"f"*64]):
            self.assertEqual(registry.main(),2)


if __name__ == "__main__":
    unittest.main()
