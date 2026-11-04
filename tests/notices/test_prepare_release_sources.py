import io
import json
import os
from pathlib import Path
import socket
import ssl
import subprocess
import sys
import urllib.error

import pytest

from tools.notices.prepare_release_sources import CATALOG, catalog_matches, digest, fetch, release_sha256_row


def test_developer_keyring_lock_matches_acquisition_catalog():
    pins = dict(
        line.split("=", 1)
        for line in CATALOG.with_name("tools.lock").read_text().splitlines()
        if line and not line.startswith("#")
    )
    keyring = json.loads(CATALOG.read_text())["debian_developer_keyring"]
    assert pins["debian_developer_keyring_package_version"] == keyring["package_version"]
    assert pins["debian_developer_keyring_package_sha256"] == keyring["package_sha256"]
    assert pins["debian_developer_keyring_sha256"] == keyring["sha256"]


def test_catalog_is_portable_and_keeps_six_distinct_index_routes():
    catalog = json.loads(CATALOG.read_text())
    encoded = CATALOG.read_text()
    assert "/home/" not in encoded
    assert "/tmp/" not in encoded
    assert "status_output" not in encoded
    assert "signature_verification" not in encoded
    assert len(catalog["groups"]) == 82
    indexed = [x for x in catalog["groups"] if x["index_authentication"]]
    assert len(indexed) == 6
    assert {x["index_authentication"]["trust_root"] for x in indexed} == {
        "debian-trixie-archive", "postgresql-pgdg"
    }
    assert all(set(x["index_authentication"]) == {"trust_root", "trust_route"} for x in indexed)
    assert all(x["index_authentication"]["trust_route"] == "signed-repository-index" for x in indexed)
    keyring = catalog["debian_developer_keyring"]
    assert keyring["package_version"] == "2026.03.25"
    assert keyring["package_size"] == 33697852
    assert keyring["package_sha256"] == "7f48a8f7cd846f8b01d7a0fc65b1dc93c1a6d06981683b9db97e407c7908f0ae"
    assert keyring["sha256"] == "81e08f47b0dd8a563a2742ad90878ccefe53aa0728b095acbea3efda84381ea9"
    assert not (CATALOG.parent / "keyrings" / "debian-developer-keyring.gpg").exists()


def test_documented_direct_cli_starts_without_repository_pythonpath():
    script = CATALOG.parent / "prepare_release_sources.py"
    env = os.environ.copy()
    env.pop("PYTHONPATH", None)
    completed = subprocess.run([sys.executable, str(script), "--help"], capture_output=True, text=True, env=env)
    assert completed.returncode == 0, completed.stderr
    assert "new preparation output directory" in completed.stdout


def test_signed_inrelease_uses_unique_sha256_section_row():
    clear = "MD5Sum:\n 0123456789abcdef0123456789abcdef 7 main/source/Sources.xz\n\nSHA256:\n " + "a" * 64 + " 12 main/source/Sources.xz\nSHA512:\n " + "b" * 128 + " 12 main/source/Sources.xz\n"
    assert release_sha256_row(clear, "main/source/Sources.xz") == ("a" * 64, 12)
    duplicate = clear.replace("SHA512:", " " + "b" * 64 + " 12 main/source/Sources.xz\nSHA512:")
    with pytest.raises(ValueError, match="one complete SHA-256/size row"):
        release_sha256_row(duplicate, "main/source/Sources.xz")


def test_fetch_retries_transient_http_statuses_with_bounded_backoff(monkeypatch, capsys):
    url = "https://snapshot.debian.org/file/public-hash?signature=must-not-be-logged"
    responses = [
        urllib.error.HTTPError(url, 429, "rate limited", {}, io.BytesIO()),
        urllib.error.HTTPError(url, 503, "unavailable", {}, io.BytesIO()),
        urllib.error.HTTPError(url, 504, "gateway timeout", {}, io.BytesIO()),
        io.BytesIO(b"verified source bytes"),
    ]
    sleeps = []
    calls = []

    def fake_open(request, timeout):
        calls.append((request.full_url, timeout))
        response = responses.pop(0)
        if isinstance(response, BaseException):
            raise response
        return response

    monkeypatch.setattr("tools.notices.prepare_release_sources.urllib.request.urlopen", fake_open)
    monkeypatch.setattr("tools.notices.prepare_release_sources.time.sleep", sleeps.append)
    assert fetch(url) == b"verified source bytes"
    assert len(calls) == 4 and all(timeout == 90 for _url, timeout in calls)
    assert sleeps == [1, 2, 4]
    diagnostic = capsys.readouterr().err
    assert "attempt=1/4 outcome=retry reason=http-429" in diagnostic
    assert "attempt=2/4 outcome=retry reason=http-503" in diagnostic
    assert "attempt=3/4 outcome=retry reason=http-504" in diagnostic
    assert "attempt=4/4 outcome=success status=200 bytes=21" in diagnostic
    assert "snapshot.debian.org/file/public-hash" in diagnostic
    assert "must-not-be-logged" not in diagnostic


def test_fetch_does_not_retry_permanent_http_or_tls_failures(monkeypatch, capsys):
    calls = []

    def missing(request, timeout):
        calls.append(request.full_url)
        raise urllib.error.HTTPError(request.full_url, 404, "not found", {}, io.BytesIO())

    monkeypatch.setattr("tools.notices.prepare_release_sources.urllib.request.urlopen", missing)
    with pytest.raises(urllib.error.HTTPError):
        fetch("https://snapshot.debian.org/missing")
    assert len(calls) == 1
    assert capsys.readouterr().err == ""

    server_error_calls = []

    def server_error(request, timeout):
        server_error_calls.append(request.full_url)
        raise urllib.error.HTTPError(request.full_url, 500, "internal server error", {}, io.BytesIO())

    monkeypatch.setattr("tools.notices.prepare_release_sources.urllib.request.urlopen", server_error)
    with pytest.raises(urllib.error.HTTPError):
        fetch("https://snapshot.debian.org/server-error")
    assert len(server_error_calls) == 1

    tls_calls = []

    def bad_certificate(request, timeout):
        tls_calls.append(request.full_url)
        raise urllib.error.URLError(ssl.SSLCertVerificationError("certificate verification failed"))

    monkeypatch.setattr("tools.notices.prepare_release_sources.urllib.request.urlopen", bad_certificate)
    with pytest.raises(urllib.error.URLError):
        fetch("https://snapshot.debian.org/tls-error")
    assert len(tls_calls) == 1


def test_fetch_retries_transient_network_errors_then_fails_closed(monkeypatch, capsys):
    calls = []
    sleeps = []

    def timeout(request, timeout):
        calls.append(request.full_url)
        raise urllib.error.URLError(socket.timeout("first byte timeout"))

    monkeypatch.setattr("tools.notices.prepare_release_sources.urllib.request.urlopen", timeout)
    monkeypatch.setattr("tools.notices.prepare_release_sources.time.sleep", sleeps.append)
    with pytest.raises(ValueError, match="exhausted transient retries: TimeoutError"):
        fetch("https://snapshot.debian.org/slow?token=must-not-be-logged")
    assert len(calls) == 4
    assert sleeps == [1, 2, 4]
    diagnostic = capsys.readouterr().err
    assert "attempt=4/4 outcome=exhausted reason=TimeoutError" in diagnostic
    assert "snapshot.debian.org/slow" in diagnostic
    assert "must-not-be-logged" not in diagnostic


def test_fetch_retries_temporary_dns_failure(monkeypatch, capsys):
    calls = []
    sleeps = []

    def temporary_dns(request, timeout):
        calls.append(request.full_url)
        if len(calls) == 1:
            raise urllib.error.URLError(socket.gaierror(socket.EAI_AGAIN, "temporary name resolution failure"))
        return io.BytesIO(b"public input")

    monkeypatch.setattr("tools.notices.prepare_release_sources.urllib.request.urlopen", temporary_dns)
    monkeypatch.setattr("tools.notices.prepare_release_sources.time.sleep", sleeps.append)
    assert fetch("https://snapshot.debian.org/retry") == b"public input"
    assert len(calls) == 2
    assert sleeps == [1]
    assert "reason=dns-temporary" in capsys.readouterr().err


def test_catalog_rejects_source_version_or_stanza_drift():
    catalog = json.loads(CATALOG.read_text())
    candidates = []
    for row in catalog["groups"]:
        candidates.append({
            "source_package": row["source_package"],
            "source_version": row["source_version"],
            "license_declarations": row["license_declarations"],
            "copyright_files": row["copyright_files"],
            "file_stanzas": row["file_stanzas"],
        })
    catalog_matches(catalog, candidates)
    candidates[0]["source_version"] += ".changed"
    with pytest.raises(ValueError, match="package/version set"):
        catalog_matches(catalog, candidates)
    candidates[0]["source_version"] = catalog["groups"][0]["source_version"]
    candidates[0]["file_stanzas"] = []
    with pytest.raises(ValueError, match="stanza bindings"):
        catalog_matches(catalog, candidates)
