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

from tools.notices.prepare_release_sources import (
    CATALOG, TransientFetchError, acquire_group, catalog_matches, digest, fetch,
    release_sha256_row, validate_canonical_fallback_url,
)


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
    fallback_rows = [(group["source_package"], row) for group in catalog["groups"]
                     for row in group["source_files"] if "fallback_url" in row]
    assert len(fallback_rows) == 1
    assert fallback_rows[0][0] == "adduser"
    assert fallback_rows[0][1]["filename"] == "adduser_3.152.tar.xz"
    assert fallback_rows[0][1]["fallback_url"] == (
        "https://deb.debian.org/debian/pool/main/a/adduser/adduser_3.152.tar.xz"
    )
    keyring = catalog["debian_developer_keyring"]
    assert keyring["package_version"] == "2026.03.25"
    assert keyring["package_size"] == 33697852
    assert keyring["package_sha256"] == "7f48a8f7cd846f8b01d7a0fc65b1dc93c1a6d06981683b9db97e407c7908f0ae"
    assert keyring["sha256"] == "81e08f47b0dd8a563a2742ad90878ccefe53aa0728b095acbea3efda84381ea9"
    assert not (CATALOG.parent / "keyrings" / "debian-developer-keyring.gpg").exists()
    acl = next(x for x in catalog["groups"] if x["source_package"] == "acl" and x["source_version"] == "2.3.2-2")
    assert acl["immutable_dsc_sha1"] == "a78c0a5e511ee122ba5976bbd7cabeff0fd7cbe6"
    apt = next(x for x in catalog["groups"] if x["source_package"] == "apt" and x["source_version"] == "3.0.3")
    assert apt["immutable_dsc_sha1"] == "75cc2d8a7adec664f1b1058dcab263372da25df5"
    immutable = [x for x in catalog["groups"] if "immutable_dsc_sha1" in x]
    assert len(immutable) == 76
    assert all(len(x["immutable_dsc_sha1"]) == 40
               and all(c in "0123456789abcdef" for c in x["immutable_dsc_sha1"])
               and not x.get("index_authentication") for x in immutable)


def _immutable_dsc_fixture(source="demo", version="1-1", member_size=None):
    from tools.notices.prepare_release_sources import digest
    member_name = "demo_1.orig.tar.xz"
    member_data = b"exact source archive"
    size = len(member_data) if member_size is None else member_size
    member_sha1 = __import__("hashlib").sha1(member_data).hexdigest()
    member_sha256 = digest(member_data)
    dsc = ("-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA256\n\n"
           f"Source: {source}\nVersion: {version}\n"
           f"Checksums-Sha1:\n {member_sha1} {size} {member_name}\n"
           f"Checksums-Sha256:\n {member_sha256} {len(member_data)} {member_name}\n"
           "-----BEGIN PGP SIGNATURE-----\nfake signature fixture\n-----END PGP SIGNATURE-----\n").encode()
    return dsc, member_name, member_data, member_sha1


def _acquire_immutable_fixture(monkeypatch, tmp_path, *, source="demo", version="1-1", member_size=None,
                               descriptor_signature_ok=True, catalog_dsc_sha256=None, descriptor_sha1=None,
                               snapshot_error=None, fallback_url=None, fallback_data=None,
                               catalog_member_sha256=None):
    import hashlib
    from types import SimpleNamespace
    from tools.notices import prepare_release_sources as preparer

    dsc, member_name, member_data, member_sha1 = _immutable_dsc_fixture(source, version, member_size)
    actual_descriptor_sha1 = hashlib.sha1(dsc).hexdigest()
    locator = descriptor_sha1 or actual_descriptor_sha1
    entry = {
        "source_package": "demo", "source_version": "1-1",
        "immutable_dsc_sha1": locator,
        "dsc_sha256": catalog_dsc_sha256 or digest(dsc),
        "source_files": [{"filename": member_name,
                          "sha256": catalog_member_sha256 or digest(member_data),
                          **({"fallback_url": fallback_url} if fallback_url else {})}],
    }
    urls = []

    def fake_fetch(url):
        urls.append(url)
        if url.endswith("/" + locator):
            return dsc
        if url.endswith("/" + member_sha1):
            if snapshot_error is not None:
                raise snapshot_error
            return member_data
        if fallback_url and url == fallback_url:
            return member_data if fallback_data is None else fallback_data
        raise AssertionError(f"unexpected immutable source URL: {url}")

    def fake_run(args, **kwargs):
        assert args[0] == "gpgv"
        return SimpleNamespace(returncode=0 if descriptor_signature_ok else 1, stderr="", stdout="")

    monkeypatch.setattr(preparer, "fetch", fake_fetch)
    monkeypatch.setattr(preparer.subprocess, "run", fake_run)
    result = acquire_group(entry, tmp_path, tmp_path / "keyring.gpg", {}, {})
    return result, urls


def test_immutable_member_uses_canonical_fallback_after_transient_snapshot_exhaustion(monkeypatch, tmp_path, capsys):
    fallback_url = "https://deb.debian.org/debian/pool/main/d/demo/demo_1.orig.tar.xz"
    result, urls = _acquire_immutable_fixture(
        monkeypatch, tmp_path, fallback_url=fallback_url,
        snapshot_error=TransientFetchError("synthetic first-byte timeout"),
    )
    assert len(result["files"]) == 1
    assert urls[-2:] == [
        "https://snapshot.debian.org/file/" + __import__("hashlib").sha1(b"exact source archive").hexdigest(),
        fallback_url,
    ]
    assert "reason=transient-exhaustion" in capsys.readouterr().err


@pytest.mark.parametrize("url", [
    "http://deb.debian.org/debian/pool/main/d/demo/demo_1.orig.tar.xz",
    "https://evil.example/debian/pool/main/d/demo/demo_1.orig.tar.xz",
    "https://deb.debian.org/debian/pool/main/d/other.tar.xz",
    "https://user" + "@deb.debian.org/debian/pool/main/d/demo/demo_1.orig.tar.xz",
    "https://deb.debian.org/debian/pool/main/d/demo/demo_1.orig.tar.xz?x=1",
])
def test_canonical_fallback_url_is_limited_to_exact_debian_pool_member(url):
    with pytest.raises(ValueError, match="exact HTTPS deb.debian.org pool URL"):
        validate_canonical_fallback_url(url, "demo_1.orig.tar.xz")


@pytest.mark.parametrize("failure", ["permanent-http", "certificate", "missing-fallback"])
def test_immutable_member_does_not_fallback_for_permanent_or_unconfigured_failures(
        monkeypatch, tmp_path, failure):
    if failure == "permanent-http":
        error = urllib.error.HTTPError("https://snapshot.debian.org/file/x", 404, "not found", {}, io.BytesIO())
    elif failure == "certificate":
        error = urllib.error.URLError(ssl.SSLCertVerificationError("bad certificate"))
    else:
        error = TransientFetchError("bounded retries exhausted")
    fallback_url = "https://deb.debian.org/debian/pool/main/d/demo/demo_1.orig.tar.xz"
    with pytest.raises((ValueError, urllib.error.URLError)):
        _acquire_immutable_fixture(
            monkeypatch, tmp_path, snapshot_error=error,
            fallback_url=None if failure == "missing-fallback" else fallback_url,
        )


@pytest.mark.parametrize("bad_payload", [b"wrong payload length", b"other source archive"])
def test_immutable_fallback_rejects_bytes_that_fail_signed_sha1_or_size(monkeypatch, tmp_path, bad_payload):
    fallback_url = "https://deb.debian.org/debian/pool/main/d/demo/demo_1.orig.tar.xz"
    with pytest.raises(ValueError, match="immutable locator SHA-1/size mismatch"):
        _acquire_immutable_fixture(
            monkeypatch, tmp_path, fallback_url=fallback_url,
            snapshot_error=TransientFetchError("synthetic transient exhaustion"), fallback_data=bad_payload,
        )


def test_immutable_fallback_still_requires_original_catalog_sha256(monkeypatch, tmp_path):
    fallback_url = "https://deb.debian.org/debian/pool/main/d/demo/demo_1.orig.tar.xz"
    with pytest.raises(ValueError, match="catalog source-member set differs from signed .dsc"):
        _acquire_immutable_fixture(
            monkeypatch, tmp_path, fallback_url=fallback_url,
            snapshot_error=TransientFetchError("synthetic transient exhaustion"),
            catalog_member_sha256="0" * 64,
        )


def test_immutable_dsc_route_uses_only_file_urls_and_checks_members(monkeypatch, tmp_path):
    result, urls = _acquire_immutable_fixture(monkeypatch, tmp_path)
    assert len(result["files"]) == 1
    assert all("snapshot.debian.org/file/" in url for url in urls)
    assert not any("/mr/" in url for url in urls)


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        ({"source": "other"}, "identity differs"),
        ({"descriptor_signature_ok": False}, "maintainer signature check failed"),
        ({"member_size": 999}, "immutable locator SHA-1/size mismatch"),
        ({"catalog_dsc_sha256": "0" * 64}, "exact .dsc differs from catalog"),
        ({"descriptor_sha1": "0" * 40}, "immutable .dsc locator SHA-1 mismatch"),
    ],
)
def test_immutable_dsc_route_rejects_unbound_inputs(monkeypatch, tmp_path, kwargs, message):
    with pytest.raises(ValueError, match=message):
        _acquire_immutable_fixture(monkeypatch, tmp_path, **kwargs)


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
