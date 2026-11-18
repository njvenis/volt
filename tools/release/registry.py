#!/usr/bin/env python3
"""Read-only GHCR tag checks; only an authoritative manifest 404 means absent."""
from __future__ import annotations

import argparse
import base64
import json
import hashlib
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request

REPOSITORY = "njvenis/volt"
RELEASE_VERSION_TAGS = {"0.1.0-rc.2", "0.1.0-rc.3"}
REGISTRY = "https://ghcr.io"
ACCEPT = ", ".join((
    "application/vnd.oci.image.index.v1+json",
    "application/vnd.oci.image.manifest.v1+json",
    "application/vnd.docker.distribution.manifest.list.v2+json",
    "application/vnd.docker.distribution.manifest.v2+json",
))


class NoRedirect(urllib.request.HTTPRedirectHandler):
    """Never forward registry credentials or bearer tokens to a redirect host."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise urllib.error.HTTPError(req.full_url, code, "registry redirect refused", headers, fp)


def _opener():
    return urllib.request.build_opener(NoRedirect()).open


def _request(opener, request, *, timeout=20):
    """Use the supplied opener with the same interface as urlopen for tests."""
    try:
        return opener(request, timeout=timeout)
    except (ValueError, UnicodeError):
        raise RuntimeError("GHCR transport rejected request data") from None


def _pull_token(opener, username: str | None, password: str | None) -> str:
    token_url = f"{REGISTRY}/token?" + urllib.parse.urlencode({"scope": f"repository:{REPOSITORY}:pull"})
    headers = {"Accept": "application/json"}
    if username is not None or password is not None:
        if not username or not password:
            raise RuntimeError("GHCR authentication requires both username and token")
        raw = f"{username}:{password}".encode("utf-8")
        headers["Authorization"] = "Basic " + base64.b64encode(raw).decode("ascii")
    try:
        with _request(opener, urllib.request.Request(token_url, headers=headers)) as response:
            token_doc = json.loads(response.read())
    except urllib.error.HTTPError as exc:
        raise RuntimeError(f"GHCR token request failed closed with HTTP {exc.code}") from None
    except urllib.error.URLError:
        raise RuntimeError("GHCR token request failed closed: network error") from None
    except (ValueError, TypeError):
        raise RuntimeError("GHCR token response was invalid") from None
    token = token_doc.get("token") or token_doc.get("access_token") if isinstance(token_doc, dict) else None
    if not isinstance(token, str) or not re.fullmatch(r"[A-Za-z0-9._~+/-]+=*", token):
        raise RuntimeError("registry did not return a pull token")
    return token


def _manifest_request(tag: str, token: str) -> urllib.request.Request:
    url = f"{REGISTRY}/v2/{REPOSITORY}/manifests/{urllib.parse.quote(tag, safe='.-_')}"
    return urllib.request.Request(url, method="HEAD", headers={"Authorization": f"Bearer {token}", "Accept": ACCEPT})


def unused_tag(tag: str, opener=None, *, username=None, password=None, anonymous=False) -> bool:
    opener = opener or _opener()
    if anonymous and (username is not None or password is not None):
        raise RuntimeError("anonymous verification cannot include credentials")
    token = _pull_token(opener, None if anonymous else username, None if anonymous else password)
    try:
        with _request(opener, _manifest_request(tag, token)):
            return False
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return True
        raise RuntimeError(f"GHCR tag check failed closed with HTTP {exc.code}") from None
    except urllib.error.URLError:
        raise RuntimeError("GHCR tag check failed closed: network error") from None


def tag_digest(tag: str, opener=None, *, username=None, password=None, anonymous=False) -> str:
    opener = opener or _opener()
    if anonymous and (username is not None or password is not None):
        raise RuntimeError("anonymous verification cannot include credentials")
    token = _pull_token(opener, None if anonymous else username, None if anonymous else password)
    try:
        with _request(opener, _manifest_request(tag, token)) as response:
            digest = response.headers.get("Docker-Content-Digest")
    except urllib.error.HTTPError as exc:
        raise RuntimeError(f"GHCR tag check failed closed with HTTP {exc.code}") from None
    except urllib.error.URLError:
        raise RuntimeError("GHCR tag check failed closed: network error") from None
    if not digest or not re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
        raise RuntimeError(f"registry returned no immutable digest for tag {tag}")
    return digest


def manifest_bytes(digest: str, *, username=None, password=None) -> bytes:
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
        raise RuntimeError("manifest digest malformed")
    opener = _opener()
    token = _pull_token(opener, username, password)
    request = _manifest_request(digest, token)
    request.method = "GET"
    with _request(opener, request) as response:
        raw = response.read()
    if "sha256:" + hashlib.sha256(raw).hexdigest() != digest:
        raise RuntimeError("registry manifest bytes differ from digest")
    return raw


def manifest_document(digest: str, *, username=None, password=None) -> dict:
    return json.loads(manifest_bytes(digest, username=username, password=password))


def verify_child(digest: str, config_id: str, *, username=None, password=None) -> None:
    doc = manifest_document(digest, username=username, password=password)
    if doc.get("config", {}).get("digest") != config_id or not isinstance(doc.get("layers"), list) or not doc["layers"]:
        raise RuntimeError("published child does not bind admitted image config")


def validate_index(doc: dict, amd64: str, arm64: str) -> None:
    if doc.get("schemaVersion") != 2 or doc.get("mediaType") not in {
            "application/vnd.oci.image.index.v1+json", "application/vnd.docker.distribution.manifest.list.v2+json"}:
        raise ValueError("published index media/schema differs")
    if amd64 == arm64 or any(not re.fullmatch(r"sha256:[0-9a-f]{64}", value) for value in (amd64, arm64)):
        raise ValueError("index child digests must be distinct immutable digests")
    expected = {("linux", "amd64"): amd64, ("linux", "arm64"): arm64}
    rows = doc.get("manifests", [])
    found = {}
    if len(rows) != 2:
        raise ValueError("index requires exactly two children")
    for row in rows:
        platform = row.get("platform", {})
        key = (platform.get("os"), platform.get("architecture"))
        if key not in expected or key in found or platform.get("variant") not in (None, "v8"):
            raise ValueError("index platform duplicate or unsupported")
        found[key] = row.get("digest")
    if found != expected:
        raise ValueError("index child bindings differ")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--version-tag", required=True)
    parser.add_argument("--sha-tag", required=True)
    parser.add_argument("--amd64-tag")
    parser.add_argument("--arm64-tag")
    parser.add_argument("--expected-digest")
    parser.add_argument("--expected-amd64-digest")
    parser.add_argument("--expected-arm64-digest")
    parser.add_argument("--anonymous", action="store_true", help="verify public pull access without credentials")
    args = parser.parse_args()
    if args.version_tag not in RELEASE_VERSION_TAGS or not re.fullmatch(r"sha-[0-9a-f]{40}", args.sha_tag):
        parser.error("only explicitly prepared RC2/RC3 version and full source-SHA tags are accepted")
    source_sha = args.sha_tag.removeprefix("sha-")
    rc3_tags = (f"sha-{source_sha}-linux-amd64", f"sha-{source_sha}-linux-arm64")
    if args.version_tag == "0.1.0-rc.3":
        if (args.amd64_tag, args.arm64_tag) != rc3_tags:
            parser.error("RC3 requires the exact source-bound amd64 and arm64 child-image tags")
    elif args.amd64_tag or args.arm64_tag or args.expected_amd64_digest or args.expected_arm64_digest:
        parser.error("platform child tags are supported only for the fixed multi-platform RC3")
    if not args.expected_digest and (args.expected_amd64_digest or args.expected_arm64_digest):
        parser.error("expected platform digests require an expected index digest")
    username = password = None
    if not args.anonymous:
        username = os.environ.get("GITHUB_ACTOR")
        password = os.environ.get("GH_TOKEN")
        if not username or not password:
            print("GHCR preflight requires GITHUB_ACTOR and GH_TOKEN", file=sys.stderr)
            return 2
    try:
        if args.expected_digest:
            if not re.fullmatch(r"sha256:[0-9a-f]{64}", args.expected_digest):
                raise RuntimeError("expected digest is malformed")
            checks = [(args.version_tag, args.expected_digest), (args.sha_tag, args.expected_digest)]
            if args.version_tag == "0.1.0-rc.3":
                for tag, digest in ((args.amd64_tag, args.expected_amd64_digest),
                                    (args.arm64_tag, args.expected_arm64_digest)):
                    if not isinstance(digest, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
                        raise RuntimeError("RC3 requires both immutable child image digests")
                    checks.append((tag, digest))
            for tag, expected in checks:
                actual = tag_digest(tag, username=username, password=password, anonymous=args.anonymous)
                if actual != expected:
                    raise RuntimeError(f"tag {tag} resolves to {actual}, expected {expected}")
            print("all required GHCR tags resolve to their expected immutable index/platform digests")
            return 0
        tags = [args.version_tag, args.sha_tag]
        if args.version_tag == "0.1.0-rc.3":
            tags.extend([args.amd64_tag, args.arm64_tag])
        for tag in tags:
            if not unused_tag(tag, username=username, password=password, anonymous=args.anonymous):
                raise RuntimeError(f"immutable release tag already exists: {tag}")
        print("all required GHCR version, source-SHA and platform tags are unused")
        return 0
    except RuntimeError as exc:
        print(str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
