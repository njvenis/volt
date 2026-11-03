#!/usr/bin/env python3
"""Read-only GHCR collision check: only authoritative 404 means an unused tag."""
from __future__ import annotations

import argparse
import json
import sys
import re
import urllib.error
import urllib.parse
import urllib.request

REPOSITORY = "njvenis/volt"
ACCEPT = ", ".join((
    "application/vnd.oci.image.index.v1+json",
    "application/vnd.oci.image.manifest.v1+json",
    "application/vnd.docker.distribution.manifest.list.v2+json",
    "application/vnd.docker.distribution.manifest.v2+json",
))


def unused_tag(tag: str, opener=urllib.request.urlopen) -> bool:
    token_url = "https://ghcr.io/token?" + urllib.parse.urlencode({"scope": f"repository:{REPOSITORY}:pull"})
    try:
        with opener(token_url, timeout=20) as response:
            token_doc = json.loads(response.read())
        token = token_doc.get("token") or token_doc.get("access_token")
        if not token:
            raise RuntimeError("registry did not return a pull token")
    except (urllib.error.HTTPError, urllib.error.URLError) as exc:
        raise RuntimeError(f"GHCR token request failed closed: {exc}") from exc
    request = urllib.request.Request(
        f"https://ghcr.io/v2/{REPOSITORY}/manifests/{urllib.parse.quote(tag, safe='.-_')}",
        method="HEAD", headers={"Authorization": f"Bearer {token}", "Accept": ACCEPT},
    )
    try:
        with opener(request, timeout=20):
            return False
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return True
        raise RuntimeError(f"GHCR tag check failed closed with HTTP {exc.code}") from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(f"GHCR tag check failed closed: {exc}") from exc


def tag_digest(tag: str, opener=urllib.request.urlopen) -> str:
    token_url = "https://ghcr.io/token?" + urllib.parse.urlencode({"scope": f"repository:{REPOSITORY}:pull"})
    with opener(token_url, timeout=20) as response:
        token_doc = json.loads(response.read())
    token = token_doc.get("token") or token_doc.get("access_token")
    if not token: raise RuntimeError("registry did not return a pull token")
    request = urllib.request.Request(f"https://ghcr.io/v2/{REPOSITORY}/manifests/{urllib.parse.quote(tag, safe='.-_')}", headers={"Authorization": f"Bearer {token}", "Accept": ACCEPT})
    with opener(request, timeout=20) as response:
        digest = response.headers.get("Docker-Content-Digest")
    if not digest or not re.fullmatch(r"sha256:[0-9a-f]{64}", digest): raise RuntimeError(f"registry returned no immutable digest for tag {tag}")
    return digest


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--version-tag", required=True)
    parser.add_argument("--sha-tag", required=True)
    parser.add_argument("--expected-digest")
    args = parser.parse_args()
    if args.version_tag != "0.1.0-rc.1" or not re.fullmatch(r"sha-[0-9a-f]{40}", args.sha_tag):
        parser.error("only the approved RC1 and full source SHA tag are accepted")
    try:
        if args.expected_digest:
            if not re.fullmatch(r"sha256:[0-9a-f]{64}", args.expected_digest):
                raise RuntimeError("expected digest is malformed")
            for tag in (args.version_tag, args.sha_tag):
                actual = tag_digest(tag)
                if actual != args.expected_digest:
                    raise RuntimeError(f"tag {tag} resolves to {actual}, expected {args.expected_digest}")
            print("both immutable GHCR tags resolve to the expected digest")
            return 0
        for tag in (args.version_tag, args.sha_tag):
            if not unused_tag(tag):
                raise RuntimeError(f"immutable release tag already exists: {tag}")
        print("GHCR version and source-SHA tags are unused")
        return 0
    except RuntimeError as exc:
        print(str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
