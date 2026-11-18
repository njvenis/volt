#!/usr/bin/env python3
"""Render the RC4 trusted-page bootstrap command for a signed small package.

This is release tooling, not a verifier and not a runnable default installer.
The values must come from the independently trusted release page. In
particular, a package must never provide the Cosign image or signer identity
used to authenticate its own launcher.
"""
from __future__ import annotations

import argparse
import re
import sys


VERSION = "0.1.0-rc.4"
SIGNER = ("https://github.com/njvenis/volt/"
          ".github/workflows/release-rc4.yml@refs/heads/main")
ISSUER = "https://token.actions.githubusercontent.com"
COSIGN_IMAGE = ("gcr.io/projectsigstore/cosign:v3.1.4@"
                "sha256:0f06154836d2de34f887a5c273506d52ca43edaa1d9e53e6510fa78a48f69c2d")
VERIFIER_IMAGE_PATTERN = r"ghcr\.io/njvenis/volt-installer-verifier@sha256:[0-9a-f]{64}"


def render_bootstrap(*, version: str, signer: str, issuer: str, verifier_image: str) -> str:
    """Return a POSIX command whose first execution is trusted Cosign only."""
    if version != VERSION:
        raise ValueError("easy-install bootstrap is reserved for the future RC4 package")
    if signer != SIGNER or issuer != ISSUER:
        raise ValueError("bootstrap signer must be the exact RC4 main workflow and GitHub Actions issuer")
    if not re.fullmatch(VERIFIER_IMAGE_PATTERN, verifier_image):
        raise ValueError("trusted release page must pin the exact official verifier OCI digest")
    # The current directory is the extracted, user-downloaded package. The
    # trusted command mounts it read-only and invokes no package code until the
    # independently pinned verifier accepts the exact launcher blob.
    return "\n".join((
        "set -eu",
        'verify_dir=$(mktemp -d "${TMPDIR:-/tmp}/volt-launcher.XXXXXX")',
        'trap \'rm -rf "$verify_dir"\' 0 HUP INT TERM',
        'cat ./launcher.sh > "$verify_dir/launcher.sh"',
        'cat ./launcher.sigstore.json > "$verify_dir/launcher.sigstore.json"',
        'cat ./installer.bundle.tar.gz > "$verify_dir/installer.bundle.tar.gz"',
        'cat ./installer.bundle.sigstore.json > "$verify_dir/installer.bundle.sigstore.json"',
        'chmod 0400 "$verify_dir/launcher.sh" "$verify_dir/launcher.sigstore.json" '
        '"$verify_dir/installer.bundle.tar.gz" "$verify_dir/installer.bundle.sigstore.json"',
        'docker run --rm --read-only --cap-drop=ALL '
        '--security-opt=no-new-privileges --tmpfs /tmp:rw,noexec,nosuid,size=16m '
        '--env HOME=/tmp '
        '--mount "type=bind,src=$verify_dir,dst=/package,readonly" '
        f'{COSIGN_IMAGE} verify-blob --bundle /package/launcher.sigstore.json '
        f'--certificate-identity {signer} --certificate-oidc-issuer {issuer} '
        f'/package/launcher.sh',
        'docker run --rm --read-only --cap-drop=ALL --security-opt=no-new-privileges '
        '--tmpfs /tmp:rw,noexec,nosuid,size=16m --env HOME=/tmp '
        f'{COSIGN_IMAGE} verify --certificate-identity {signer} '
        f'--certificate-oidc-issuer {issuer} {verifier_image}',
        'docker run --rm --read-only --cap-drop=ALL --security-opt=no-new-privileges '
        '--tmpfs /tmp:rw,noexec,nosuid,size=16m --env HOME=/tmp '
        f'{COSIGN_IMAGE} verify-attestation --type https://slsa.dev/provenance/v1 '
        f'--certificate-identity {signer} --certificate-oidc-issuer {issuer} {verifier_image}',
        f'VOLT_EXPECTED_VERIFIER_IMAGE={verifier_image} VOLT_EXPECTED_VERSION={version} '
        f'VOLT_EXPECTED_SIGNER={signer} VOLT_EXPECTED_ISSUER={issuer} VOLT_BOOTSTRAP_VERIFIER_VERIFIED=1 '
        'sh "$verify_dir/launcher.sh" install',
        "",
    ))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", required=True)
    parser.add_argument("--signer", required=True)
    parser.add_argument("--issuer", required=True)
    parser.add_argument("--verifier-image", required=True)
    args = parser.parse_args()
    try:
        sys.stdout.write(render_bootstrap(version=args.version,
            signer=args.signer, issuer=args.issuer, verifier_image=args.verifier_image))
    except ValueError as exc:
        parser.error(str(exc))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
