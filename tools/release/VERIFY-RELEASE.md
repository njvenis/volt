# Verify a VOLT RC3 release

This file is a separate GitHub Release asset. Obtain it from the VOLT release page over HTTPS before trusting an archive. RC3 is an evaluation prerelease.

## Prerequisites

- Python 3.11 or later, Git, OpenSSL, gpgv, Docker Engine or Docker Desktop, and Docker Compose v2.
- Network access to the public VOLT GitHub repository and the official Cosign release asset pinned in the fixed RC3 source.
- The matching architecture archive: `amd64` for x86-64 or `arm64` for Apple Silicon/ARM64.

## Verify before loading

The archive is untrusted input at this point. Do not read its manifest to choose source code, a verifier, or an installer. First obtain the fixed RC3 source from the public VOLT repository's `v0.1.0-rc.3` release tag and use only its maintained verifier and pinned Cosign installer:

```sh
mkdir -m 700 volt-rc3-check
cd volt-rc3-check
ARCH=arm64 # use amd64 on x86-64
ARCHIVE="../volt-0.1.0-rc.3-linux-${ARCH}.tar.gz"
REPOSITORY=https://github.com/njvenis/volt.git
RELEASE_TAG=v0.1.0-rc.3
TAG_REFS="$(git ls-remote "$REPOSITORY" "refs/tags/${RELEASE_TAG}" "refs/tags/${RELEASE_TAG}^{}")"
SOURCE_SHA="$(printf '%s\n' "$TAG_REFS" | awk -v peeled="refs/tags/${RELEASE_TAG}^{}" '$2 == peeled {print $1}')"
if [ -z "$SOURCE_SHA" ]; then
  SOURCE_SHA="$(printf '%s\n' "$TAG_REFS" | awk -v direct="refs/tags/${RELEASE_TAG}" '$2 == direct {print $1}')"
fi
case "$SOURCE_SHA" in
  (*[!0-9a-f]*|'') echo "RC3 source tag was not found" >&2; exit 1 ;;
esac
test "${#SOURCE_SHA}" -eq 40
git clone --no-checkout "$REPOSITORY" trusted-source
git -C trusted-source fetch --no-tags origin "$SOURCE_SHA"
git -C trusted-source checkout --detach "$SOURCE_SHA"
test "$(git -C trusted-source rev-parse HEAD)" = "$SOURCE_SHA"
python3 trusted-source/tools/release/install_cosign.py
/tmp/volt-release-tools/cosign initialize
python3 trusted-source/tools/release/archive.py verify \
  --archive "$ARCHIVE" \
  --cosign /tmp/volt-release-tools/cosign \
  --source-sha "$SOURCE_SHA"
```

The fixed release tag, retrieved from the public maintainer repository, determines which verifier code runs and the expected archive source. Archive contents cannot select or replace that code. The verifier checks the signed manifest's fixed workflow identity
`https://github.com/njvenis/volt/.github/workflows/release-rc3.yml@refs/heads/main`
and issuer `https://token.actions.githubusercontent.com`. It validates the signed closed inventory, exact source bundle and snapshot, architecture/image identities, image-bound notices and scan, and the Compose bundle's shared registry index digest. It also requires the signed `source_commit` to match the source commit resolved from the fixed release tag.

Only after successful verification, load the image through the same trusted helper:

```sh
python3 trusted-source/tools/release/archive.py load \
  --archive "$ARCHIVE" \
  --cosign /tmp/volt-release-tools/cosign \
  --source-sha "$SOURCE_SHA"
```

This verifies the signed archive before asking Docker to import the image. Do not run `docker load` directly on an unverified archive.

## Install

Download `volt-compose.tar.gz` and `volt-compose.tar.gz.sha256` from the same release. Authenticate the standalone bundle against the signed embedded bytes before extraction. A self-checksum alone does not authenticate an installer:

```sh
python3 trusted-source/tools/release/archive.py authenticate-bundle \
  --archive "$ARCHIVE" --bundle volt-compose.tar.gz \
  --cosign /tmp/volt-release-tools/cosign --source-sha "$SOURCE_SHA"
if command -v sha256sum >/dev/null 2>&1; then
  sha256sum -c volt-compose.tar.gz.sha256
else
  shasum -a 256 -c volt-compose.tar.gz.sha256
fi
mkdir -m 700 installer
tar -xzf volt-compose.tar.gz -C installer
```

Then enter the extracted `volt-compose-0.1.0-rc.3` directory and follow its README. It contains local password-admin setup, OIDC/Okta configuration, Compose, backup and restore instructions. The bundle pins the exact published multi-platform image index digest. Keep the secret-file permissions described in those instructions.

The signature authenticates the RC3 release workflow's manifest and payload inventory. It is not a third-party security certification or a claim that your local Okta tenant was tested.

Verification/bootstrap requires Git and network access for the independently trusted release tag, pinned Cosign and Sigstore trust material. Archive verification also uses local Git and gpgv for bundled source and Debian signatures. Runtime installation needs no source build, Node.js or npm. Loading the authenticated image avoids transferring image layers again; Docker/Compose may still contact GHCR for the pinned reference, and external OIDC requires its issuer network. This guide does not establish fully offline verification or an offline external-identity runtime. The OCI index carries its own signature and provenance binding both child digests; each child carries its architecture-specific SPDX SBOM and source provenance.
