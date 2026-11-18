# Verify a VOLT RC3 release

This file is a separate GitHub Release asset. Obtain it from the VOLT release page over HTTPS before trusting an archive. RC3 is an evaluation prerelease.

## Prerequisites

- Python 3.11 or later, Git, OpenSSL, Docker Engine or Docker Desktop, and Docker Compose v2.
- Network access to the public VOLT GitHub repository and the official Cosign release asset pinned in the signed source commit.
- The matching architecture archive: `amd64` for x86-64 or `arm64` for Apple Silicon/ARM64.

## Verify before loading

Read `source_commit` from the archive manifest only as a locator. Do not execute or install any file from the archive. Retrieve the exact public source commit and use its maintained verifier and pinned Cosign installer:

```sh
mkdir -m 700 volt-rc3-check
cd volt-rc3-check
ARCH=arm64 # use amd64 on x86-64
ARCHIVE="../volt-0.1.0-rc.3-linux-${ARCH}.tar.gz"
SOURCE_SHA="$(tar -xOf "$ARCHIVE" manifest.json | python3 -c 'import json,sys; print(json.load(sys.stdin)["source_commit"])')"
git clone --no-checkout https://github.com/njvenis/volt.git trusted-source
git -C trusted-source fetch --no-tags origin "$SOURCE_SHA"
git -C trusted-source checkout --detach "$SOURCE_SHA"
python3 trusted-source/tools/release/install_cosign.py
/tmp/volt-release-tools/cosign initialize
python3 trusted-source/tools/release/archive.py verify \
  --archive "$ARCHIVE" \
  --cosign /tmp/volt-release-tools/cosign \
  --source-sha "$SOURCE_SHA"
```

The verifier checks the Cosign bundle against the fixed identity
`https://github.com/njvenis/volt/.github/workflows/release-rc3.yml@refs/heads/main`
and issuer `https://token.actions.githubusercontent.com`. It validates the signed closed inventory, exact source bundle and snapshot, architecture/image identities, image-bound notices and scan, and the Compose bundle's shared registry index digest. The source commit value is not trusted until signature verification succeeds.

Only after successful verification, load the image through the same trusted helper:

```sh
python3 trusted-source/tools/release/archive.py load \
  --archive "$ARCHIVE" \
  --cosign /tmp/volt-release-tools/cosign \
  --source-sha "$SOURCE_SHA"
```

This verifies the signed archive before asking Docker to import the image. Do not run `docker load` directly on an unverified archive.

## Install

Download `volt-compose.tar.gz` and `volt-compose.tar.gz.sha256` from the same release and verify the checksum before extraction:

```sh
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
