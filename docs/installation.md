# RC2 Compose installation and historical RC1 launcher

## RC2 Compose installation

VOLT `0.1.0-rc.2` is the current Linux/amd64 Compose-compatible evaluation image. Its immutable registry reference is:

```sh
VOLT_RELEASE_IMAGE='ghcr.io/njvenis/volt@sha256:a7130e38b88b781d93d84c4ddd022ba45716a06b89949a2923e1dd531db2eac1'
```

The RC2 prerelease is published. Its assets include the standalone source-free Compose bundle, checksum, signed Linux/amd64 offline archive, and external release-verification instructions. The image passed the hosted synthetic Compose demo, cold backup/restore, and offline-preview qualification.

### Download and verify the source-free bundle

Download the standalone Compose bundle, its checksum, the signed offline archive, and the external release-verification instructions:

```sh
if ! mkdir -p volt-rc2-release; then echo 'Cannot create download directory' >&2; exit 1; fi
if ! cd volt-rc2-release; then echo 'Cannot enter download directory' >&2; exit 1; fi
if ! gh release download v0.1.0-rc.2 --repo njvenis/volt \
    --pattern volt-compose.tar.gz \
    --pattern volt-compose.tar.gz.sha256 \
    --pattern volt-0.1.0-rc.2-linux-amd64.tar.gz \
    --pattern VERIFY-RELEASE.md; then
  echo 'Release asset download failed; stop without using any local files' >&2
  exit 1
fi
```

Assets are also available directly: [Compose bundle](https://github.com/njvenis/volt/releases/download/v0.1.0-rc.2/volt-compose.tar.gz), [bundle checksum](https://github.com/njvenis/volt/releases/download/v0.1.0-rc.2/volt-compose.tar.gz.sha256), [signed offline archive](https://github.com/njvenis/volt/releases/download/v0.1.0-rc.2/volt-0.1.0-rc.2-linux-amd64.tar.gz), and [VERIFY-RELEASE.md](https://github.com/njvenis/volt/releases/download/v0.1.0-rc.2/VERIFY-RELEASE.md). The checksum confirms transfer integrity; use the authenticated outer archive to verify the standalone bundle's identity.

Before extracting either the Compose bundle or image, follow the external `VERIFY-RELEASE.md` instructions after authenticating them through the release owner or another trusted channel. Those instructions use an independently authenticated verifier checkout at controller commit `90f48211e65c9ae0556419dc7f8329170386287c` to verify the archive's image-source commit `0af679d77754060f2f89368830a92ddb6e3f2122` and image ID `sha256:09412fdcda1a77a6182829061e202f83e767f8cfaecce2cc5b3e9443c3c35461`. Keep those identities distinct: the controller supplies the verifier; it is not the source revision built into the image. Provision Cosign's official Sigstore trust through its official procedure or use an already provisioned trusted store. Never take a trust root or its only checksum from the archive. This trust bootstrap can use Git, but Git is not an installation or runtime prerequisite for the extracted source-free bundle.

```sh
if ! git clone https://github.com/njvenis/volt.git volt-rc2-verifier; then echo 'Verifier checkout failed' >&2; exit 1; fi
if ! git -C volt-rc2-verifier checkout --detach 90f48211e65c9ae0556419dc7f8329170386287c; then echo 'Verifier checkout identity failed' >&2; exit 1; fi
if ! test "$(git -C volt-rc2-verifier rev-parse HEAD)" = 90f48211e65c9ae0556419dc7f8329170386287c; then echo 'Unexpected verifier checkout identity' >&2; exit 1; fi
if ! python3 volt-rc2-verifier/tools/release/archive.py verify \
    --archive volt-0.1.0-rc.2-linux-amd64.tar.gz --cosign cosign \
    --source-sha 0af679d77754060f2f89368830a92ddb6e3f2122 \
    --image-id sha256:09412fdcda1a77a6182829061e202f83e767f8cfaecce2cc5b3e9443c3c35461; then
  echo 'Signed archive verification failed; do not extract the bundle or load the image' >&2
  exit 1
fi
```

The outer archive signature and signed manifest authenticate the included Compose bundle. Confirm the separately downloaded bundle is byte-for-byte identical to that authenticated member; the sidecar checksum alone is not a trust anchor:

```sh
if ! tar -xOf volt-0.1.0-rc.2-linux-amd64.tar.gz volt-compose.tar.gz > volt-compose-embedded.tar.gz; then echo 'Cannot read authenticated bundle member' >&2; exit 1; fi
if ! cmp volt-compose.tar.gz volt-compose-embedded.tar.gz; then echo 'Standalone bundle differs from the authenticated archive; stop' >&2; exit 1; fi
if ! sha256sum -c volt-compose.tar.gz.sha256; then echo 'Bundle checksum failed; stop' >&2; exit 1; fi
if ! tar -xzf volt-compose.tar.gz; then echo 'Bundle extraction failed; stop' >&2; exit 1; fi
if ! cd volt-compose-0.1.0-rc.2; then echo 'Expected versioned bundle directory is missing' >&2; exit 1; fi
```

The bundle's README contains the demo and external OIDC setup, identity-linking, authority initialization, lifecycle, and backup instructions. The installer is source-free: installation does not clone VOLT, install Node.js/npm, install a browser, or build the application. Runtime prerequisites are Docker Engine with Compose v2, Python 3.11+, and OpenSSL. External mode also requires a separately operated provider-specific identity-sync publisher; OIDC login alone does not establish current source membership or permissions.

### Pull and run online

Verify the registry signature and pull by immutable digest, not a mutable tag:

```sh
VOLT_RELEASE_IMAGE='ghcr.io/njvenis/volt@sha256:a7130e38b88b781d93d84c4ddd022ba45716a06b89949a2923e1dd531db2eac1'
if ! cosign verify \
    --certificate-identity https://github.com/njvenis/volt/.github/workflows/release.yml@refs/heads/main \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com \
    "$VOLT_RELEASE_IMAGE"; then
  echo 'Image signature verification failed; do not pull or initialize' >&2
  exit 1
fi
if ! docker pull --platform linux/amd64 "$VOLT_RELEASE_IMAGE"; then echo 'Image pull failed; do not initialize' >&2; exit 1; fi
if ! python3 setup.py init /var/lib/volt/demo --mode demo --project volt-demo --image "$VOLT_RELEASE_IMAGE"; then echo 'Initialization failed; stop' >&2; exit 1; fi
if ! python3 setup.py start /var/lib/volt/demo; then echo 'Startup failed; stop' >&2; exit 1; fi
```

Continue with the extracted bundle README to link the synthetic administrator and explicitly initialize authority. The demo uses synthetic identity and loopback ingress. For external OIDC, follow the separate external-mode instructions and operate the required identity-sync publisher. Do not expose the upstream or recovery port publicly. Configure host TLS at the reverse proxy and use the exact HTTPS callback and trusted origins.

### Install offline

The signed archive's verification procedure can load its image without a registry pull. Use the signed manifest's `image_id` (local Docker image/config ID) as the `--image` value:

```sh
# Return from volt-compose-0.1.0-rc.2 to volt-rc2-release.
if ! cd ..; then echo 'Cannot return to release directory' >&2; exit 1; fi
if ! python3 volt-rc2-verifier/tools/release/archive.py verify \
    --archive volt-0.1.0-rc.2-linux-amd64.tar.gz --cosign cosign \
    --source-sha 0af679d77754060f2f89368830a92ddb6e3f2122 \
    --image-id sha256:09412fdcda1a77a6182829061e202f83e767f8cfaecce2cc5b3e9443c3c35461; then
  echo 'Signed archive verification failed; do not load or extract' >&2
  exit 1
fi
if ! python3 volt-rc2-verifier/tools/release/archive.py load \
    --archive volt-0.1.0-rc.2-linux-amd64.tar.gz --cosign cosign; then
  echo 'Image archive verification or load failed; do not initialize' >&2
  exit 1
fi
if ! tar -xOf volt-0.1.0-rc.2-linux-amd64.tar.gz volt-compose.tar.gz > volt-compose-embedded.tar.gz; then echo 'Cannot read authenticated bundle member' >&2; exit 1; fi
if ! cmp volt-compose.tar.gz volt-compose-embedded.tar.gz; then echo 'Standalone bundle differs from the authenticated archive; stop' >&2; exit 1; fi
if ! sha256sum -c volt-compose.tar.gz.sha256; then echo 'Bundle checksum failed; stop' >&2; exit 1; fi
if ! tar -xzf volt-compose.tar.gz; then echo 'Bundle extraction failed; stop' >&2; exit 1; fi
if ! tar -xOf volt-0.1.0-rc.2-linux-amd64.tar.gz manifest.json > manifest.json; then echo 'Cannot read verified manifest' >&2; exit 1; fi
if ! image_id="$(python3 -c 'import json; print(json.load(open("manifest.json"))["image_id"])')" || [ -z "$image_id" ]; then echo 'Cannot obtain signed local image ID' >&2; exit 1; fi
if ! cd volt-compose-0.1.0-rc.2; then echo 'Expected versioned bundle directory is missing' >&2; exit 1; fi
if ! python3 setup.py init /var/lib/volt/demo --mode demo --project volt-demo --image "$image_id"; then echo 'Initialization failed; stop' >&2; exit 1; fi
if ! python3 setup.py start /var/lib/volt/demo; then echo 'Startup failed; stop' >&2; exit 1; fi
```

`image_id` is a local image identity, distinct from the registry digest in `VOLT_RELEASE_IMAGE`. For a complete offline flow, extract the signed `manifest.json` and Compose bundle as described in the archive's `VERIFY.txt`; verify the bundle checksum after the outer archive has authenticated it. Do not substitute the registry digest for `--image` after `docker load`.

This is a local evaluation installation path, not production-readiness evidence or a general migration, upgrade, backup-retention, or independent-host recovery procedure. See [backup and restore limits](../deploy/compose/backup-restore.md).

## Historical RC1 launcher

RC1 remains a separate, immutable launcher-only evaluation release. It does not implement the RC2 Compose contract or external-OIDC mode split. The instructions below reproduce that historical launcher path.

VOLT `0.1.0-rc.1` supports fresh Linux/amd64 installations with synthetic data and a local synthetic OIDC provider. It does not upgrade historical development volumes or establish production readiness. The launcher binds the UI/API and identity provider to loopback; run the browser on the same host. Do not expose this preview publicly or supply production credentials.

The [RC1 release](https://github.com/njvenis/volt/releases/tag/v0.1.0-rc.1) is the canonical source for artifacts and verification evidence. This guide runs the published image without rebuilding it. For a source build, use [the development preview guide](local-preview.md).

### Prerequisites

- A Linux/amd64 Docker Engine environment and permission to use its daemon.
- Git, Python 3.13+, OpenSSL, Node.js and npm. RC1's development tooling pins Node.js 24.21.0.
- Cosign, installed from a trusted distribution, for registry signature verification.
- The lockfile-pinned Playwright package and matching Chromium, installed below, plus Chromium's host runtime dependencies.
- Free loopback ports 8180 and 8190, and disk space for the image, checkout, browser, persistent volumes and evidence. The compressed offline bundle alone is about 2.06 GB; allow additional space for extraction and Docker storage.
- Network access to GitHub, GHCR, npm, the Playwright browser distribution and signature verification services for the online path.

### 1. Obtain the exact launcher source

Run the commands in order in one shell. Use a new directory and retain this checkout for the instance's lifecycle.

```sh
git clone --branch v0.1.0-rc.1 --single-branch https://github.com/njvenis/volt.git volt-rc1
cd volt-rc1
git checkout --detach d6e7868091839fcf1374b45397d2aa2c5964f97c
test "$(git rev-parse HEAD)" = d6e7868091839fcf1374b45397d2aa2c5964f97c
test -z "$(git status --porcelain)"
npm --prefix ui ci
(cd ui && npx playwright install chromium)
```

Stop if any command fails. If Playwright reports missing system libraries, install the dependencies it identifies for your host before continuing. The npm packages and browser support the evaluation smoke test; these commands do not build the application image. Do not edit the checkout: the launcher requires a committed, clean revision.

### 2. Verify and pull the released image

The expected signing identity is the release workflow on `main`, not the tag ref. A failed verification must stop installation.

```sh
VOLT_RC1_IMAGE='ghcr.io/njvenis/volt@sha256:c0c49bc9c38a0ea946d1868748fcaadbf9e7e79dfd50b24d2b276c83c4d18497'
cosign verify \
  --certificate-identity https://github.com/njvenis/volt/.github/workflows/release.yml@refs/heads/main \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  "$VOLT_RC1_IMAGE" && \
docker pull --platform linux/amd64 "$VOLT_RC1_IMAGE"
```

The version tag is `ghcr.io/njvenis/volt:0.1.0-rc.1`; the commands use the immutable registry digest. No registry credentials are required and RC1 has no `latest` tag.

After the verified pull succeeds, obtain the local image ID from that exact digest reference:

```sh
VOLT_RC1_IMAGE_ID="$(docker image inspect --format '{{.Id}}' "$VOLT_RC1_IMAGE")"
test -n "$VOLT_RC1_IMAGE_ID"
```

**The registry digest and local image ID are different identities.** Supply the local config/image ID returned by `docker image inspect` to `--expected-image-id`; do not substitute the registry digest. The launcher independently checks the local ID, source revision, version label and platform before creating resources.

### 3. Initialize, start and sign in

Choose a fresh instance name (`rc1` below). Keep the same name for subsequent commands. If the default ports are occupied, choose unused ports with the two `init` options and use the resulting URL.

```sh
export XDG_STATE_HOME="${XDG_STATE_HOME:-$HOME/.local/state}"
export PREVIEW_EVIDENCE="$PWD/evidence/g7-local-preview/rc1"
python3 tools/g7_local_preview.py init rc1 --api-port 8180 --oidc-port 8190
python3 tools/g7_local_preview.py start rc1 --no-build \
  --expected-image-id "$VOLT_RC1_IMAGE_ID" \
  --expected-image-source-revision d6e7868091839fcf1374b45397d2aa2c5964f97c \
  --expected-image-version 0.1.0-rc.1 \
  --expected-platform linux/amd64
python3 tools/g7_local_preview.py wait rc1
python3 tools/g7_local_preview.py status rc1
python3 tools/g7_local_preview.py link-admin rc1
python3 tools/g7_local_preview.py smoke rc1 --evidence "$PREVIEW_EVIDENCE"
```

Stop and inspect errors before continuing to the next command. `wait` reports `health=healthy` on success. Run `link-admin` only once: it explicitly links the synthetic subject to `volt-local-preview-admin`; repeating it returns a conflict. The initial smoke signs in, establishes the preview policy/authority and creates an audited synthetic access group through the public UI/API.

Open **http://127.0.0.1:8180/** and select **Sign in**. The synthetic provider supplies the local preview identity; no enterprise account or production password is needed. The automated smoke verifies the expected issuer, subject and principal. This provider is only for disposable local evaluation.

`init` creates private secrets and recovery TLS material under `$XDG_STATE_HOME/volt/g7-preview/rc1`. Keep this directory private. The instance owns one container, a private bridge network and three persistent volumes for PostgreSQL, DefectDojo media and VOLT state. A bare `docker run` does not perform this initialization.

### 4. Stop, resume and verify persistence

From the same source checkout, retain the same evidence directory used for the initial smoke:

```sh
python3 tools/g7_local_preview.py stop rc1
python3 tools/g7_local_preview.py restart rc1
python3 tools/g7_local_preview.py wait rc1
python3 tools/g7_local_preview.py smoke rc1 --readback --evidence "$PREVIEW_EVIDENCE"
```

Stop/restart retains state. Readback compares the saved synthetic object, revision and audit evidence. Use `restart` for an existing container, not another `start` or `init`.

RC1 does not support switching an initialized instance to a different image. An interrupted first initialization must resume with the same image binding; missing established resources require investigation rather than automatic recreation. See [operations and troubleshooting](operations.md).

### 5. Remove the evaluation instance

Only when its data is no longer needed:

```sh
python3 tools/g7_local_preview.py destroy rc1
```

**This deletes the instance's three volumes and private configuration.** The helper checks resource ownership and does not prune unrelated Docker resources. The image, source checkout and separately stored smoke evidence remain.

### Offline bundle

The release supplies `volt-0.1.0-rc.1-linux-amd64.tar.gz`, `VERIFY-RELEASE.md`, a signed manifest and signature bundle. Follow **[VERIFY-RELEASE.md](https://github.com/njvenis/volt/releases/download/v0.1.0-rc.1/VERIFY-RELEASE.md)** before extraction or image loading. Independently provision the required Sigstore trust; checksums alone do not authenticate the bundle.

After verification, follow the bundled `launcher-guide.txt` and use its verified manifest values with `start --no-build`. The bundle includes source and the loadable image, but the host still needs the launcher/browser prerequisites. Provision npm dependencies, Chromium and trust material before disconnecting; the image archive alone is not a fully offline host installer.

For configuration and scope, see [configuration](configuration.md), [deployment boundaries](deployment.md), [release evidence](releasing.md) and [security reporting](../SECURITY.md).
