# VOLT installation releases

## RC3 Compose installation

This is the target installation procedure for the planned VOLT `0.1.0-rc.3` evaluation prerelease. Use it only after the RC3 tag, signed archives, bundle and corrected external verification guide have actually been published. It is not a claim that publication has occurred. The planned release targets Docker Engine and Docker Desktop with native Linux `amd64` and `arm64` images. Apple Silicon users should select `linux/arm64`; x86-64 users should select `linux/amd64`. These are Linux container platforms and do not establish a native macOS container runtime. RC3 is not a production deployment.

After publication, the release page is expected to contain a signed offline archive for each platform, a standalone source-free Compose bundle and external release-verification instructions. Use the archive matching the Docker engine where the image will run. A checksum sidecar detects transfer damage; it does not establish who published the files. Do not extract the bundle, load an image, or run any archive-contained helper until the independent verification steps below have succeeded.

### Download the matching release files

Once the release is published, choose the platform explicitly. Keep the signed archive, the standalone bundle and its checksum together until verification is complete:

```sh
export VOLT_RELEASE_TAG=v0.1.0-rc.3
export VOLT_PLATFORM=linux/arm64 # Apple Silicon; use linux/amd64 for x86-64.
case "$VOLT_PLATFORM" in
  linux/arm64) VOLT_ARCH=arm64 ;;
  linux/amd64) VOLT_ARCH=amd64 ;;
  *) echo 'Unsupported VOLT platform' >&2; exit 1 ;;
esac
mkdir -p "$HOME/volt-rc3-release"
export VOLT_RELEASE_DIR="$HOME/volt-rc3-release"
cd "$VOLT_RELEASE_DIR"
gh release download "$VOLT_RELEASE_TAG" --repo njvenis/volt \
  --pattern "volt-0.1.0-rc.3-linux-${VOLT_ARCH}.tar.gz" \
  --pattern volt-compose.tar.gz \
  --pattern volt-compose.tar.gz.sha256 \
  --pattern VERIFY-RELEASE.md
export VOLT_ARCHIVE="$VOLT_RELEASE_DIR/volt-0.1.0-rc.3-linux-${VOLT_ARCH}.tar.gz"
export VOLT_BUNDLE="$VOLT_RELEASE_DIR/volt-compose.tar.gz"
```

The following are the expected permanent asset URLs after publication:

- [RC3 release page](https://github.com/njvenis/volt/releases/tag/v0.1.0-rc.3)
- [Linux/arm64 signed archive](https://github.com/njvenis/volt/releases/download/v0.1.0-rc.3/volt-0.1.0-rc.3-linux-arm64.tar.gz)
- [Linux/amd64 signed archive](https://github.com/njvenis/volt/releases/download/v0.1.0-rc.3/volt-0.1.0-rc.3-linux-amd64.tar.gz)
- [Source-free Compose bundle](https://github.com/njvenis/volt/releases/download/v0.1.0-rc.3/volt-compose.tar.gz)
- [Bundle checksum](https://github.com/njvenis/volt/releases/download/v0.1.0-rc.3/volt-compose.tar.gz.sha256)
- [External verification instructions](https://github.com/njvenis/volt/releases/download/v0.1.0-rc.3/VERIFY-RELEASE.md)

### Verify before extraction or image load

Begin with the independently obtained fixed `v0.1.0-rc.3` repository tag. Follow the corrected `VERIFY-RELEASE.md` to resolve the source SHA from that trusted tag, check out that exact source, provision the pinned Cosign/Sigstore trust, and verify and load the signed archive. Never let an archive field such as `source_commit` select verifier code. The signed archive binds the source, platform image, common multi-platform index, selected-child SPDX/notices and scan evidence. Its `registry_digest`/`image_index_id` identify the multi-platform index; `image_id`/`image_config_id` identify the selected platform image, and `platform_manifest_digest` identifies that platform manifest. Do not treat the index digest as the local Docker image ID. Do not trust a verifier, checksum, signature key or Sigstore root solely because it was included in the downloaded archive. Authenticate the separate bundle below before extracting or executing it.

The planned signed offline archive binds the versioned source bundle and image evidence. After the signed archive verifies (and, for offline installs, after its image is loaded through the trusted helper), authenticate the downloaded standalone bundle against its signed embedded bytes. Keep the trusted `SOURCE_SHA` resolved from the fixed tag in the same shell. The helper must succeed before checksum inspection or extraction; the sidecar checksum only detects transfer damage. The bundle root is expected to be versioned as `volt-compose-0.1.0-rc.3`.

```sh
python3 trusted-source/tools/release/archive.py authenticate-bundle \
  --archive "$VOLT_ARCHIVE" --bundle "$VOLT_BUNDLE" \
  --cosign /tmp/volt-release-tools/cosign --source-sha "$SOURCE_SHA"
tar -xOf "$VOLT_ARCHIVE" volt-compose.tar.gz > "$VOLT_RELEASE_DIR/volt-compose-embedded.tar.gz"
cmp "$VOLT_BUNDLE" "$VOLT_RELEASE_DIR/volt-compose-embedded.tar.gz"
EXPECTED_BUNDLE_SHA="$(awk '{print $1}' "$VOLT_RELEASE_DIR/volt-compose.tar.gz.sha256")"
ACTUAL_BUNDLE_SHA="$(python3 -c 'import hashlib,sys; print(hashlib.sha256(open(sys.argv[1],"rb").read()).hexdigest())' "$VOLT_BUNDLE")"
test "$EXPECTED_BUNDLE_SHA" = "$ACTUAL_BUNDLE_SHA"
mkdir -m 700 -p "$HOME/volt-rc3-bundle"
tar -xzf "$VOLT_BUNDLE" -C "$HOME/volt-rc3-bundle"
cd "$HOME/volt-rc3-bundle/volt-compose-0.1.0-rc.3"
```

For an online install, use the exact registry digest reported by authenticated release metadata, not a mutable tag or a digest copied from an older release. For an offline install, use the local image ID and platform from the verified archive manifest. Keep the registry digest, local Docker image ID, source commit and source snapshot distinct; they identify different objects.

### Install the local password-admin demo

The ordinary install needs Docker Engine with Compose v2, Python 3.11 or newer and OpenSSL command-line tools. The separate verification bootstrap needs Git, the pinned Cosign helper and network access for the trusted fixed source tag and Sigstore trust provisioning; `gh` is used by the download example. An offline image import is possible only after those verifier and trust materials have been provisioned and the archive and bundle authenticated. After verification and extraction, ordinary runtime setup does not require a VOLT source checkout, Git, Node.js, npm or a browser package download. Apple Silicon selects a Linux `arm64` container; macOS Docker Desktop itself has not been exercised. The local demo uses synthetic identity and does not contact Okta; external OIDC login and membership sync require connectivity to the configured issuer/API.

For an online install, after the archive has been authenticated, construct the immutable registry reference from its signed digest and pull the declared platform:

```sh
VOLT_SIGNED_PLATFORM="$(tar -xOf "$VOLT_ARCHIVE" manifest.json | python3 -c 'import json,sys; print(json.load(sys.stdin)["platform"])')"
test "$VOLT_SIGNED_PLATFORM" = "$VOLT_PLATFORM"
VOLT_REGISTRY_DIGEST="$(tar -xOf "$VOLT_ARCHIVE" manifest.json | python3 -c 'import json,sys; print(json.load(sys.stdin)["registry_digest"])')"
python3 -c 'import re,sys; assert re.fullmatch(r"sha256:[0-9a-f]{64}", sys.argv[1])' "$VOLT_REGISTRY_DIGEST"
VOLT_IMAGE="ghcr.io/njvenis/volt@$VOLT_REGISTRY_DIGEST"
docker pull --platform "$VOLT_PLATFORM" "$VOLT_IMAGE"
```

For an offline image import, the corrected `VERIFY-RELEASE.md` first provisions trust and verifies the archive with the pinned verifier. After the bundle-authentication command above succeeds, use the loaded platform image ID and platform from the authenticated manifest:

```sh
VOLT_IMAGE="$(tar -xOf "$VOLT_ARCHIVE" manifest.json | python3 -c 'import json,sys; print(json.load(sys.stdin)["image_id"])')"
VOLT_PLATFORM="$(tar -xOf "$VOLT_ARCHIVE" manifest.json | python3 -c 'import json,sys; print(json.load(sys.stdin)["platform"])')"
```

For either install mode, initialize the local demo from the extracted bundle:

```sh
mkdir -p "$HOME/.local/share/volt"
python3 setup.py init "$HOME/.local/share/volt/demo" --mode demo \
  --project volt-demo --image "$VOLT_IMAGE" --platform "$VOLT_PLATFORM" \
  --bootstrap-principal local-testing-admin \
  --demo-subject local-testing-admin-subject \
  --demo-admin-username local-testing-admin
python3 setup.py start "$HOME/.local/share/volt/demo"
python3 setup.py status "$HOME/.local/share/volt/demo"
```

`init` prompts twice for the local administrator password without echoing it. Use at least 16 characters. The installer stores only a salted scrypt verifier in the private instance directory; it has no default password and does not accept the password in a command argument or environment variable. This account exists only in the labelled demo and authenticates through the local OIDC provider.

Complete the public browser flow in this order. The configured subject must be linked before sign-in; authority setup follows successful password login:

```sh
python3 setup.py link-admin "$HOME/.local/share/volt/demo"
```

Open `http://127.0.0.1:8180/`, choose **Sign in**, and enter the username and password from `init`. After sign-in, use the browser's storage inspector to copy the `uvm_session` cookie. Then initialize demo policy and native authority. The command prompts for the cookie without echoing it; do not paste the value into shell history or a command argument:

```sh
python3 setup.py initialize-authority "$HOME/.local/share/volt/demo"
```

The local provider uses the configured OIDC issuer and subject. The synthetic group mapping caps the access granted by native membership; neither a provider group nor a sign-in alone creates native roles or source scopes. Complete an audited access-group action in the browser and confirm its audit/readback before treating the install journey as exercised.

The app and local provider bind to loopback. To keep the instance and data, use `status`, `stop` and `start`:

```sh
python3 setup.py status "$HOME/.local/share/volt/demo"
python3 setup.py stop "$HOME/.local/share/volt/demo"
python3 setup.py start "$HOME/.local/share/volt/demo"
```

Back up the image identity and all three persistent stores together, following the source-free bundle's [`backup-restore.md`](../deploy/compose/backup-restore.md). `cleanup` without destructive flags retains data. Permanent removal is explicit and verifies ownership of the project's resources:

```sh
python3 setup.py cleanup "$HOME/.local/share/volt/demo" \
  --remove-data --confirm-project volt-demo
```

This removes the private instance secrets and its owned volumes. Never use `docker volume prune` for VOLT cleanup. If startup does not become healthy, inspect `status`, `docker logs volt-demo-volt-1`, Docker Engine health and the admitted image platform. If ports are occupied, initialize a fresh instance with unused `--http-port`, `--recovery-port` and `--oidc-port` values; do not repeat the one-time `link-admin` step on an established instance.

### Optional Okta OIDC evaluation

Follow [the bundle's Okta setup](../deploy/compose/README.md#optional-okta-oidc-evaluation) to configure the login Web app, separate read-only Management API service app, local private files and exact account/group mappings. Use only locally approved role UUIDs and exact source-scope tuples. Effective access is the intersection of current native grants, explicit current Okta group mappings and configured source-scope ceilings. Group removal revokes existing sessions and removes mapped permissions from a fresh sign-in; adding a group never creates native grants. The publisher fails closed when account, assignment, group or heartbeat data is missing or stale. Do not map by email or display name.

These steps configure a local evaluation. They do not demonstrate live Okta compatibility, production hosting, or macOS Docker Desktop execution. The actual tenant administrator must complete and record the real Okta browser login and permission-scoped audited action in their tenant.

<a id="rc2-compose-installation"></a>
## RC2 Compose installation

**Historical immutable release:** RC2 instructions and identities below are retained for reproducibility. For a new evaluation, use [RC3 Compose installation](#rc3-compose-installation). Do not substitute RC3 flags, assets, images or verifier identities into an RC2 procedure.

VOLT `0.1.0-rc.2` was the Linux/amd64 Compose-compatible evaluation image. This historical section preserves its immutable registry reference and verification procedure:

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

RC1 uses its synthetic fixture identity; its immutable helper and image do not support a local username/password account. Open **http://127.0.0.1:8180/** and select **Sign in**. The fixture establishes the configured synthetic subject, and the automated smoke verifies the expected issuer, subject and principal. This is disposable local evaluation, not an enterprise sign-in.

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
