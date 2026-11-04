# Install RC1 for local evaluation

VOLT `0.1.0-rc.1` supports fresh Linux/amd64 installations with synthetic data and a local synthetic OIDC provider. It does not upgrade historical development volumes or establish production readiness. The launcher binds the UI/API and identity provider to loopback; run the browser on the same host. Do not expose this preview publicly or supply production credentials.

The [RC1 release](https://github.com/njvenis/volt/releases/tag/v0.1.0-rc.1) is the canonical source for artifacts and verification evidence. This guide runs the published image without rebuilding it. For a source build, use [the development preview guide](local-preview.md).

## Prerequisites

- A Linux/amd64 Docker Engine environment and permission to use its daemon.
- Git, Python 3.13+, OpenSSL, Node.js and npm. RC1's development tooling pins Node.js 24.21.0.
- Cosign, installed from a trusted distribution, for registry signature verification.
- The lockfile-pinned Playwright package and matching Chromium, installed below, plus Chromium's host runtime dependencies.
- Free loopback ports 8180 and 8190, and disk space for the image, checkout, browser, persistent volumes and evidence. The compressed offline bundle alone is about 2.06 GB; allow additional space for extraction and Docker storage.
- Network access to GitHub, GHCR, npm, the Playwright browser distribution and signature verification services for the online path.

## 1. Obtain the exact launcher source

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

## 2. Verify and pull the released image

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

## 3. Initialize, start and sign in

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

## 4. Stop, resume and verify persistence

From the same source checkout, retain the same evidence directory used for the initial smoke:

```sh
python3 tools/g7_local_preview.py stop rc1
python3 tools/g7_local_preview.py restart rc1
python3 tools/g7_local_preview.py wait rc1
python3 tools/g7_local_preview.py smoke rc1 --readback --evidence "$PREVIEW_EVIDENCE"
```

Stop/restart retains state. Readback compares the saved synthetic object, revision and audit evidence. Use `restart` for an existing container, not another `start` or `init`.

RC1 does not support switching an initialized instance to a different image. An interrupted first initialization must resume with the same image binding; missing established resources require investigation rather than automatic recreation. See [operations and troubleshooting](operations.md).

## 5. Remove the evaluation instance

Only when its data is no longer needed:

```sh
python3 tools/g7_local_preview.py destroy rc1
```

**This deletes the instance's three volumes and private configuration.** The helper checks resource ownership and does not prune unrelated Docker resources. The image, source checkout and separately stored smoke evidence remain.

## Offline bundle

The release supplies `volt-0.1.0-rc.1-linux-amd64.tar.gz`, `VERIFY-RELEASE.md`, a signed manifest and signature bundle. Follow **[VERIFY-RELEASE.md](https://github.com/njvenis/volt/releases/download/v0.1.0-rc.1/VERIFY-RELEASE.md)** before extraction or image loading. Independently provision the required Sigstore trust; checksums alone do not authenticate the bundle.

After verification, follow the bundled `launcher-guide.txt` and use its verified manifest values with `start --no-build`. The bundle includes source and the loadable image, but the host still needs the launcher/browser prerequisites. Provision npm dependencies, Chromium and trust material before disconnecting; the image archive alone is not a fully offline host installer.

For configuration and scope, see [configuration](configuration.md), [deployment boundaries](deployment.md), [release evidence](releasing.md) and [security reporting](../SECURITY.md).
