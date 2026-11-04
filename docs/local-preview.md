# Development preview from source

To evaluate the published image without building it, follow [RC1 installation](installation.md). This guide describes source-build development and lower-level launcher behaviour.

This is a local development image preview from the committed source revision and pinned dependencies in `Dockerfile.g7`. It is synthetic local proof, not an Okta, AWS, production, external deployment, or release-gate result. The synthetic provider and bootstrap administrator have no identity outside this disposable preview.

## Requirements

Use Docker, Python 3.13+, OpenSSL, Node/npm, and Playwright's pinned Chromium. The Playwright package version is pinned in `ui/package-lock.json`; install its matching browser from the repository root:

```sh
npm --prefix ui ci
(cd ui && npx playwright install chromium)
```

The smoke uses Playwright's installed Chromium by default. Set `CHROMIUM_EXECUTABLE_PATH` only when using a compatible system Chromium. Choose unused API and OIDC ports. Do not put production credentials or data in the preview. Run these commands from a committed, clean source revision.

## Initialize and start

```sh
export XDG_STATE_HOME="${XDG_STATE_HOME:-$HOME/.local/state}"
export PREVIEW_EVIDENCE="$PWD/evidence/g7-local-preview/demo"
python3 tools/g7_local_preview.py init demo --api-port 8180 --oidc-port 8190
python3 tools/g7_local_preview.py start demo
python3 tools/g7_local_preview.py wait demo
python3 tools/g7_local_preview.py status demo
python3 tools/g7_local_preview.py link-admin demo
python3 tools/g7_local_preview.py smoke demo --evidence "$PREVIEW_EVIDENCE"
```

`init` generates a new cryptographic ownership token, private secrets, and local recovery TLS material under `$XDG_STATE_HOME/volt/g7-preview/demo`. Container, network, and volume names include the token suffix, and their token/resource identifiers are checked before lifecycle operations. The private custom bridge separates the synthetic OIDC provider from unrelated Docker bridge containers. The existing ingress guard accepts only loopback or the exact private-network gateway peer and exact `127.0.0.1`/`localhost` Host values. The helper publishes UVM and synthetic OIDC on loopback only; recovery control remains unpublished.

The default `start` path builds the revision-qualified local image from this clean helper checkout. To start an image loaded from a separately transferred archive without rebuilding, use `start --no-build` and supply its full immutable image ID, expected OCI source revision, version label, and supported platform. The helper checks all four against Docker image inspect before creating any resource, repeats the check immediately before launch, and passes the immutable image ID to `docker run`. The helper checkout must still be the exact clean revision recorded by `init`; its `helper_revision` is tracked separately from the loaded image's `image_source_revision` so a maintained launcher can operate an older immutable image without claiming to be part of that image.

Before creating a container, network or volume, the helper persists the admitted image ID, source revision, version and platform in the instance record. An interrupted initialization can resume only with that exact binding. A partial state with no binding, or an attempted image switch, is refused; destroy the verified owned resources and initialize a new instance. RC1 is for fresh installations and does not adopt historical development volumes.

For example, after loading the image archive, use the verified ID and metadata from its manifest:

```sh
python3 tools/g7_local_preview.py start demo --no-build \
  --expected-image-id sha256:FULL_64_HEX_IMAGE_ID \
  --expected-image-source-revision FULL_40_HEX_SOURCE_REVISION \
  --expected-image-version local-preview \
  --expected-platform linux/amd64
```

This release preview helper currently admits `linux/amd64`. Missing or mismatched image identity, source revision, version, or platform is refused before Docker resource creation.

The helper rejects a symlinked instance directory or `instance.json`, mismatched stored instance names, and private configuration paths outside that instance. An intentionally symlinked `XDG_STATE_HOME` is allowed. During an interrupted first initialization, `start` can complete still-missing resources carrying that initialization's exact ownership token and resource labels. Once a container ID has been recorded, the instance is established: `start`, `stop`, `restart`, `wait`, `link-admin`, and `smoke` require its exact container, private network, and all three volumes. If any established resource is missing, the helper refuses to recreate or rebind it; inspect retained evidence before choosing a recovery path. `destroy` remains available and removes only the still-present resources whose recorded ownership and IDs match.

The smoke command verifies the signed-in session's exact configured issuer, subject, principal, and OIDC mode. It also runs a short-lived peer on the private bridge and requires the middleware's exact `403 ingress_peer_forbidden` response. It opens the actual administration page, waits for the loaded view and enabled create control, performs the bounded public API operation, refreshes the page, and requires the created object to render. The command receipt must match the requested action, target, object, revision, and audit event. Public history must contain the exact receipt audit ID and actor. Browser captures, receipt, public readback, and smoke state are written to the evidence directory.

The synthetic login subject is `volt-local-preview-admin-subject`, linked once to `volt-local-preview-admin` by the single documented `link-admin` command. Do not repeat that link command for an already linked preview; the API returns a conflict instead of silently treating an arbitrary 409 as success. Initial policy and native authority are established through the supported browser/API workflow. No product tables are edited directly.

## Persistence and cleanup

The instance owns three persistent volumes for PostgreSQL, DefectDojo media, and UVM state, plus one isolated bridge network. `stop` and `restart` preserve the container and data. After restart, the readback smoke signs in again, verifies the loaded administration view, and compares the same public object, revision, audit ID, actor, and full audit after-value saved by the initial smoke.

```sh
python3 tools/g7_local_preview.py stop demo
python3 tools/g7_local_preview.py restart demo
python3 tools/g7_local_preview.py wait demo
python3 tools/g7_local_preview.py smoke demo --readback --evidence "$PREVIEW_EVIDENCE"
python3 tools/g7_local_preview.py destroy demo
```

`destroy` first verifies the exact container ID, ownership token and creation labels for every existing target, then removes only that instance's container, three volumes, private network, and local private configuration. It never prunes Docker resources. Keep the evidence directory after destruction. The exact-SHA image remains locally available and can be removed separately by its full preview tag if desired.

A preview remains persistent until `destroy` is run. The helper uses no production provider, external network service, G7 test clock, fault-injection flag, registry, or external deployment.
