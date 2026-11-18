# Future RC4 installer asset process

This is a release-time procedure for a future RC4 cut. RC3 remains the published Compose release. Nothing in this procedure changes a historical tag or asset, publishes an image, or makes a locally signed fixture a production trust root.

## Build and admit the assets

Start from one reviewed source commit whose Compose package version is `0.1.0-rc.4`. The `Portable checks` workflow runs for pull requests, pushes, and manual checks. Its `verifier-native` and `runtime-native-artifacts` jobs require `uname -m` to match the requested architecture (`ubuntu-24.04`/`x86_64` for amd64 and `ubuntu-24.04-arm`/`aarch64` for arm64); each builds for that native platform. It transfers `runtime.tar` or `verifier.tar`, its SHA-256 sidecar, source commit and source snapshot, and image metadata as a two-day Actions artifact named `volt-easy-rc4-runtime-{amd64,arm64}` or `volt-easy-rc4-verifier-{amd64,arm64}`. The dependent `runtime-local-index` job checks each transfer hash, commit, source snapshot, image labels and platform, then pushes only into its owned `127.0.0.1:46150` registry and verifies both indexes contain exactly one real Linux child per architecture. It retains the raw indexes and child maps as `volt-easy-rc4-local-index-evidence`. It has no registry publication or signing permission and does not qualify a signed installer package or browser journey.

The verifier image digest is selected by the trusted release process and embedded into the signed launcher before any signatures are produced. The launcher does not contain a launcher hash in the descriptor or runtime provenance. This keeps the asset graph acyclic:

1. Configure GitHub environment `volt-rc4-publication` with required human reviewers. A maintainer manually dispatches `.github/workflows/release-rc4.yml` from `main` with the successful push run ID, its exact source SHA, an accepted qualification evidence URI and `publish_approved=true`. The workflow rejects a PR/manual candidate run, an already used tag/release or GHCR tag, missing reviewer protection, and any platform artifact whose transfer hash, source commit/snapshot, image labels or architecture disagree. It pushes amd64/arm64 runtime and verifier children to GHCR, creates both immutable multi-platform indexes, checks the exact child digests, and keylessly signs the indexes with the fixed identity `https://github.com/njvenis/volt/.github/workflows/release-rc4.yml@refs/heads/main` and GitHub Actions OIDC issuer. This workflow is manual and has not been dispatched.
2. Pin the verifier index digest in the launcher before building or signing the bundle.
3. Build the closed RC4 bundle with both immutable references:

   ```sh
   python3 tools/build_compose_bundle.py build \
     --output "$OUT/installer.bundle.tar.gz" \
     --image-reference "$RUNTIME_INDEX_REFERENCE" \
     --verifier-reference "$VERIFIER_INDEX_REFERENCE" \
     --source-root "$APPROVED_SOURCE_ROOT"
   python3 tools/build_compose_bundle.py verify \
     --archive "$OUT/installer.bundle.tar.gz" \
     --source-root "$APPROVED_SOURCE_ROOT" \
     --verifier-reference "$VERIFIER_INDEX_REFERENCE"
   ```

4. Generate the runtime provenance predicate from the admitted source revision/snapshot, runtime index digest, both actual platform child digests, and exact bundle SHA-256. Attach and verify it with the release workflow identity and normal Sigstore transparency checks.
5. Produce the small launcher and its bundle signature. Sign the exact launcher bytes and the exact closed bundle bytes. Do not mutate either after signing.
6. Assemble the outer package from the signed bundle and detached Sigstore bundles:

   ```sh
   python3 tools/release/build_easy_installer.py \
     --output "$OUT/volt-compose-0.1.0-rc.4-installer.tar.gz" \
     --bundle "$OUT/installer.bundle.tar.gz" \
     --launcher-signature "$OUT/launcher.sigstore.json" \
     --bundle-signature "$OUT/installer.bundle.sigstore.json" \
     --verifier-reference "$VERIFIER_INDEX_REFERENCE" \
     --source-root "$APPROVED_SOURCE_ROOT"
   ```

7. Generate the trusted-page bootstrap command with the fixed RC4 signer, OIDC issuer, and the same verifier digest:

   ```sh
   python3 tools/release/easy_bootstrap.py \
     --version 0.1.0-rc.4 \
     --signer 'https://github.com/njvenis/volt/.github/workflows/release-rc4.yml@refs/heads/main' \
     --issuer 'https://token.actions.githubusercontent.com' \
     --verifier-image "$VERIFIER_INDEX_REFERENCE"
   ```

The release workflow constructs the source-bound runtime predicate and verifier SLSA statement, signs and verifies both indexes and attestations, signs the exact launcher and bundle bytes, and runs the packaged independent verifier against the signed bundle, live runtime index and selected native amd64 image before assembling the small package. The bootstrap uses the pinned official Cosign image to verify the launcher and verifier image/provenance before invoking the launcher. The launcher then verifies the bundle and complete runtime graph before archive extraction or candidate helper execution. The local `--local-admission-fixture` path accepts only loopback references and externally provisioned fixture trust; it must never be used to render a public package or choose production policy.

## Acceptance before publication

Run the maintained qualifier with `--auth-mode local --admission-fixture` against the exact signed package and a fresh source-bound two-platform runtime index. Preserve the full command, source/index digests, raw signer/verifier outputs, browser evidence, cleanup, and exits. A sample blob signature, a one-platform image, or a structurally generated bundle does not qualify the installer journey. Do not dispatch a release workflow or publish images until the full admission and lifecycle review has accepted the candidate.

The current local amd64 production verifier measurement is recorded in `docs/compose-install-validation.md`. Re-measure compressed OCI layers for each final architecture/index; Docker's uncompressed image size is a separate value.
