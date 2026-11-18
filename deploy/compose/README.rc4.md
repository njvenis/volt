# VOLT Compose local installer — 0.1.0-rc.4 source package

VOLT `0.1.0-rc.4` is a future candidate, not a published release. RC3 remains the latest published Compose package. Do not infer that an RC4 source bundle built locally is signed, released, supported for production, or ready to run.

A future signed standalone installer package will contain `launcher.sh`, `installer.bundle.tar.gz`, and detached Sigstore bundles for the launcher and installer archive. The independently authenticated release page will pin the official Cosign and verifier image digests plus the fixed RC4 workflow identity. Run only the complete bootstrap command from that trusted page; it verifies the launcher and verifier image before invoking the launcher. Running `launcher.sh` directly is unsupported.

The host launcher requires Docker Engine and Compose v2. It authenticates the inner installer and immutable runtime before executing runtime helpers. It uses only POSIX shell, Docker, and Compose on the host; Python and OpenSSL are invoked inside the verified runtime. The installer does not mount a Docker socket into any container.

The independent verification image is an additional download. A native `linux/amd64` production-target verifier build measured 105,296,038 bytes as Docker's uncompressed image size. Its loopback-registry OCI manifest reported 105,286,740 compressed layer bytes and 105,296,038 total bytes including the image config and manifest descriptors. This measurement is for that local amd64 build; it does not claim a published RC4 image or an arm64 transfer size. The downloadable source package itself does not contain this verifier image.

The first local account is claimed in the browser at the loopback setup URL. The one-use capability is shown only on a controlling terminal; unattended operation reports a mode-0600 private file path. Additional accounts are created with the `account create-account` command and receive a one-use enrolment capability. Local auth uses persistent VOLT accounts and a one-hour absolute session lifetime. The synthetic identity provider is not started.

Only fresh Linux/amd64 and Linux/arm64 Compose installations are intended. Loopback HTTP is the only implemented ingress for this candidate; server HTTPS configuration, desktop portability qualification, native scanner integration, and cross-version upgrades are not claimed. Back up the PostgreSQL, media, and state stores together while stopped. Recovery capabilities must be revoked before ingress is restored.

This source bundle is not an upgrade package. Preserve RC3 and all existing installations; do not use it to replace historical assets or mutate published releases.

Authenticated runtime reference: `VOLT_RELEASE_IMAGE_REFERENCE`
