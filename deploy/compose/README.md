# VOLT Compose installation bundle

This bundle installs an existing VOLT supervised image. It does not clone VOLT source, install Node.js, run npm, or build the application. Bundle version is in `VERSION`; the archive manifest covers every installation file. Runtime prerequisites are Docker Engine with Compose v2, Python 3.11+, OpenSSL, and an admitted platform image. Use the platform-specific image/archive supplied for your machine; do not rely on emulation as proof of native support.

The default Compose profile uses external OIDC. The local synthetic demo requires the explicit `demo` overlay. Demo identity is generated and labelled as synthetic; it does not establish Okta, AWS, or production integration. For online installs, supply the digest-pinned release image reference printed in this bundle; for offline installs, use the verified local image ID described below. RC1 remains a historical launcher-only release and is rejected by this Compose bundle.

## Verify and initialize

Verify the release/archive signature and its bundle identity using the release's external verification instructions before extracting it. A sidecar checksum only detects transfer damage; by itself it does not authenticate the publisher. Keep the extracted bundle and instance directory private and retain both for the full lifecycle.

### macOS/Linux local demo

The demo is intended for disposable local evaluation with synthetic identity and data. On macOS, install Docker Desktop and wait for its engine to become ready. On Linux, use Docker Engine with the Compose v2 plugin. Both platforms need Python 3.11+ and OpenSSL. Use a fresh directory under your home folder; no shell needs root privileges:

```sh
mkdir -p "$HOME/volt-evaluation"
cd "$HOME/volt-evaluation"
# Put the verified, extracted Compose bundle in this directory first.
export VOLT_PLATFORM=linux/arm64 # Apple Silicon; use linux/amd64 for an x86-64 host.
docker pull --platform "$VOLT_PLATFORM" VOLT_RELEASE_IMAGE_REFERENCE
python3 setup.py init "$HOME/.local/share/volt/demo" --mode demo \
  --project volt-demo --image VOLT_RELEASE_IMAGE_REFERENCE --platform "$VOLT_PLATFORM" \
  --bootstrap-principal local-testing-admin \
  --demo-subject local-testing-admin-subject
python3 setup.py start "$HOME/.local/share/volt/demo"
python3 setup.py status "$HOME/.local/share/volt/demo"
```

Use the platform declared by the verified package manifest and pull/load that same platform. The installer compares it with Docker's inspected image OS/architecture, records it in the instance, and pins Compose to it. For example, `docker pull --platform "$VOLT_PLATFORM" VOLT_RELEASE_IMAGE_REFERENCE`; on Apple Silicon use the native `linux/arm64` artifact. For a verified offline archive, use its local image ID plus the `platform` value from its signed manifest. The installer binds the app and demo identity provider to loopback. Open `http://127.0.0.1:8180/`, choose **Sign in**, and use the synthetic sign-in offered by the local provider. This is a named synthetic OIDC identity, not a password account, Okta login, or production identity. No password is created or stored. `--bootstrap-principal` and `--demo-subject` are stable local test IDs; omit both to use the documented defaults. The exact configured subject is linked once by the next command.

```sh
python3 setup.py link-admin "$HOME/.local/share/volt/demo"
```

After sign-in, copy the `uvm_session` cookie value from the browser's storage inspector. Then initialise the demo's initial policy and native authority using the hidden prompt (the value is not echoed or passed in shell arguments):

```sh
python3 setup.py initialize-authority "$HOME/.local/share/volt/demo"
```

This command checks that the session belongs to the configured bootstrap principal and performs a permission-scoped readback. Complete an audited administration action in the browser and confirm its readback before treating the demo journey as exercised. Keep the instance directory: it contains generated keys and secrets with mode `0600`, and the directory is mode `0700`. Do not commit or share it.

To stop while preserving the instance and data, run `python3 setup.py stop "$HOME/.local/share/volt/demo"`. `start` resumes that exact instance. `cleanup` without flags stops and retains data. Permanent removal requires `python3 setup.py cleanup "$HOME/.local/share/volt/demo" --remove-data --confirm-project volt-demo`; this deletes the instance secrets and its owned volumes. Never use `docker volume prune` for this lifecycle.

If startup does not become healthy, stop and inspect `python3 setup.py status`, `docker logs volt-demo-volt-1`, Docker Desktop/Engine health, and whether the selected image matches the host platform. If default ports are occupied, choose unused `--http-port`, `--recovery-port`, and `--oidc-port` values during `init`; the helper checks them before creating resources. If the admin link was already created, do not repeat it: it is intentionally one-time and auditable. If authority initialisation rejects the session, sign in as the configured principal and retry with the current session cookie.

For a demo, use a fresh project and instance path as shown above. The demo issuer and subject are fixed by the generated local configuration; `link-admin` links that exact synthetic subject to the selected bootstrap principal using the protected operator credential inside the container. The provider is only published on loopback. Use `--http-port`, `--recovery-port`, and `--oidc-port` at initialization when those defaults are occupied.

For external OIDC, prepare a config based on [`oidc.example.json`](oidc.example.json), set the exact application callback and trusted origins, and provide the client secret as a private file. Pull the same digest-pinned release image shown in `VOLT_RELEASE_IMAGE_REFERENCE`, then initialize using that reference:

For an Okta evaluation, create an **OIDC Web Application** integration and enable the **Authorization Code** flow. Assign only the evaluation users/group. Set its sign-in redirect URI to the exact HTTPS callback, `https://<your-host>/api/v1/auth/callback`; the callback host must also be included exactly in `--allowed-hosts`. Use your Okta authorization server's exact issuer URI and its discovery URL (commonly `<issuer>/.well-known/openid-configuration`), the generated client ID, and the client secret in a regular private file outside the extracted bundle and source control. Okta must be able to reach the HTTPS callback through a trusted TLS endpoint; the app upstream remains loopback-bound. Configure `oidc.json` from the example with those exact values and trusted HTTPS origins, then pass its path and secret-file path to `init`. See [Okta's OIDC web app setup](https://developer.okta.com/blog/integrator-setup) and [authorization-code flow](https://developer.okta.com/docs/guides/implement-grant-type/-/main/).

For the external command below, set `VOLT_PLATFORM` to the platform in the verified package manifest (for example, `linux/arm64` on Apple Silicon) and pull that platform explicitly. The client-secret file must be mode `0600`; do not paste its value into a command or config file.

This config enables protocol setup only. Real external authorization is not ready from OIDC alone: VOLT requires a separately operated trusted identity-sync publisher with fresh, monotonic membership snapshots and approved group-to-role/source-scope mappings. Missing, stale, or contradictory membership keeps authorization unavailable. This Compose bundle does not implement that publisher or choose organisational roles/scopes. Until that dependency is implemented and exercised, treat Okta config/protocol checks as synthetic validation and do not claim a usable Okta evaluation. After it exists, use the exact callback, link the exact Okta `iss` and stable `sub` (not email/display name), initialise authority, then perform and record a real browser sign-in and permission-scoped audited action.

```sh
export VOLT_PLATFORM=linux/arm64 # Replace with the verified package platform.
docker pull --platform "$VOLT_PLATFORM" VOLT_RELEASE_IMAGE_REFERENCE
python3 setup.py init /var/lib/volt/evaluation --mode external --image VOLT_RELEASE_IMAGE_REFERENCE --platform "$VOLT_PLATFORM" \
  --project volt-evaluation --external-config ./oidc.json \
  --client-secret-file ./oidc-client-secret \
  --bootstrap-principal volt-admin \
  --allowed-hosts volt.example.org
python3 setup.py start /var/lib/volt/evaluation
python3 setup.py link-admin /var/lib/volt/evaluation \
  --issuer https://id.example.org/ --subject 'provider-stable-subject' \
  --rationale 'Approved evaluation bootstrap' \
  --evidence-ref change-123
```

For an offline install, first verify and load the signed release archive using its `VERIFY.txt` instructions. Initialize with the loaded local Docker image ID from the archive's signed `manifest.json` `image_id` field, for example:

```sh
VOLT_IMAGE_ID="$(python3 -c 'import json; print(json.load(open("manifest.json"))["image_id"])')"
VOLT_PLATFORM="$(python3 -c 'import json; print(json.load(open("manifest.json"))["platform"])')"
python3 setup.py init "$HOME/.local/share/volt/demo" --mode demo --project volt-demo \
  --image "$VOLT_IMAGE_ID" --platform "$VOLT_PLATFORM" \
  --bootstrap-principal local-testing-admin --demo-subject local-testing-admin-subject
```

Use the `image_id` and `platform` values as-is from the authenticated archive manifest. The image ID is the local Docker image ID, distinct from the registry digest used by the online pull command above. The installer rejects a platform value that differs from Docker inspection.

After the exact subject is linked, sign in through the configured browser callback, copy that session's `uvm_session` cookie value using the browser storage inspector, and run `python3 setup.py initialize-authority /var/lib/volt/evaluation`. The command accepts the cookie only at a hidden terminal prompt and forwards it over stdin to the container. It rejects any session whose principal differs from `--bootstrap-principal`. This explicit operator step initializes policy/native authority and verifies permission-scoped readback; browser smoke does not establish authority.

Use the exact OIDC issuer and subject from the identity provider; email and display names do not establish identity. The link-admin command is one-time and auditable. Configure a TLS reverse proxy on the host and set the callback to its HTTPS origin. The Compose upstream is bound to loopback. The application does not treat forwarded host or protocol headers as authority. The proxy must preserve the configured Host and callback; do not expose the upstream or recovery port publicly. Do not put secrets in the config JSON.

External mode also requires a separate trusted identity-sync integration. OIDC claims prove the authenticated issuer and subject; they do not establish current source-account membership, revocation state, or permission scope. The provider-specific publisher must authenticate with the configured sync secret, send the configured provider ID, publish strictly monotonic snapshots, and refresh its heartbeat within `heartbeat_max_age_seconds`. The snapshot DTO carries provider ID and revision, not a mapping-revision attestation; mapping revision comes from the admitted server configuration. Revocations must appear in a newer complete snapshot. Missing, stale, regressed, or contradictory snapshots keep identity authorization unavailable. Do not derive snapshots from ID tokens or expose the loopback sync adapter outside the application boundary. The integration owner must implement and operate this publisher before real evaluation; the generic Compose installer does not supply one.

Setup generates private database, application, OIDC synchronization/operator and recovery TLS secrets. For external mode it copies the supplied OIDC client secret into the private instance directory. Back up these files with the image identity and all three persistent volumes; losing encryption keys can make retained data unreadable. Files on the host are plaintext protected by mode `0600` and directory mode `0700`.
The recovery bundle includes a host-held client certificate and private key at `secrets/recovery-client.crt` and `secrets/recovery-client.key`; keep the key mode `0600`. The temporary CA private key is deleted after issuing the server and client leaves. Recovery remains loopback-bound and is not a public ingress endpoint.

## Lifecycle

`stop` stops the single supervised container while retaining its container, network and all three volumes. `start` resumes the exact admitted image and verifies resource owner labels before touching Docker. `cleanup` without flags is retaining. Destructive cleanup requires `--remove-data --confirm-project <exact-project>`; it verifies the instance owner token on every extant container, network and volume before removal. Never run `docker volume prune` for VOLT lifecycle management.

Initialization refuses an existing instance path or existing Compose resource names. It never overwrites a secret, changes an OIDC config silently, adopts a volume, or changes the admitted image. A changed image requires a separately reviewed migration/upgrade process; restoring an older image does not roll back schema state.

See [`backup-restore.md`](backup-restore.md) for the bounded cold backup and restore procedure and its limits. This bundle is a local evaluation installation path, not production-ready deployment evidence.
