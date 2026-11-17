# VOLT Compose installation bundle

This bundle installs an existing VOLT supervised image. It does not clone VOLT source, install Node.js, run npm, or build the application. Bundle version is in `VERSION`; the archive manifest covers every installation file. Host prerequisites are Docker Engine with Compose v2, Python 3.11 or newer, OpenSSL CLI (used by the installer to generate local TLS keys and certificates), and an admitted platform image. Use the platform-specific image/archive supplied for your machine; do not rely on emulation as proof of native support.

The default Compose profile uses external OIDC. The local synthetic demo requires the explicit `demo` overlay. Demo identity is generated and labelled as synthetic; it does not establish Okta, AWS, or production integration. For online installs, supply the digest-pinned release image reference printed in this bundle; for offline installs, use the verified local image ID described below. RC1 remains a historical launcher-only release and is rejected by this Compose bundle.

## Verify and initialize

Verify the release/archive signature and its bundle identity using the release's external verification instructions before extracting it. A sidecar checksum only detects transfer damage; by itself it does not authenticate the publisher. Keep the extracted bundle and instance directory private and retain both for the full lifecycle.

### macOS/Linux local demo

The demo is intended for disposable local evaluation with synthetic data and a password-authenticated local testing administrator. On macOS, install Docker Desktop and wait for its engine to become ready. On Linux, use Docker Engine with the Compose v2 plugin. On either platform, install Python 3.11 or newer and the OpenSSL command-line tools. Use a fresh directory under your home folder; no shell needs root privileges:

The local provider, username/password login and synthetic identity sync run on the machine; the demo does not need an Okta tenant or external identity service. An online image pull needs registry access. A verified offline bundle and loaded image can be installed without a source checkout, Node.js, npm, or an Okta connection.

`init` asks twice for the local account password with hidden terminal prompts. Choose at least 16 characters. It stores only a randomly salted scrypt verifier in the private instance directory; no default password exists. This username/password is for the disposable local demo only. The local provider issues the configured OIDC issuer/subject after successful sign-in, so the normal subject link, session, membership, policy and audit checks still apply.

Sign-in failures use the same response for an unknown username and an incorrect password. The local provider rate-limits after ten failed attempts from one client address within five minutes.

```sh
mkdir -p "$HOME/volt-evaluation"
cd "$HOME/volt-evaluation"
# Put the verified, extracted Compose bundle in this directory first.
export VOLT_PLATFORM=linux/arm64 # Apple Silicon; use linux/amd64 for an x86-64 host.
docker pull --platform "$VOLT_PLATFORM" VOLT_RELEASE_IMAGE_REFERENCE
python3 setup.py init "$HOME/.local/share/volt/demo" --mode demo \
  --project volt-demo --image VOLT_RELEASE_IMAGE_REFERENCE --platform "$VOLT_PLATFORM" \
  --bootstrap-principal local-testing-admin \
  --demo-subject local-testing-admin-subject \
  --demo-admin-username local-testing-admin
python3 setup.py start "$HOME/.local/share/volt/demo"
python3 setup.py status "$HOME/.local/share/volt/demo"
```

Use the platform declared by the verified package manifest and pull/load that same platform. The installer compares it with Docker's inspected image OS/architecture, records it in the instance, and pins Compose to it. For example, `docker pull --platform "$VOLT_PLATFORM" VOLT_RELEASE_IMAGE_REFERENCE`; on Apple Silicon use the native `linux/arm64` artifact. For a verified offline archive, use its local image ID plus the `platform` value from its signed manifest. The installer binds the app and local identity provider to loopback. `--bootstrap-principal`, `--demo-subject` and `--demo-admin-username` are explicit local test identifiers; the first two must remain stable for the instance. The browser login is available only after the exact configured subject has been linked to the bootstrap principal. Complete the steps in this order: start the instance, link the local demo subject, sign in with the configured username/password, then initialise authority.

```sh
python3 setup.py link-admin "$HOME/.local/share/volt/demo"
```

Now open `http://127.0.0.1:8180/`, choose **Sign in**, and enter the username and password selected during `init`. The local provider issues the stable configured OIDC subject after verifying the scrypt password hash. After sign-in, copy the `uvm_session` cookie value from the browser's storage inspector. Then initialise the demo's initial policy and native authority using the hidden prompt (the value is not echoed or passed in shell arguments):

```sh
python3 setup.py initialize-authority "$HOME/.local/share/volt/demo"
```

This command checks that the session belongs to the configured bootstrap principal and performs a permission-scoped readback. Complete an audited administration action in the browser and confirm its readback before treating the demo journey as exercised. Keep the instance directory: it contains generated keys and secrets with mode `0600`, and the directory is mode `0700`. Do not commit or share it.

To stop while preserving the instance and data, run `python3 setup.py stop "$HOME/.local/share/volt/demo"`. `start` resumes that exact instance. `cleanup` without flags stops and retains data. Permanent removal requires `python3 setup.py cleanup "$HOME/.local/share/volt/demo" --remove-data --confirm-project volt-demo`; this deletes the instance secrets and its owned volumes. Never use `docker volume prune` for this lifecycle.

If startup does not become healthy, stop and inspect `python3 setup.py status`, `docker logs volt-demo-volt-1`, Docker Desktop/Engine health, and whether the selected image matches the host platform. If default ports are occupied, choose unused `--http-port`, `--recovery-port`, and `--oidc-port` values during `init`; the helper checks them before creating resources. If the admin link was already created, do not repeat it: it is intentionally one-time and auditable. If authority initialisation rejects the session, sign in as the configured principal and retry with the current session cookie.

For a demo, use a fresh project and instance path as shown above. The demo issuer and subject are fixed by the generated local configuration; `link-admin` links that exact local OIDC subject to the selected bootstrap principal using the protected operator credential inside the container. The provider is only published on loopback. Use `--http-port`, `--recovery-port`, and `--oidc-port` at initialization when those defaults are occupied.

For external OIDC, prepare `oidc.json` from [`oidc.example.json`](oidc.example.json). The following steps configure Okta OIDC login and its separate read-only membership publisher. They make no tenant request until the container starts.

1. In Okta, create an **OIDC Web Application** integration with the **Authorization Code** flow, assign only the evaluation users/group, and set the sign-in redirect URI to the exact HTTPS callback `https://<your-host>/api/v1/auth/callback`. Configure the TLS endpoint so Okta can reach it; the Compose upstream remains loopback-bound. Set `oidc.json`'s `issuer`, discovery URL, `client_id`, exact callback, and trusted HTTPS origins from this login app. Put its client secret in a regular host file with mode `0600`, outside the extracted bundle and source control.
2. Create a separate **API Services** OAuth service app for the publisher. Register its public signing key and use `private_key_jwt` with the Client Credentials grant. Grant only `okta.apps.read`, `okta.users.read`, and `okta.groups.read`; assign an appropriately restricted read-only admin role/resource set that can read this OIDC app's assignments, the assigned users' state, and group memberships. Scope grants and admin-resource assignment are both required; do not enable the setting that automatically grants service apps Super Admin. Okta's [service-app OAuth guide](https://developer.okta.com/docs/guides/implement-oauth-for-okta-serviceapp/), [permissions catalog](https://developer.okta.com/docs/api/openapi/okta-management/guides/permissions), [Applications API](https://developer.okta.com/docs/api/openapi/okta-management/management/tags/application), [Users API](https://developer.okta.com/docs/api/openapi/okta-management/management/tags/user) and [Groups API](https://developer.okta.com/docs/api/openapi/okta-management/management/tags/group) describe the available setup and reads.
3. The login issuer and Management API token issuer are distinct settings. `oidc.json` uses the issuer selected for user sign-in (often `https://<org>/oauth2/default`). The publisher uses the Okta org Management API issuer `https://<org>/oauth2/v1` to obtain scoped API tokens, and reads `https://<org>/api/v1`. Set the same exact org origin in `oidc.json`'s trusted endpoint origins. Put the service app's private key in a host file with mode `0600`; the publisher uses `private_key_jwt`, so it does not need a service-app client secret.
4. Configure explicit mappings. In `oidc.json`, set an approved provider ID, `source_scope_ceilings`, and `group_mappings` from each exact Okta group ID to already-approved role IDs and source-scope tuples within those ceilings. In [`okta-publisher.example.json`](okta-publisher.example.json), set the same provider ID and group IDs, the Okta Web App ID, API service-app client ID/key ID, and `subject_by_user_id` from exact Okta user IDs to the stable `sub` values produced by the configured login issuer. Do not map by email or display name. Keep the example poll interval (30 seconds) and heartbeat maximum age (120 seconds), or preserve at least three polling intervals within the freshness limit.

Set `VOLT_PLATFORM` to the platform in the verified package manifest (for example, `linux/arm64` on Apple Silicon) and pull that platform. The key path in the publisher example must point to the host private key; the installer copies it into the private instance directory and rewrites it to the container mount. The client secret and private key values are never passed in command arguments or environment variables.

```sh
export VOLT_PLATFORM=linux/arm64 # Replace with the verified package platform.
docker pull --platform "$VOLT_PLATFORM" VOLT_RELEASE_IMAGE_REFERENCE
python3 setup.py init /var/lib/volt/evaluation --mode external --image VOLT_RELEASE_IMAGE_REFERENCE --platform "$VOLT_PLATFORM" \
  --project volt-evaluation --external-config ./oidc.json \
  --client-secret-file ./oidc-client-secret \
  --okta-publisher-config ./okta-publisher.json \
  --bootstrap-principal volt-admin \
  --allowed-hosts volt.example.org
python3 setup.py start /var/lib/volt/evaluation
python3 setup.py status /var/lib/volt/evaluation
```

Validate the admitted publisher configuration locally inside the running image without contacting Okta:

```sh
docker compose -f /path/to/verified/compose-bundle/compose.yaml \
  --env-file /var/lib/volt/evaluation/.env -p volt-evaluation exec -T volt \
  /opt/uvm/venv/bin/python -m uvm.auth.okta_publisher \
  --config /run/uvm-g7-secrets/okta-publisher.json --validate-only
```

Check the publisher's retained last-success time; this is local process status, not a live Okta test:

```sh
docker compose -f /path/to/verified/compose-bundle/compose.yaml \
  --env-file /var/lib/volt/evaluation/.env -p volt-evaluation exec -T volt \
  /opt/uvm/venv/bin/python -m uvm.auth.okta_publisher \
  --config /run/uvm-g7-secrets/okta-publisher.json --status
```

Then link the exact login issuer and stable subject, sign in through the browser, initialize authority, and exercise an audited action:

```sh
python3 setup.py link-admin /var/lib/volt/evaluation \
  --issuer https://id.example.org/ --subject 'provider-stable-subject' \
  --rationale 'Approved evaluation bootstrap' \
  --evidence-ref change-123
```

Missing or failed API pages, account-state reads, assignments, or group traversal do not publish a partial snapshot. Deleted app assignments and memberships disappear from the next complete snapshot, which applies existing session revocation. Publisher failures are retried without refreshing the heartbeat; after the configured freshness limit, authorization fails closed. Use `python3 setup.py stop /var/lib/volt/evaluation` to stop the supervised stack while preserving data, and `start` to resume it. A successful local config check is not real tenant validation: the operator must perform and record an actual Okta browser sign-in and audited permission-scoped action in their tenant.

For an offline install, first verify and load the signed release archive using its `VERIFY.txt` instructions. Initialize with the loaded local Docker image ID from the archive's signed `manifest.json` `image_id` field, for example:

```sh
VOLT_IMAGE_ID="$(python3 -c 'import json; print(json.load(open("manifest.json"))["image_id"])')"
VOLT_PLATFORM="$(python3 -c 'import json; print(json.load(open("manifest.json"))["platform"])')"
python3 setup.py init "$HOME/.local/share/volt/demo" --mode demo --project volt-demo \
  --image "$VOLT_IMAGE_ID" --platform "$VOLT_PLATFORM" \
  --bootstrap-principal local-testing-admin --demo-subject local-testing-admin-subject \
  --demo-admin-username local-testing-admin
```

Use the `image_id` and `platform` values as-is from the authenticated archive manifest. The image ID is the local Docker image ID, distinct from the registry digest used by the online pull command above. The installer rejects a platform value that differs from Docker inspection.

After the exact subject is linked, sign in through the configured browser callback, copy that session's `uvm_session` cookie value using the browser storage inspector, and run `python3 setup.py initialize-authority /var/lib/volt/evaluation`. The command accepts the cookie only at a hidden terminal prompt and forwards it over stdin to the container. It rejects any session whose principal differs from `--bootstrap-principal`. This explicit operator step initializes policy/native authority and verifies permission-scoped readback; browser smoke does not establish authority.

Use the exact OIDC issuer and subject from the identity provider; email and display names do not establish identity. The link-admin command is one-time and auditable. Configure a TLS reverse proxy on the host and set the callback to its HTTPS origin. The Compose upstream is bound to loopback. The application does not treat forwarded host or protocol headers as authority. The proxy must preserve the configured Host and callback; do not expose the upstream or recovery port publicly. Do not put secrets in the config JSON.

External mode without `--okta-publisher-config` still requires a separate trusted identity-sync integration. OIDC claims prove the authenticated issuer and subject; they do not establish current source-account membership, revocation state, or permission scope. The included Okta publisher sends complete, strictly increasing snapshots through the existing loopback adapter, authenticates with the generated sync secret, and uses the configured provider's group mappings and heartbeat maximum age. The snapshot DTO carries provider ID and revision, not a mapping-revision attestation; mapping revision comes from the admitted server configuration. Revocations appear in a newer complete snapshot. Missing, stale, regressed, or contradictory snapshots keep identity authorization unavailable. Do not derive snapshots from ID tokens or expose the loopback sync adapter outside the application boundary.

Setup generates private database, application, OIDC synchronization/operator and recovery TLS secrets. For external mode it copies the supplied OIDC client secret into the private instance directory. Back up these files with the image identity and all three persistent volumes; losing encryption keys can make retained data unreadable. Files on the host are plaintext protected by mode `0600` and directory mode `0700`.
The recovery bundle includes a host-held client certificate and private key at `secrets/recovery-client.crt` and `secrets/recovery-client.key`; keep the key mode `0600`. The temporary CA private key is deleted after issuing the server and client leaves. Recovery remains loopback-bound and is not a public ingress endpoint.

## Lifecycle

`stop` stops the single supervised container while retaining its container, network and all three volumes. `start` resumes the exact admitted image and verifies resource owner labels before touching Docker. `cleanup` without flags is retaining. Destructive cleanup requires `--remove-data --confirm-project <exact-project>`; it verifies the instance owner token on every extant container, network and volume before removal. Never run `docker volume prune` for VOLT lifecycle management.

Initialization refuses an existing instance path or existing Compose resource names. It never overwrites a secret, changes an OIDC config silently, adopts a volume, or changes the admitted image. A changed image requires a separately reviewed migration/upgrade process; restoring an older image does not roll back schema state.

See [`backup-restore.md`](backup-restore.md) for the bounded cold backup and restore procedure and its limits. This bundle is a local evaluation installation path, not production-ready deployment evidence.
