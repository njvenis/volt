# VOLT Compose installation bundle

This bundle installs an existing VOLT supervised image. It does not clone VOLT source, install Node.js, run npm, or build the application. Bundle version is in `VERSION`; the archive manifest covers every installation file. Runtime prerequisites are Docker Engine with Compose v2, Python 3.11+, OpenSSL, and an admitted `linux/amd64` image.

The default Compose profile uses external OIDC. The local synthetic demo requires the explicit `demo` overlay. Demo identity is generated and labelled as synthetic; it does not establish Okta, AWS, or production integration. For online installs, supply the digest-pinned release image reference printed in this bundle; for offline installs, use the verified local image ID described below. RC1 remains a historical launcher-only release and is rejected by this Compose bundle.

## Verify and initialize

Verify the archive using the published sidecar checksum before extracting it. Keep the extracted bundle and instance directory private and retain both for the full lifecycle.

For a disposable demo, use a fresh project and path:

```sh
python3 setup.py init /var/lib/volt/demo --mode demo --project volt-demo --image VOLT_RELEASE_IMAGE_REFERENCE
python3 setup.py start /var/lib/volt/demo
python3 setup.py status /var/lib/volt/demo
python3 setup.py link-admin /var/lib/volt/demo
```

Open `http://127.0.0.1:8180/` and sign in. Copy the `uvm_session` cookie value from the browser's storage inspector, then run `python3 setup.py initialize-authority /var/lib/volt/demo` and paste it at the hidden prompt. The source-free installer verifies the exact configured principal, bootstraps the initial policy, activates native authority once, waits for readiness, and checks a permission-scoped public readback. Repeating it preserves existing grants and audit history. The browser smoke only verifies this initialized state and performs its separate audited readback operation. `link-admin` explicitly links the fixed synthetic issuer and exact subject to the demo bootstrap principal; it uses the protected operator credential inside the container. The provider is only published on loopback. Use `--http-port` and `--oidc-port` at initialization when those defaults are occupied.

For external OIDC, prepare a config based on [`oidc.example.json`](oidc.example.json), set the exact application callback and trusted origins, and provide the client secret as a private file. Pull the same digest-pinned release image shown in `VOLT_RELEASE_IMAGE_REFERENCE`, then initialize using that reference:

```sh
docker pull VOLT_RELEASE_IMAGE_REFERENCE
python3 setup.py init /var/lib/volt/evaluation --mode external --image VOLT_RELEASE_IMAGE_REFERENCE \
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
python3 setup.py init /var/lib/volt/demo --mode demo --project volt-demo --image sha256:<verified-local-image-id>
```

Use the `image_id` value as-is. It is the local Docker image ID, distinct from the registry digest used by the online pull command above.

After the exact subject is linked, sign in through the configured browser callback, copy that session's `uvm_session` cookie value using the browser storage inspector, and run `python3 setup.py initialize-authority /var/lib/volt/evaluation`. The command accepts the cookie only at a hidden terminal prompt and forwards it over stdin to the container. It rejects any session whose principal differs from `--bootstrap-principal`. This explicit operator step initializes policy/native authority and verifies permission-scoped readback; browser smoke does not establish authority.

Use the exact OIDC issuer and subject from the identity provider; email and display names do not establish identity. The link-admin command is one-time and auditable. Configure a TLS reverse proxy on the host and set the callback to its HTTPS origin. The Compose upstream is bound to loopback. The application does not treat forwarded host or protocol headers as authority. The proxy must preserve the configured Host and callback; do not expose the upstream or recovery port publicly. Do not put secrets in the config JSON.

External mode also requires a separate trusted identity-sync integration. OIDC claims prove the authenticated issuer and subject; they do not establish current source-account membership, revocation state, or permission scope. The provider-specific publisher must authenticate with the configured sync secret, send the configured provider ID, publish strictly monotonic snapshots, and refresh its heartbeat within `heartbeat_max_age_seconds`. The snapshot DTO carries provider ID and revision, not a mapping-revision attestation; mapping revision comes from the admitted server configuration. Revocations must appear in a newer complete snapshot. Missing, stale, regressed, or contradictory snapshots keep identity authorization unavailable. Do not derive snapshots from ID tokens or expose the loopback sync adapter outside the application boundary. The integration owner must implement and operate this publisher before real evaluation; the generic Compose installer does not supply one.

Setup generates private database, application, OIDC synchronization/operator and recovery TLS secrets. For external mode it copies the supplied OIDC client secret into the private instance directory. Back up these files with the image identity and all three persistent volumes; losing encryption keys can make retained data unreadable. Files on the host are plaintext protected by mode `0600` and directory mode `0700`.
The recovery bundle includes a host-held client certificate and private key at `secrets/recovery-client.crt` and `secrets/recovery-client.key`; keep the key mode `0600`. The temporary CA private key is deleted after issuing the server and client leaves. Recovery remains loopback-bound and is not a public ingress endpoint.

## Lifecycle

`stop` stops the single supervised container while retaining its container, network and all three volumes. `start` resumes the exact admitted image and verifies resource owner labels before touching Docker. `cleanup` without flags is retaining. Destructive cleanup requires `--remove-data --confirm-project <exact-project>`; it verifies the instance owner token on every extant container, network and volume before removal. Never run `docker volume prune` for VOLT lifecycle management.

Initialization refuses an existing instance path or existing Compose resource names. It never overwrites a secret, changes an OIDC config silently, adopts a volume, or changes the admitted image. A changed image requires a separately reviewed migration/upgrade process; restoring an older image does not roll back schema state.

See [`backup-restore.md`](backup-restore.md) for the bounded cold backup and restore procedure and its limits. This bundle is a local evaluation installation path, not production-ready deployment evidence.
