# Packaged local recovery companion contract (v1)

Implemented coordination contract for delivery; source-bound synthetic verification is recorded separately. Actual packaged execution remains delivery-owned. Base6622bbe5e25532038ed287ef2b2cf61d29255ea7; UI62a remains accepted. No helper signing/import or backend/installer/Python runner change belongs to this companion.

All inputs below travel on protected stdin. Paths are non-secret CLI metadata. Use a task-private existing0700 directory; state files are0600 regular files, bounded1MiB, never symlinks. Do not collect these private files as evidence. The runner owns deletion in finally. Session and recovery state destinations must not already exist; the raw cookie output may replace an existing owned0600 regular file. Cookie and saved-session paths must differ canonically and by inode. Both are admitted together, with exact descriptors held, before browser launch/login; invalid raw-cookie output therefore cannot follow a successful login. Ancestor symlink aliases, file symlinks, hardlinks and special files are rejected. Native Linux /proc/self/fd anchors file operations to admitted private parent descriptors; hosts without that facility fail closed. Opens use NONBLOCK/NOFOLLOW; reads are capped at1MiB+1 even if files grow, and identity/size/permissions are rechecked. Destinations are checked before login/upload. Stdin is bounded64KiB. No credential/cookie/capability/proof bytes may be supplied in argv/env or logged. Public evidence contains only fixed result flags and empty-credential screenshots.

## Capture a genuinely authenticated browser before backup/restore

`node tools/compose_release_login.mjs ORIGIN PRIVATE_COOKIE_PATH --local-stdin --save-browser-state PRIVATE_SESSION_PATH`

Stdin unchanged: `{ "username": "...", "password": "..." }`. Existing positional demo/OIDC invocation and local invocation without save flag remain supported. Login must establish actual200/local_session before writing. New private JSON state: `{schema_version:1,kind:"local_browser_session",origin,captured_at,principal_id,storage_state:{cookies:[<actual Playwright uvm_session cookie>],origins:[]}}`. This is captured browser state, not an operator-built cookie. The existing private raw cookie output remains compatible. Capture does not log out; restore must occur with more than120seconds of captured cookie TTL remaining at verification startup. The exact session request requires a further30second margin and a15second timeout; cookie expiry is rechecked through its401 response and final check. The actual Cookie header on that browser request must contain the captured value; it is compared in memory and never logged.

## Check the saved pre-restore browser session, without login

`node tools/g7_local_preview_smoke.mjs --local --origin ORIGIN --evidence EVIDENCE --verify-restored-session --browser-state PRIVATE_SESSION_PATH`

No stdin credentials and no login. Loads the actual saved Playwright state, confirms matching origin/previous authenticated principal metadata and an unexpired session cookie, then requires exact401 authentication_required from GET auth/session. Public error envelope schema1, correlation UUID, empty details and fixed Authentication required message are required. Claimed local config, visible Sign in to VOLT and absence of setup/sign-out controls are required. Anonymous protected deployment access must also be401 authentication_required. An expired/missing cookie,503,403 or arbitrary failed request cannot pass. No fresh login may mask rejection.

## Prove restored setup stays consumed/closed

`node tools/g7_local_preview_smoke.mjs --local --origin ORIGIN --evidence EVIDENCE --verify-setup-closed --credentials-stdin`

Stdin: `{ "username": "UNIQUE_PROBE_USERNAME", "password": "VALID_NEW_PROBE_PASSWORD", "display_name": "Probe account", "capability": "ORIGINAL_CONSUMED_SETUP_CAPABILITY" }`. The runner must generate an unused probe username and a valid15–128 character password. Start anonymous, require exact local/claimed config and claimed UI, then POST the normal public setup claim. Actual backend35e/662 contract rejects consumed/restored capability with401 authentication_required (not generic409). Require no session cookie, subsequent session/deployment401, unchanged claimed config, and normal login with probe credentials401. This verifies public inability to create/authenticate a new admin; no DB row-count claim.

## Recovery phase1: fresh login, discover source, upload fresh credential

`node tools/g7_local_preview_smoke.mjs --local --origin ORIGIN --evidence EVIDENCE --recovery-prepare --recovery-state PRIVATE_RECOVERY_PATH --credentials-stdin`

Stdin: `{ "username":"LOCAL_ACCOUNT", "password":"LOCAL_PASSWORD", "scanner": { "display_name":"SOURCE_LABEL", "account_label":"ACCOUNT_LABEL", "environment_label":"ENVIRONMENT_LABEL", "username":"QUALYS_READER", "password":"FRESH_QUALYS_PASSWORD", "rationale":"...", "evidence_ref":"..." } }`.

Human labels select exactly one source via authorised connector/scanner reads; zero/ambiguous matches fail. IDs are derived from public readback. Require quarantine/fresh-credential-needed before upload. Submit credential through the visible form and confirm actual201 receipt and fresh-ready readback, with fields immediately empty. No save/test/activation/provider call. Write private metadata `{schema_version:1,kind:"scanner_recovery",origin,principal_id,connector_id,source_id,source_tuple,secret_id,version_id,recovery_epoch_id,configuration_revision}`. No password, cookie or private proof in this state.

Delivery then performs REAL host approval with its owned qualified helper, outside this companion. The companion never signs, imports, constructs proof or claims a usable unqualified host command.

## Recovery phase2: explicit apply, test, activate and persisted readback

`node tools/g7_local_preview_smoke.mjs --local --origin ORIGIN --evidence EVIDENCE --recovery-complete --recovery-state PRIVATE_RECOVERY_PATH --credentials-stdin`

Stdin: `{ "username":"LOCAL_ACCOUNT", "password":"LOCAL_PASSWORD", "scanner": { "rationale":"...", "evidence_ref":"..." } }`.

Fresh login and matching authorised source/actor/state binding are required. Real current approval must be available/unexpired for the exact recorded source/credential/epoch/configuration. Drive visible Apply host clearance, Test connection, Activate configuration separately; validate outgoing current public fences and audited receipts. Existing admitted operation polling reuses the frozen UI command; receipt-less200 failed/partial/interrupted is not success. Require persisted public readback clear+active with matching configuration/credential/test proof after reload. No collect is implied, and no live Qualys availability is assumed. Explicit Test connection may contact the configured provider; delivery supplies the authorised fixture/runtime.

Each special mode is exclusive of setup/register/readback/provider-revocation and of the other special modes. Failure emits only a fixed safe message; no raw response, parse diagnostic, URL secret, trace/HAR or credential screenshot. Result stdout contains fixed pass flags only. Existing --setup, --register-scanner, OIDC/demo and local login paths remain compatible.

Runtime companion dependencies: keep ui/scripts/local-companion-state.mjs, ui/scripts/scanner-companion-contract.mjs and the maintained ui/openapi.json beside the existing repository tools and ui/node_modules. No new npm dependency is introduced. The helper owns private-file/shape/error validation only; it is not a second harness or privileged API.

Reviewer correction: scanner and credential POSTs are intercepted before dispatch, validated against a freshly read full public vector (including the actual secret slot revision), and bound to the outgoing UUID/action/source/configuration/credential/test snapshot. Scanner receipts and operations must satisfy the exported strict DTO plus original request/audit bindings. Polling compares the exact frozen original request bytes before every replay. Missing IDs, response-derived IDs, changed vectors or incomplete audit envelopes cannot pass. Credential input bytes are compared in memory with the entered values. No private data enters output or evidence.
