# Adopted local recovery implementation interfaces

Root records joint backend/delivery adoption of the concrete interfaces below, following local recovery profile design GO at 1f19741. This is implementation authority within the approved scope, not executable acceptance. Delivery accepts all six producer/custody/backup requirements. Runtime uvm UID/GID is 1800; the dedicated host fence directory and file must admit that mapping without broadening API mounts. Resolved configuration and real inspection, including restart, remain required.

The additional fixed delivery preparation interface is `python -m uvm.installer.recovery_authority prepare --request-stdin --instance-root /instance`, inside the admitted networkless, socket-free ephemeral helper. `/instance` is a narrowly mounted, validated owned instance for this host maintenance operation only; it is never an API ancestor mount. The request is a closed versioned configuration envelope containing installation/journal identity and admitted path policy, never key bytes or client-selected trust roots. Delivery must publish its exact closed request/response schema before backend integration claims. Preparation returns safe inventory/identity metadata only and creates each key/config/fence exclusively under the existing host instance lock. Resume validates committed bytes/identities and never regenerates missing material. Approval uses the separately specified read-only signer mounts.

Original checkpoint below is retained verbatim as provenance; “proposed” and “not implemented” describe its checkpoint state. Same-reviewer design/interface recheck and implementation acceptance remain separate.

# Local recovery interface checkpoint for root + delivery adoption

Read-only proposal, 2026-11-18. Backend source remains clean and frozen at
`42543e13a8c3defc44d0316542905b29c1f9d171` (same-Reviewer scoped GO; 81 tests).
No recovery implementation, migration, provider/installer/UI edit or new test run
is implied. This pins spellings for adopted `local-recovery-profile.md` design
GO1f19741; it does not reopen its policy/crypto choices. Legacy external/demo
schema1 and G7 signed startup-token paths remain unchanged.

## 1. Config and key locations

Use only `UVM_LOCAL_RECOVERY_CONFIG_FILE=/etc/volt/local-recovery.json` in the
explicit new local profile. It is a closed JSON object, mode0600, staged through
the existing root entrypoint mechanism and then readable by `uvm`. No operator
private path appears in API config. Exact proposed fields/values:

```json
{
  "schema_version": 1,
  "profile": "volt_local_recovery_v1",
  "installation_id": "INSTALLATION_UUID",
  "issuer_key_id": "ISSUER_KEY_UUID",
  "operator_key_id": "OPERATOR_KEY_UUID",
  "operator_id": "local-host:INSTALLATION_UUID",
  "issuer_public_key_file": "/run/uvm-local-recovery/issuer.pub",
  "issuer_private_key_file": "/run/uvm-local-recovery/issuer.key",
  "operator_public_key_file": "/run/uvm-local-recovery/operator.pub",
  "material_key_file": "/run/uvm-local-recovery/material.key",
  "restore_fence_file": "/run/volt-restore-fence/fence.json",
  "proof_store": {"kind": "postgresql", "schema_revision": "0067"}
}
```

UUID markers here mean canonical real UUID strings, not accepted literal
markers. `operator_id` is the exact fixed string derived from the configured
installation UUID. Key IDs are generated once independently; issuer/operator
public keys must differ and private issuer seed must derive its configured
public key. Material key is independently random32 bytes and must not equal
any other admitted private key. Validate lengths, regular files, no symlinks,
permissions/ownership, and trusted configured paths using bounded descriptor
reads. Unsupported/unknown fields/types/profile/version fail. The existing
local-auth.json closed schema stays unchanged; installation IDs must agree with
it and with persisted local_auth_installation. No schema1 fallback in local
recovery dispatch.

Host inventory and narrow mounts (all under selected private instance root):

| Host file | API input mount | Runtime use |
| --- | --- | --- |
| local-recovery.json | /run/secrets/local-recovery.json:ro | validated stage to /etc/volt/local-recovery.json |
| secrets/local-recovery-runtime/issuer.key | /run/secrets/local-recovery-issuer.key:ro | stage /run/uvm-local-recovery/issuer.key |
| secrets/local-recovery-runtime/material.key | /run/secrets/local-recovery-material.key:ro | stage /run/uvm-local-recovery/material.key |
| secrets/local-recovery-runtime/issuer.pub | /run/secrets/local-recovery-issuer.pub:ro | stage /run/uvm-local-recovery/issuer.pub |
| secrets/local-recovery-runtime/operator.pub | /run/secrets/local-recovery-operator.pub:ro | stage /run/uvm-local-recovery/operator.pub |
| secrets/local-restore-fence/ (only fence.json) | /run/volt-restore-fence:ro | read independent live fence; no DB/state-volume substitute |
| secrets/local-recovery-authority/operator.key | **NEVER API-mounted** | ephemeral host signing helper only |
| secrets/local-recovery-authority/host.json | **NEVER API-mounted** | fixed helper config only |

All host secret directories0700/files0600; runtime stage directory0700/files0600
owned uvm:uvm, ephemeral and not a persistent proof/key replacement source.
The fence directory/file must have the admitted UID/GID mapping allowing the
API to read its mode0600 file while its mount stays read-only. Directory mount
allows host atomic replacement without a stale single-file bind inode; it
contains no other host state. Existing bootstrap directory is separate.

Private Ed25519 keys are raw32-byte private seeds; public keys raw32 bytes;
material key raw32 random bytes. Existing strict standard Base64 signatures are
64-byte Ed25519 signatures. Nothing is PEM, hex-encoded private material or an
AES-key reuse. Stage sensitive inputs without printing values. Public key files
are narrow mounts too; do not mount a parent secrets directory.

Host-only `host.json` closed fields:
`schema_version=1,profile,installation_id,operator_id,operator_key_id,
operator_private_key_file,operator_public_key_file,issuer_key_id,
issuer_public_key_file,restore_fence_file,journal_file`.
Exact host helper path values: operator_private_key_file=/authority/operator.key,
operator_public_key_file=/authority/operator.pub,
issuer_public_key_file=/authority/issuer.pub,
restore_fence_file=/authority/fence/fence.json,
journal_file=/authority/instance.json. Mount host.json at /authority/host.json;
these are individual narrow read-only mounts (fence is its dedicated directory),
not an ancestor authority/instance mount. Other identity values exactly match the
validated API configuration. Paths here are helper paths, not API paths.
Neither a browser nor stdin request selects a key/path/root.

Delivery must check resolved Compose AND actual container inspection: no API
bind source or resolved symlink/ancestor contains operator.key/host.json, no
Docker socket/broad instance/home/backup mount, no private bytes in env, config,
DB or logs. API receives operator PUBLIC only. The isolated signer uses the
pinned admitted image, network=none, no socket/extra capabilities, read-only
rootfs and narrow read-only authority/journal/fence inputs; private tmpfs only.

## 2. Independent restore custody and configured restart

A raw UUID is an epoch identifier, NOT proof of host custody. Retain the same
existing restore UUID semantics; add this local-only closed custody envelope,
not another signing trust root:

```json
{
  "schema_version": 1,
  "profile": "volt_local_recovery_v1",
  "installation_id": "INSTALLATION_UUID",
  "journal_id": "JOURNAL_UUID",
  "restore_generation": 0,
  "recovery_epoch_id": null
}
```

New instance preparation generates journal_id once, writes generation0/null
before any runtime boot, and pins the same tuple in the protected host instance
journal. Every explicit admitted restore persists a NEW canonical restore UUID
and increments generation in the independent host journal/fence BEFORE runtime
or restored ingress can start. No null reset, old journal adoption, automatic
key regeneration or DB-derived host epoch. Journal ID is an identity, not a key
or new authority. The host journal additionally retains its existing project,
owner token, image, volume/admission and restore_pending/imported/revocation
records; the API fence does not duplicate/expose those authority values.

On every configured start/resume delivery validates selected instance ownership,
private paths/modes/owners, journal/fence installation+journal+generation+epoch
agreement, admitted image, resolved AND actual mounts, and key/config identity
inventory. It rejects missing/changed/contradictory material rather than
regenerating it. It persists successful backend acknowledgement against that
exact current journal tuple. The backend independently validates configured
installation, fence shape/custody constraints and its committed profile/key
binding before worker startup. Neither backend reading a plain UUID nor a
client-submitted journal object is labelled independent host verification.

Reserve migration0067 (parent0066) for the private proof and installation binding
state actually required here: installation/profile + fixed key identities and
fingerprints/config binding + journal_id + applied_restore_generation +
applied_recovery_epoch_id, append-only signed attestations and host approvals,
and approval consumption/supersession linkage. Use existing connector recovery
JSON, audit, reconciliation intents, receipts and shared command occupancy;
no duplicate command ledger or provider table. Proof bodies/commitments stay
private. A unique version/epoch attestation binding and approval ID/content
binding prevent replacement/reuse. Exact SQL can remain backend implementation.

Material restart defect in current source: install_connector_routes startup
calls apply_restore_quarantine for an existing epoch; its same-epoch no-op only
covers state=quarantined. It would re-quarantine a successfully cleared scanner.
For the new profile, durable applied generation/epoch must instead decide:

* Initial generation0/null with matching persisted initial binding: normal
  start, no fabricated restore or clearance.
* New host generation/UUID admitted by the current journal: one policy-first
  transaction revokes restored local sessions/capabilities, quarantines every
  registered restored source, disables active configurations, invalidates old
  approvals/tests and records applied generation/epoch plus audit. Retries of
  that same completed application are idempotent.
* Same generation/epoch on restart: validate consistency and preserve committed
  quarantine/awaiting_activation/cleared activation state. Never re-run the
  restore merely because the epoch file exists; never clear anything on boot.
* Host null/older generation against a previously applied restore, same
  generation with different UUID, installation/journal/key contradiction,
  missing file/mount or incomplete acknowledgement: fail before workers/ports.
  A new restore applies its new epoch; a configured restart cannot silently
  invent or accept one. A later ordinary configuration change must not cause
  reapplication of the same restore.

Fixed startup sequence for delivery to pin:
1. Hold existing instance maintenance lock; keep restored ingress unpublished
   and workers stopped. Validate host custody/admission/mount exclusions.
2. Stage validated local config/keys; run standard Alembic upgrade through0067.
   Perform existing local-auth first-install preparation only for an unclaimed
   installation as today, never rotate an existing setup token on resume.
3. Fixed new maintenance `validate-local-recovery` validates persisted local
   installation/config/keys/fence and initializes only the missing initial
   profile binding for the admitted new installation. No key replacement,
   signing, credential issue, clearance or network. Conflicts fail closed.
4. Fixed new maintenance `apply-local-restore-fence` applies/acknowledges the
   exact current host tuple atomically as above. Null initial state is a checked
   no-restore acknowledgement; it never revokes normal sessions on each boot.
5. Existing `initialize-scanner-rule` after migrated/private state is valid;
   existing validated provisioning semantics/idempotency remain intact.
6. Only then create/start normal API and existing lifecycle hooks, followed by
   scanner_worker_lifespan. The local-profile hook validates durable applied
   custody instead of blindly reapplying legacy quarantine. Preserve other
   prior hooks and external/demo behavior. Host verifies exact acknowledgements
   and actual mounts before publishing restored ingress. No automatic test,
   approval, activation, collection or external network from these operations.

Steps3–4 use trusted configured files, no arbitrary body/options; their safe
schema1 acknowledgement includes operation,profile,installation_id,journal_id,
restore_generation,recovery_epoch_id,status=validated/applied/already_applied,
plus counts for revoked sessions/capabilities/quarantined connectors (zero on
idempotent readback). It contains no proof/key/secret material. These operations
are proposals, not currently implemented commands.

## 3. Proof bytes and maintenance JSON wire

C(x) is exactly json.dumps(x,sort_keys=True,separators=(",",":")) encoded UTF-8,
default ASCII escaping, no newline. Reject duplicate members/nonfinite/floating
values/unknown fields where the closed schema admits no such type. Signature
bytes are Ed25519(C(document without top-level signature)); signature is strict
standard Base64. A(document) is lowercase SHA256 hex of C(the COMPLETE signed
attestation, INCLUDING signature). No JSON pretty-print/newline/hash prefix is
part of those signed/hash bytes.

The adopted schema2 attestation closed signed fields are EXACTLY:
`schema_version=2,profile=volt_local_recovery_v1,
document_type=credential_attestation,attestation_id,installation_id,
issuer_key_id,connector_id,source_id,source_tuple,secret_id,version_id,
purpose=qualys_vm_basic,recovery_epoch_id,issued_at,issued_after_epoch=true,
freshness_policy=no_retained_password_reuse_v1,credential_commitment,signature`.
source_tuple is exactly `{source_family:"qualys",source_account_id,scope_key}`.
The existing crypto decrypts/parses ALL retained Basic versions including revoked
ones. Compare HMAC-SHA256 tags for prefix `VOLT.local-recovery.password-equality.v1`
+ one NUL byte + C({installation_id,connector_id,secret_id,purpose,password}).
Evaluate every retained tag with hmac.compare_digest (all tags32bytes), accumulate
reuse without early exit, and never return the matched index. Username/version/
epoch are absent ONLY from equality. Preserve exact password;
never trim/case-fold. Malformed/undecryptable retained versions fail closed.

credential_commitment is lowercase64hex HMAC-SHA256 under the separate material
key over prefix `VOLT.local-recovery.credential.v1` + one NUL byte +
C({profile,installation_id,connector_id,source_id,source_tuple,secret_id,
version_id,purpose,recovery_epoch_id,credential:{username,password}}).
No equality tag/plaintext hash/matched index/credential enters public readback,
audit or logs. Encrypt new value + private attestation + audit in one transaction
only after the check passes; no silent quarantine clearing. Existing terminal
submission/version handling runs first; replay never compares a version against
itself to manufacture a fresh upload. Revalidate actual decrypted current
credential commitment on each recovery use.

The host approval closed signed fields are EXACTLY:
`schema_version=2,profile=volt_local_recovery_v1,
document_type=operator_clearance,approval_id,installation_id,operator_key_id,
operator_id,connector_id,source_id,source_tuple,secret_id,version_id,
purpose=qualys_vm_basic,configuration_revision,recovery_epoch_id,
attestation_sha256,rationale,evidence_ref,issued_at,expires_at,signature`.
Issued timestamps canonical UTC Z, never future; expiry strictly after issuance
and <=15minutes later. Issuer issuance >=current epoch application time and <=now.
IDs canonical UUIDs except configured operator_id. The host checks the exact
attestation/key/material-independent context against its journal; backend
rechecks actual material binding and every current persisted fence at import,
apply, test and activation. No new key is fetched from a document field.

Proposed fixed additions to existing backend maintenance module:

```
python -m uvm.auth.maintenance scanner-recovery-targets --config /etc/volt/local-auth.json --input -
python -m uvm.auth.maintenance scanner-recovery-request --config /etc/volt/local-auth.json --input -
python -m uvm.auth.maintenance scanner-recovery-import --config /etc/volt/local-auth.json --input -
```

`--input -` is stdin; alternate `--input-file` accepts only bounded regular
mode0600 private file (mutually exclusive). No JSON/proof/secret/cookie in argv
or env. Config path is the fixed admitted runtime path. No generic actor, grant,
SQL, script, shell or trust-root input. Safe fixed failures to stderr; proof
request stdout is private machine transport only, never ordinary console logs.

Targets input is exactly `{schema_version:1,profile,installation_id}`; safe
output `{schema_version:1,profile,installation_id,targets:[...]}` with only
connector_id,source_id,display_name,account_label,platform_id,state and
configuration_revision. Host wrapper prompts/selects an unambiguous label using
this response; the user never copies internal IDs.

Request input is exactly:

```json
{
  "schema_version": 1,
  "profile": "volt_local_recovery_v1",
  "installation_id": "INSTALLATION_UUID",
  "connector_id": "CONNECTOR_UUID",
  "source_id": "SOURCE_UUID",
  "configuration_revision": 1,
  "rationale": "Approve the fresh credential for this restored source",
  "evidence_ref": "Operator's recovery record"
}
```

Backend selects the actual allocated active slot/version and exact current
attestation; no caller-selected credential/proof/key. Request does not create
another attestation, change quarantine or perform a connection test. Require
current closed recovery workflow and fresh bound attestation; return private
closed object with `schema_version=1,profile,operation=scanner_recovery_approval_request,
installation_id,operator_key_id,operator_id,journal_id,restore_generation,
recovery_epoch_id,target,attestation,attestation_sha256,rationale,evidence_ref`.
`target` exactly connector_id,source_id,source_tuple,secret_id,version_id,purpose,
configuration_revision,display_name,account_label. `attestation` is the complete
signed schema2 object above. This private response contains commitment/proof
material and must never be logged or returned by browser APIs.

Delivery fixed ephemeral producer signature proposal:
`python -m uvm.installer.recovery_authority approve --request-stdin
--authority-config /authority/host.json`.
This is a proposed delivery-owned module/entrypoint, not an existing executable.
It receives the request on stdin and independently reads pinned narrow host
journal/fence/issuer-public/operator-private mounts. It verifies exact request
schema, issuer signature/key, A(attestation), installation/journal/generation/
epoch and target consistency before signing; fixed configured operator identity,
fresh approval UUID, issued_at=now, expires_at=now+15min. It emits ONLY the closed
signed schema2 approval on private stdout. No network or API authority bypass.

Import input is EXACTLY that signed schema2 approval (no client trust settings or
wrapper). Under current trusted maintenance authority + policy-first locks,
validate all bindings/signature/time/current version/attestation/host fence.
Append approval and existing audit/intent/receipt atomically; supersede a prior
approval explicitly and invalidate pending test, returning workflow to quarantine
with disabled lifecycle and active configuration null. Refuse novel import into
already-cleared normal operation. Exact same ID/content import returns its
original acknowledgement, including after apply; changed reused ID conflicts.
No new clearance or test occurs on replay. Safe acknowledgement closed fields:
`schema_version=1,profile,operation=scanner_recovery_import,installation_id,
connector_id,source_id,approval_id,approval_expires_at,state=imported,
audit_event_id,command_id` (the original immutable acknowledgement on replay).
Import's audit identity is truthful configured host-maintenance installation/
operator provenance, not a forged browser actor. Existing ledger/occupancy guards
apply to generated maintenance command IDs too.

Delivery's user entry remains `sh ./volt recovery approve-scanner` with its
existing instance selector plus `--source LABEL --rationale TEXT --evidence-ref
TEXT`. Exact wrapper flags must be implemented/admitted by delivery before docs
claim them. It lists/selects safe targets, streams request to the isolated signer,
then streams approval into fixed runtime import; shows only safe source/status/
expiry acknowledgement. No copied cookie, key, proof or internal ID step.
Private temporary dirs0700/files0600; cleanup on success/error/interruption;
retained backup/evidence never leaks private proof values into console logs.

## 4. Public provider DTO and browser command

Provider-owned proposal (no provider edit here): add REQUIRED `ScannerView.recovery`
with this exact frozen dataclass / closed OpenAPI object:

```
RecoveryView(
  state: Literal['clear','quarantined','awaiting_activation'],
  epoch_id: str | None,
  fresh_credentials_required: bool,
  fresh_version_ready: bool,
  clearance_state: Literal['missing','available','applied','expired','invalidated'],
  approval_id: str | None,
  approval_expires_at: str | None,
)
```

No nested schema_version; ScannerView's schema_version remains1. All seven fields
required, nullable only as stated. epoch_id is null only before any restore;
UUID otherwise. fresh_version_ready is server-derived from current active slot,
valid epoch-bound attestation and actual decrypted material commitment (never a
client flag). clearance_state=available means currently valid imported proof;
applied means consumed by this exact awaiting_activation workflow; expired or
invalidated is truthful closed state. After successful activation, state=clear
and fresh_credentials_required=false; later approval expiry must not disable an
already-cleared scanner. approval ID/expiry can retain historical provenance;
clearance_state may become expired while state remains clear. No proof, digest,
key, path, operator private data or comparison result is exposed. Missing current
proof/material makes fresh_version_ready=false; it cannot authorize a lease.

Existing public operation is the shared endpoint; the ACTION is new and not yet
implemented, despite reusing the existing envelope:

```json
{
  "schema_version": 1,
  "command_id": "NEW_COMMAND_UUID",
  "action": "connector.recovery.clearance.apply",
  "target_id": "00000000-0000-4000-8000-000000000000",
  "membership_ids": [],
  "expected_revisions": {
    "target": 1, "policy": 1, "identity_membership": 0, "owners": 0,
    "authority": 1, "connector": 1, "source": 1, "secret_source": 1,
    "secret": 1
  },
  "payload": {
    "connector_id": "CONNECTOR_UUID", "source_id": "SOURCE_UUID",
    "secret_id": "ALLOCATED_SLOT_UUID", "version_id": "FRESH_VERSION_UUID",
    "recovery_epoch_id": "CURRENT_RESTORE_UUID",
    "rationale": "Apply the host approval", "evidence_ref": "Recovery record"
  }
}
```

POST /api/v1/assessment/commands with ordinary current browser session,
Origin/application-json/CSRF. Payload exactly those seven fields. Numbers above
are illustrative; copy the COMPLETE actual vector from the existing public
secret-slot readback for the exact connector/source/slot. This secret-specific
command uses the actual slot-head revision in expected_revisions.secret;
scanner commands continue secret=null. Do not invent an expected vector from
private DB helpers or conflate the all-zero registration sentinel with this
connector sentinel. No approval_id/proof/key/actor override in browser body:
backend resolves the one current imported matching approval for this binding.

Require current exact connector.configure plus source authorization even for
bootstrap admin/replay; shared command occupancy before claims. Under same live
policy-first transaction, validate revisions, allocated purpose/slot/current
version/config/epoch/attestation/approval expiry and unused approval. Consume it
into this command, move quarantined->awaiting_activation, keep fresh required,
lifecycle disabled/active config null, invalidate old test, advance connector
revision once, atomically append existing audit/intent/receipt. Replay requires
current authorization and exact original family/actor/body, returns original
receipt; a new command cannot consume the same approval again. Rollback is total.

Test alone may lease the exact fresh version while awaiting_activation only
under current signature/material/epoch/session/grant checks; release policy/DB
locks before HTTP. No collection/publication while closed. Activation requires
that same current config/version/epoch/approval and exact successful test within
15min AND unexpired approval through activation. Commit clears fresh required
and activates once with truthful audit provenance. New credential/config/epoch
or explicit replacement approval invalidates prior tests; boot/import/upload do
not automatically test or activate. Normal clear-state operations stop depending
on short-lived approval expiry after successful activation.

## 5. Exact delivery confirmations still required before implementation

1. Accept/change the concrete mount/stage names and UID/GID mapping above,
   including read-only fence directory and operator-private exclusion proven by
   resolved Compose AND real inspection. Confirm validation runs on configured
   resume/restart, not just first install.
2. Deliver one-shot key/config/fence preparation with existing instance lock,
   create-exclusive files, raw encodings, fsync/atomic replace and committed
   inventory; resume validates, never silently generates missing keys. Provide
   exact generation/helper entrypoint signature in the pinned admitted image.
3. Extend protected host journal with journal_id/restore_generation/epoch tuple;
   persist the independent fence before restored runtime starts, forbid stale
   mismatch, pin exact startup steps and backend acknowledgement checks above.
   Current root setup.py has restore flags but no local-profile custody envelope;
   G7 signed token code is not falsely claimed as this local producer.
4. Accept/implement the fixed networkless signing helper signature and user
   wrapper flags/streaming/private-temp cleanup; provide its real committed ref
   before backend claims end-to-end host approval acceptance.
5. Protected coordinated backup includes local-auth.json + AES key, local-
   recovery.json, runtime issuer/private+public/material keys, operator private+
   public host authority config, current fence+independent host journal, DB proof/
   epoch/approval-consumption state and the COMPLETE /opt/uvm/state volume.
   Operator private backup stays in protected host instance/secrets backup,
   OUTSIDE EVERY API mount/volume/served archive. Verify bytes/owner/modes on
   restore, exact key/config identities before ingress; missing retained crypto
   cannot bypass revoked-version decryption/freshness checks. No silent enrolment.
6. Existing agreed evidence setting remains
   UVM_SCANNER_EVIDENCE_DIR=/opt/uvm/state/scanner-evidence, uvm:uvm0700, covered by
   whole state-volume backup. No guessed alternate directory or new evidenceenv.

These are finite producer/custody/ordering inputs for root to pin jointly, not a
request to reopen the adopted profile. Backend implementation can start after
root records delivery-compatible adoption; provider supplies RecoveryView, UI
uses its safe fields, delivery owns all helper/key/backup/launcher code. Scoped
425 GO and historical source/evidence are preserved throughout.


## Live fence ownership amendment

The adopted [live-fence custody mapping](live-fence-custody.md) supersedes the earlier fence-only0700/0600 modes with host-owned fixed-group0710/0640 and a closed restore_fence_custody binding. Other private files and external/demo behavior remain unchanged. Actual non-root and mount admission proof is required.
