# Local recovery host helper wire contract

This private instance maintenance interface runs only in the admitted VOLT
image as an ephemeral container with `--network none`, no Docker socket, a
read-only root filesystem, and a single narrowly mounted private instance at
`/instance`. The instance mount is not present in the API container. The helper
must run while the existing instance lifecycle lock is held.

The launcher obtains its bounded request with `request --instance-root
/instance` using a read-only bind. It sends that exact document to `prepare` over
stdin using one writable instance bind, then uses `validate --request-stdin`
with a read-only bind on every later configured lifecycle operation. The
request and response are mode-0600 files in the launcher's private temporary
directory; neither is evaluated as shell. The `operator.key` and `host.json`
stay in the host authority directory and are never part of the API's Compose
mount set.

## Preparation request

The launcher supplies this complete JSON object on stdin to
`python -m uvm.installer.recovery_authority prepare --request-stdin
--instance-root /instance`. It contains no key bytes, trust roots, image
references, or caller-selected filesystem paths. Members and path-policy values
are closed and exact:

```json
{
  "schema_version": 1,
  "profile": "volt_local_recovery_v1",
  "installation_id": "canonical UUID",
  "journal_id": "canonical UUID",
  "path_policy": {
    "api_config": "local-recovery.json",
    "runtime_directory": "secrets/local-recovery-runtime",
    "authority_directory": "secrets/local-recovery-authority",
    "fence_directory": "secrets/local-restore-fence",
    "journal": "instance.json"
  }
}
```

Input is bounded to 16 KiB. Duplicate JSON keys, noninteger numbers, unknown
members, noncanonical UUIDs, or any path-policy difference fail closed. The
helper creates all files exclusively and returns only this safe inventory:

```json
{
  "schema_version": 1,
  "profile": "volt_local_recovery_v1",
  "status": "prepared",
  "installation_id": "canonical UUID",
  "journal_id": "canonical UUID",
  "issuer_key_id": "canonical UUID",
  "operator_key_id": "canonical UUID",
  "issuer_public_sha256": "64 lowercase hex",
  "operator_public_sha256": "64 lowercase hex",
  "restore_generation": 0,
  "recovery_epoch_id": null
}
```

Resume validates the complete committed inventory and returns its identities;
it never regenerates a missing key or silently adopts a different journal.
After a restore, both `instance.json` and the independent fence carry the new
generation and restore UUID. Validation requires exact agreement and changes
neither record. Partial preparation fails closed for operator recovery. The
response never contains private key, material key, or proof bytes.

## Offline operator approval

The admitted runtime helper also exposes the fixed signing interface
`python -m uvm.installer.recovery_authority approve --request-stdin
--authority-config /authority/host.json`. The caller is only
`sh ./volt recovery approve-scanner --source LABEL --rationale TEXT
--evidence-ref TEXT`. It obtains current safe target labels and a private
approval request from the local API, then runs the signer with `--network none`,
a read-only root, and six read-only host binds: `operator.key`, `operator.pub`,
`issuer.pub`, `host.json`, the dedicated fence directory, and `instance.json`.
The operator private key and complete state directory are never mounted into
the API or signer together. The signer verifies the closed request, issuer
signature, attestation digest, target, and current journal/fence tuple before
producing a 15-minute operator signature. Request, approval, and API receipt
remain in a mode-0700 temporary directory and are removed at exit. Only the
source label, imported state, and expiry are printed.

## Live fence and acknowledged startup

The adopted fence-only mapping keeps the host UID from the validated instance
root. Its dedicated directory is host-owned, GID1800, mode0710; fence.json is
host-owned, GID1800, mode0640. The closed API configuration pins
`restore_fence_custody={owner_uid:HOST_UID,runtime_gid:1800}`. Other private
files remain0600 and directories0700. Preparation uses the admitted root helper
with only CHOWN, SETUID and DAC_OVERRIDE on the isolated instance mount to
publish this mapping. Runtime receives the dedicated directory read-only at
`/run/volt-restore-fence`; it reopens the live envelope rather than a copy.

Preparation commits SHA256 fingerprints for both configurations, local storage
key and all issuer/operator/material files in `local_recovery_inventory` before
acknowledging success. It fsyncs the custody directories and their secrets
parent before the instance journal. Resume rejects replacement bytes, even
when a replacement signing pair is internally consistent.

The root-only `/usr/local/bin/uvm-local-maintenance` entry point reads an
entrypoint-created ephemeral root0600 environment file. It supplies the database
and configured key paths without putting credentials into Docker arguments or
configuration. Recovery operations drop to UID/GID1800; account capability
delivery retains host ownership of its separate private directory. Startup
initialises an empty local installation through the supported auth constructor,
prepares setup only when unclaimed, then validates/applies the live fence and
initialises the fixed scanner rule before workers start.

`acknowledge --request-stdin --instance-root /instance` accepts only the closed
backend apply-local-restore-fence acknowledgement for the exact current host
installation, journal, generation and epoch. It validates custody and committed
fingerprints again, atomically records the safe acknowledgement and releases
restore admission only after offline import. Restored startup first uses the
closed-ingress overlay; it verifies actual image/mounts and the acknowledgement
before recreating with normal ingress. No count, status or tuple is inferred
from ordinary readiness. `advance-fence` is the fixed root helper used by
restore-provision: it increments generation, creates a new epoch and publishes
only a correctly owned/mapped fence before committing the pending journal.

## Initial start admission and bootstrap release

The start directory is the fixed path-policy member
`start_directory=secrets/local-start-admission`. It is stable, host-owned0700;
only `admission.json` is durably present, host-owned0600. Its sole API mount is
read-only `/run/volt-start-admission`. The record is exactly the closed schema
in the adopted `local-start-admission.md`; no environment boolean authorizes
initialization. `UVM_LOCAL_START_IMAGE_ID` and
`UVM_LOCAL_START_RESOURCES_SHA256` carry only independently admitted expected
immutable identities, and must exactly match the protected record.

`prepare-start --request-stdin --instance-root /instance` accepts the closed
actual inspection object with members `containers` (one API inspect object),
`volumes` (three owned named-volume inspect objects), and `networks` (one owned
bridge inspect object). It checks exact image/owner/mounts, empty local-volume
driver options, network identity and IPAM. Its canonical resource projection is:

```
{schema_version:1,image_id,image_id_kind,project,owner_token,
 network:{name,id,driver:"bridge",internal,subnet,gateway},
 volumes:[{name,driver:"local",scope,mountpoint,options:{}}]}
```

Volumes sort by name; all other values come from the validated instance and
actual resource inspection. The hash is lowercase SHA256 of canonical sorted
compact JSON. It excludes timestamps, transient container IDs, health and
process state. Typed image identity and actual selected-child evidence are
retained separately in image admission; an index alone is not selected-platform
proof. Journal fields are `host_instance_directory`, `local_start_resources`,
`local_start_admission`, `local_start_admission_sha256`, and
`local_start_record_pending`, and `local_start_environment_pending_sha256`.
The final environment hash is durably pinned before its atomic replacement;
only that exact planned hash may reconcile a crash forwards. The resource projection cannot change on normal
resume. Explicit offline restore invalidates it before admission of new owned
resources; the new epoch is never initial preparation.

Initial true is possible only for the independently unestablished, unacknowledged
generation0/null journal. Resource/record creation is journalled as pending,
then atomically published and fsynced, then committed complete. A missing
configured record fails closed. A durable true-to-false disarm published just
before a crash may reconcile forward; it can never become true again.

Both host start paths first create the container with unpublished ingress,
validate actual mounts/resources, prepare the record and expected hash, and
recreate with those fixed inputs before starting. The root entrypoint consumes
initial permission once per container before any PostgreSQL initialization;
automatic retries with a stale initial record fail closed. Only a controlled
host-locked recreation may retry still-unacknowledged preparation. Disarmed
starts never run the local installation constructor, initialize a missing
profile, or issue setup; the existing-only backend apply operation validates
identity/profile before migrations.

Bootstrap migrations and fixed recovery maintenance produce their exact safe
acknowledgement at `/run/uvm-maintenance/applied.json` before normal API/workers
and without waiting for health. The host validates it, durably publishes
`initial_preparation=false` BEFORE journal establishment, records the exact
acknowledgement, then invokes the root-only fixed
`python -m uvm.installer.start_admission release` via protected stdin. It accepts
only the current disarmed record and retains it in a root0600 in-container
release file. The entrypoint's bounded release wait requires both the current
live disarm and that exact host release before workers start. No health-to-ack
cycle or user-held plan is used. Initial/recovery ingress is published only
through subsequent configured recreation and renewed admission/release.
