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
