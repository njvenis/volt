# Adopted host start admission for initial local preparation

Root adopts this narrow host-maintenance boundary to distinguish initial preparation from an established instance with lost data. It follows the reviewer's identified minimal boundary and preserves the accepted backend recovery and exact-schema rules. It is not a signing root, user approval step, environment bypass or authority grant. Implementation and executable acceptance remain pending.

## Closed record and custody

The admitted networkless delivery helper, under the existing exclusive instance lock, validates the selected instance journal, committed custody fingerprints, current exact backend acknowledgement, admitted immutable image and actual owned resources. It generates this closed record; browser input and runtime database contents never choose its initial permission:

```json
{
  "schema_version": 1,
  "profile": "volt_local_recovery_v1",
  "document_type": "local_start_admission",
  "installation_id": "<canonical UUID>",
  "journal_id": "<canonical UUID>",
  "restore_generation": 0,
  "recovery_epoch_id": null,
  "image_id": "sha256:<64 lowercase hex>",
  "resources_sha256": "<64 lowercase hex>",
  "initial_preparation": true
}
```

Numbers are nonnegative integers excluding booleans; the epoch is null only for generation zero. The resource digest binds the helper's canonical admitted current ownership/resource inspection projection; its exact format and journal field names must be pinned in the delivery helper contract before execution. Missing or contradictory actual resources cannot be represented as admitted.

Use a dedicated stable host directory `secrets/local-start-admission/`, containing only `admission.json`, owned by the validated selected host UID with directory0700/file0600. Mount only that directory read-only at `/run/volt-start-admission`; no whole journal, operator-private parent, writable API mount or secret bytes. The root entrypoint uses bounded, nonblocking, no-follow descriptor reads and exact owner/mode/type checks against the validated existing host custody mapping. It validates installation/journal/generation/epoch against the live fence, and immutable image/resource identity against the existing admitted start inputs. There is no fallback to a loose environment boolean.

The dedicated directory stays stable and only its file is atomically replaced with correct custody before publication. A single-file bind retaining a stale initial inode is not sufficient. The host journal pins the current record identity/digest and establishment state; startup never adopts a mismatching record. Directory restoration requires stopped workers and renewed mount admission.

## Initial permission and durable disarming

`initial_preparation=true` is generated only when the independent host journal explicitly remains in initial preparation, has no successful initialization/fence acknowledgement, and has generation zero/null epoch. Resource ownership and source/image admission must already be validated. A pending restore is never initial preparation.

This permission is necessary in addition to an empty database for the bounded missing-head initial migration route and for fresh PostgreSQL `initdb`. An established/acknowledged instance with missing database, schema head or profile binding fails closed before initialization, migrations or setup capability issuance. Existing older/newer schema heads and upgrade/restore admission remain closed under their existing contracts; this record is not a general migration licence.

Initial preparation runs with ingress unpublished and without application workers or administrator exposure. After required migration/local identity/profile/fence maintenance succeeds, the host validates the exact committed acknowledgement, durably publishes `initial_preparation=false` FIRST, then records establishment and releases workers/ingress. The host lock alone is not an atomicity guarantee against container restarts; partial transitions must reconcile forward without ever regenerating initial permission. Use an explicit bootstrap-maintenance phase or a bounded closed-ingress handshake; no indefinite held user plan. Recreate the configured service if necessary so it reads the current projection. Any crash/contradictory partial transition must resume under the host lock and fail closed until reconciled.

Every configured start refreshes and validates the projection under the lock. An acknowledged generation-zero instance cannot regain initial permission. A new restore binds its new generation/epoch with initial permission false. Both supported start paths and automatic container restarts must observe the current disarmed record; no copied or stale startup record may reopen initialization.

## Decisive checks and ownership

Delivery owns the producer, lock/journal/resource binding, private mount, entrypoint reader and both start/restore transitions. No new backend authority or private journal API exposure is introduced. Required proof includes fresh initial boot; interrupted pre-migration preparation; exact acknowledgement and durable disarm before workers; configured generation-zero database loss denial; missing/changed record denial; pending-restore denial; and actual read-only narrow mount inspection on the ordinary host mapping. Existing external/demo behavior must remain unchanged.


## Required implementation conditions from review

Disarmed starts reject missing local installation identity or recovery/profile bindings even with schema head0067. All constructors, profile initialization and setup capability issuance are guarded, in addition to initdb and missing-head migrations. The bootstrap acknowledgement is obtainable through the bounded maintenance phase before normal API/workers and before ordinary application health; health cannot be a prerequisite for disarming.

Before execution, delivery pins the canonical resource projection, normalized JSON hashing, typed image identity and journal fields in its helper contract. Bind actual admitted resource ownership and mount configuration, excluding volatile health/timestamps. Image identity is the exact authenticated config or selected-child manifest, with its type retained; an index identifier alone is not a selected-child witness.
