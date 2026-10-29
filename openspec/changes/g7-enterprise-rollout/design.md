# G7 deployment and operations design

## Boundaries

VOLT and DefectDojo CE remain separate applications with separate database roles. VOLT communicates with DefectDojo through supported APIs. State-changing decisions commit with their audit events and recoverable outbound intent. No release, production deployment or writer cutover follows solely from local implementation or fixture tests.

The deployment target contains the VOLT API, UI and workers, pinned DefectDojo CE processes, separate UVM and CE databases, and the required broker in one supervised container. A local OIDC provider is a test fixture; provider compatibility must be checked against the selected identity service before release. Access groups govern authorization; ownership teams represent accountability and do not grant access.

## Data and operational controls

Ingestion timestamps are distinct from scanner observation and collection times. New SLA versions use authoritative VOLT ingestion commits and preserve prior issued reports. Approved exceptions accept risk, capture remaining SLA time and resume at expiry without erasing earlier breaches.

Audit history has a read-only, permission-scoped application view and an independently controlled SIEM copy. Export receipts, retries and reconciliation expose missing or changed records. Detection data and operational logs have distinct preservation periods; no deletion policy is inferred while retention semantics remain unsettled.

Infrastructure operates backups. Restore procedures coordinate VOLT data, DefectDojo state/media and queued external effects. External failure observation must remain available when the application container is unavailable. Writer cutover fences the outgoing writer and reconciles uncertain operations before enabling a replacement.

## G7-REC-01 current-image schema transition

The current-main Docker journey is version-specific: candidate B is the image built from the exact tested source snapshot and its complete image/package digests are retained. Its normal startup accepts only its declared schema head, `0061`. A separately labelled historical fixture continues to prove the previously accepted `0058` to `0059` transition; that fixture is not evidence for current-main compatibility.

For the current-image journey, the host controller journals a compatibility admission bound to the source image A, target candidate B, both package manifests, signed archive, epoch 1 and fresh forward volume IDs. The admission names exactly `0058` to `0061`; it does not authorize arbitrary migration destinations. Candidate B may enter verification-only, control-only recovery on the admitted archive head `0058`. In that mode only the recovery-control listener is available: product APIs, CE, workers and outbound product effects remain stopped until the host records the restored transition. After the explicit migration completes, only head `0061` may pass the current candidate's released runtime checks. Intermediate `0059` and `0060` heads are accepted only while the same admission and control-only migration context is active. Normal mode rejects every head except the image's exact declared head. Unknown, multiple, unadmitted or mismatched heads fail before initialization or effects.

The authorized migration chain is pinned to the repository revisions and their exact effects:

| Revision | Exact schema effect |
| --- | --- |
| `0059` | Create empty `g7_backup_projection_evidence` with primary key `deployment_id` and nullable `application_evidence_record_id` and `effective_evidence_record_id` columns. |
| `0060` | Create empty `collection_request_reservations` with its declared primary key, foreign key to `collection_runs`, unique `(run_id, attempt_no)`, and the `attempt_no`, `page_ordinal`, and digest-length checks. |
| `0061` | Add nullable `ingestion_evidence.byte_size` and check it is null or between 0 and 16777216; pre-existing records remain null and unchanged. |

The expected inventory is computed from the captured `0058` source inventory, exact migration definitions, and retained host-journal receipts. It permits only the three named schema effects, the `alembic_version` transition, empty new-table contents, and exact journal-derived recovery-control row/field deltas. It does not permit migration-created product rows, changes to existing product payloads, desired-revision changes, CE table or media changes beyond journaled recovery controls, or changes inferred from candidate observations alone. Any unrecognized table, column, constraint, schema head, row, payload, or control-field delta rejects rollback.

Forward migration runs on fresh epoch-1 volumes. PostgreSQL DDL and the Alembic version update execute in the migration transaction; an injected failure at each revision boundary must leave the database at the original `0058` inventory or at a fully committed known head, never an accepted partial schema. Recovery does not downgrade this database. It keeps ingress and egress fenced, verifies zero post-backup product writes and no unresolved external effects, then restores the original signed archive with its bound source image A onto a separate fresh volume set at a strictly higher external recovery epoch. The rollback attestation compares complete UVM and CE table/schema/row-payload inventories and CE media digests, and epoch-2 readback is signed over the restored A image/package, archive, new volume IDs, connector context and current CE/UVM/media state. The retained post-backup controls are replayed from the host journal; they are not fabricated in the archive or treated as migration output.

The migration and rollback proof must demonstrate that recovery-control startup against schema `0058` does not query tables introduced by `0059`/`0060` or the `0061` column before migration. Product and CE readers start only after migration and the signed restored-state gate. If that isolation or transactional failure property cannot be established, the current-image journey remains unverified and its dependent activation stays paused.

## Versioned operational settings

The first setting slice is deployment-scoped observer timing. A VOLT command stores the desired revision, audit record, receipt and application intent atomically. A separately controlled host service validates and applies the revision, then reports the effective state. The UI distinguishes pending, applied, failed and uncertain states and shows last-known effective configuration during VOLT outages. A rollback creates a new revision. Host policy and controller credentials remain outside VOLT.

See `docs/g7-observer-settings-contract.md` for the request and readback contract. Local timing values are fixtures, not release policy.

## Verification

Each development result names its source revision, dependencies, fixtures, environment, exact command, output, exit status and cleanup. Unit and synthetic tests do not substitute for live service integration or target-environment recovery. Migration, audit, authorization and writer changes require focused rollback and recovery checks before dependent activation.
