# G7 deployment and operations design

## Boundaries

VOLT and DefectDojo CE remain separate applications with separate database roles. VOLT communicates with DefectDojo through supported APIs. State-changing decisions commit with their audit events and recoverable outbound intent. No release, production deployment or writer cutover follows solely from local implementation or fixture tests.

The deployment target contains the VOLT API, UI and workers, pinned DefectDojo CE processes, separate UVM and CE databases, and the required broker in one supervised container. A local OIDC provider is a test fixture; provider compatibility must be checked against the selected identity service before release. Access groups govern authorization; ownership teams represent accountability and do not grant access.

## Data and operational controls

Ingestion timestamps are distinct from scanner observation and collection times. New SLA versions use authoritative VOLT ingestion commits and preserve prior issued reports. Approved exceptions accept risk, capture remaining SLA time and resume at expiry without erasing earlier breaches.

Audit history has a read-only, permission-scoped application view and an independently controlled SIEM copy. Export receipts, retries and reconciliation expose missing or changed records. Detection data and operational logs have distinct preservation periods; no deletion policy is inferred while retention semantics remain unsettled.

Infrastructure operates backups. Restore procedures coordinate VOLT data, DefectDojo state/media and queued external effects. External failure observation must remain available when the application container is unavailable. Writer cutover fences the outgoing writer and reconciles uncertain operations before enabling a replacement.

## Versioned operational settings

The first setting slice is deployment-scoped observer timing. A VOLT command stores the desired revision, audit record, receipt and application intent atomically. A separately controlled host service validates and applies the revision, then reports the effective state. The UI distinguishes pending, applied, failed and uncertain states and shows last-known effective configuration during VOLT outages. A rollback creates a new revision. Host policy and controller credentials remain outside VOLT.

See `docs/g7-observer-settings-contract.md` for the request and readback contract. Local timing values are fixtures, not release policy.

## Verification

Each development result names its source revision, dependencies, fixtures, environment, exact command, output, exit status and cleanup. Unit and synthetic tests do not substitute for live service integration or target-environment recovery. Migration, audit, authorization and writer changes require focused rollback and recovery checks before dependent activation.
