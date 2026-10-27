# VOLT project context

VOLT (Vulnerability Ownership & Lifecycle Tracking) is a DefectDojo Community Edition based vulnerability lifecycle application.

## Product invariants

- DefectDojo CE remains the finding engine and is accessed through supported APIs. VOLT persistence is separate, with no direct writes to DefectDojo tables.
- Namespaced source-native identifiers lead grouping. CVE relationships do not merge distinct groups.
- Workload rebuilds and scanner refreshes preserve lineage, detection history, decisions, ownership and issue associations.
- Missing or incomplete source data, accepted risk and exclusions are not remediation.
- Permissions are enforced by the server. Assessment writes commit atomically with their audit events.
- Sensitive source data, credentials, raw findings and internal identifiers stay within their authorised environment.
- UI and API behaviour communicate pending, stale, denied, conflicting and failed states clearly.

## Product target

The local proof of concept exercises intended workflows at smaller scale. The deployment target is a supervised, self-contained image with UVM, DefectDojo CE, separate databases and required runtime processes. The target includes interchangeable OIDC, configurable access groups and ownership teams, auditable assessment, reporting, integration recovery, an in-application audit view, independent SIEM export, notifications and coordinated backup/restore.

Local fixtures and containers establish only the behaviour they exercise. They do not establish live scanner semantics, named identity-provider compatibility, cloud hosting, external messaging, SIEM receipt or production recovery.

## Development model

Use requirement IDs and OpenSpec scenarios to state behaviour. Keep the verified `openspec/specs/` directory limited to behaviour established by the project's verification process. A proposed change or passing mock does not establish deployed behaviour.
