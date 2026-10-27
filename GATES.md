# Development and verification

VOLT is developed in small, reviewable increments. A feature description, OpenSpec scenario, test, or successful local build is not by itself a claim that an external integration or production deployment has been verified.

## Evidence labels

- **Synthetic/local** means behaviour was exercised with generated fixtures or local services.
- **Integration verified** means the named service and version were actually used, with the tested revision and result recorded.
- **Production ready** is a release decision requiring deployment-specific security, operations, recovery and integration review. No such claim is made by this repository.

## Invariants

- DefectDojo Community Edition remains a dependency and is accessed through supported APIs. VOLT does not write directly to its database tables.
- Source-native vulnerability identifiers lead grouping. CVE overlap alone does not merge groups or erase occurrences.
- Rebuilds and scanner refreshes preserve lineage, assessment, ownership and issue associations.
- Missing or incomplete scanner data, risk acceptance and exclusions do not count as remediation.
- State-changing actions are authorised on the server and commit with their audit records.
- Credentials, raw findings and private environment identifiers stay in their authorised environment.

## Current development areas

The active OpenSpec change describes the G7 deployment and operational target. Its scenarios are acceptance goals, not execution records. Local fixture evidence remains limited to the behaviour and environment it actually exercised. Identity-provider, scanner, GitHub, Slack, SIEM, cloud-hosting and production recovery claims require their named services and must be verified independently.

Keep test outputs in temporary directories or an explicitly selected local evidence directory. Do not commit credentials, raw production data, private reports or generated run logs.
