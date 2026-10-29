## 1. Design and interfaces

- [ ] 1.1 [AGENT] Review deployment, identity, audit/SIEM, retention, backup/restore and cutover contracts against the requirement scenarios.
- [ ] 1.2 [AGENT] Define interfaces, migrations, failure handling, rollback and exact verification environments for each implementation increment.
- [ ] 1.3 [HUMAN] Select deployment-specific production policy, identity and operational values before release activation.

## 2. Development checkpoints

- [ ] 2.1 [AGENT] Verify deployment-scoped observer timing through API, UI and independent host readback, including stale revision, denial, persistence failure, outage and rollback behaviour.
- [ ] 2.2 [AGENT] Verify VOLT-managed access groups, ownership teams, current authorization, approval eligibility and session revocation.
- [ ] 2.3 [AGENT] Verify ingestion-based SLA, exception pause/resume, retained breach history and configurable expiry warnings.
- [ ] 2.4 [AGENT] Verify application audit viewing, independent SIEM export receipts/reconciliation, data preservation classes and failure alerts.
- [ ] 2.5 [AGENT] Verify one-container process supervision, network boundaries, durable state, coordinated backup/restore and upgrade rollback in a named disposable environment. For G7-REC-01, retain separately labelled historical `0058→0059` evidence and current-main `0058→0061` evidence; bind the current image/package pair and source archive/image, prove control-only startup before migration, exact migration inventories and rollback on separate fresh volumes at a higher recovery epoch, fail closed on partial/unknown schema drift, and retain continuous effect fences and zero post-backup product writes.
- [ ] 2.6 [AGENT] Run strict OpenSpec validation and the relevant integrated journey; record exact source, environment, commands, outputs, exits and cleanup; obtain independent review.

## 3. Release and external validation

- [ ] 3.1 [EXTERNAL] Validate named identity, scanner, GitHub, messaging, SIEM and infrastructure integrations in their authorised environments.
- [ ] 3.2 [EXTERNAL] Validate issue adoption, one-writer cutover, comparison and rollback before live writer migration.
- [ ] 3.3 [HUMAN] Authorise or reject release and production cutover for the reviewed source, targets and rollback plan.
- [ ] 3.4 [HUMAN] Make the separate G7 pass/fail decision against executed evidence and explicit exclusions.
