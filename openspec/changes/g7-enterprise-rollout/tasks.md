## 1. Design and interfaces

- [ ] 1.1 [AGENT] Review deployment, identity, audit/SIEM, retention, backup/restore and cutover contracts against the requirement scenarios.
- [ ] 1.2 [AGENT] Define interfaces, migrations, failure handling, rollback and exact verification environments for each implementation increment.
- [ ] 1.3 [HUMAN] Select deployment-specific production policy, identity and operational values before release activation.

## 2. Development checkpoints

- [ ] 2.1 [AGENT] Verify deployment-scoped observer timing through API, UI and independent host readback, including stale revision, denial, persistence failure, outage and rollback behaviour.
- [ ] 2.2 [AGENT] Verify VOLT-managed access groups, ownership teams, current authorization, approval eligibility and session revocation.
- [ ] 2.3 [AGENT] Verify ingestion-based SLA, exception pause/resume, retained breach history and configurable expiry warnings.
- [ ] 2.4 [AGENT] Verify application audit viewing, independent SIEM export receipts/reconciliation, data preservation classes and failure alerts.
- [ ] 2.5 [AGENT] Verify one-container process supervision, network boundaries, durable state, coordinated backup/restore and upgrade rollback in a named disposable environment. For G7-REC-01, retain separately labelled historical `0058→0059` evidence and source-bound current-main `0058→0061` evidence; bind image/package pairs and source archives/images, prove control-only startup before migration, exact migration inventories and rollback on separate fresh volumes at a higher recovery epoch, fail closed on partial/unknown schema drift, and retain continuous effect fences and zero post-backup product writes.
- [ ] 2.6 [AGENT] Run strict OpenSpec validation and the relevant integrated journey; record exact source, environment, commands, outputs, exits and cleanup; obtain independent review.
- [ ] 2.7 [AGENT] After independent review of the RuleV1 context contract, implement optional immutable `workload_context_fields` and migration `0062`; prove the full matrix: known stored context plus omitted input retains coverage; conflict remains unresolved with no new coverage or existing-clock erasure; missing stored context is not backfilled; only unavailable required selectors for prospective G7 create gaps; unused optional context does not blanket-gap; already G5-pinned episodes remain G5. Preserve legacy empty-context digest/fingerprint/replay bytes and assert non-empty canonical preimages, strict stored-array validation, context-only non-selection, match-field ambiguity, atomic graph/SLA rollback with separate source retention, and exact current-schema inventory.
- [ ] 2.8 [AGENT] Run focused identity tests, full operations suite, affected current-image schema recovery checks, UI build, strict pinned OpenSpec validation and the maintained `--exception-sla-only` journey. Retain the captured source-bound `0058→0061` proof without rerunning absent a defect; execute distinct narrow `0061→0062` and current-candidate `0058→0062` proofs. Retain exact snapshots, commands, outputs, exits and cleanup.

## 3. Release and external validation

- [ ] 3.1 [EXTERNAL] Validate named identity, scanner, GitHub, messaging, SIEM and infrastructure integrations in their authorised environments.
- [ ] 3.2 [EXTERNAL] Validate issue adoption, one-writer cutover, comparison and rollback before live writer migration.
- [ ] 3.3 [HUMAN] Authorise or reject release and production cutover for the reviewed source, targets and rollback plan.
- [ ] 3.4 [HUMAN] Make the separate G7 pass/fail decision against executed evidence and explicit exclusions.
