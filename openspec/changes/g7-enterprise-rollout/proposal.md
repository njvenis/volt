# G7: Deployment readiness and controlled rollout

## Why

Define the deployment and operational behaviour needed to run VOLT with DefectDojo CE while preserving authorization, audit, data integrity and recovery boundaries.

## Scope

The target is a supervised, self-contained Docker image containing UVM, pinned DefectDojo CE, separate application databases and required runtime processes. It includes interchangeable standards-based OIDC, VOLT-managed access groups and ownership teams, ingestion-based SLA calculations, risk exceptions with pause/resume, an in-application audit viewer, an independently controlled SIEM copy, configurable Slack/email warnings, externally operated backups, coordinated recovery and controlled writer cutover. The local G7 SLA slice proposes a versioned `RuleV1` context-field mechanism so policy facts such as environment can be retained from authoritative identity-writer input without becoming identity correspondence evidence. Known retained context remains usable when omitted by a later observation; conflicts remain unresolved without new coverage or erasing an admitted clock; missing stored context is never backfilled, and only a missing selector required for a prospective G7 episode creates a coverage gap. Existing G5-pinned episodes remain G5. This proposal does not authorize production policy values.

Local Docker and synthetic-provider checks are limited to their labelled fixture behaviour. They do not establish AWS, Okta, live scanner, GitHub, Slack, email, SIEM or production infrastructure compatibility.

## Operational settings

Versioned settings retain desired revisions, scoped permissions, audit records and command receipts. Independent infrastructure reports whether a desired revision is effective. Rollback publishes a new revision. VOLT does not receive general host administration authority.

## Requirements

Primary requirements: NFR-04, CR-11, FR-AS-02/03/05, FR-OW-01, FR-AU-01/02, FR-NT-01, FR-GH-04 and FR-OP-01. The detailed scenarios are in `specs/g7-enterprise-rollout/spec.md`.
