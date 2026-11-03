# VOLT documentation

Use this index to find the current runnable guidance and the detailed product contracts. Contract and scenario documents describe specific development scope; they are not automatically installation or production-operation instructions.

## First steps

- [Local preview](local-preview.md): build and run the synthetic loopback preview, sign in, exercise its smoke path, and stop or destroy it.
- [Configuration inputs](configuration.md): generated preview settings, packaging example values, and required secret files.
- [Packaging and deployment boundary](deployment.md): image contents, verification scope, dependencies, and controls a deployer must supply.
- [Operations and recovery references](operations.md): local health/status, lifecycle, troubleshooting, and the status of recovery/upgrade/monitoring guidance.

## By topic

| Topic | Start here |
| --- | --- |
| Local installation/evaluation | [Local preview](local-preview.md) — this repository has no generic production installer |
| Configuration and deployment | [Configuration inputs](configuration.md), [deployment boundary](deployment.md) |
| Product behavior and maturity | [Requirements](../REQUIREMENTS.md), [development gates](../GATES.md), [active change](../openspec/changes/g7-enterprise-rollout/) |
| Architecture and domain decisions | [Architecture decision records](adr/), [DefectDojo boundary](adr/0001-defectdojo-engine.md), [native grouping](adr/0002-native-vulnerability-grouping.md) |
| Local operations and troubleshooting | [Operations guide](operations.md) |
| Operations: backup and restore | [Backup settings and recovery contract](g7-backup-settings-contract.md) — draft development contract, not a production runbook |
| Operations: retained data and audit | [Data-preservation contract](g7-data-preservation-contract.md), [local verification record](g7-data-preservation-verification.md) |
| Operations: upgrades and rollback | [Upgrade/rollback development delta](g7-upgrade-rollback-development-delta.md) — bounded local proof, not a generic upgrade procedure |
| Operations: host monitoring and settings | [Observer settings](g7-observer-settings-contract.md), [host runtime](g7-observer-host-runtime.md), [operational alerts](g7-operational-alert-contract.md) |
| Assessment, identity, and exception behavior | [Native access/ownership API contract](g7-native-access-ownership-api-contract.md), [exception/SLA contract](g7-exception-sla-implementation-contract.md) |
| UI and accessibility | [UI requirements](ui-requirements.md), [`design/tokens.json`](../design/tokens.json) |
| Security and responsible reporting | [Security policy](../SECURITY.md), [requirements](../REQUIREMENTS.md) |
| Development and checks | [Runbook](../RUNBOOK.md), [contributing](../CONTRIBUTING.md), [OpenSpec changes](../openspec/changes/) |
| Licensing and dependencies | [Apache-2.0 licence](../LICENSE), [third-party notices](../THIRD-PARTY-NOTICES.md) |

No public registry, general-purpose production installer, Compose/Helm deployment, or complete production backup/upgrade runbook is provided by this repository.
