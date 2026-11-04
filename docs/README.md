# VOLT documentation

Use this index to find the current runnable guidance and the detailed product contracts. Contract and scenario documents describe specific development scope; they are not automatically installation or production-operation instructions.

## First steps

- [Primary installation: source-free Compose bundle](../deploy/compose/README.md): new evaluation installs, explicit compatible candidate image, external OIDC configuration and local demo mode.
- [Install RC1](installation.md): verify and run the published Linux/amd64 image without rebuilding, or use the signed offline bundle.
- [Development preview](local-preview.md): build and run the synthetic loopback preview, sign in, exercise its smoke path, and stop or destroy it.
- [Configuration inputs](configuration.md): generated preview settings, packaging example values, and required secret files.
- [Packaging and deployment boundary](deployment.md): image contents, verification scope, dependencies, and controls a deployer must supply.
- [Operations and recovery references](operations.md): local health/status, lifecycle, troubleshooting, and the status of recovery/upgrade/monitoring guidance.

## User and operator guidance

Production operation remains outside the supported scope. Compose is the primary installation path for new work; it is not yet backed by a published compatible image. RC1 documentation is historical and its launcher remains a separate path.

| Topic | Start here |
| --- | --- |
| New installation | [Source-free Compose bundle](../deploy/compose/README.md) — candidate image required; development contract |
| Historical released-image evaluation | [Install RC1](installation.md) — fresh Linux/amd64 installations with synthetic identity |
| Configuration and deployment | [Configuration inputs](configuration.md), [deployment boundary](deployment.md) |
| Local operations and troubleshooting | [Operations guide](operations.md) |
| Security and responsible reporting | [Security policy](../SECURITY.md) |
| Licensing and dependencies | [Apache-2.0 licence](../LICENSE), [third-party notices](../THIRD-PARTY-NOTICES.md) |

## Engineering contracts and reference

Requirements, gates, ADRs and G7 contracts retain their stated verification boundaries. They are supporting engineering material, not additional installation steps.

| Topic | Start here |
| --- | --- |
| Development from source | [Development preview](local-preview.md) |
| Release artifacts and evidence | [RC1 release](https://github.com/njvenis/volt/releases/tag/v0.1.0-rc.1), [maintainer release guide](releasing.md) |
| Product behavior and maturity | [Requirements](../REQUIREMENTS.md), [development gates](../GATES.md), [active change](../openspec/changes/g7-enterprise-rollout/) |
| Architecture and domain decisions | [Architecture decision records](adr/), [DefectDojo boundary](adr/0001-defectdojo-engine.md), [native grouping](adr/0002-native-vulnerability-grouping.md) |
| Operations: backup and restore | [Backup settings and recovery contract](g7-backup-settings-contract.md) — draft development contract, not a production runbook |
| Operations: retained data and audit | [Data-preservation contract](g7-data-preservation-contract.md), [local verification record](g7-data-preservation-verification.md) |
| Operations: upgrades and rollback | [Upgrade/rollback development delta](g7-upgrade-rollback-development-delta.md) — bounded local proof, not a generic upgrade procedure |
| Operations: host monitoring and settings | [Observer settings](g7-observer-settings-contract.md), [host runtime](g7-observer-host-runtime.md), [operational alerts](g7-operational-alert-contract.md) |
| Assessment, identity, and exception behavior | [Native access/ownership API contract](g7-native-access-ownership-api-contract.md), [exception/SLA contract](g7-exception-sla-implementation-contract.md) |
| UI and accessibility | [UI requirements](ui-requirements.md), [`design/tokens.json`](../design/tokens.json) |
| Development and checks | [Runbook](../RUNBOOK.md), [contributing](../CONTRIBUTING.md), [OpenSpec changes](../openspec/changes/) |

A public RC1 image and signed offline bundle are available. Compose bundle sources are maintained for development, but its required compatible image is not yet published. Helm deployment and a production backup/upgrade runbook are not provided.
# Installation and operations

- [Source-free Compose bundle](../deploy/compose/README.md)
- [Compose cold backup and restore limits](../deploy/compose/backup-restore.md)
- [Installation guide](installation.md)
- [Configuration guide](configuration.md)
- [Operations guide](operations.md)
