# Packaging and deployment boundary

## What the repository provides

`Dockerfile.g7` builds a development image from pinned DefectDojo CE and Valkey bases and the VOLT source. The image includes the local application processes and PostgreSQL/Valkey runtime components. The local preview helper currently admits only `linux/amd64` images. Its `start --no-build` mode can run an already loaded image only after checking its immutable image ID, source revision, version label, and platform against operator-supplied expected values; it does not publish or download that image. No public registry, image archive, Compose/Helm chart, general installer, or production deployment workflow is supplied.

For the supported local evaluation path, use [the local preview guide](local-preview.md). The preview exposes the API/UI and synthetic OIDC provider on loopback and isolates its Docker network. It uses three persistent volumes for PostgreSQL data, DefectDojo media, and VOLT state. `stop` retains them; `destroy` removes them.

## What a deployer must provide

This image target does not define production secret delivery, public ingress or TLS termination, DNS, network policy, storage classes, host observation, backup scheduling, off-host retention, restore authority, or incident monitoring. Those controls must be designed, supplied, and verified for the chosen environment. The local preview's loopback bindings and generated synthetic credentials are not deployment defaults.

The container's three local volumes do not by themselves constitute a backup or coordinated recovery plan. The [backup/recovery contract](g7-backup-settings-contract.md) and [upgrade/rollback development delta](g7-upgrade-rollback-development-delta.md) describe bounded development work, not a general production procedure. Live identity providers, scanners, GitHub, messaging/email, SIEM, and cloud hosting require their own configured endpoints, credentials, network access, and integration evidence.

The combined image's package-level third-party notices have not been fully audited. Do not redistribute a built image until [THIRD-PARTY-NOTICES.md](../THIRD-PARTY-NOTICES.md) is completed for that artifact. Source licensing and image redistribution are separate questions.
