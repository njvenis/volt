# Packaging and deployment boundary

## What the repository provides

`Dockerfile.g7` is the build recipe used for RC1 and development images; it builds an image from pinned DefectDojo CE and Valkey bases and the VOLT source. The image includes the local application processes and PostgreSQL/Valkey runtime components. RC2 is the Compose-compatible Linux/amd64 evaluation release with a source-free installer bundle and digest-pinned published image; see [RC2 installation](installation.md#rc2-compose-installation). RC1 remains available from public GHCR and as a signed historical launcher archive. The separate local preview helper admits only `linux/amd64` images; its `start --no-build` mode checks immutable image ID, source revision, version label, and platform against operator-supplied expected values. No Helm chart, general production installer or production deployment workflow is supplied.

RC1 v0.1.0-rc.1 is a fresh-install release. It does not upgrade or adopt historical development volumes. The launcher saves the immutable image binding before creating Docker resources and refuses a changed image or an unbound partial initialization. Same-image stop/restart is supported for an established instance.

For current Compose evaluation, use [RC2 installation](installation.md#rc2-compose-installation); the [historical RC1 launcher](installation.md#historical-rc1-launcher) remains separate and is not Compose-compatible. For source builds, use [the development preview guide](local-preview.md). The preview exposes the API/UI and synthetic OIDC provider on loopback and isolates its Docker network. It uses three persistent volumes for PostgreSQL data, DefectDojo media, and VOLT state. `stop` retains them; `destroy` removes them.

## What a deployer must provide

This image target does not define production secret delivery, public ingress or TLS termination, DNS, network policy, storage classes, host observation, backup scheduling, off-host retention, restore authority, or incident monitoring. Those controls must be designed, supplied, and verified for the chosen environment. The local preview's loopback bindings and generated synthetic credentials are not deployment defaults.

The container's three local volumes do not by themselves constitute a backup or coordinated recovery plan. The [backup/recovery contract](g7-backup-settings-contract.md) and [upgrade/rollback development delta](g7-upgrade-rollback-development-delta.md) describe bounded development work, not a general production procedure. Live identity providers, scanners, GitHub, messaging/email, SIEM, and cloud hosting require their own configured endpoints, credentials, network access, and integration evidence.

RC1 passed the release workflow's image-specific notice checks and includes the resulting inventory and source evidence in its signed offline bundle; see [THIRD-PARTY-NOTICES.md](../THIRD-PARTY-NOTICES.md). A new or modified image requires its own complete collection and verification. Source licensing and image redistribution remain separate questions.
# Compose evaluation deployment

The RC2 source-free Compose bundle runs one supervised image with separate persistent PostgreSQL, media and VOLT state volumes. Its published digest-pinned image is a distinct immutable release from RC1; a runtime change is not retroactively attributed to RC1, and RC1 does not meet the Compose contract. External OIDC and local synthetic demo modes have separate admission and startup rules. See the [RC2 installation guide](installation.md#rc2-compose-installation) for the signed bundle and image reference.
