# Packaging and deployment boundary

## What the repository provides

`Dockerfile.g7` is the build recipe used for the evaluation images; it builds from pinned DefectDojo CE and Valkey bases and the VOLT source. The supervised image contains VOLT, DefectDojo CE, PostgreSQL, Valkey and the required runtime processes. The current RC3 Compose evaluation release provides native `linux/amd64` and `linux/arm64` images with a signed per-platform offline archive and source-free installer bundle; see [RC3 installation](installation.md#rc3-compose-installation). RC1 remains a signed historical launcher release and RC2 remains an immutable historical Compose release. The separate local preview helper checks immutable image ID, source revision, version label and platform against operator-supplied expected values. No Helm chart, general production installer or production deployment workflow is supplied.

RC1 v0.1.0-rc.1 is a fresh-install release. It does not upgrade or adopt historical development volumes. The launcher saves the immutable image binding before creating Docker resources and refuses a changed image or an unbound partial initialization. Same-image stop/restart is supported for an established instance.

For current Compose evaluation, use [RC3 installation](installation.md#rc3-compose-installation). The [historical RC2 Compose release](installation.md#rc2-compose-installation) and [RC1 launcher](installation.md#historical-rc1-launcher) retain separate immutable instructions. For source builds, use [the development preview guide](local-preview.md). The preview exposes the API/UI and synthetic OIDC provider on loopback and isolates its Docker network. It uses three persistent volumes for PostgreSQL data, DefectDojo media, and VOLT state. `stop` retains them; `destroy` removes them.

## What a deployer must provide

This image target does not define production secret delivery, public ingress or TLS termination, DNS, network policy, storage classes, host observation, backup scheduling, off-host retention, restore authority, or incident monitoring. Those controls must be designed, supplied, and verified for the chosen environment. The local preview's loopback bindings and generated synthetic credentials are not deployment defaults.

The container's three local volumes do not by themselves constitute a backup or coordinated recovery plan. The [backup/recovery contract](g7-backup-settings-contract.md) and [upgrade/rollback development delta](g7-upgrade-rollback-development-delta.md) describe bounded development work, not a general production procedure. Live identity providers, scanners, GitHub, messaging/email, SIEM, and cloud hosting require their own configured endpoints, credentials, network access, and integration evidence.

RC1 passed the release workflow's image-specific notice checks and includes the resulting inventory and source evidence in its signed offline bundle; see [THIRD-PARTY-NOTICES.md](../THIRD-PARTY-NOTICES.md). A new or modified image requires its own complete collection and verification. Source licensing and image redistribution remain separate questions.
# Compose evaluation deployment

The RC3 source-free Compose bundle runs one supervised image with separate persistent PostgreSQL, media and VOLT state volumes. External OIDC and local synthetic demo modes have separate admission and startup rules. The RC2 Compose release and RC1 launcher remain distinct immutable historical releases; their image identities and instructions are not replaced by RC3. See the [RC3 installation guide](installation.md#rc3-compose-installation) for signed bundle verification and platform selection.
