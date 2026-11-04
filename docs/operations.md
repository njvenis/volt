# Operations and troubleshooting

This guide covers disposable local evaluation using either [the released RC1 image](installation.md) or [a development source build](local-preview.md). It is not a production operations runbook. Examples below use the instance name `demo`; substitute `rc1` if you followed the RC1 installation guide.

## Preview status and health

Run commands from the same committed, clean checkout used to initialize the preview:

```sh
python3 tools/g7_local_preview.py status demo
python3 tools/g7_local_preview.py wait demo
```

`status` reports the owned container's Docker state. `wait` waits for Docker's image health check and reports `health=healthy` on success. The browser UI is at the URL printed by `start` (default `http://127.0.0.1:8180/`); the synthetic OIDC provider uses loopback port 8190 by default. The UVM health endpoint is `http://127.0.0.1:8180/healthz`.

If a port is already in use, initialize another preview with unused `--api-port` and `--oidc-port` values. If Chromium is not found, install the lockfile-pinned browser as described in [the preview guide](local-preview.md), or set `CHROMIUM_EXECUTABLE_PATH` to a compatible local browser. If the helper reports that its source revision changed after initialization, return to that clean revision or destroy and initialize a new preview. If an established owned resource is missing, the helper refuses to recreate or rebind it; preserve its evidence and inspect the failure before taking action.

## Stop, resume, and remove

- `stop <name>` stops the container and retains the instance configuration, network, and three data volumes.
- `restart <name>` restarts the existing container; follow with `wait <name>` and, when needed, `smoke <name> --readback --evidence <directory>` to check the saved synthetic operation.
- `destroy <name>` removes only resources whose ownership identifiers match that instance, including its three volumes and private configuration. It does not prune unrelated Docker resources. Retain evidence separately if needed.

See the exact lifecycle and command sequence in [the local preview guide](local-preview.md).

## Backup, upgrades, and monitoring

The repository does not provide a general production backup/restore or upgrade procedure. The [backup/recovery contract](g7-backup-settings-contract.md), [preservation contract](g7-data-preservation-contract.md), and [upgrade/rollback delta](g7-upgrade-rollback-development-delta.md) are scoped development contracts and evidence references; use their stated status before treating them as operational instructions. Host observation and alerting guidance is likewise in development contracts: [observer settings](g7-observer-settings-contract.md), [host runtime](g7-observer-host-runtime.md), and [operational alerts](g7-operational-alert-contract.md). They do not establish production monitoring or recovery readiness.

For development verification, use [RUNBOOK.md](../RUNBOOK.md). For vulnerability reporting status, see [SECURITY.md](../SECURITY.md).
