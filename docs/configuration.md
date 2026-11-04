# Configuration inputs

## Local preview

The local preview does not require a hand-written environment file. `tools/g7_local_preview.py init <name>` generates private configuration, local TLS material, and synthetic credentials under `$XDG_STATE_HOME/volt/g7-preview/<name>` (defaulting to `$HOME/.local/state`). Keep that state directory private. The helper mounts its secret directory read-only into the container and owns the preview's ports, network, and volumes. See [RC1 installation](installation.md) for the released-image commands or [the development preview guide](local-preview.md) for source builds.

## Development image packaging

[`docker/g7/config.env.example`](../docker/g7/config.env.example) contains non-secret example settings for database names/storage paths, internal ports, synthetic DefectDojo bootstrap identity fields, and optional warning-worker settings. It is not loaded automatically by a production environment manager and is not a production configuration.

At startup, `docker/g7/entrypoint.sh` requires these files in `/run/secrets`:

- `uvm_db_password`, `ce_db_password`
- `ce_admin_password`, `ce_secret_key`, `ce_credential_key`, `uvm_cursor_secret`
- `recovery-server.crt`, `recovery-server.key`, `recovery-ca.crt`

OIDC mode additionally requires `oidc_client_secret`, `oidc_sync_secret`, and `oidc_operator_secret`, with references supplied by the OIDC configuration. Connector tokens, webhook secrets, local signing keys, and notification credentials are optional inputs when the corresponding integration is configured. File contents must be managed by the operator and kept outside source control; no real values belong in the example file.

The recovery TLS files are for the image's recovery-control boundary. They do not configure public ingress TLS. See [packaging/deployment boundaries](deployment.md) before adapting this target to another environment.
