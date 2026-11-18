# Backend shared contract checkpoint

Status: proposed concrete backend spellings for runtime/UI coordination, 2026-11-18. Public endpoint paths follow adopted `docs/easy-install-api-contract.md`.

## Runtime selection and private file

- Environment: `UVM_AUTH_MODE=local`; absent means existing default/legacy selection and never implicitly converts an existing database.
- File: `/etc/volt/local-auth.json` (runtime configurable via `UVM_LOCAL_AUTH_CONFIG_FILE`). JSON schema is exactly:
  `{"schema_version":1,"installation_id":"<uuid>","public_origin":"<bare origin>","secret_source":{"kind":"encrypted_local_v1","secret_source_id":"<uuid>","key_path":"<absolute path>"},"bootstrap_delivery":{"kind":"private_file","path":"<absolute path>"},"session_policy":{"ttl_seconds":3600},"trusted_ingress":{"mode":"loopback|https","allowed_hosts":["<host[:port]>"],"allowed_peer_cidrs":["<loopback-or-private CIDR>"]}}`.
- `key_path` uses the existing connector format: exactly 32 raw bytes in a regular mode-0600 file; key ID is the UUID in the secret-source config and existing `UVM_CONNECTOR_LOCAL_KEY_ID`. No new key encoding.

## Host maintenance CLI

`python -m uvm.auth.maintenance <operation> --config /etc/volt/local-auth.json` using the installed runtime interpreter; operations: `prepare-setup`, `rotate-setup`, `create-account --username ... --display-name ...`, `issue-enrolment --username ...` (reissue for an existing pending account), `issue-recovery --username ...`, `disable-account --username ...`, `revoke-capabilities` (post-restore). Secrets/capabilities go only to configured private delivery file, never stdout or capability argv values. Setup TTL is fixed at 30 minutes; recovery and enrolment TTLs are fixed at 15 minutes; absolute session TTL is fixed at 3600 seconds. Capability digest is domain-separated over purpose, installation, target account, generation, credential revision and secret; the opaque locator is never authority by itself.

## Response DTOs

All success JSON objects use `schema_version: 1`. `GET /api/v1/auth/config`: `{schema_version,mode,setup_state}`. `POST /api/v1/auth/setup/claim`: `{schema_version,authenticated,principal_id,receipt_id,credential_mode,csrf_token,protected_admin,access_groups,source_scopes,authority}` (201 + local cookie). Session representation preserves current fields and adds `credential_mode:"local_session"`, `csrf_token`, and server-derived `protected_admin` (true only when the current principal is in persisted `native_authority.bootstrap_admins`). `GET /api/v1/deployment`: `{schema_version,installation_id,connector_registry_revision,can_register_connector,connectors,policy_revision,authority_revision}`; each connector summary is `{connector_id,lifecycle,connector_revision,configuration_revision,source_revision,environment_label,source:{source_id,source_family,source_account_id,scope_key}}`, with no secret/configuration data.

Registration uses its adopted new-registration V1 shape (kept separate from the existing general assessment command DTO): `{schema_version:1,command_id,action:"connector.binding.register",target_id:"00000000-0000-0000-0000-000000000000",membership_ids:[],expected_policy_revision,expected_authority_revision,expected_connector_registry_revision,payload:{display_name,source_family,source_account_id,scope_key,environment_label,rationale,evidence_ref,grant_initial_read}}`. Revision values are top-level, strict and have no aliases. The success body reuses the assessment receipt shape `{schema_version,command_id,decision_id,audit_event_id,intent_id,committed_revision,projection,action,target_id,policy_revision,intents,result}`; `result` includes `effect:"native_administration_state_committed"`, `policy_revision`, `authority_revision`, and `allocated_ids:{connector_id,source_id,access_group_id,role_id}` plus the committed connector registry revision and disabled state. Exact replay keeps the same receipt, changed payload conflicts.

Error conventions follow API contract: generic 401, state 409, validation 422, rate 429 + Retry-After, unavailable 503; Origin/CSRF 403.

## Command outcome reconciliation

`POST /api/v1/assessment/commands/{command_id}/abandon` accepts the complete unchanged registration request under `command` plus a non-empty disposition `rationale` and `evidence_ref`: `{schema_version:1,command:<exact original registration body>,rationale,evidence_ref}`. Submit and abandon digest the exact body with actor identity; neither rewrites the held request. The endpoint requires the current local protected bootstrap-admin session (including the ordinary Origin/CSRF checks), then takes the same policy serialization lock as command submission. Its terminal outcome is bound to command ID, actor and canonical request digest and is audited in the same transaction as the tombstone. It returns `disposition:"committed"` with the original receipt if that exact command already committed, or `disposition:"not_committed"` with command ID, digest, actor, audit event ID and commit timestamp after persisting the terminal tombstone. Changed actor/content conflicts. Submission of the old command ID after a not-committed disposition is rejected as `409 command_terminal`; it cannot later commit. Missing readback, 404 and transport failure are not dispositions.

## Adapter boundary map

Current Qualys and Sysdig scheduled collector classes are cursor-scripted fixture clients and do not fetch live APIs. The Qualys generic adapter parses scanner XML into a DefectDojo Generic Findings import payload; it is not a source client or VOLT ingestion writer. `CEReadClient` is an injected-transport, GET-only reader for the allowlisted CE products, engagements, tests, findings and endpoints routes. The `ce_import` operator CLI is the opposite data direction: it reads an already retained VOLT run and POSTs an authorized `import-scan` or `reimport-scan` request to CE, using operator-provided CE credentials. The existing connector configuration/stage/validation path is GitHub-specific. There is no supported live scanner or CE-to-VOLT ingestion adapter today; registering a source tuple creates a disabled authorization binding only and does not claim configuration, validation or activation readiness.

A CE-as-upstream path would need supported CE-to-VOLT synchronization, including bounded/pinned list/read operations, stable source-native identity and provenance mapping, pagination and retention, source-account/scope mapping and atomic persisted collection runs/observations. Direct scanner support would instead need a real provider client, credential lifecycle, scanner coverage/pagination semantics, native identity mapping and ingestion writer. Neither capability is implemented by this installer checkpoint.

## OpenAPI export

`tools/export_openapi.py` now merges route declarations from bearer, OIDC and local auth modes using disposable synthetic configuration and in-memory SQLite. This controls documentation generation only. Runtime route admission continues to use the deployed `UVM_AUTH_MODE` and persisted identity mode.
