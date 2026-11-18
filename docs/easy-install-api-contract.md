# Proposed easy-install interface, version 1

Design authority: openspec/changes/easy-compose-install/design.md. This is a new-instance extension, not a claim of implemented endpoints. Preserve existing OIDC/demo and their current permission checks.

## Browser API

Responses use schema_version 1 and Cache-Control: no-store. New credential endpoints require exact Origin and JSON; authenticated writes require existing CSRF. Do not echo submitted secrets. Local session cookies reuse the application's protected session lifecycle, with credential_mode local_session. Local mode is selected explicitly and checked against persisted installation mode.

| Method/path | Request | Success |
| --- | --- | --- |
| GET /api/v1/auth/config | none | mode local/oidc/demo; setup_state required/claimed/unavailable/not_applicable; no identities or secret metadata |
| POST /api/v1/auth/setup/claim | capability, username, display_name, password | 201; principal_id, receipt_id, local session cookie; no source fields |
| POST /api/v1/auth/local/login | username, password | current session representation and cookie |
| GET /api/v1/auth/session | existing cookie | existing fields plus local_session mode and current CSRF token |
| POST /api/v1/auth/local/password | current_password, new_password, CSRF | 204, all sessions revoked, cookie cleared |
| POST /api/v1/auth/local/recovery | capability, new_password | 204; normal subsequent sign-in |
| POST /api/v1/auth/local/enrol | capability, new_password | 204; activates only the host-created pending account, no authority, then normal sign-in |
| Existing logout | existing CSRF contract | persisted local revocation and cookie clearing |
| GET /api/v1/deployment | valid protected administrator session | installation_id, connector_registry_revision, can_register_connector, safe connector summaries and current policy/authority revisions |
| Existing assessment commands endpoint | connector.binding.register using existing command envelope | existing committed receipt with allocated IDs/revisions |

not_applicable applies only to non-local modes. Invalid authentication/capability is generic 401; claimed/state/revision conflict 409; safe field validation 422; throttling 429 with Retry-After; unavailable persistence 503. Origin/CSRF denials preserve established 403 semantics. Session alone confers no deployment or scanner authority.

## Connector registration command

Use the existing assessment commands endpoint with a registration-specific schema-1 envelope: caller-generated stable command_id, action connector.binding.register, deployment target UUID 00000000-0000-0000-0000-000000000000, empty membership_ids, top-level expected_policy_revision/expected_authority_revision/expected_connector_registry_revision and payload display_name/source_family/source_account_id/scope_key/environment_label/rationale/evidence_ref/grant_initial_read. Strictly validate this shape; nested expected_revisions and the legacy internal target sentinel are not aliases for this new public action. Existing regular assessment V1 envelopes remain unchanged. Submission and abandonment bind the exact original public object and actor; never rewrite a retained request to translate schemas. Allocate internal connector/source/group/role IDs server-side. Validate supported adapter semantics and uniqueness. An identical replay returns its receipt; changed payload conflicts.

Registration is a protected bootstrap-administrator operation, not a new broadly grantable permission. It creates a disabled binding and exact-source connector.read/configure/secret.manage grants atomically. The UI makes grant_initial_read an explicit visible default; when selected it grants only exact-source assessment.read/audit.read with the existing all_current membership rule. No assessment write, approval or remediation grant is implicit. Normal native administration remains configurable. Source expansion is a protected audited browser action; external OIDC ceilings remain unchanged.

An uncertain registration remains frozen until its outcome is established. Explicit operator reconciliation uses `POST /api/v1/assessment/commands/{command_id}/abandon`, with `{schema_version: 1, command: <complete original registration envelope>, rationale, evidence_ref}` and the current local protected administrator's session and CSRF protection. Under the same policy serialisation as registration, the service first checks an exact actor/action/request-digest-bound committed receipt. It returns `disposition: committed` with that original receipt when present. Otherwise audit and a durable terminal tombstone commit together before returning `disposition: not_committed` with `command_id`, `request_digest`, `actor_id`, `audit_event_id` and `committed_at`. Later submission of that abandoned ID fails with `command_terminal`; conflicting actor or content is rejected. A definitive abandonment permits an explicitly reviewed new command with current revisions. Absence, generic conflict, timeout or network failure never establishes non-commit. A confirmed original receipt is reconciled against exact allocated identities and source binding; a later valid lifecycle transition does not invalidate the historical receipt.

The intended next UI route requires adapter-appropriate configuration/secret/validation/activation APIs and supported encrypted-local secret binding IDs. Current inspection establishes that the existing configuration API is GitHub-specific and that Qualys/Sysdig collection clients are fixtures. On 18 November 2026 the user selected Qualys as the first supported scanner. Its configuration and ingestion contract and implementation remain pending; a disabled registry binding is not a working scanner. Fixture environment lookup is not the local-mode registry. Network calls and external validation occur only at explicit authorised stages.

## Native local-v2 target ceiling

The initial concrete action ceiling is policy.read, access_group.read, ownership.team.read, ownership.team.manage, connector.read, connector.configure, connector.secret.manage, assessment.read and audit.read; it is not an effective grant. Legacy finding selectors/source_scopes are initially empty. Initial effective membership grants only the first three administrative reads with target_scope {kind: deployment, deployment_ids: [installation UUID]}. Protected bootstrap powers remain separate.

For local native contract version 2, use exact deployment targets for administrative read/team actions, exact connector_ids plus registered connector/source-pair ceilings for the three connector actions, and kind source_read with all_current for assessment.read/audit.read within a non-empty exact source tuple list. Existing v1 finding selectors remain unchanged. No fake finding/service IDs or wildcard expansion is allowed. Deployment-only groups may have empty source_scopes only if every permission is an exact deployment target.

Registration atomically appends only its exact connector/source pair and source tuple to the appropriate ceilings, then its exact effective grants/membership. Optional explicit initial read adds only that same tuple to source_read_targets. It changes no action/limit/duty ceiling or unrelated binding. Validate the connector/source association, not an unbound cross-product of IDs and source sets. See design.md for the complete limits and duty defaults. Broader assessment/approval policy is not silently seeded by the installer.

## Purpose-separated account capabilities

The protected host account-create operation makes a pending account/principal with no verifier, bootstrap status or native membership and issues its activation capability. The enrol endpoint cannot select another account, rename a principal or grant roles. Recovery cannot activate pending/disabled accounts. Setup, enrolment and recovery capabilities bind purpose, installation UUID, target account or unclaimed installation, generation and applicable credential revision in a domain-separated digest; a public locator alone is never authority. Reject all cross-purpose/installation/account/generation use. Reissue and credential changes invalidate old account capabilities. After restore, revoke outstanding enrolment and recovery capabilities before opening local ingress; pending accounts require explicit fresh enrolment issuance.

## Runtime/helper coordination

Bootstrap follows the [independent verifier amendment](../openspec/changes/easy-compose-install/bootstrap-amendment.md): an externally supplied immutable verifier-image pin contains signature and graph/archive policy, and no candidate-runtime helper runs before complete graph admission. The verifier is not selected by downloaded metadata and receives no Docker socket. Production never accepts fixture trust; local transparency testing is a separately provisioned, owned development composition.

Delivery and backend use UVM_AUTH_MODE=local explicitly; absent/new value must not switch an existing OIDC/demo installation. Local file configuration schema 1 carries installation UUID, exact public origin, local secret-source ID/key path, bootstrap delivery path, session policy and trusted-ingress data. It contains no raw password or token in ordinary environment variables. Agree exact field spellings in a small shared contract checkpoint before dependent implementation.

A version-1 helper inside the admitted runtime accepts fixed operations prepare/validate-instance/validate-inspection/render-compose/make-tls/inventory/recovery through data files/stdin. It returns status/phase/safe error/output digests, never executable shell or diagnostics containing secrets. Host wrapper owns Docker/Compose calls and validates ownership; no helper receives the Docker socket. Local maintenance registers/rotates setup, issues account enrolment/recovery and performs post-restore generation revocation using audited services under the same lock order.

## UI and evidence boundary

First setup asks only for the one-use capability and human account details. Preserve normal password-manager behaviour, branded light-theme focus/error/loading states and honest empty data. New registration/configuration states must distinguish disabled, saved, validation failed and activated. Non-admin local sessions retain ordinary scoped product views without calling protected deployment endpoints as their data source.

Never persist credential inputs in browser storage, URLs, traces, screenshots, HAR, console payloads or raw HTTP diagnostic bodies. Exact backend response DTO/schema and generated TypeScript updates remain the UI owner's files after this contract is fixed. Any incompatible interface change returns to the primary for a recorded amendment.

## Concrete coordination checkpoint, 18 November 2026

These spellings coordinate implementation; they do not establish executed behaviour. Local configuration defaults to `/etc/volt/local-auth.json`, overridable through `UVM_LOCAL_AUTH_CONFIG_FILE`. Its schema-1 object contains `installation_id`, `public_origin`, `secret_source` (`kind: encrypted_local_v1`, `secret_source_id`, `key_path`), `bootstrap_delivery` (`kind: private_file`, `path`), `session_policy` (`ttl_seconds: 3600`) and `trusted_ingress` (`mode`, `allowed_hosts`). The key file contains the existing connector format of 32 raw bytes, with private regular-file permissions. Host allowlisting does not replace explicit trusted-peer validation. The one-hour absolute session lifetime remains the accepted design; the backend draft's 43200-second value is not adopted.

The claim/session representation includes server-derived `protected_admin`, true only for a current persisted bootstrap administrator. Deployment discovery uses `installation_id`, `connector_registry_revision`, `can_register_connector`, `connectors`, `policy_revision` and `authority_revision`, alongside `schema_version`. Connector summaries expose identifiers, exact source tuple, lifecycle and revisions without configuration secrets.

Registration uses `expected_policy_revision`, `expected_authority_revision` and `expected_connector_registry_revision` in the existing command envelope. Its committed receipt's `result` includes `allocated_ids` with `connector_id`, `source_id`, `access_group_id` and `role_id`, plus committed registry revision and disabled state. Identical replay returns the original receipt; changed payload conflicts.

Packaged maintenance invokes the installed `uvm.auth.maintenance` module with `--config` and an operation: `prepare-setup`, `rotate-setup`, `create-account`, `issue-recovery`, `disable-account` or `revoke-capabilities`. Account operations select a username; account creation also takes a display name. Capabilities are written only to the configured private delivery file. No host Python or uv is required. Exact additional enrolment-reissue arguments and nested connector summary schemas remain the backend owner's next checkpoint; they must retain the purpose-separated lifecycle above.
