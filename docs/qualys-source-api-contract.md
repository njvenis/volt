# Proposed Qualys VM source API, version1

Design: [Qualys amendment](../openspec/changes/easy-compose-install/qualys-design.md). Proposed interfaces, not available-route claims. Preserve GitHub and regular assessmentV1 semantics. All DTOs include schema_version1/no-store/safe errors. Require exact Origin/JSON, current session, CSRF for writes and server-side exact authorisation.

## Registration

Keep [the registration-specific outer envelope](easy-install-api-contract.md), all-zero deployment target and three top-level expected_* fences. For Qualys, payload is exactly display_name,source_family=qualys,account_label,environment_label,product=qualys_vm,platform_id,scope={kind:account_visible},rationale,evidence_ref,grant_initial_read. Replace manual source_account_id/scope_key with generated stable identifiers. Never rewrite retained requests; validate/digest the submitted provider payload exactly.

Committed receipt returns generated source tuple, allocated connector/source/group/role IDs, disabled lifecycle, committed revisions and credential_slots.qualys_vm_basic.secret_id. Labels are not identity. Another subscription/platform/scope requires another binding; successful access cannot verify vendor subscription identity.

## Routes and DTOs

| Method/path | Request | Success |
| --- | --- | --- |
| GET /api/v1/scanners/{connector_id}?source_id=… | none | ScannerView |
| POST /api/v1/scanners/{connector_id}/commands | ScannerCommand |200 audited receipt or typed terminal operation readback;202 OperationView while running |
| GET /api/v1/scanners/{connector_id}/operations/{operation_id}?source_id=… | none | OperationView |
| GET /api/v1/scanners/{connector_id}/runs/{run_id}/detections?source_id=…&limit=…&cursor=… | none | DetectionPage |

ScannerCommand: schema_version,command_id,action,target_id=connector UUID,membership_ids=[],expected_revisions,payload. This differs from deployment registration. Preserve existing revision meanings: target,policy,identity_membership,owners,authority,connector,source,secret_source,secret, including established zero values. Scanner-command secret is null; explicit credential_version_id fences its credential snapshot. ScannerView returns the complete vector.

Every payload includes source_id,rationale,evidence_ref. Actions:

| Action | Additional payload |
| --- | --- |
| scanner.configuration.save |settings |
| scanner.connection.test |configuration_revision,credential_version_id |
| scanner.configuration.activate |configuration_revision,credential_version_id,validation_operation_id |
| scanner.collection.start |configuration_revision,credential_version_id |
| scanner.configuration.disable |none |

settings is exactly product=qualys_vm,api_version=2.0,platform_id,scope={kind:account_visible},collection_mode=manual. Platform/scope match immutable registration. Configuration/credential changes advance connector revision and invalidate validation/activation. Limits are fixed server policy.

ScannerView: connector_id,source_id,source_tuple,display_name,account_label,environment_label,product,platform_id,scope,lifecycle,configuration_revision,active_configuration_revision,credential={secret_id,version_id|null,state,revision},expected_revisions,validation|null,limits,collection_mode=manual,schedule_supported=false,latest_attempt_run_id|null,latest_complete_run_id|null,collection_recency={status:never|recent|stale,as_of,last_complete_at|null}. No username/password/ciphertext/raw XML.

OperationView: operation_id,command_id,kind=test|collect,status=running|succeeded|partial|failed|interrupted,configuration_revision,credential_version_id,started_at,finished_at|null,run_id|null,error_code|null,receipt_id|null. Receipts bind command/connector/source IDs,actor/action/request digest,committed revisions,audit-event ID,UTC timestamp,result. Local command results give lifecycle/configuration revision; test/collect identify operation/run. Before dependent UI code, backend/provider checkpoint must pin exact receipt fields and nested validation/limits schema without changing these semantics.

Replay metadata receipts only after current authorisation; changed actor/content conflicts. Durable test/collection admission reserves command ID before HTTP, replay issues no additional request. Process loss marks interrupted; no automatic network restart. Vendor failure is a typed operation result. Errors:401/403 authentication/authority,404 absent scoped resource,409 state/revision/idempotency,422 safe validation,429 local admission throttle,503 persistence unavailable. Generic absence/error never proves noncommit.

The200 command response is a disjoint schema union. An audited ScannerCommandReceipt has its required decision/audit/intent fields. Terminal operation readback is OperationView with receipt_id=null and status failed,partial or interrupted; it reports operational state without asserting an audited commit. HTTP200 alone is never receipt proof. A succeeded operation without its required receipt is an inconsistent state and fails closed with a safe error, rather than returning this variant. Running OperationView uses202. GET operation metadata may describe a succeeded operation with its non-null receipt reference normally. No terminal replay issues another network request. Request schemas and each success variant must appear in OpenAPI and validate representative actual wire responses, including interrupted receipt-less replay.

## Credentials and permissions

Reuse POST /api/v1/connectors/{connector_id}/secrets/{secret_id}/versions, purpose=qualys_vm_basic. input.kind=value contains JSON string with exactly username/password; render separate browser fields and clear immediately. Preserve existing submission/version IDs,revision fences,uncertainty reconciliation/terminal-ID rules,encrypted-local crypto/nonce/version lifecycle and restore quarantine. Trusted submission/resolver enforces purpose/connector/allocated-slot/version association; crypto AAD alone does not replace purpose checks. No second credential store or browser key path.

connector.read permits safe configuration/operation metadata; connector.configure save/test/activate/disable/manual collection; connector.secret.manage secret lifecycle; assessment.read detection/dashboard data; audit.read audit readback. Current typed local-v2 exact connector/source grants govern all operations/outbound fences. No implicit assessment/SOD expansion.

## Detection readback

DetectionPage: run_id,as_of,items,next_cursor,retrieval,coverage,source_freshness,collection_recency. Items preserve observation ID,optional native group ID,QID,host ID,type,severity,vendor status,port/protocol/SSL with explicit absence,original unique detection ID,vendor/collection timestamps,identity-resolution state,opaque raw-evidence ref/digest. No raw body or unauthorised host metadata.

Keyset cursor/default50/max100 binds principal,current grant fingerprint,connector/source/run and retained snapshot. Collection age is distinct from source freshness/coverage. Local-only save/secret/activate stages cause no HTTP; explicit connection test does not ingest probe data. A populated source view implies neither workload resolution,remediation,scheduling nor live-tenant acceptance.

## Allocated secret revision checkpoint

CredentialView adds required `revision`, the non-negative current allocated secret-head revision, including zero before the first version. The backend reads it under the same current-authorised metadata transaction and the provider serializes it as `ScannerView.credential.revision`. The existing connector read/secret-management permissions remain authoritative; no credential material is exposed. Scanner-command `expected_revisions.secret` remains null as previously agreed. Secret submission/revocation/reconciliation use the actual `credential.revision` in their existing secret-specific revision vector; the UI must never infer zero from an empty slot or overwrite scanner command fences with a guessed value. This additive metadata field unblocks the first submission and is distinct from credential version identity.

## Trusted fixed rule initialization

The backend-owned host maintenance entry point is `python -m uvm.auth.maintenance initialize-scanner-rule --config <validated-local-config>` inside the admitted runtime. The normal installer invokes it automatically after migrations/private-state validation and before scanner worker startup; end users do not enter rules, identity IDs or native-authority commands.

Validate explicit local mode, the private instance configuration/key-source identity and the persisted installation UUID. Hold an installation-scoped PostgreSQL SESSION maintenance lock across existing `IdentityRepository.provision_rule` and its independent transaction; do not wrap that service in a nested outer policy transaction that deadlocks. Current immutable mode/config checks and the authorisation evaluator run at the appropriate guarded boundaries. Always release the session lock/connection on success/failure. No network or caller-selected rule/body/action/actor is accepted.

Only `qualys_source_only_rule()` is permitted: rule_id `qualys_vm_source_only_v1`, version1, workload_match_fields=(provisioning_key,), verified_asset_locator=false, workload_context_fields=(), with no matching inputs invented at collection. A real host-maintenance evaluator verifies the fixed canonical definition digest, exact installation/config target, expected `identity.rule_provision` action and validated host invocation; every other request denies. Its AuthorisationDecision records truthful host-maintenance identity, exact scope, request/correlation/evidence and UTC provenance. Record actual policy state separately where applicable; do not describe a fixed contract version as the current application policy revision. Use the existing validated repository and its immutable decision/definition persistence, not direct rule-table insertion or an always-allow fixture evaluator.

Repeated same-content initialization is idempotent; a conflicting retained definition fails without overwrite. This operation grants no application permission, verified workload, assessment write or external authority. Missing initialization leaves collection unavailable; it never triggers an untrusted provider authorizer. Legacy modes/rules remain unchanged. Delivery owns the fixed invocation/phase journal; backend owns the maintenance service, decision and tests.

## Adopted shared transaction checkpoint, 18 November 2026

Restore recovery follows the proposed [local authority profile](../openspec/changes/easy-compose-install/local-recovery-profile.md). Its host producer, strict proof schema and recovery application transition must pass design review before implementation. Normal bridge/protocol acceptance does not imply a usable restore path or bypass quarantine.

The primary adopts the concrete protocol declarations at commit171285a in uvm/scanners/contracts.py. This records interface agreement, not backend implementation or authorization acceptance. The provider owns new scanner tables/coordinator; the backend owns existing authority, registration, crypto and audit/intent/receipt services.

ScannerRuntimeAdapters.transaction(request,action,connector_id,source_id,expected_revisions=None,snapshot=None) yields ScannerTransaction with read-only connection and snapshot properties. The backend opens one outer transaction, acquires existing policy/connector locks, rederives the current session and exact registered source grant, checks revisions/retained lifecycle/active configuration/credential/restore fences, then yields. Normal exit commits once; exceptions roll back shared and provider writes together. The handle cannot escape its context. Provider mutators accept this same Connection; nested independent engine transactions/commits are prohibited.

read_registration_metadata(transaction=...) returns exact stored connector/source/source tuple, human labels, product/platform/scope, lifecycle, configuration/active revisions and allocated credential-slot/version/state. ExpectedRevisions.secret is nullable for scanner commands; unconfigured read/save snapshots may have no credential version. Credential-attempt operations reject missing/inactive versions. Read paths use connector.read or assessment.read; the fixed scanner command actions map to connector.configure. No arbitrary caller-selected permission name or source association is accepted.

On the live transaction, read_command(command_id,request_digest) checks current actor/action/source and returns existing intent/receipt without replaying HTTP. Replay lookup does not apply stale historical expected revisions; a novel command is admitted under its submitted revision vector. record_audited_intent(command_id,request_digest,rationale,evidence_ref,operation_id,run_id) and provider operation admission share the transaction. record_audited_receipt(intent_id,result,shared_state=None) verifies intent binding, writes audit/receipt and applies only the allowed shared connector projection. SharedStateChange is lifecycle/configuration_revision/active_configuration_revision; save advances and stages once, activate uses the exact recent proof, disable clears active state. Test/collect admission/completion do not spuriously advance connector revisions. Racing duplicate admissions roll back and re-read under current authority.

No network, credential lease, private evidence I/O or independently committing observation/identity repository call occurs inside the shared lock. Each outbound attempt has short fresh admission/fence transactions; credential_attempt yields a purpose/connector/source/allocated-slot/version-bound redacted lease only after releasing the DB lock. Independent evidence/observation/identity commits remain checkpointed and unpromoted until final pointer/run publication and terminal receipt commit together under current authority. Failure metadata cannot create publication authority. Reads and returned receipts follow durable commit/readback.

Exact nested serialization follows dataclasses in contracts.py: validation has status/checked_at/configuration_revision/credential_version_id/operation_id/error_code; limits has the seven approved numeric bounds; collection_recency has status/as_of/last_complete_at. Receipt uses the existing command/decision/audit/intent/projection/intents fields plus occurred_at. Typed result variants are save/disable {lifecycle,configuration_revision}, test {operation_id,status,error_code}, activate {lifecycle,configuration_revision,active_configuration_revision}, collect {operation_id,run_id,status,error_code}. OperationView represents running work; terminal receipts do not claim a running result. Retrieval is {status:complete|partial|failed,reason_codes}; coverage/source_freshness are {status:unknown,reason_codes}. None of these declarations establishes actual policy, audit atomicity or public-route execution.


## Scanner command disposition amendment

The adopted [scanner disposition contract](../openspec/changes/easy-compose-install/scanner-command-disposition.md) defines the strict abandon endpoint, current-authorised receipt/operation recovery and audited terminal non-commit proof. Generic conflict or absence is never proof that a held command can be replaced. Implementation and executable acceptance remain pending.
