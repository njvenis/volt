# Qualys amendment, 18 November 2026

The user selected **Qualys** after disclosure that current collection clients are fixtures and GitHub configuration is not scanner configuration. Adopt VM/VMDR Host Detection List XML API v2 as the first source. This supersedes the proposal's assumption that existing adapters already satisfy scanner onboarding. It does not authorise live tenant contact, employer data, publication or production claims. The approved installer/account boundaries remain unchanged.

## Supported increment

Browser registration, local configuration, encrypted credential submission, explicit connection test, activation, **manual** collection and persisted source-observation readback are included. Scheduling, private-cloud/custom hosts, other Qualys products and CE import are excluded. Use the vendor Host Detection List endpoint with TLS-verified Basic authentication and X-Requested-With: VOLT. Allowlist reviewed official origins for US1/US2/US3/EU1/EU2/IN1 server-side; never accept arbitrary URLs/headers/queries.

The first scope is all hosts visible to the credential's account. Explain that vendor permissions bound visibility; recommend a suitably scoped dedicated Reader/API account. A successful test proves access, not subscription identity, scan freshness or complete asset coverage. Changing subscription/platform/intended scope requires another binding.

Registration asks only for display/account/environment labels, platform and explicit initial-read choice. Generate account-authority/source-scope/connector/source/group/role/credential-slot IDs server-side. Labels are not identity. See [the scanner API](../../../docs/qualys-source-api-contract.md) for exact DTOs and operation boundaries.

## Collection and state

Registration/save/secret submission/activation/disable cause zero external requests. Explicit test reads one bounded page via the production protocol/parser and does not ingest probe rows; truncation is acceptable for a probe, never proof of complete retrieval. Activation requires a successful test within15 minutes, bound to source/configuration/credential revisions and restore epoch. Manual collect requires that active snapshot.

Persist actor/action/request-digest-bound operation admission before HTTP. One running operation per connector. Replay returns the original operation, never another outbound request. Recheck current exact-source authority/lifecycle/credential/restore epoch before every attempt and final publication. Configuration or credential changes invalidate validation/activation. Restart marks unfinished operations interrupted, never silently reissues requests. Preserve distinct metadata-command and secret-submission uncertainty semantics.

Fixed initial limits:10 pages,10MiB/page,50MiB/operation,100000 detection rows,120-second overall deadline,30-second request timeout,at most3 attempts/page. Honour Retry-After only within deadline; no retry for authentication/configuration rejection. Reaching a limit produces partial/failed retrieval, never complete. No universal vendor rate is assumed.

Request the full declared account-visible latest-list scope, including documented New/Active/Fixed/Reopened states and supported detection types; no differential/date/severity/QID filters. Verify actual parameter spellings against official documentation during implementation. Validate warning1980 continuations against fixed origin/path/query semantics, permitting only documented paging progression. Reject redirects/cycles/unsafe or missing continuations/unexpected XML roots.

## Evidence, identity and authority

Reuse CollectionRunV1, AttemptFact, PageFact, IngestionStore, ObservationRepository.write_run and IdentityRepository.resolve_retained. Privately retain exact successful XML pages with bounded atomic writes, digests and no symlink traversal; expose no raw XML/username/password/provider error in browser/log/audit. Failed responses retain safe bounded metadata. Disable external entities and DTD/network resolution; tolerate vendor DOCTYPE declarations without fetching them and bound XML depth/size.

Page record_count means hosts; detection ordinals follow page/host/detection document order. Observations reference page digest and position. Group by (qualys,qualys_vm_qid_v1,generated account authority,QID); preserve host/QID/type/port/protocol/SSL/original UNIQUE_VULN_ID as source lineage. Do not assume unique-ID lifecycle stability, merge on CVEs, or replace missing vendor timestamps with collection time.

Do not manufacture remediable workload/component identity from host metadata. Source-only identity rules retain unverified component/workload results while producing supported native QID groups. Fixed/absence/ignored/failed collection never creates engineering confirmation, assessment writes or episode closure.

Existing repositories own separate transactions: use durable idempotent finalisation checkpoints (evidence, observations, detection metadata, native resolution, final run publication), not invented cross-repository atomicity. Report succeeded only after durable readback; interrupted finalisation remains visible.

Core coverage/source freshness remain unknown where existing proof services cannot establish them. Collection recency is separate: never/recent/stale, stale after24 hours since last complete collection. Display latest partial/failed attempt beside older complete data. The useful dashboard is a Qualys source-observations view with detection/QID counts, source status/severity, host/port lineage, retrieval and unresolved-identity explanation; no verified SLA/remediation/scheduler claim.

Current authority and exact registered connector/source tuple govern connector.read/configure/secret.manage, assessment.read and audit.read. Safe operation metadata excludes finding details/count without source-read authority. No wildcard, assessment-write grant, synthetic identity or SOD expansion.

## Exclusive ownership

Backend reports additive heads0063_local_accounts,0064_connector_registry_name/binding labels,0065_command_abandonments. Reserve **0066 exclusively for the scanner Fixer**, descending from the actual committed0065. No historical migration/declaration edits.

Scanner Fixer owns new uvm/scanners/**, tests/scanners/** and the single new0066 migration. Its isolated store may own scanner configuration/operations/checkpoints/detection metadata tables and invoke existing retained observation/run services. It must not mutate shared auth/native/connector-secret/observation tables except through reviewed services. This transfer supersedes broad backend ownership only for these named new paths.

Existing backend owner retains auth/native/registration (including generated Qualys IDs/slot), shared secret-purpose enforcement/resolver, router mount and existing shared files. Publish narrow adapters for current AuthorityContext, policy lock/exact grants and purpose/connector/slot/version-bound credential resolution. No duplicate crypto. Agree concrete adapter spellings before dependent implementation; cross-owner edits return to root.

UI retains frontend/generated schemas/Node companions. Delivery retains image/entrypoint, private evidence storage in coordinated backup, installer, maintained qualification and user docs. Root records contracts and integrates an unmerged PR. No Docker socket mount or public registry/release write is authorised.

## Decisive verification

Actual local HTTP protocol fixture plus PostgreSQL and packaged browser: register→save→secret→test→activate→collect→populated source observations. Assert local-only stages issue no HTTP; two pages/QID grouping/distinct TCP-UDP records/private exact bytes/durable readback. Cover401/403/throttle/TLS-network errors, hostile XML/continuations/redirects, bounds, cross-source access, policy/credential revocation between pages, interrupted finalisation/restart and idempotent replay. Fixture transport is isolated from production origin policy and cannot be selected by ordinary installation configuration. Live Qualys remains separately unverified.


## Packaged local protocol qualification

The [qualification-only composition](qualys-packaged-fixture.md) uses an independently signed derived fixture runtime, verified TLS and an isolated fixed-hostname network. It does not add production fixture switches or establish live-provider acceptance.
