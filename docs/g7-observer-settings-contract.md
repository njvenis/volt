# G7 observer settings v1 — reviewed development contract

Status: reviewed development contract for the first `FR-OP-01` / `G7-OBS-01` slice. It chooses no production timing, recipient or host policy.

## Boundary and authority

UVM stores the desired deployment-scoped timing revision. A separate host controller owns the effective configuration, its validation policy, durable apply journal and observer/supervisor processes. The controller **pulls** desired revisions and reports results; the application container has no Docker socket, host archive credential, host signing key or general host command interface. UI Save publishes a desired revision and automatically queues application. A command receipt means *desired committed*, never *host applied*.

Add selectable `observer.timing.read` and `observer.timing.configure` actions to the native permission catalogue. Extend access-group grants with `deployment_scopes: [deployment_id]` and the trusted grantable envelope with a maximum `deployment_scopes` set. Deployment IDs are stable opaque IDs matched exactly; an absent or empty deployment scope never grants these actions. Group creation/update rejects scopes outside the ceiling. Evaluation requires the action and deployment ID in the **same complete current grant**, with all matching explicit denies applied through the existing evaluator. An A-only grant cannot cover deployment B even if its source tuple matches. Bootstrap administration can assign grants but does not gain assessment authority. Browser requests retain session and CSRF enforcement. Host service identity is bound to a registered deployment and can only read that deployment's desired revision and submit its application report. Cross-deployment service requests, forged signatures and stale report sequences are denied before receipt disclosure or mutation. No configured incident recipient is chosen by a report.

## Public v1 wire

Root: `/api/v1/operations/observer-settings/{deployment_id}`. All JSON carries `schema_version: 1`; unknown write fields, boolean revisions and mixed publish/rollback bodies are rejected.

| Method/path | Result and authority |
| --- | --- |
| `GET /` | With `observer.timing.read`: desired revision/values/digest, independently verified effective revision/digest, application status, latest report time/failure code, last signed host-policy revision/bounds/digest and their observation time/freshness, current revision tokens, and `can_configure`. Missing or stale host evidence is labelled unknown. |
| `GET /revisions/{revision}` | Same read grant; immutable historical values, digest and publication provenance. |
| `POST /commands` | With `observer.timing.configure`: publish complete values or roll back to a retained revision; returns the immutable command receipt. |
| `GET /receipts/{command_id}` | Current read grant plus same actor or explicit audit-view authority; no cross-deployment existence leak. |
| `GET /host/desired` | Deployment-bound host service only; complete canonical desired values, revision, digest, command/intent ID and expected host-policy revision. |
| `POST /host/reports` | Deployment-bound host service only; authenticated report and idempotent acknowledgement. |

`GET /api/v1/operations/observer-settings` discovers deployments from a trusted installed deployment registry, **not** from caller input or host reports. It returns only deployments for which the actor currently has `observer.timing.read`; authorisation precedes pagination and counts. Response: `{"schema_version":1,"deployments":[{"deployment_id":"g7-local","label":"Local fixture","can_configure":true}],"next_cursor":null}`. `label` is presentation only and `deployment_id` is the stable authority key. Pagination is bounded and its cursor is bound to the caller and current authority revision. Empty list is valid; an unauthorised direct deployment lookup remains non-disclosing.

### Exact JSON shapes

All revision tokens are non-negative JSON integers (never booleans); timestamps are UTC ISO 8601 strings. Optional values are present as explicit `null`, not omitted. Digests use `sha256:<lowercase hex>`. The seven timing fields in `values` are complete in every response that carries them. The example numbers below are **local fixture illustrations**, not host bounds or production policy.

`GET /{deployment_id}` returns:

```json
{
  "schema_version": 1,
  "deployment_id": "g7-local",
  "revisions": {"configuration": 2, "policy": 4, "authority": 7, "host_policy": 1},
  "desired": {"revision": 2, "digest": "sha256:...", "values": {"observation_interval_seconds": 1, "request_deadline_seconds": 8, "heartbeat_freshness_seconds": 3, "maximum_future_skew_seconds": 1, "anchor_export_lag_seconds": 30, "incident_projection_deadline_seconds": 10, "scheduler_progress_freshness_seconds": 15}, "command_id": "uuid", "committed_at": "2026-10-26T12:00:00Z"},
  "effective": {"revision": 1, "digest": "sha256:...", "verified_at": "2026-10-26T12:00:01Z"},
  "application": {"status": "pending", "operation_id": "uuid", "latest_report_id": null, "failure_code": null},
  "host_policy": {"revision": 1, "digest": "sha256:...", "bounds": {"observation_interval_seconds": {"min": 1, "max": 3600}, "request_deadline_seconds": {"min": 1, "max": 3600}, "heartbeat_freshness_seconds": {"min": 1, "max": 3600}, "maximum_future_skew_seconds": {"min": 0, "max": 3600}, "anchor_export_lag_seconds": {"min": 1, "max": 3600}, "incident_projection_deadline_seconds": {"min": 1, "max": 3600}, "scheduler_progress_freshness_seconds": {"min": 1, "max": 3600}}, "observed_at": "2026-10-26T12:00:00Z", "fresh_until": "2026-10-26T12:01:00Z", "freshness": "fresh"},
  "can_configure": true
}
```

`desired`, `effective`, `host_policy` and `application` are `null` before their first corresponding record; unconfigured `configuration` and unknown `host_policy` revision tokens are integer zero. Each bounds entry is `{"min":integer,"max":integer}` keyed by one of the seven timing names. If the signed host policy is old, `freshness` is `stale`; if its trust/time cannot be established it is `unknown`. A stale signed snapshot may support a new *desired* publication against its last-known revision but never claims host application. With no valid signed policy snapshot, publication returns `dependency_unavailable` and no revision. `effective` is the last verified applied configuration, not a health verdict. When `application` exists, its `status` is exactly `pending`, `applied`, `failed` or `uncertain`.

`GET /revisions/{revision}` returns `schema_version`, `deployment_id`, `revision`, `digest`, complete `values` (the seven-field object above), `action`, `command_id`, `actor_id`, `rationale`, nullable `evidence_ref`, `committed_at` and nullable `copied_from_revision`. A rollback record has action `observer.timing.rollback` and a non-null `copied_from_revision`; publication has `copied_from_revision:null`. It returns the historical snapshot, not a mutable pointer.

`POST /commands` and `GET /receipts/{command_id}` return the same immutable receipt object: `{"schema_version":1,"command_id":"uuid","deployment_id":"g7-local","action":"observer.timing.publish","effect":"desired_committed","request_digest":"sha256:...","configuration_revision":2,"configuration_digest":"sha256:...","evaluated_revisions":{"policy":4,"authority":7,"host_policy":1},"audit_id":"uuid","intent_id":"uuid","committed_at":"2026-10-26T12:00:00Z"}`. The POST uses HTTP 201 for a new commit and 200 for exact replay; it never describes host application. A receipt lookup can succeed after the original expected configuration revision has advanced.

`GET /host/desired` returns `schema_version`, `deployment_id` and a nullable `desired` object. When present, `desired` has `revision`, `digest`, complete seven-field `values`, `command_id`, `intent_id` and `expected_host_policy_revision`. It is `null` before any publication. The controller does not infer values from a digest.

The host submits `POST /host/reports` with `schema_version`, `deployment_id`, `report_id` (UUID), durable `sequence` (integer), `controller_instance` (opaque ID), `requested_revision`/`requested_digest`, `active_revision`/`active_digest`, `consumers` (exactly observer and supervisor, each with revision/digest/observed_at), `host_policy` (revision, complete bounds, digest and `freshness_seconds`), `outcome` (`applied`, `failed`, `uncertain`), `observed_at`, `failure_code` (nullable sanitised code), and `signature`. For a policy-only initial/status report, requested and active revision/digest may be null; consumer readback still identifies last-good state. Canonical signature input is UTF-8 JSON of every field except `signature`, sorted object keys, compact separators, preserved array order, finite numbers and normalised UTC timestamps. The controller signs with a host-held Ed25519 private key; UVM verifies against a deployment-bound public key pinned outside editable UVM settings. The service authentication and signature are both required. A signed policy snapshot can only update through a strictly newer durable report sequence.

The error envelope is `{"schema_version":1,"error":{"code":"revision_conflict","message":"...","correlation_id":"uuid","details":{"outcome":"not_committed","expected_revisions":null,"current_revisions":null,"lookup_url":null}}}`. The three detail members are always present and nullable; `outcome` is `not_committed` for a proved local rollback and `unknown` only when the commit result cannot be established. The UI renders stable codes and never echoes untrusted raw messages or report text.

`POST /commands` takes `command_id` (UUID), `action` (`observer.timing.publish` or `observer.timing.rollback`), `expected_revisions` (`configuration`, `policy`, `authority`, `host_policy`), `rationale`, optional `evidence_ref`, and exactly one of `values` or `rollback_revision`. The route supplies the deployment ID. A rollback copies historical values into a **new** revision and revalidates them against current host policy; it does not reactivate an old revision.

The seven required `values` fields, in seconds, are `observation_interval_seconds`, `request_deadline_seconds`, `heartbeat_freshness_seconds`, `maximum_future_skew_seconds`, `anchor_export_lag_seconds`, `incident_projection_deadline_seconds`, and `scheduler_progress_freshness_seconds`. Accept finite integers within the explicit host-owned bounds; all durations are positive except non-negative future skew. No value disables a detector. The existing bundled revision-3 file (1, 8, 3, 1, 30, 10, 15 seconds in that order) is a **local fixture only**, never a production default. In particular, do not add a relationship rule that silently rejects its 3-second heartbeat limit against its 8-second request deadline; preserve truthful stale results.

At command entry, check **current disclosure authorisation first**, then look up the retained command ID and compare its original actor, deployment, action and complete request digest. Exact same-actor replay returns the original receipt without rechecking the original expected revisions or creating effects; changed content conflicts. Only a command without a retained receipt enters fresh execution. Under ordered authority and settings locks, recheck identity, exact scope, deny precedence, all expected revisions and host-policy continuity. Commit immutable settings, sanitised audit event, command receipt and host-application intent in one transaction. Definite persistence failure rolls everything back. Lost COMMIT acknowledgement remains uncertain until exact receipt lookup. The receipt binds actor, deployment, action, request/settings digests, desired revision, evaluated policy/authority revisions, audit ID and intent ID, and states only `desired_committed`.

Use the existing versioned error envelope with code, correlation ID and `details.outcome` of `not_committed` or `unknown`. Invalid values return 400; missing authentication 401; CSRF/scope denial 403; undisclosable records 404; stale revision, conflicting command or unresolved earlier application 409; dependency failure or uncertain commit 503. Do not mark a known rollback as unknown. One unresolved application per deployment is allowed; a further publish cannot silently overtake it.

## Independent application

Host-owned versioned policy fixes deployment identity, trusted UVM endpoint, supported contract version, numeric bounds, polling/deadline settings, observer and supervisor identities, report verification key and policy-report freshness interval. UVM cannot edit that policy. Every signed host status/application report includes policy revision, complete bounds, policy digest and UTC observed time; UVM retains the latest valid signed snapshot. Public readback marks bounds `fresh` only within that host-defined interval with valid sequence/signature and no future-time anomaly. Stale bounds remain visibly last-known, not current authority. Fresh publication checks the caller's expected host-policy revision against the retained snapshot; host absence leaves any committed desired revision pending until independent validation. If host policy is absent, the controller keeps last-good operation and reports failure/uncertainty; it does not treat UVM values as its policy.

The controller validates desired schema, digest, revision order and bounds independently, writes candidate and operation identity to its durable journal, then atomically installs a complete host-owned snapshot at safe observer/supervisor boundaries. Both consumers must report the same revision and digest before `applied` is submitted. Partial application, timeout or lost acknowledgement is `uncertain` until journal and consumer readback reconcile. Definite rejection is `failed`; last verified configuration continues. Retries retain the same operation/report identity and cannot create duplicate application. During total application-container outage, host monitoring continues on last-good configuration, retaining reports for later projection.

Host report fields bind deployment, report ID, monotonic sequence, controller instance, requested revision/digest, active revision/digest, host-policy revision/bounds/digest and freshness interval, UTC observation time, outcome and sanitised failure code. Sign canonical report bytes with a host-held private key and pin its verification key outside UVM-editable settings. Identical report replay is idempotent; changed content under the same ID conflicts; out-of-order, stale or cross-deployment reports cannot set `applied`. Authentication and report ordering are rechecked on durable admission.

| Status | Meaning |
| --- | --- |
| `pending` | Desired revision committed; matching host confirmation is absent. |
| `applied` | Observer and supervisor confirmed the exact desired revision/digest. This says nothing by itself about monitored-service health. |
| `failed` | Definite rejection or failed apply, with last-good state identified. |
| `uncertain` | Apply or reporting outcome cannot be established, including partial consumer agreement. |

Every observer check uses one configuration snapshot and records its revision/digest. Changing timing cannot erase incidents, restart detection clocks, reset heartbeat sequence, clear unresolved work or manufacture healthy signals. Scheduler health remains tied to completed loop progress and monotonic elapsed time. Missing, invalid, stale or future-dated observations fail closed. Timing revision remains distinct from incident producer/binding revision. Wire observation interval and request deadline into their actual consumers so no silent hard-coded substitute survives.

## UI and verification boundary

Use VOLT design tokens. Show desired and effective revisions separately, server-supplied bounds/units, reason and evidence reference, immutable history, current grant state, pending/failed/uncertain explanations and receipt recovery. Saving automatically requests host application without a second manual approval. Refresh and rollback retain operation identity. UI controls do not substitute for server grants.

The maintained observer-only journey was run on 2026-10-27 against the pinned disposable Docker/PostgreSQL/local-OIDC environment with the command in `docs/g7-observer-host-runtime.md`. Its complete source snapshot and raw evidence are retained in the authorized private environment. It verifies rendered revisions 1→2→rollback 3, failed revision 4 and rendered recovery revision 5, uncertainty and outage recovery through revision 7, signed-report rejection, scheduler/heartbeat faults, transaction rollback, authorization denials, keyboard/a11y/reflow and owned-resource cleanup. This evidence is a development checkpoint only; it does not establish a G7 gate or release result. Matching-deny and production-environment checks remain separate.
