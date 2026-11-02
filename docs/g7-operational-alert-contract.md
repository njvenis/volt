# G7 host operational alerts — development contract draft

Status: revised contract candidate for independent review. It covers
`FR-NT-01`, `NFR-05`, and `G7-AL-01` for host-observed deployment availability
and sender health. It is not implementation approval, production policy, or
evidence of remote/production monitoring. Exception expiry warnings remain on
their existing transport and contract.

## Boundary, bootstrap, and authority

A host-owned sender runs beside the existing
`tools/g7_host_observer.py` observer and supervisor. Availability inspection is
separate from observer telemetry. The sender has only a read-only Docker inspect
capability for one exact configured container ID. It cannot start, stop, exec,
or replace containers. Inspection must match the configured image digest,
deployment label, run label, host boot identity, and container ID. A recreated
container or changed image/context is a different target and fences outstanding
work; it is never silently adopted.

A trusted bootstrap operator installs matching records in the existing UVM
incident service-binding table and incident route table and in a host-owned,
editable development catalog outside application-writable mounts. The app
records must bind the exact deployment, subject, service principal, condition,
producer, and positive configuration/binding revision. The route records the
exact recipient access group and source tuple; for container/sender-health
subjects whose evidence is not a vulnerability group, `vulnerability_group_id`
is explicitly `null`. For a route targeting a vulnerability group, it must be
that exact current group and source. The dedicated submit bearer cannot install,
change, or revoke either app record.

The host catalog is the transport authority while the app is unavailable. It
contains exact deployment/subject/principal/producer/condition/binding revision,
expected image and source-context labels, recovery epoch, and exactly one
enabled route: recipient group, exact source tuple, HTTPS destination reference,
installation/workspace/channel identity, allowlisted mentions, credential
reference, retry count/age, observation freshness, future skew, and request
deadline. It has a monotonic catalog generation and canonical digest. No
product routing setting, product configure permission, or UI is introduced.

Catalog replacement, route withdrawal, and dispatch admission use the same
stable exclusive host lock. The sender rechecks the current catalog generation,
route digest, binding tuple, target context, and credential reference while
holding the lock; it durably commits the `SENDING` record before releasing the
lock to perform network I/O. Withdrawal therefore prevents any later dispatch
admission. An I/O already admitted as `SENDING` may complete; withdrawal cannot
claim to recall bytes already sent. Credential replacement reloads the new
reference before the next admission and fences queued attempts using the old
generation; it cannot recall an already admitted request. Secrets never enter
the catalog journal or app.

App-only revocation is enforced by UVM before any projection/replay and on
recipient reads. While UVM is unavailable, the host catalog remains the
transport authority; an app-only revocation cannot be claimed to fence a host
send until the trusted operator also withdraws/advances the host catalog. This
does not grant the app principal host authority. When the app returns, its
current binding can reject old projection. The host then holds that work; it
does not bypass authorization or rewrite the producer/binding revision.

## Existing public v1 wire and exact mapping

No incident DTO, wire version, schema `0062`, or migration changes. The host
journal record sequence is independent of the API `transition_sequence` and
delivery `attempt_id`. API transition sequence is contiguous per
`(deployment_id, subject_id, condition)` and advances only for an event edge
admitted for projection; journal observations, dispatch state changes, and
attempt records do not consume it.

`POST /api/v1/integrations/incidents` accepts exactly these
`g7-operations-incident/v1` keys:

| Field | Required type and meaning |
| --- | --- |
| `schema_version` | JSON integer exactly `1`; booleans are invalid. |
| `deployment_id`, `subject_id`, `condition`, `producer_id` | Non-empty strings of at most 200 characters; exact installed binding values. `condition` is one of `source_integrity`, `siem_integrity`, `siem_export`, `container_availability`, `observer_heartbeat`, `notification_failure`, `incident_projection`, or the bounded addition `host_sender_health`. |
| `transition_id`, `episode_id`, `opening_transition_id` | Canonical lowercase/hyphenated UUID strings. |
| `transition_sequence`, `episode_generation`, `configuration_revision` | Positive JSON integers, never booleans. |
| `predecessor_id` | `null` for sequence 1 only; otherwise the exact prior projected transition UUID. |
| `transition_kind` | Exactly `opened`, `observed`, or `recovered`. This sender emits only edge transitions `opened` and `recovered`; repeated samples are journal observations, not API transitions. |
| `first_detected_at`, `observed_at` | RFC 3339 timestamps with timezone, canonicalized to UTC. `first_detected_at` is the opening time for every event in that episode. Require `first_detected_at <= observed_at <= API admission time + the exact deployment's retained verified observer future-skew limit`. |
| `recovered_at` | Explicit `null` except on `recovered`; then UTC recovery evidence time, `observed_at <= recovered_at <= API admission time + that same retained verified observer future-skew limit`. |
| `evidence_refs` | Required array, at most 100 bounded non-empty strings of at most 1,000 characters. Each is a sanitized opaque host evidence reference; no raw findings, paths, URLs with credentials, tokens, or free-form diagnostics. |

The full key set above is exact: missing or unknown keys reject. `transition_id`
is also the application notification-intent primary key; the host does not
invent a separate application intent ID. It journals an `intent_id` equal to
the immutable transition UUID. Compute the transition payload digest as
lowercase SHA-256 hex of canonical UTF-8 JSON (sorted keys, compact separators,
finite values, preserved array order) over the exact submitted object.

For sequence 1, an `opened` transition has null predecessor, generation 1,
`opening_transition_id == transition_id`, and a new episode UUID. Recovery
uses the same episode UUID, generation, opening transition ID, and original
`first_detected_at`; its predecessor is the exact opening transition or most
recent prior transition if observed events are ever admitted. The sender does
not emit `observed`. A subsequent outage after recovery increments generation
by one, uses a new episode and opening transition ID, and increments the API
stream sequence by one. Never reset the API sequence from a new host journal or
recovery epoch.

The transition POST acknowledgement is accepted only after parsing exactly
the v1 object keys `schema_version`, `status`, `transition_id`,
`transition_sequence`, `episode_id`, `episode_generation`, and `payload_digest`;
`schema_version` is integer `1`, `status` is `projected`, and all identity,
sequence, generation and digest fields exactly match the submitted transition
and locally computed digest. HTTP 200/201 alone is not an acknowledgement. Exact replay may return
the stored projection result; the sender validates the same fields. Any
conflicting, missing, malformed, or mismatched acknowledgement leaves host
projection unacknowledged/held. Do not treat host acknowledgement loss as a
public UVM `unknown` state: the committed transition may already be visible in
UVM; before commit, it is absent.

Delivery uses
`POST /api/v1/integrations/incidents/{transition_id}/delivery` and exactly
these `g7-incident-delivery/v1` fields:

| Field | Required type and meaning |
| --- | --- |
| `schema_version` | JSON integer exactly `1`; booleans are invalid. |
| `attempt_id` | Canonical UUID uniquely assigned to one transport attempt and reused only for exact body replay. |
| `outcome` | Exactly `accepted`, `failed`, or `uncertain`. |
| `attempted_at` | Canonical UTC RFC 3339 dispatch-start time with exactly six fractional digits, e.g. `2026-11-02T20:00:00.000000Z`. Reject offsets, missing/other fractional precision, and alternate spellings. For a new attempt it must be at or after that transition's `observed_at`, strictly after the prior new attempt, and not future-dated beyond the exact deployment's retained verified observer future-skew limit. Delayed projection after app downtime is allowed; host retry-age bounds govern whether to send/retry, not whether to catch up an already recorded outcome. |
| `receipt_ref` | Explicit null unless accepted; then a sanitized opaque provider receipt of 1–256 printable characters. |
| `failure_detail` | Explicit null for accepted; otherwise exactly one of `provider_rejected`, `rate_limited`, `provider_unavailable`, `transport_pre_submit`, `response_invalid`, `submission_uncertain`, or `local_persistence_failed`; never raw response text. |

The exact key set is required. Record a separate host-only
`outcome_completed_at`; it does not replace the wire `attempted_at`. Delivery
is projected only after the transition acknowledgement and in transition
predecessor order. Each attempt result, whether accepted, failed, or uncertain,
is retained and projected in attempt order; catch-up may not skip earlier
outcomes and submit only the latest. A replay body is the same decoded JSON
object content, not byte-identical HTTP whitespace/key order. Because
`attempted_at` has exactly one accepted wire spelling and UUIDs/enums are
canonical, and reference/failure strings are stored verbatim, schema 0062 can
reconstruct the complete accepted object from existing columns; no request
digest/raw-body column is claimed. Exact retry of an already admitted
`attempt_id` with identical reconstructed object content returns the same
transition/attempt/outcome identity and `idempotent: true` before checking
new-attempt ordering. It does not repeat the original new-attempt acknowledgement
flags. Reusing that ID with changed body content conflicts.

The delivery acknowledgement must be exactly one of these v1 JSON shapes:
`{schema_version,status,transition_id,attempt_id,outcome,idempotent}` for an
exact replay (`idempotent: true`), or the same keys plus `superseded` for a new
attempt (`idempotent: false`, `superseded: false` under strict ordering).
`status` is `projected`; all IDs and `outcome` must exactly match the submitted
transition/attempt. A bare 2xx is not acknowledgement. Existing public state remains only `pending`, `accepted`,
`failed`, or `uncertain`. Focused validator/state-machine corrections in this
increment must use actual JSON integers (not bool), bounded nullable safe
references/failure codes, causal timestamp bounds using the retained verified
observer future-skew limit for the exact deployment, immutable exact replay,
and strictly increasing new attempt order. If that exact-deployment verified
timing basis is absent, stale, or invalid, fail closed without disclosure or
mutation rather than substituting a sender-supplied limit; current binding
authorization remains before any replay receipt disclosure. A delayed older failed result cannot
overwrite a later accepted or uncertain terminal result. Once accepted or
uncertain is terminal for the intent, no stale failure can downgrade it.

## Journal lifecycle, replay, and fences

The host journal is append-only and digest chained, with a separate monotonic
record sequence, durable stream heads, events, attempts, projection status, and
all route/target contexts. It binds deployment, subject, condition, producer
and binding revision, observer timing revision, recovery epoch, Docker boot and
container/image identity, source-context digest, catalog generation/digest,
route revision/digest, evidence references, timestamps, payload digests,
transport classification, provider receipt, and exact UVM acknowledgement.
Persist by atomic file replacement plus file and parent-directory `fsync`
under a stable exclusive lock. Corruption, truncation, failed lock/fsync, or
sequence/digest mismatch is not an empty genesis and cannot reset lineage.

Same binding, same image/context/epoch restart permits exact replay of the
stored transition/attempt IDs and bodies. UVM checks current service binding
before replay; therefore when UVM has advanced/revoked that binding, replay is
denied before receipt disclosure. A changed binding, producer, host recovery
epoch, image, source context, catalog authority, or route fences old work as
`HELD`; it is not rewritten to new IDs/content or retargeted. Advance/install a
new producer/configuration fence without resetting the app stream head or
episode. If an older transition or outcome is unacknowledged, that stream stays
blocked: no later transition may skip its predecessor. Trusted reconciliation
to establish the app stream head and resolve fenced effects is deferred from
this increment; until a separate trusted reconciliation occurs, the stream is
held and no successful catch-up is claimed. A trusted genesis is valid only
when both retained host history and the existing app stream are proven absent;
it cannot reset an existing app stream.

For every edge, persist observation and immutable intent before network I/O;
recheck catalog/context and persist `SENDING` with attempt UUID before send;
persist classified outcome and completion time before projecting. A crash or
write failure after `SENDING` is uncertain and never auto-resubmitted. Known
pre-submit failure or explicit provider rejection is failed; only classified
retryable failure may receive a new attempt UUID within retry limits. A timeout,
connection loss, malformed response, crash after submission, or failed outcome
journal commit is uncertain and held. Correlation IDs do not imply exactly-once.

Only a direct HTTPS response with 2xx, JSON `ok: true`, exact configured
channel identity, and non-empty provider acceptance timestamp/receipt is
accepted. Refuse redirects. Bound `Retry-After`; do not let it exceed the
configured retry deadline/count. Outbound content is a fixed allowlist of
condition, display label, opaque incident ID, UTC times, bounded status,
approved runbook link, and configured mention IDs. No raw findings, private
identifiers, host paths, tokens, provider body, or unfiltered errors.

Repeated observations do not create reminders or API transitions. If an outage
recovers before its opening reaches `SENDING`, journal it as canceled-before-
submission and suppress both opening and recovery notifications for that
episode; allocate no API transition sequence. If opening submission has begun,
it cannot be called canceled. On a known failed/retryable opening attempt, keep
the opening transition and each real attempt in the API stream. When recovery
is durably observed, mark the episode recovered and suppress every queued,
not-yet-admitted opening retry, even if an earlier attempt was rejected or a
retry deadline is pending. Dispatch admission rechecks the episode/edge state
under the same stable lock as `SENDING`; an attempt already admitted as
`SENDING` may complete, but no later retry can start. Do not create an attempt
record or failed result for a retry that never reached admission. Then send and
project at most one recovery edge. If opening is uncertain, keep it uncertain
and never retry it; after a separately verified recovery, send one recovery
edge because the opening may have reached the recipient. Host status
`canceled`, `held`, or `unknown` remains host-only and is never encoded as a
fabricated API delivery outcome. Every API transition creates a pending app
intent; therefore any transition without transport delivery must be recorded
with its actual failed/uncertain outcome, not left pending as if sent. Application
intent projection does not activate a second application dispatcher.

## Host inspection and qualifying recovery

Inspection liveness and service recovery are distinct predicates. Liveness is
true only for a fresh successful inspect of the exact configured container ID,
matching image digest/deployment/run labels, and a recognized Docker state.
`running` establishes container liveness only. `exited` establishes outage;
`created`, `restarting`, `paused`, `dead`, missing, unauthorized, malformed,
mismatched or contradictory inspection is unknown. A fresh `running` result
without qualifying telemetry is unknown and does not close an active outage or
reset its episode. A changed Docker `StartedAt`/restart identity from the
retained exact container context is a restart boundary and requires fresh
post-start evidence.

The current observer state file has these recovery-relevant fields:
`last_check.at`, `last_check.http_status`, `last_check.error`,
`last_check.anchor_export.status`, `last_check.incident_projection.status`,
`last_completed_loop_at`, `loop_sequence`, `scheduler.status`,
`scheduler.loop_sequence`, `active_revision`, `active_digest`, and
`configuration_contract`; supervisor state supplies `supervision.status`,
`supervision.heartbeat_age_seconds`, and its own `last_completed_loop_at`.
Do not assume it has per-check start time, container
ID, image, or source-context fields. `last_check.at` is set only after the
telemetry HTTP request and subsequent anchor/lag work return; it does not prove
when that HTTP request began. At the outage/restart barrier, retain last seen
`loop_sequence`, observer process identity (PID plus process start identity),
host boot identity, timing revision/digest, and monotonic/UTC time. The host
supervisor enforces exactly one writer for this observer state file. After a
new container `StartedAt` or outage barrier, first observe a strictly newer
completed loop from that same single observer process/boot and exact context,
and discard it as a barrier loop regardless of its result. Only a strictly
later completed loop from the same unchanged process/boot/context can qualify.
The single observer executes loops serially; its later HTTP request therefore
starts after the discarded loop completed. If the observer process, host boot,
timing context, or container context changes between those loops, discard the
barrier and begin again; missing retained baseline/process identity means
recovery is unknown.

For the qualifying later loop require `last_completed_loop_at`, `loop_sequence`
and `last_check.at` after the discarded barrier completion and after current
Docker `StartedAt`; `last_check.http_status == 200`, `last_check.error == null`,
both `last_check.anchor_export.status` and
`last_check.incident_projection.status` in `{healthy, late}`, fresh
`scheduler.status == healthy` and `supervision.status == healthy`, and
`active_revision` / `active_digest` matching the verified effective host
snapshot and both observer/supervisor readbacks whose `observed_at` remains
within configured freshness. This loop sequence barrier proves its telemetry
request began after the prior loop completed; a pre-outage HTTP success followed
by blocked anchor work cannot qualify merely because its completion timestamp
is later. The sender brackets the observer-state read with successful inspect
of the same exact container context and records read start/end monotonic and
UTC times plus boot identity. The inspected context and process identity must
remain unchanged across the qualifying loop and read. The observer only records
known statuses after validating the expected deployment telemetry shape;
`unknown` cannot qualify. Only then can `running` plus service evidence close
the active episode.

A pre-outage cached `last_check`, heartbeat fresh only by its old timestamp,
state from another container/boot/context, stale scheduler progress, or a timing
change cannot prove recovery. `anchor_export` or `incident_projection` failure
remains its own health event and does not fabricate container recovery. If the
existing bounded telemetry/state does not provide one of the required fields,
recovery remains unknown until it does; no new wire/schema is implied. Clock
continuity records host boot identity and monotonic elapsed time alongside UTC.
Wall-clock regression, sender restart without provable continuity, or a future
timestamp makes evidence stale/unknown; restart never renews prior freshness.
Unknown does not close an active episode. Observer timing revision remains
separate from incident binding revision and cannot reset episode/freshness.

## Failure visibility and authorization

The independent host supervisor checks completed sender-loop progress,
heartbeat age, durable journal cursor and outstanding-work deadline. Sender
dead/stale/corrupt/persistence faults are retained as immutable edges in a
separate supervisor-owned durable health journal and never depend on the sender
journal. This increment registers exactly one additional condition,
`host_sender_health`, for that stream (allowlist/API correction only, no
migration). Its exact bootstrap tuple is the stable deployment ID, opaque
subject `host-sender:<deployment-local-opaque-id>`, service principal
`g7-host-operational-alert-sender` (actor kind `service`, sole role
`integration.incident.submit`), producer
`g7-host-operational-alert-sender/v1`, condition `host_sender_health`, and a
strictly positive installed configuration revision. The matching service
binding row sets `subject_type: host_sender`, `producer_revision: 1`,
`enabled: true`, and the exact principal/deployment/subject/condition/producer
tuple. Install exactly one enabled route with stable route ID
`g7-host-sender-health-v1`, its positive current route revision, the same
deployment/subject, configured current recipient access group and exact source
tuple, and `vulnerability_group_id: null`. The stream key is exactly
`(deployment_id, subject_id, host_sender_health)`. The independent supervisor
is the fault observer and journal owner, not an API bearer, Slack sender, or
second dispatcher.

Only after the supervised sender process has restarted and verified its
runtime and health-projection path may it consume supervisor journal edges.
The health-projection path has its own durable cursor/stream state in the
supervisor-owned health journal; it does not read, reset, or bless a corrupt
main sender journal. If the main journal is corrupt, normal streams remain held
while this restricted health-only recovery path may report the fault. The
resumed sender uses the normal durable lifecycle: it allocates the next health
transition in the supervisor journal, admits and performs a real configured
host HTTPS notification attempt, persists the actual result, projects the
transition in sequence, and only after exact transition acknowledgement
projects that attempt's actual accepted, failed, or uncertain outcome. Recovery
of the sender is a later edge with its own real send attempt and same ordered
projection. If the sender remains dead, no notification attempt or application
projection is claimed; the independent journal retains the fault. Once resumed,
it can perform the real notification while UVM is still unavailable and retain
the result for later ordered projection. UVM unavailability holds projection,
not the independent observation or host transport. No synthetic
failed/uncertain delivery is invented for an attempt never admitted, and no
in-platform projection is claimed until a real notification attempt has an
outcome and the transition is accepted. This does not recursively alert
through a failed sender: the independent supervisor only records locally; the
resumed verified sender later performs the actual notification. Use existing
`incident_projection` for projection failure and `notification_failure` for
delivery failure. A failure of the platform alert path remains in the
independent host log.

For public readback, preserve the existing exact route evaluation: current
recipient-group membership; `integration.health.read` in that same recipient
group; exact current source tuple; deployment/group scope; and all current
matching principal, group, and global denials/revocation. Membership alone, a
grant in another group, or a different source never grants visibility. The
service principal remains exactly `integration.incident.submit` with current
enabled binding and cannot read broadly or edit the binding/route. Source and
recipient negatives remain required.

## Decisive local journey and corrections

Use the maintained G7 container journey with an
`--operational-alerts-only` selector in that same runner. The pinned disposable
environment is DefectDojo CE, PostgreSQL, labelled local OIDC, Docker and shared
Chromium; no external provider or production endpoint. Prove actual HTTPS
fixture delivery while UVM is stopped, exact transition/attempt projection
catch-up after app recovery, same-binding idempotent replay, and blocked fenced
replay after binding/context/epoch changes. Also prove recipient same-group
grant, missing/wrong group or source, matching deny and revoked membership;
known retry; uncertain no-resend; crash after provider acceptance before
journal/projection acknowledgement; route withdrawal concurrent with dispatch;
sender kill/dead-loop and corrupt/persistence failure visible independently;
and exact outage/recovery evidence that rejects cached pre-restart telemetry.
Include the delayed-anchor negative: a pre-outage successful telemetry HTTP
response whose anchor lookup completes after restart must be discarded as the
first post-barrier completed loop, and cannot certify recovery; require a later
serial loop whose request begins after that barrier. Include a known-429 opening
attempt with a queued retry, recovery before retry admission, and assert the
retry is suppressed while the real failed attempt remains projected and at
most one recovery edge is sent. Include supervisor-journal fault retention
while the sender is dead/corrupt, then resumed sender consumption with an actual
notification attempt and ordered health-stream projection; assert no synthetic
delivery result exists before that attempt.

Add public API negatives for bool schema/revision integers, unknown/missing
fields, malformed/null/oversized references, future/open-ended timestamps,
causal recovery bounds, duplicate attempt IDs with changed body, exact replay,
out-of-order new attempts, stale failure after accepted/uncertain, and ordered
projection catch-up. For delivery replay, reject alternate timestamp spellings
and accept only exactly six fractional digits followed by `Z`; verify the
normalized database timestamp reconstructs the sole accepted wire representation
and exact replay returns `idempotent: true` with stable transition/attempt/
outcome identity. Verify transaction rollback and absence of partial
transition/attempt receipts on write failure. Run the existing exception-warning
journey as a regression check because its transport remains separate. Capture
the exact source snapshot, image/config/fixture digests, invocation, raw output,
exit, and owned-resource cleanup outside the repo. The deployed-image check is
external validation, not a local prerequisite; no external provider is used.
Human visual, release, and G7 decisions remain separate.
