## ADDED Requirements

### Requirement: NFR-04 Final container deployment
Final deployment SHALL provide one supervised, self-contained Docker image intended for AWS hosting, containing UVM, pinned DefectDojo CE, databases and required processes. It SHALL have interchangeable standards-based OIDC sign-in with Okta as the named provider target, enforceable UVM-managed permissions, infrastructure-operated backups and demonstrated coordinated recovery across container replacement. Local fake-provider and Docker proof SHALL be labelled and SHALL NOT claim real Okta or AWS integration.

#### Scenario: G7-ID-01 local OIDC linking and scope
- **WHEN** a named disposable container completes an OIDC exchange with a labelled fake provider and a subject linked through the controlled principal process
- **THEN** UVM grants only the current configured scope through API and UI and records the evaluated identity/policy revisions on a state-changing command
- **AND** an unlinked or incorrectly linked subject, or a GitHub actor linked only by matching email/display name, gains no authority

#### Scenario: G7-ID-03 named provider integration
- **WHEN** the selected release candidate connects through its interchangeable OIDC boundary to the named Okta target
- **THEN** sign-in, subject linking, denied links, session lifecycle and current UVM permission enforcement are verified against that target with revision-bound evidence
- **AND** local fake-provider execution is retained only as local proof, not substituted for Okta integration

#### Scenario: G7-ID-02 revocation and stale membership
- **WHEN** a UVM access-group membership is removed while a user has an existing session or pending command
- **THEN** the removed group's grants no longer authorise reads or commits, while unrelated current grants remain usable, and the effective membership revision is retained
- **AND** when account access is revoked, all existing sessions are terminated and new sign-in and stale commands are denied from the effective revocation point
- **AND** the account-revocation trigger, in-flight race and meaning of immediate denial are specified and tested; local fixture measurements do not imply production target compliance

#### Scenario: G7-RBAC-01 application-managed access groups
- **WHEN** the bootstrap administrator creates, changes or deletes a UVM access group, selects its action permissions, or changes user membership
- **THEN** server-side permissions and approval eligibility reflect current versioned membership, and each change is audited
- **AND** ownership teams remain distinct from access groups and administrator status does not silently grant assessment authority

#### Scenario: G7-OWN-01 native ownership sources
- **WHEN** UVM manages multiple accountable people and stable-ID teams with effective-dated membership for an affected portion
- **THEN** UVM retains each stable owner identity and effective period through API/UI readback without collapsing people, teams or portions
- **AND** access-group changes do not silently rewrite accountable ownership or confer assessment authority

#### Scenario: G7-EXC-01 SLA and exception workflow
- **WHEN** an authorised user sets an SLA rule or requests an exception from a finding
- **THEN** the request retains finding/resource context, rationale and compensating controls; eligible approvers receive a notification and see an open-request queue, can approve or deny with a reason and choose expiry through a calendar control; approved requests appear in a scoped register with approval date
- **AND** approval accepts risk, captures the remaining SLA duration and pauses enforcement; the active view tracks exception expiry, sends configured advance Slack/email warnings, and at expiry resumes the captured remaining duration without erasing earlier breach history or implying remediation

#### Scenario: G7-SLA-01 ingestion-based start and preserved provenance
- **WHEN** UVM first commits an affected finding's ingestion or later reimports, rebuilds, transfers or recurs that membership
- **THEN** the evolved SLA version uses the first authoritative UVM ingestion commit of the applicable membership/episode as its start, and later refresh, owner transfer or rebuild does not reset it
- **AND** scanner observation, source collection and ingest timestamps remain distinct; historical issued G5 reports retain their recorded clock basis and no prior source time is fabricated

#### Scenario: G7-SLA-ID-CTX-01 policy context without identity correspondence
- **WHEN** an authorized versioned `RuleV1` declares optional context fields such as environment or service identity and the retained-observation writer receives matching inputs
- **THEN** only `workload_match_fields` may discover, select, create or rebuild a workload; context fields are retained as policy-selection facts on a newly created workload but never contribute candidate or correspondence evidence
- **AND** context alone cannot create/select a workload, shared context across distinct native workloads cannot merge them, distinct match keys remain separate, and ambiguous match evidence remains unresolved
- **AND** known stored context with an omitted follow-up input remains retained and usable for applicable SLA selection; omission does not weaken existing coverage
- **AND** conflicting supplied context after a unique match produces unresolved evidence, no staged identity graph or new SLA coverage, and no erasure/reset of an already admitted membership clock; separately committed source-observation retention remains
- **AND** missing stored context remains unavailable even if later supplied; no automatic enrichment/backfill occurs, and only an unavailable selector required by prospective G7 selection creates a coverage gap; missing unused optional context does not blanket-create a gap
- **AND** an episode already pinned to G5 remains G5, including later membership in that same episode after prospective G7 policy activation
- **AND** the empty-context default preserves exact legacy definition digest, request-fingerprint bytes, persisted identity reconstruction and replay; non-empty context is ordered immutable definition data and appears in definition/request fingerprints only for non-empty context
- **AND** stored context definitions are validated as actual arrays of unique valid strings disjoint from match names before reconstruction, and context fields are never scalar-correction targets
- **AND** context persistence, identity resolution and coupled G7 episode/receipt/evaluation commit atomically; any failure leaves no partial identity or SLA state
- **AND** migration `0062` adds only non-null `identity_rule_definitions.workload_context_fields` with default `[]`, preserves old digests and rows, blocks downgrade while non-empty definitions exist, and is admitted only through exact schema-head and inventory checks
- **AND** public SLA selection uses context produced by actual identity writers; browser code does not synthesize context or calculate coverage, and a missing-context gap occurs only when retained context lacks a selector required for prospective G7 selection

#### Scenario: G7-NET-01 private access and webhook ingress
- **WHEN** intended users and GitHub deliver valid and invalid requests to the named single-container candidate
- **THEN** authorised access and authenticated webhook processing work while public database, admin and DefectDojo operational access are denied
- **AND** network configuration, secret references and negative-test results are revision-bound

#### Scenario: G7-PKG-01 process and persistence boundary
- **WHEN** the exact pinned image starts, loses a critical child process, stops or is replaced on the named disposable Docker host
- **THEN** exactly one application container runs its required processes with ordered initialisation and honest readiness, UVM and CE use distinct database roles, and durable database/media state survives replacement
- **AND** no application credential may read or write the other application's database; durable application data remains available after replacement

#### Scenario: G7-HOST-01 named AWS target
- **WHEN** the selected self-contained image runs on the named AWS hosting and externally managed durable-storage configuration
- **THEN** runtime readiness, intended ingress, replacement persistence, restricted internal services and infrastructure backup/restore interfaces are verified with actual configuration and operator identities
- **AND** disposable Docker evidence alone does not establish AWS target readiness

#### Scenario: G7-AU-01 in-application audit and SIEM export
- **WHEN** an authorised viewer reads audit history or a SIEM export succeeds, fails or falls behind
- **THEN** a permission-scoped, read-only UVM viewer exposes retained audit history, and complete events reach an independently controlled SIEM copy through a documented ingestible format with durable receipt, retry and reconciliation
- **AND** UVM/CE credentials cannot alter the independent copy; missing or changed SIEM records and export failures are visible without rewriting a committed assessment; audit storage integrity and one-year preservation are verified

#### Scenario: G7-RET-01 data-class preservation
- **WHEN** product data or ingestion logs reach their stated preservation periods
- **THEN** the selected storage/backup design demonstrates one-year preservation of detection/product data and three-month preservation of operational logs, including scanner-ingest success/failure records, through authorised readback
- **AND** no automatic deletion is inferred from those minimum periods while the simultaneous no-deletion requirement remains unresolved

#### Scenario: G7-AL-01 Slack and failure alerts
- **WHEN** a configured event produces a Slack notification, acknowledgement or delivery failure
- **THEN** authorised channel and group routing, delivery receipts, authenticated replay-safe button/reply acknowledgements and group-scoped in-platform failure alerts are retained
- **AND** upcoming exception expiry uses configured Slack and/or email channels with auditable delivery/failure state; acknowledgement alone never approves or extends an exception or confirms remediation, and complete-container failure has an observable detection path outside the unavailable application

#### Scenario: G7-AL-HOST-01 independent host outage and sender health alerts
- **WHEN** the trusted bootstrap operator installs matching exact service-binding, route, and host-catalog records and the host sender observes container outage, candidate recovery, or sender failure
- **THEN** only a fresh successful inspection of the exact container ID/image digest/deployment/run context can establish liveness; recovery requires a causal post-start request barrier: discard the first newer completed loop after outage/restart, then accept only a strictly later successful serial loop from the same single observer process, host boot, exact context, current timing revision, and fresh supervisor/scheduler state
- **AND** missing, stale, contradictory, unauthorized, mismatched, or cached pre-outage observations remain unknown; unknown does not close an active outage, reset its episode, or renew old freshness
- **AND** outage and qualifying recovery each create at most one edge transition per episode; repeated samples and a provably unsent canceled episode do not create reminders or consume API stream sequence, while `SENDING` and uncertain work is never called canceled
- **AND** when recovery is durably observed, all queued not-yet-admitted retries for that opening are suppressed under the dispatch lock even after an earlier rejected/retryable attempt; already admitted I/O may finish, recorded attempts remain truthful, and no attempt is fabricated for suppressed work
- **AND** host journal record sequence is separate from contiguous API transition sequence; transition UUID is the app intent key, recovery retains opening episode/generation/time, and exact transition/attempt acknowledgements are checked beyond HTTP status
- **AND** exact same-binding restart replay preserves IDs and bodies; changed binding, producer, image, context, catalog generation, route, or recovery epoch fences old work as held without resetting stream sequence or rewriting it, and no later event skips a blocked predecessor before trusted reconciliation
- **AND** host intent and `SENDING` are durable before I/O; known rejection/retryable failure and post-submission uncertainty remain distinct, every attempt is projected in order, and uncertain sends are never automatically resent
- **AND** focused existing API validator/state-machine corrections enforce true JSON integers, exact shapes, bounded nullable safe references, causal/future timestamp limits, exact immutable replay, increasing new-attempt order, and protection against stale failures overwriting terminal accepted/uncertain state, without changing v1 wire or schema
- **AND** host observation and the independent supervisor continue while UVM is unavailable; exact transitions are projected only under current binding authorization, and delivery outcomes only after the exact transition acknowledgement and current binding authorization, while projection loss cannot erase host evidence or imply application-side unknown/healthy status
- **AND** outbound notifications contain only allowlisted sanitized operational context, and transport acceptance requires an exact HTTPS provider acceptance response; a correlation ID alone does not claim exactly-once delivery
- **AND** current same-recipient-group/source authorization with matching denials governs readback, and service submission uses only the dedicated bound `integration.incident.submit` principal
- **AND** sender-dead/stale/persistence faults are durably journalled by the independent supervisor and later consumed only by the verified resumed sender on the exact `host_sender_health` stream: service principal `g7-host-operational-alert-sender` with sole `integration.incident.submit`, producer `g7-host-operational-alert-sender/v1`, `subject_type: host_sender`, `producer_revision: 1`, exact deployment-local subject and positive binding revision, and route `g7-host-sender-health-v1` with same subject and `vulnerability_group_id: null`; real notification attempts precede delivery outcomes, while dead/corrupt/unavailable paths remain explicitly unprojected without fabricated outcomes or recursive sending
- **AND** delivery replay accepts only the canonical six-fractional-digit UTC `attempted_at` representation, reconstructs the stored v1 body without a new digest column, and exact replay returns stable identity/outcome with `idempotent: true`; the API fails closed when exact-deployment verified timing bounds are unavailable
- **AND** the maintained disposable journey covers app-down HTTPS delivery and exact catch-up, replay/fencing, route withdrawal, authorization negatives, malformed/future/order/rollback/idempotency API negatives, uncertain crash recovery, delayed-anchor/pre-outage request rejection, queued-retry suppression after recovery, independent sender death and health-stream catch-up, canonical timestamp replay, and separate exception-warning regression

#### Scenario: G7-CFG-01 connector and secret settings
- **WHEN** an authorised administrator configures the selected secret-source or GitHub connected-app integration
- **THEN** configuration, credential lifecycle, rotation, scope and failure states follow a reviewed contract without exposing secret values in audit or UI output
- **AND** a researched encrypted-local or 1Password choice and GitHub installation flow are specified before production activation

### Requirement: FR-OP-01 Versioned operational settings
Authorised operational configuration SHALL retain immutable desired revisions, scoped permissions, atomic audit and command receipts, and independently verified effective revisions. Local development values SHALL be fixture-labelled and changeable. A rollback SHALL create a new revision; UVM SHALL NOT gain general host authority.

#### Scenario: G7-OBS-01 observer timing through UI and independent host
- **WHEN** an authorised administrator saves complete deployment-scoped observer timing values or rolls back through the UI
- **THEN** UVM atomically retains the desired revision, audit, receipt and application intent, and the independent host controller validates and applies that exact revision without a second manual approval
- **AND** public UI/API readback distinguishes pending, applied, failed and uncertain from the independently confirmed observer and supervisor revision/digest; last-good monitoring continues through application-container outage or a rejected apply while the host observer remains available
- **AND** stale revisions, invalid values, grant withdrawal, service spoofing and failed persistence cannot create an applied claim or a partial publication
- **AND** the bundled revision-3 timing values remain labelled local fixtures, while fixed scope, audit, archive/observer independence and honest health rules continue to apply

#### Scenario: G7-REC-01 coordinated restore and upgrade rollback
- **WHEN** a monitored backup is restored into a replacement container or a dependency/schema upgrade is rolled back in a disposable candidate
- **THEN** UVM and DefectDojo mappings, decisions, media, audit history and queued intents reconcile through supported interfaces without fabricating remediation or history
- **AND** actual restoration and outage measurements are retained without inventing an owner-approved availability, RPO or RTO target
- **AND** the current-main candidate B, whose package and image digests are bound in the host-journaled compatibility admission, upgrades the archive's exact 0058 UVM schema to 0061 on fresh forward volumes at recovery epoch 1; the previously accepted 0058 to 0059 transition remains separately labelled historical proof and SHALL NOT substitute for this current-image journey
- **AND** that admission authorizes only the exact ordered migration chain 0058 to 0059 to 0060 to 0061: 0059 creates `g7_backup_projection_evidence` with its declared primary key and nullable evidence-reference columns; 0060 creates `collection_request_reservations` with its declared key, foreign key, unique and check constraints; 0061 adds nullable `ingestion_evidence.byte_size` and its declared bounded-value check. The expected inventory is derived from these migration definitions and the retained host journal, not from broad table or field allowlists
- **AND** the forward restore is bound to the signed archive and source image A context; rollback restores that original archive using its bound prior image A on a different fresh volume set at a strictly higher external recovery epoch, without downgrading the forward database or reusing forward volumes
- **AND** the rollback decision is bound to complete UVM and DefectDojo table schemas, row identities and row-payload inventories and CE media digests, allowing only the exact migration deltas above and exact journal-derived recovery-control row/field changes; extra desired revisions, arbitrary state-field changes, unexpected schemas, same-count payload changes and unrelated table changes SHALL reject rollback
- **AND** epoch-2 verification is signed over the current A UVM, CE and media readbacks and exact image/package/archive/volume/connector context
- **AND** normal startup accepts only the image's exact declared head; current B upgrade-verification startup accepts source head 0058 only with the exact signed and journaled 0058-to-0061 admission, and accepts intermediate heads 0059/0060 only during that same controlled migration/recovery context; unknown, multiple, incompatible or unadmitted heads SHALL reject before effects or initialization
- **AND** post-backup product writes are zero, migration/control changes are independently inventoried, continuous ingress/egress fences remain active through migration and rollback, and uncertain external effects remain held for reconciliation

#### Scenario: G7-CUT-01 controlled legacy issue cutover
- **WHEN** the authorised operator adopts verified existing issue IDs and changes the writer for a live target
- **THEN** the outgoing writer is fenced and uncertain in-flight effects are reconciled before its replacement starts; comparison and readback show one writer per target, preserved issue associations and trustworthy history
- **AND** rollback fences the new writer and reconciles its uncertain effects before restoring the old one
- **AND** production execution remains blocked without separate release/cutover authorisation

### Requirement: CR-11 Data protection boundary
Sensitive source data, credentials, raw findings and internal identifiers SHALL remain within their authorised private environment unless explicitly cleared for transfer. Generic development SHALL NOT depend on receiving them.

#### Scenario: G7-WS-01 authorised environment boundary
- **WHEN** an external-environment validation requires private automation source
- **THEN** the operator receives a local validation packet and the remote scaffold does not require source or credentials to be transferred
- **AND** any permitted attestation identifies the tested revision, private evidence reference, observed result and limits without claiming remote agent execution

These are target acceptance scenarios, not executed evidence. Selected production configuration and target verification remain release work. Development results identify inputs, fixtures, exact commands, interfaces and the named environment. Issue adoption and live cutover require separate validation and authorization. No fixture value becomes a production default. `TRACEABILITY.md` maps cross-cutting requirement coverage.
