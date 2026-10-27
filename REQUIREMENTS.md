# UVM hard requirements

Status: draft target baseline. SHALL statements describe proposed requirements for review and do not imply implementation approval or verification.

### CR-01 — Engine dependency

DefectDojo Community Edition SHALL provide the underlying finding engine and configured deduplication. UVM SHALL preserve supported upgrade boundaries and SHALL NOT write directly to its tables.

### CR-02 — Native grouping

The system SHALL group by stable namespaced source-native vulnerability identifier and SHALL retain CVE relationships without automatically merging groups sharing a CVE.

### CR-03 — Rebuild continuity

A verified successor incarnation SHALL retain logical workload and finding continuity, original detection history, assessment history and issue associations.

### CR-04 — Occurrence preservation

Grouping/deduplication SHALL preserve the evidence and identities required to distinguish affected instances, components and remediation portions.

### CR-05 — Decision survival

Scanner ingestion SHALL NOT overwrite human assessments, accepted risk or audit history.

### CR-06 — No false remediation

Missing, stale, partial or failed scanner retrieval SHALL NOT be counted as remediation. Risk acceptance, exclusion and duplicate removal SHALL NOT count as patching.

### CR-07 — Closure authority

An authorised engineering confirmation SHALL count as remediation for its explicitly recorded membership; whole-group remediation SHALL require all portions complete or an authorised confirmation covering all remaining portions.

### CR-08 — Permission enforcement

Every state-changing operation SHALL enforce configurable permissions and scope server-side, including inbound GitHub actions and bulk operations.

### CR-09 — Audit atomicity

Assessment changes and their durable audit events SHALL commit atomically; failure to record the event SHALL prevent the change.

### CR-10 — Evidence honesty

Gate claims SHALL identify the actual code/config revision and environment tested; mocks SHALL NOT be reported as real integration evidence.

### CR-11 — Work boundary

Sensitive source data, credentials, raw findings and internal identifiers SHALL remain within their authorised private environment unless explicitly cleared for transfer. Generic development SHALL NOT depend on receiving them.

### FR-ID-01 — Explainable matching

The resolver SHALL record matching inputs, rule version and outcome; ambiguous correspondence SHALL be visible and SHALL NOT guess a match.

### FR-ID-02 — Identity changes

Identity-rule migrations, workload merges/splits and corrected mappings SHALL preserve lineage, expose assessment impact and support audited correction.

### FR-IN-01 — Collection

Qualys and Sysdig adapters SHALL collect on a configurable schedule, daily by default locally, with bounded retries, pagination accounting and explicit completeness/freshness.

### FR-IN-02 — Reimport

Recurring import SHALL target stable registered DefectDojo contexts with absence closure disabled and reactivation behaviour explicitly mapped to UVM policy.

### FR-OW-01 — Multiple owners

Owner sets SHALL support multiple people, teams or both, with stable identities and effective-dated membership.

UVM SHALL manage ownership-team identities and memberships natively, link people to stable local accounts, and keep accountable ownership separate from RBAC access groups.

### FR-OW-02 — Portions

Ownership portions SHALL identify exact affected membership; partial confirmation SHALL affect only that portion and SHALL preserve outstanding work.

### FR-OW-03 — Routing

Routing SHALL support explicit assignment, configured metadata rules and an unresolved queue; manual overrides SHALL persist until explicitly changed or expired.

### FR-AS-01 — Overrides

Severity overrides SHALL retain original source ratings, rationale, actor, scope and history, and SHALL follow configured authorisation.

### FR-AS-02 — Acceptance

Risk acceptance SHALL have defined membership, accountable owner, rationale, expiry and approval history; extension SHALL create a linked decision.

From a vulnerability record, an authorised user SHALL be able to request an exception with prefilled vulnerability and affected-resource context, rationale and compensating controls. Eligible approvers SHALL receive a review item, approve or deny with rationale, and set an expiry on approval. Approved decisions SHALL appear in a permission-scoped exception register with their approval date. Approval SHALL accept the risk and pause the affected SLA with its remaining duration captured. While active, exception expiry SHALL be the displayed time target. At expiry the SLA SHALL resume with that remaining duration; prior breach history SHALL remain intact. An exception SHALL NOT count as remediation or on-time completion. Configurable advance alerts for upcoming expiry SHALL support Slack and email.

### FR-AS-03 — Configurable roles

Administrators with delegated authority SHALL be able to configure roles, actions, scopes, approval limits and separation-of-duties rules without code changes.

UVM SHALL provide administrator-controlled access-group creation, deletion, user membership and selectable RBAC permissions. A bootstrap administrator role SHALL exclusively control access-group and permission configuration. Approval authority SHALL be assignable through access-group permissions and rechecked against current eligible membership when exercised. Organisational policy governance may remain external while UVM retains executable configuration and its audit history.

### FR-AS-04 — Recurrence

Reliable positive observations newer than confirmed remediation SHALL reopen affected exposure and the existing issue, preserve first detection and create one recurrence event per episode.

### FR-AS-05 — Administrative secret configuration

An authorised administrator SHALL be able to configure a researched encrypted-local-secret or 1Password-vault integration through settings. The provider, cryptographic scheme, credential lifecycle and secret display boundaries require a reviewed design before implementation.

### FR-GH-01 — Single issue

Each native vulnerability group SHALL have one managed GitHub issue; affected instances, people, teams and partial progress SHALL be represented without losing ownership information.

### FR-GH-02 — Bidirectional flow

Authorised ownership and remediation actions SHALL flow from GitHub into UVM; outbound changes SHALL preserve human content and prevent feedback loops.

### FR-GH-03 — Recovery

Integration SHALL support durable pending writes, duplicate prevention, retry, conflict visibility and recovery after a create-before-ledger crash.

### FR-GH-04 — Connected application setup

GitHub connection SHALL use a researched connected-application authorisation and credential lifecycle. Existing token-file and webhook proof remains bounded local evidence until a reviewed migration and target connection are verified.

### FR-ME-01 — SLA coverage

Reports SHALL distinguish eligible exposure with computable SLA deadlines, coverage gaps, overdue exposure and on-time remediation using explicit denominators.

SLA deadline configuration SHALL require a selectable delegated permission. Under the evolved policy, the SLA start SHALL be the first authoritative UVM ingestion commit for the affected membership/episode, separate from scanner observation, collection and later refresh timestamps. Reimport, rebuild, transfer or owner change SHALL NOT restart that clock. The new policy and its prospective migration, recurrence and historical-report treatment SHALL be versioned; previously issued G5 results retain their original basis.

### FR-ME-02 — Historical metrics

Reports SHALL reproduce historical results with policy version, as-of time, data watermark and counting unit; accepted risk and source failure SHALL remain visible.

### FR-ME-03 — Stakeholder reporting

The product SHALL provide on-demand operational, engineering and executive reporting, filtered by authorised scope with non-duplicated enterprise totals.

### FR-AU-01 — Audit protection

Audit records SHALL retain actor, origin, before/after values, membership, timestamps, rationale and correlation ID, with protected storage, export and visible failure states.

The evolved G7 target SHALL store audit history in UVM with a read-only, permission-scoped viewer and export complete events to an independently controlled SIEM copy. Durable export receipts, retry and reconciliation SHALL make missing or altered SIEM copies visible; UVM/CE credentials SHALL NOT alter that independent history. The previous mandatory host-archive location is superseded; previously tested host controls are historical local proof. Internal storage integrity, export failure and full-container outage boundaries require a reviewed design.

### FR-AU-02 — Retention classes

Product data, including vulnerability detections and their retained source evidence, SHALL be preserved for one year. Operational logs, including scanner-ingest success and failure records, SHALL be preserved for three months. The simultaneous no-deletion instruction SHALL prevent inferred automatic disposal until its deletion and legal-hold meaning is resolved in a reviewed policy.

### FR-NT-01 — Slack alerts and acknowledgements

UVM SHALL support a Slack app that sends configurable, professionally formatted channel alerts with role/group mentions, accepts authenticated button or reply acknowledgements, and raises a permission-scoped in-platform alert when delivery fails. Acknowledgement SHALL NOT itself approve an exception, change an assessment or confirm remediation without the separately authorised command contract.

Upcoming approved-exception expiries SHALL trigger advance alerts through configurable Slack and email channels. Alert offsets, recipients, delivery attempts and failures SHALL be retained; alert delivery SHALL NOT extend or approve an exception.

### FR-OP-01 — Versioned operational settings

Authorised administrators SHALL manage operational settings through versioned, scoped product workflows. Each change SHALL retain immutable values and provenance, an atomic audit and command receipt, and a recoverable desired-versus-effective application result. A rollback SHALL publish a new revision. Separately controlled infrastructure consumers SHALL independently validate and acknowledge application; UVM SHALL NOT gain general host, Docker or archive authority.

The first G7 increment SHALL expose deployment-scoped observer timing through API and UI with separately grantable read/configure actions. UI Save SHALL automatically request host application. Pending, applied, failed and uncertain states SHALL distinguish a locally committed desired revision from a host-verified effective revision. An unavailable application SHALL NOT stop the host observer's last verified configuration.

Later reviewed increments SHALL cover observer/alert routing, backups/recovery, archive retention, ingress and secret sources. Organisational values and numeric development fixtures SHALL remain changeable; fixture values SHALL NOT become approved production policy through a local test.

### FR-UI-01 — Visual quality

The POC and product SHALL use the original VOLT visual theme, reusable design tokens and a polished, accessible interface with visual review evidence.

### FR-UI-02 — Operational states

Each relevant workflow SHALL implement loading, empty, error, stale, forbidden, conflict, pending-sync and success states; hidden controls SHALL NOT be the permission boundary.

### FR-UI-03 — Workflow completeness

UI SHALL support grouped findings, occurrence detail, owners, assessment, partial remediation, acceptance approvals, audit history, unresolved queues, integration health and reports.

### NFR-01 — Accessibility

The application SHALL target WCAG 2.2 AA, including keyboard operation, visible focus and non-colour status cues. Release claims SHALL use measured evidence.

### NFR-02 — Performance

Filtered finding views SHALL target p95 under three seconds on an agreed representative dataset and named environment; volume and concurrency SHALL be fixed before performance sign-off.

### NFR-03 — POC fidelity

The local POC SHALL exercise the intended domain, permission, audit and workflow semantics at smaller scale, rather than substitute disposable demo behaviour.

### NFR-04 — Final container deployment

The final product SHALL ship as one self-contained supervised Docker image intended for AWS hosting, containing UVM, DefectDojo CE, their databases and required runtime processes. It SHALL provide standards-based interchangeable OIDC sign-in, with Okta as the named provider target, enforceable scope permissions, durable state and demonstrated coordinated recovery across container replacement. External infrastructure SHALL execute backups; the application SHALL provide the consistency, restore and readback contract. A labelled local OIDC provider proves only local behaviour and SHALL NOT be described as real Okta or AWS integration.

### NFR-05 — Failure visibility

Failures and missed expected runs SHALL raise observable in-platform health events. Slack delivery failure SHALL create an in-platform alert; audit data SHALL be exportable for SIEM alerting. The replacement design SHALL state how a complete container outage and failure of an in-platform alert are observed, without claiming that an unavailable container alerted on itself.

### NFR-06 — Change control

Implementation SHALL follow approved OpenSpec changes and gate evidence. Material design drift SHALL require an amendment before dependent implementation proceeds.

G7 SHALL advance through rolling, independently reviewed, environment-labelled development checkpoints recording behaviour, exact executable source, raw results and cleanup. No fixed organisational policy or named release candidate SHALL be required for local development. Owner-set release configuration, D-09 cutover in the external environment, production activation and the human G7 gate decision SHALL remain separate future decisions. Scoped authorisation, audit atomicity, independent archive/observer authority, fail-closed errors, honest health and controlled writer cutover remain mandatory invariants in every increment.

## Requirements discipline

Each OpenSpec change names affected IDs, adds concrete scenarios, and maps them to evidence. A requirement is implemented only after relevant scenarios pass in the required environment. Tests for one subset do not imply all related integrations passed. Deletions and altered semantics require a recorded amendment, impact assessment and authorised decision.

SLA thresholds, role assignments, AWS service, secret provider and live volume targets require reviewed configuration when a real release is selected, not hidden constants. Development may use explicit, editable, environment-labelled fixtures. The evolved audit/data/ingestion-log retention periods are target requirements; deletion semantics remain unresolved under FR-AU-02. LLM functionality is outside this scaffold's required scope; it cannot be inserted into identity, permission, approval or remediation decisions without a separately reviewed proposal.
