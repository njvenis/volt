# UI requirements and design acceptance

The proof of concept must look and behave like the intended product. Functional completion alone is not a visual pass. `design/tokens.json` defines the original VOLT design tokens; visual review evaluates representative screens and the implemented experience.

The product roadmap includes administrator access-group/ownership management, a finding-based exception request and approval register, a read-only permission-scoped audit viewer, Slack delivery/acknowledgement states and connector/secret settings. These are distinct workflows; their user journeys and operational states require implementation and visual review.

The 2026-10-19 clarification requires an active exception to show accepted risk, the time remaining until expiry and configured advance Slack/email warnings. At expiry, show the resumed SLA with its captured remaining time and preserve any earlier breach history. Present UVM ingest time and scanner observation as separate labelled values. Audit UI reads UVM history; SIEM delivery/receipt is a distinct status, not an implication that a view has exported successfully.

## Information architecture

User direction, 7 October 2026: all user-facing UI language must use sensible, human-readable English for security professionals. Use familiar security terms, clear actions and concise explanations. Explain implementation-specific concepts in ordinary language; retain exact IDs and technical provenance in optional calculation or audit detail when useful. Labels must preserve the meaning of scope, denominators, unknowns, acceptance, exclusions and remediation.

The interface must have deliberate visual hierarchy and stylistic variation rather than uniformly plain panels. Use the original VOLT palette for structural surfaces, action and selection accents, differentiated panel emphasis, typography and spacing. Status uses labelled icons and semantic accents with non-colour cues. Preserve accessible contrast, dense-data usability and responsive behaviour. Visual review evidence is required for release claims.

| Workspace | Required user work |
|---|---|
| Overview | Current risk, SLA coverage/breaches, source freshness; drill into each number |
| Vulnerabilities | Native-ID grouped table, source/CVE filters, severity, owners, counts, age, due dates |
| Finding detail | Occurrences, image/workload history, ownership portions, assessments, issue and audit timeline |
| My/team work | Assigned portions, partial completion, reasons and due dates |
| Assessment queue | Unassessed findings, overrides, acceptance proposals/approvals/expiry |
| Unresolved | Identity ambiguity, missing ownership, SLA gaps and synchronisation conflicts |
| Reports | Saved scope/time views, executive summaries and exports |
| Integrations | Run health, freshness, failures, retry state and source completeness |
| Administration | Configurable roles, policy, routing and connectors subject to permission |

## Interaction acceptance

- Multi-select owner control distinguishes people from teams and shows scope of each portion.
- Bulk assessment shows eligible/denied counts and result per target; it cannot silently expand selection beyond the active filter.
- Confirmation explains affected membership and whether action is portion-level or whole-group. Concurrent membership changes are surfaced before acceptance.
- Preserve human context on navigation: URL/filter state, sorting, selected row and scroll where appropriate. Saved views are permission-scoped.
- Show native scores and assessed severity as separate values. Show CVEs as linked references, not replacement primary identity.
- Distinguish patched, partially remediated, accepted, overdue, unknown and stale. Use text and icons as well as colour.
- Every headline number links to the precise underlying dataset with identical filters, denominator and as-of time.
- Show pending sync separately from a committed assessment. A spinner cannot imply GitHub has already changed.
- Application views never trigger ingestion or a state-changing planning run through a read request.

## Required designs before broad frontend implementation

At least five representative screens: dense findings table, finding detail with multiple ownership portions, assessment/approval form, executive SLA view, and integration/unresolved health. Include a full multi-owner remediation journey and acceptance expiry journey. Review normal, empty, loading, error, stale, forbidden, conflict and pending-sync examples. The scaffold provides requirements, not approved mockups; G0 must produce and review them.

## Accessibility and responsive behaviour

Target WCAG 2.2 AA. Test keyboard-only use, escape/focus return, visible focus, accessible labels, announcements for asynchronous changes, table semantics, zoom/reflow and target sizes. Dense tables can use a contained horizontal viewport where necessary; surrounding navigation/forms must reflow. Proposed desktop evidence sizes: 1440x900 and 1280x800, plus narrow/reflow checks. Do not declare mobile feature parity without a defined requirement.

## G7 operational settings

Provide versioned UI management of operational settings in reviewed increments: observer timing first, then observer/alert routing, backups/recovery, archive retention, ingress and secret sources. Observer Save automatically requests host application; show desired and independently verified effective revisions separately, with pending, applied, failed and uncertain outcomes, history, rollback-as-new-revision, stale/conflict and receipt recovery. Show server-supplied bounds and units without promoting fixture values to production policy. Use VOLT tokens, keyboard/focus, live status announcements and responsive reflow/accessibility evidence. Hidden controls are not the authority boundary.

## Visual gate

Use the shared values in `design/tokens.json`. A visual review records the UI revision, tokens, viewport and representative data. Review alignment, hierarchy, density, focus, truncation, contrast, states and consistency. Unreviewed generic admin components do not automatically satisfy FR-UI-01. New components require reusable variants, not isolated one-off styling.

## G3 local workflow acceptance

Finding detail, owner/portion controls, assessment form, acceptance/approval queue, bounded administration and audit history extend the accepted G2 shell. Confirmations preview exact current membership/revision; a conflict preserves rationale but clears stale confirmation and requires refreshed acknowledgement. Bulk outcomes are per target. Suspended acceptance is visibly ineffective with actionable exposure; renewal/replacement retains history. Committed decisions and pending projection are distinct; GitHub success is not simulated. SLA fields are preserved values or unknown/uncomputed until G5.

The G3 design requires all relevant loading/empty/error/stale/forbidden/conflict/pending-sync/success examples, keyboard/dialog focus, accessible people/team labels, live outcome announcements and non-colour cues at the approved desktop and reflow viewports. Browser assertions and visual captures are future evidence, not approval of new mockups or completed product quality.
