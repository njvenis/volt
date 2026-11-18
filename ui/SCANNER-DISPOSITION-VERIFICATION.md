# Scanner command disposition UI candidate

Scope: FR-UI-01/02/03, NFR-01, CR-09/10/11. Input root
`dbb0bc5b45ac3952628d7aec835d4b66e62a4ca6` includes provider793 and backend425.
The root reported scoped independent GO for their endpoint/occupancy work. This
record is UI candidate evidence, not independent UI or packaged acceptance.

A held scanner command now offers explicit abandonment review. The browser freezes
its complete original command and first rationale/evidence in a separate retained
request before dispatch. Replay after loss or reload sends that exact body; it
never refreshes the original fences or silently edits metadata. The generated
strict request and three-way response DTOs come from the implemented route.

Disposition validation checks current actor, the provider's canonical actor-plus-
command digest, command/action/connector/source, and the complete variant shape:

- Audited `not_committed` requires the terminal audit UUID/time. It enables a new
  review, which fetches current scanner metadata and exact-source permissions.
  The user reviews the selected action and current revisions, then separately
  submits with a new command UUID. No original ID is reused or automatically sent.
- `committed` must carry the matching original audited receipt and source projection.
  Receipt recovery clears the retained request without submitting a replacement.
- `admitted` must carry the matching running or receipt-less failed/partial/interrupted
  operation. It never permits replacement or claims definitive non-commit.

Generic404/409, current denial, persistence/network failure, malformed schema,
wrong actor/digest/source/action/audit/time and mixed-family conflict do not release
requests. The UI does not interpret shared command-ID occupancy itself; only the
reviewed audited proof can establish noncommit under the namespace amendment.
Unsupported retained formats stay blocked without migration. Other pending secret
requests cannot be bypassed by replacement. Source-local read denial, immediate
credential clearing and unavailable recovery clearance are preserved.

Replacement review has explicit labels, focus on its heading and existing light
brand components. Synthetic browser screenshots at320/390/1440 contain empty
credential fields; existing axe/WCAG thresholds remain zero. The maintained Node
qualification companion is unchanged: its normal journey still fails safely on
conflict/receipt-less outcomes and does not silently abandon or replace commands.
A future routed packaged recovery exercise must drive these explicit review steps.

Raw evidence: `/var/tmp/volt-easy-install-20261118/evidence/ui/scanner-disposition/`.
The exact root input and owned source overlays were archived before generation,
structural builds, focused rendered checks, transport tests and full verification.
Raw logs and exit files preserve the initial union-narrowing compile failure and
review label/focus failures alongside corrected results. No assertions were weakened.

Transport checks execute the production frontend serializer and response guards,
then validate the captured body and representative response against generated
OpenAPI using Draft2020-12, and against the provider's real strict parser/canonical
digest. This performs no database write or provider network request. Browser
responses are synthetic; public packaged proof awaits the delivery environment.
No backend/provider/Compose edits, Docker mutations, live Qualys, publication,
recovery bypass or human visual acceptance are claimed. UI ownership continues
through independent review and the later public packaged journey.

Final verification: 407 UI tests passed, exit0; 45 focused transport/schema tests
passed, exit0; generated API drift check passed, exit0; immediate/final builds
passed, exit0; pinned strict OpenSpec four passed, exit0. Replacement lifecycle,
credential and recent successful test-proof gates remain enforced in the browser
as well as being rechecked by the server. Existing build chunk-size warning only.
