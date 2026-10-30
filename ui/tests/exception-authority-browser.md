# Exception authority UI verification

The group read supplies `assessment.authority_revision`, an integer >= 0. The UI copies it into `expected_revisions.authority` only for G7 exception submit/approve. Historical DTOs may omit it for existing readers and commands; G7 forms display an explicit refresh message and cannot submit without it. A malformed present revision rejects the group read. No administration request or inferred revision is used.

## Synthetic checks

From the repository root:

```sh
node ui/tests/exception-authority-contract.test.mjs
G7_UI_EVIDENCE_DIR=/tmp/volt-exception-authority-ui/check node ui/tests/exception-authority-browser.mjs
npm --prefix ui test
npm --prefix ui run build
tools/g0_ci/openspec/node_modules/.bin/openspec validate --all --strict
git diff --check -- ui/
```

The browser check renders the actual AssessmentCommand and uses the real group parser, command builder and receipt parser. All requests are intercepted synthetic fixtures; it does not establish API authorization, audit atomicity or integration. It covers submit and approve, a server-shaped 409, rationale preservation, cleared acknowledgement, refreshed authority, preserved episode/evaluation guards, a missing-revision form and recovery, keyboard focus trapping/return, 1280px desktop and 390px reflow, and axe WCAG A/AA checks. Screenshots, requests/payloads/receipts and axe output go to the selected evidence directory. Automated checks are not human visual approval or full WCAG conformance.

## Handoff to the maintained real API journey

Backend/runtime owner retains `tools/g7_observer_journey_browser.mjs` and the Docker runner. Exercise these controls using the actual permitted requester/approver sessions; do not replace their command requests with hand-built POSTs.

1. Open the finding's Exceptions tab. Use `page.getByRole('button', {name:'Request an exception', exact:true})`. In `page.getByRole('dialog', {name:'Request an exception', exact:true})`, select each exact occurrence with `getByRole('checkbox', {name:occurrenceId, exact:true})`. Fill labels `Accountable owner`, `Resource context`, `Compensating controls`, `Proposed expiry (UTC)` and `Reason`. Datetime-local values use `YYYY-MM-DDTHH:mm` (nonzero seconds may use `:ss`). Check `getByRole('checkbox', {name:/I have reviewed/})` and click `getByRole('button', {name:'Save decision', exact:true})`.
2. Register a response listener **before** Save for POST `/api/v1/assessment/commands`. Retain its actual `request().postDataJSON()` and response body/status. Assert action, target, exact membership, authority equal to the group GET used by the form, all four existing revision fields, episode/evaluation guards, and payload. Assert a successful receipt binds that command ID, has audit/decision IDs and the expected committed revision. Wait for the dialog's `getByRole('region', {name:'Saved decision'})`; close with Done, then refresh.
3. Scope approval to `page.locator('[data-exception-pending="'+acceptanceId+'"]')`, then its `Approve exception` button. Fill `Approved expiry (UTC)` and `Reason` in the `Approve exception` dialog, confirm membership, and Save. Capture/assert that actual request and receipt, including `expected_request_revision` and selected expiry. This must run as a currently eligible approver; opening administration or adding admin permission is not part of the UI flow.
4. For an authority conflict, change current authority via the runtime owner's authorized fixture while the form remains open. Save must return 409/no effects. Rationale must remain, acknowledgement must be unchecked, and Save must remain disabled. Click `Refresh instance list`, wait for fresh group and SLA reads, reselect submit membership as needed, review and acknowledge again. The new command must have the freshly read authority and a new command ID. Existing membership/policy/episode/evaluation checks remain server enforced.
5. For post-approval and post-expiry readback, click the application's `getByRole('button', {name:'↻ Refresh', exact:true})` control or genuinely reload. Register the group GET wait before that action. Bind assertions to that newly returned DTO, not an older direct API request or an unchanged mounted screen.
6. Select `page.locator('[data-exception-id="'+acceptanceId+'"]')`. Within it select `getByRole('region', {name:'SLA state for '+occurrenceId, exact:true})` for **each** atom. Assert that acceptance's current state, each atom's exact state label, target `<time datetime>`, exact server remaining-seconds text, frozen duration (or `No active pause`), and both breach flags. Paused target/remainder labels are `Exception expires` / `Time to exception expiry at refresh`; other states use `Current SLA target` / `Remaining SLA duration at refresh`. Null duration is `Unknown`; numeric values are rendered with `toLocaleString('en-GB', {maximumFractionDigits:20}) + ' seconds'`. Gap state remains explicitly unknown. A gap atom's labels must never establish resumption of another atom.

Negative controls must reject the stale paused response and a wrong state/value within the selected atom. Retain current readback, actual command/receipt, screenshot, source snapshot/image and cleanup in the maintained journey's evidence. UI clocks remain server supplied; there is no browser deadline or SLA arithmetic.
