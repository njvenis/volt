# Local account UI verification (implementation checkpoint)

Requirements FR-UI-01/02/03 and NFR-01; adopted contract:
`docs/easy-install-api-contract.md`.

`node --test ui/tests/local-access.test.mjs` runs rendered synthetic HTTP
response tests on loopback port 46380. It proves form requests, clearing,
feedback, focus, reflow and axe checks only. Hanging setup/password requests
clear credential fields before a response; actual App navigation closes or
remounts populated credential forms, including browser back navigation. It does not prove persistent
accounts, PostgreSQL, operator capabilities or packaged installation.
Screenshots are opt-in through `VOLT_UI_EVIDENCE` after fields are empty.

The maintained `tools/compose_release_login.mjs` keeps the legacy positional
`origin cookiePath username` and password-only stdin invocation. Local callers
can use `origin cookiePath --local-stdin` and supply a JSON object containing
`username` and `password` over protected stdin. The cookie output remains a
private transport artifact, not an end-user login requirement.

The maintained `tools/g7_local_preview_smoke.mjs` adds `--local --origin URL
--evidence DIRECTORY --credentials-stdin`, receiving the same JSON over stdin.
This checkpoint exercises local sign-in, explicit session response polling,
secret-form removal, and sign-out confirmation. Add `--setup` to claim the first
administrator using additional `capability` and `display_name` stdin fields.
The `--register-scanner` branch can register and read back a disabled scanner,
but currently fails qualification explicitly because the supported scanner
configuration handoff is not pinned. It does not substitute the GitHub App
editor for scanner configuration or report the full journey as successful. Its stdin `scanner` object contains
`display_name`, `source_family`, `source_account_id`, `scope_key`,
`environment_label`, `rationale`, `evidence_ref` and boolean `grant_initial_read`.
No validation or activation is implicit. Both optional branches require the
server-derived protected-administrator flag. It does not run the legacy
OIDC policy-grant mutation journey against local accounts. The existing OIDC
arguments and journey remain supported.

Never use credential values in arguments, environment, logs, screenshots,
traces or HAR. Feed stdin from an operator-controlled private file or pipe.
`node --test ui/tests/local-credential-input.test.mjs` executes both maintained
companions with malformed and incorrectly shaped credential input. It requires
a fixed safe stderr message, exit 1 and no credential markers in either output.

Neither companion's local branch has yet been exercised against a packaged
runtime. The protected dashboard, nested connector summaries, allocated-ID readback,
current-lifecycle reconciliation and frozen uncertain retry are covered by
rendered synthetic tests. A confirmed receipt is accepted after another
administrator activates the connector, provided allocated IDs, exact source,
installation and registry readback match. A different source still blocks
reconciliation. Qualys is no longer routed into the GitHub App editor.

Reviewed replacement uses the explicit `/assessment/commands/{command_id}/abandon`
contract adopted at root86af200. The operator reviews the retained registration,
supplies a reason and evidence reference, and confirms before any request. The
UI verifies command ID, actor-bound canonical request digest and either an exact
committed receipt or terminal non-commit audit identity/timestamp. Only verified
terminal non-commit unlocks a separate review with freshly loaded revisions;
submission then allocates a new UUID. The original envelope is never transformed.
Generic409, absence, network failure and malformed or mismatched responses keep
the command held. No automatic abandonment or replacement is performed.
The backend draft currently requires a different original V1 envelope from the
earlier pinned registration DTO; root must reconcile this before actual integration. Full packaged verification and generation from the final
backend schema remain pending integration. Scanner-family input is checked
by the backend; no unsupported adapter list is fabricated in this checkpoint.
