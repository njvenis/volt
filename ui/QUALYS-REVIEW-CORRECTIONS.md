# Qualys UI review corrections

This checkpoint follows UI candidate `7369935` and merges the exact root development
candidate `53c75bd64c0035d2569023d54a7ad2a63489e5bb`. The backend candidate remains
under independent review; merging it does not establish runtime acceptance.
Scope: FR-UI-01/02/03, NFR-01, CR-09/10/11. Earlier immutable evidence remains at
`/var/tmp/volt-easy-install-20261118/evidence/ui/qualys/`.

Changes:

- Require `ScannerView.credential.revision` and use the exact returned integer for
  secret submission/reconciliation. Explicit zero supports first submission; no
  fallback, guessed zero or legacy connector-slot read remains. Scanner metadata
  commands retain `expected_revisions.secret=null`.
- Treat exact connector-permissions GET `forbidden`/`source_scope_forbidden` responses
  as scoped denial, alongside scanner reads. Both concurrent sibling responses are
  exercised in both completion orders. Authentication, CSRF, session revocation,
  identity failures, writes and other paths retain global session failure handling.
- Reset the credential form synchronously at the start of source refresh, before
  either network request. Hanging and failed refreshes cannot retain populated
  username/password fields; navigation clearing remains covered.
- Validate command HTTP status and disjoint response shapes. Running OperationView
  requires 202. Terminal failed/partial/interrupted readback requires 200 and null
  receipt_id; it reports operational state without claiming an audited completion.
  Succeeded-without-receipt, mismatched command/version/configuration/kind and
  contradictory status/body responses fail closed. Normal GET succeeded operation
  metadata with its receipt reference is still accepted.
- The maintained Node companion stops on receipt-less terminal operations and
  requires receipt decision/audit/intent IDs before claiming an audited completion.

Original scanner commands remain byte-identical on generic409, absence, uncertainty
or receipt-less terminal readback. Dependent replacement/abandonment UI remains on
HOLD until root adopts the provider's actor/body-bound audited contract. No recovery
clearance action or automatic retry was added.

Verification records and pre-invocation immutable owned-source archives are under
`/var/tmp/volt-easy-install-20261118/evidence/ui/qualys-review/`. The merged base ID
and executable source are retained separately. Actual rendered App/managed Chromium
checks use synthetic API responses on port46380; transport checks exercise production
request/response guards with synthetic fetch responses. These are not packaged
backend or live Qualys proof. Screenshots contain only cleared credential fields.

Provider request/response OpenAPI corrections are pending a committed ref. Generated
artifacts have deliberately not been rewritten against the interim untyped routes;
generate/check API must run after that candidate is supplied. The earlier missing
slot-revision dependency is resolved by the adopted required field. Actual packaged
browser execution remains delivery-coordinated, with the same UI correction owner.

Executed results on the merged checkpoint:

- Immediate `npm run build --prefix ui`: exit0.
- Focused rendered regressions: 17 passed, exit0.
- Scanner transport/session-boundary regressions: 27 passed, exit0.
- `node --test ui/tests/*.test.mjs`: 372 passed, one failed, exit1. The sole failure
  is the unchanged exporter-versus-committed-schema assertion in
  `api-generator.test.mjs:68`, caused by the newly merged interim provider routes.
- `npm run check:api --prefix ui`: exit1; drift is exactly `ui/openapi.json` and
  `ui/src/generated/api/Paths.ts`. The check did not modify either file.
- `npx --yes @fission-ai/openspec@1.11.0 validate --all --strict`: four passed, exit0.
- Maintained companion syntax: exit0; safe-input regressions pass in the full suite.

No assertions or thresholds were weakened to hide the pending export dependency.
