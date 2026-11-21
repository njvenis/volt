# Qualys UI checkpoint

Implements the adopted Qualys VMDR UI contract from base
`0d3cbb115d80c5e6a414d63bb5ad7b6fd842b303` for FR-UI-01/02/03 and NFR-01.
This is a review candidate, not packaged-runtime or live-Qualys acceptance.

The protected overview accepts human labels, an allowlisted regional platform,
account-visible scope and an explicit default-on read grant. Registration derives
its type from the generated OpenAPI request and validates the response's allocated
IDs, generated source tuple and credential slot against deployment and scanner
readback. Labels are not identity. Existing retained commands are never migrated.

The scanner workspace uses its own configuration, credential, test, activation,
manual collection and persisted-observation views. Ordinary users reach authorised
sources through scoped connector discovery without protected deployment inventory.
GitHub configuration remains separate. Writes use current server revision vectors;
unknown command outcomes retain the exact original request in session storage.
Credential values stay in memory, preserve password whitespace and clear from the
form immediately, on navigation and on refresh. Only submission identifiers are
retained. Recovery quarantine offers no clearance action.

The source view distinguishes latest attempt from older complete data, partial,
failed and interrupted operations, observation lineage and vendor versus collection
timestamps. Coverage and source freshness remain unknown; collection recency and
unresolved workload identity are labelled separately. Scoped scanner read denial
is visible locally; authentication and CSRF failures retain session handling.

## Executed evidence

Raw logs, exits and cleared-form screenshots:
`/var/tmp/volt-easy-install-20261118/evidence/ui/qualys/`.
Use `/var/tmp/volt-easy-install-20261118/env.sh` for pinned tool versions and
`PLAYWRIGHT_BROWSERS_PATH=/var/tmp/volt-easy-install-20261118/ui-browsers`.

- Locked `npm ci --prefix ui`: exit 0.
- `npm run generate:api --prefix ui` from the committed exporter: exit 0.
- `npm run check:api --prefix ui`: exit 0, non-repairing drift check.
- Immediate and final `npm run build --prefix ui`: exit 0. Existing chunk-size warning.
- `node --test ui/tests/*.test.mjs`: 337 passed, exit 0.
- `npx --yes @fission-ai/openspec@1.11.0 validate --all --strict`: four passed, exit 0.
- Maintained companion syntax and malformed/incorrect credential input: 18 passed,
  exit 0. This does not establish its execution against the packaged application.

Browser tests use the actual rendered App and managed Chromium on synthetic port
46380. Registration and scanner screens have 320/390/1440 reflow and zero existing
WCAG axe violations. Screenshots are taken after credential fields are empty.
The collection sequence fixture starts with an existing allocated credential
version and covers rotation. It does not disguise first-submission dependency.
The contract test validates actual serialized registration/abandonment against the
exported required schema and the real backend pre-persistence shape validator;
it performs no database write and is not a backend public journey.

## Runtime dependencies and routing

1. First credential submission is intentionally blocked on this base. ScannerView
   returns `expected_revisions.secret=null`, and the existing connector read lists
   only slots with versions. The newly allocated slot has no readable head revision.
   Backend must provide the current allocated-slot revision through an adopted read
   contract; the UI must not guess zero or infer revision from state/labels.
2. Provider ScannerService/router is not in this base. Supply its committed combined
   candidate before provider schema export and packaged integration. Scanner DTOs
   currently implement adopted `uvm/scanners/contracts.py`, not generated route proof.
3. Delivery owns the disposable packaged/PostgreSQL/protocol fixture and Python
   runner. UI retains correction ownership for the maintained Node companion.
4. Restore clearance remains held. No bypass, live tenant request, production,
   human visual approval or final end-to-end acceptance is claimed.

The maintained companion keeps its old OIDC signature and local login paths.
Its `--local --register-scanner --credentials-stdin` branch now expects protected
stdin JSON with local `username/password` and nested `scanner` containing
`display_name,account_label,platform_id,environment_label,rationale,evidence_ref,
grant_initial_read,username,password`. The nested credentials belong to Qualys.
Regions are us1/us2/us3/eu1/eu2/in1. `--setup` additionally uses the existing
capability/display_name input. No credentials go in argv, environment or evidence.
The explicit branch drives register → save → credential → test → activate → collect
and verifies persisted detections; a denied read cannot satisfy it. Delivery must
supply the correct fixture credentials and read grant. Pending operations poll the
same frozen UI command and observe actual HTTP responses.

Test servers/browser contexts/temp bundles are closed by test cleanup. No Docker,
DB, n8n, live-provider or unrelated resources were mutated.
