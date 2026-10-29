# Data preservation browser handoff

FR-UI-01/02, FR-AU-01/02, G7-AU-01 and G7-RET-01. This helper verifies an authenticated read-only browser journey against a caller-owned endpoint. It does not create a baseline, run an observer, authenticate, export events, replace a container or establish elapsed preservation. The backend outcome owner runs it from the maintained real journey after creating independent expected inventories.

```sh
CHROMIUM_EXECUTABLE_PATH=/home/nicho/.cache/ms-playwright/chromium-1234/chrome-linux64/chrome \
node ui/tests/preservation-audit-browser.mjs \
  --origin http://127.0.0.1:<port> \
  --storage-state /private/disposable-session.json \
  --expectations /private/preservation-expectations.json \
  --evidence /tmp/volt-g7-preservation-audit-evidence/<run>/browser
```

Use the lockfile-pinned Playwright 1.61.1 and Chromium 1234. The helper also exports `runPreservationBrowserStep({page, origin, expectations, evidenceDirectory})` for an already authenticated Playwright page. It uses no mocks or response interception. The provided session must load the existing session route and candidate scope. A denied summary can still have a candidate; candidates never imply grants. Native session `authority.group_scopes` is a mapping of group IDs to arrays of three-string tuples, while `source_scopes` is an array of three-string tuples. Group IDs and grants are never reconstructed into browser permissions.

## Expectations, version 1

The JSON object has these fields:

| Field | Required meaning |
| --- | --- |
| `schema_version` | Integer `1`. |
| `id` | Safe filename label using letters, numbers, `_` or `-`. |
| `synthetic_labels` | `true`; screenshots require a disposable fixture with synthetic labels. Do not supply production/private labels. |
| `scope` | Exact `{source_family, source_account_id, scope_key}`. No wildcard. |
| `status` | Expected summary HTTP status: `200`, `404` or `503`. |
| `summary` | For 200, the complete expected contract summary, including snapshot ID, signed check/validity times, fingerprints, mask reasons, environment, three complete class DTOs, uncovered classes and elapsed preservation. `response_at` may be omitted: it is the only response field excluded from equality. Do not obtain expected counts or record inventory by simply copying the response under test. |
| `records` | For 200, an object mapping each class with established counts to its complete ordered array of expected item DTOs, including every explicit null and all raw/canonical digests. A legitimately empty class maps to `[]`. Omit classes with null counts or masked authority. |
| `evidence` | Optional array of `{class_id, record_key, status, sha256, size}`. For successful downloads, `sha256` is the exact raw-byte digest (hex or `sha256:` hex), and `size` is the exact byte count. For denied/error downloads, set expected status (e.g. 404); digest and size can be omitted. The class and record key must identify a rendered permitted link. Every listed download must be exercised. |
| `error_code` | For non-200 summaries, the bounded expected error envelope code. |
| `timeout_ms` | Optional 1,000–180,000 milliseconds; default 30,000. |

`ui/tests/preservation-fixtures.mjs` and the synthetic browser test demonstrate complete DTOs, nullable/masked classes and generated expected rows. Their synthetic clocks and numbers are test inputs, not policy.

The helper enters through Integrations → Data preservation, selects the exact tuple, refreshes and compares both summary responses to expectations. It asserts rendered report identity/check time, all class counts/states, audit-copy counts/state, uncovered classes and the elapsed-preservation limitation. It navigates every record page, checking exact complete item content and rendered record keys/states. It opens each rendered Digest provenance disclosure and compares all three exact labels and raw/canonical values, including every null placeholder, against the independent expected inventory; an inaccessible class must have no records expectation. It exercises listed evidence links, verifies successful downloads by hash and length, and deletes the temporary downloads. The UI also binds the download header and body to the selected report item’s admitted raw digest: the expected raw digest takes precedence, with the observed raw digest used when an unexpected member has no expected digest. A canonical record digest is never used for a byte download. Raw evidence is not rendered or copied into the evidence directory.

All context requests are observed from initial navigation through the final screenshot. Any method other than GET/HEAD/OPTIONS fails the journey. This includes unrelated writes, not only preservation routes. Authentication must be established before invocation. The helper also checks keyboard focus, axe WCAG 2/2.1/2.2 AA tags and page overflow at 1440, 390 and 320 pixels. Automated checks do not constitute full accessibility conformance or human visual approval.

Output is `<id>-browser.json` plus viewport screenshots. Failures use bounded diagnostic codes, never assertion dumps of API bodies, cookies or private evidence. Failure screenshots are permitted only because synthetic labels are mandatory. The caller retains the exact executable source/lock/configuration, expectations and process exit, and owns environment cleanup. Browser-generated evidence must remain outside tracked source.

## Local synthetic verification

```sh
npm --prefix ui ci --offline --no-audit --no-fund
npm --prefix ui run build
node ui/tests/preservation-contract.test.mjs
G7_UI_EVIDENCE_DIR=/tmp/volt-g7-ui-preservation-evidence \
  node ui/tests/preservation-browser.test.mjs
```

The synthetic test starts an ephemeral loopback HTTP server, uses Chromium 1234, and closes both in `finally`. It requires local loopback/browser execution authority, but no Docker or external service. It exercises verified, unknown/missing-report, masked, denied, outage, gap, failed, empty, stale, evidence-denied, loading and explicit cursor-reset states. Negative regressions require wrong scope/report/count/state/content expectations and unexpected writes to fail with specific assertion codes; a timeout cannot satisfy them. Additional regressions corrupt rendered expected/observed/canonical digest values and a null placeholder while leaving API responses correct, and require the rendered-digest assertion to fail. A self-consistent wrong download body/header must be blocked against the admitted report digest. These fixtures are UI/contract evidence only; the backend owner must separately invoke the helper against the real disposable installation and independently retained inventories.
