# G4 synthetic command-preview fixtures

These are **synthetic contract inputs**, not live execution evidence or approval.
They preserve the public DTO shape and partial-remediation state for local
consumer checks. Original execution evidence remains outside this release.
`provenance.json` records source and fixture hashes and exact extraction rules.

- `partial-group-dto.json`: the disposable POC GroupView. Its latest-receipt
  identifiers are replaced consistently with deterministic synthetic UUIDs;
  membership, revisions, states, ownership and coverage remain unchanged.
  External GitHub identities and issue links use the synthetic policy below. This does not retain or claim an actual command receipt.
- `g4-live-journey.json`: despite its compatibility filename, this is only a
  `partial_command.preview` template, not a journey log. All request-overwritten
  fields are omitted. Its signature is 64 zeroes, a shape-only contract value
  without signing authority. Actor/session fixtures, real signatures, commands,
  posted comments, acknowledgements, receipts and the rest of the trace are absent.

## Local verification

From the repository root, install the locked UI dependencies, build the UI and
run the exported fixture check:

```sh
npm --prefix ui ci
npm --prefix ui run build
npm --prefix ui test
```

The test runner is `ui/tests/public-g4-fixtures.test.mjs`. It supplies a synthetic
preview UUID, exact command, expected revisions/exposures, digest and expiry,
then exercises the production DTO and preview consumers with intercepted fetch
responses. It renders the GitHub context to static markup and checks its links.
It opens no browser, starts no server and contacts no provider or backend.

The public export does not include historical browser/integration journeys,
private runtime fixtures or execution evidence. This local fixture check proves
only consumer validation, rendering and rejected identity mismatches; it does not
establish live integration, actual signing authority or gate acceptance.

## Public fixture identity policy

All six G4 fixtures listed in `provenance.json` use the synthetic account
`900000001`, repository `900000002` and issue numbers 101–104. The preview uses
`I_SYNTHETIC_VOLT_G4_101` and account-link UUID
`40000000-0000-4000-8000-000000000101`. Issue links use the reserved
`https://github.example.invalid/volt-fixture/repository/issues/` origin/path,
so they cannot point to a real repository. These are shape-valid fixture
identifiers, with no provider authority or real credential.

Partial-remediation and all A/B successor stages share issue 101. Scrollable
scope, coverage reasons and language scenarios use issues 102, 103 and 104.
The versioned `/uvm v1` command syntax and confirmation/recurrence semantics
remain unchanged. Original `source_sha256` values identify historical source
inputs; current `fixture_sha256` values bind the sanitised bytes.

Run `npm --prefix ui test` for current fixture
digests, synthetic identity closure, production DTO/preview validation,
rendered links and wrong-account/repository rejection. These focused contract
checks are local fixture verification only; no browser journey is advertised.
