# API declaration generation

Install locked Python and UI dependencies from the repository root, then generate:

```sh
uv sync --locked
npm --prefix ui ci
npm --prefix ui run generate:api
npm --prefix ui run check:api
npm --prefix ui run build
```

`generate:api` exports `create_app().openapi()` to `ui/openapi.json` using explicit
synthetic configuration and disposable in-memory SQLite. It excludes ambient
`UVM_*` configuration before importing the app factory. It neither starts a server
nor contacts an external API. Only local schema references are accepted.

Declarations are written to `ui/src/generated/api/Paths.ts`, `Webhooks.ts`,
`Components.ts` and a type-only `index.ts`. This directory is generated output;
regeneration replaces its contents. `check:api` regenerates in temporary storage
and fails on changed schema/declaration bytes, missing files or unexpected output.
It does not repair drift. Commit both the schema and generated declarations after
an approved API change.

The generator is `openapi-types-generator` 1.0.0 (MIT). The driver imports its
version-bound internal parsers and directly pins `json-schema-to-typescript`
13.1.2 and `@stoplight/json-ref-resolver` 3.1.6. Separate modules prevent duplicate
shared declarations produced by the stock CLI's concatenated output. Version
checks and synthetic contract tests guard this internal interface. TypeScript
7.0.2 is the only compiler; no legacy compiler is installed for generation.

This is type-only output. It does not generate an SDK, transport or validators,
and does not replace handwritten API wrappers or runtime guards. Undescribed
parts of the server's OpenAPI schema remain unknown; generation does not establish
new API validation or external integration behaviour (CR-10, NFR-06).

For CI, run `check:api` after both dependency installs, then build and install the
matching browser before running all tests:

```sh
npm --prefix ui run check:api
npm --prefix ui run build
(cd ui && npx playwright install --with-deps chromium)
node --test ui/tests/*.test.mjs
```

`api-generator.test.mjs` checks required, optional and nullable properties,
unions, intersections, request and error response contracts with positive and
negative strict TypeScript assertions. It also checks deterministic output,
non-mutating drift detection, synthetic export and external-reference rejection.
All test schema values are synthetic. The existing Portable and pinned OpenSpec
checks remain required.
