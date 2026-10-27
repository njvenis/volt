# VOLT

**Vulnerability Ownership & Lifecycle Tracking** (VOLT) is a DefectDojo Community Edition based application for connecting vulnerability findings to affected assets, accountable owners, assessment decisions and remediation progress.

The VOLT name is provisional and subject to trademark clearance.

VOLT keeps source-native vulnerability identifiers as the primary grouping key. A shared CVE is a relationship and does not merge otherwise distinct findings. Rebuilds, new scans and partial remediation must preserve the history and decisions already recorded for affected assets.

## Current status

This is an early development project. The included local tests use synthetic fixtures. They do not establish compatibility with a live scanner, a production DefectDojo deployment, an identity provider, GitHub, Slack, a SIEM, or cloud infrastructure. No production readiness or deployment claim is made.

DefectDojo CE is a runtime dependency. VOLT integrates with it through supported APIs and keeps its own persistence separate; it does not write directly to DefectDojo's database tables.

## Development

Requirements: Python 3.13.15 or later, `uv`, Node.js and npm. For the pinned OpenSpec validator, use the package and lockfile under `tools/g0_ci/openspec`.

```sh
uv sync --locked
npm --prefix ui ci
npm --prefix ui run build
npm --prefix tools/g0_ci/openspec ci
tools/g0_ci/openspec/node_modules/.bin/openspec validate --all --strict
```

Run the self-contained synthetic test suites with:

```sh
uv run python -m unittest discover -s tests/engine -v
uv run python -m unittest discover -s tests/identity -v
uv run python -m unittest tests.ingestion.test_run -v
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for the development workflow and [SECURITY.md](SECURITY.md) for private vulnerability reporting.
