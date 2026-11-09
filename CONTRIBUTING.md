# Contributing

Thanks for considering a contribution. VOLT is under active development; please open an issue before starting a large change so its scope and interface can be reviewed.

## Local checks

Use the pinned project dependencies and synthetic data only. The core local checks are:

```sh
uv sync --locked --python 3.13.15
uv run python -m unittest discover -s tests/engine -v
uv run python -m unittest discover -s tests/identity -v
uv run python -m unittest tests.ingestion.test_run -v
npm --prefix ui ci
npm --prefix ui run build
npm --prefix tools/g0_ci/openspec ci
tools/g0_ci/openspec/node_modules/.bin/openspec validate --all --strict
```

Changes to database models or migrations should include a focused migration check. Changes to the interface should include a UI build and relevant browser coverage. State clearly which checks ran and which external services were replaced by fixtures.

## Data and reports

Do not add credentials, raw vulnerability records, private environment identifiers, production exports, or private screenshots to issues or pull requests. Use synthetic fixtures and redact logs before sharing them. Do not describe fixture results as live service integration evidence.

## Pull requests

Keep changes focused, include a concise rationale, update relevant documentation, and report exact commands and results. Preserve the supported API boundary with DefectDojo CE; VOLT must not write directly to its database tables.

## Security

RC1 is an evaluation release. Do not report sensitive findings in public issues or pull requests. Use [GitHub private vulnerability reporting](https://github.com/njvenis/volt/security/advisories/new), which is enabled, and follow [SECURITY.md](SECURITY.md). Reporting is best effort with no response-time or remediation SLA.
