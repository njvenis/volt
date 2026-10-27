# VOLT

**Vulnerability Ownership & Lifecycle Tracking** (VOLT) is an early-stage application built around [DefectDojo Community Edition (CE)](https://github.com/DefectDojo/django-DefectDojo). It is being developed to connect vulnerability findings with affected assets, accountable owners, assessment decisions and remediation progress.

DefectDojo CE remains the finding engine. VOLT is intended to add lifecycle and ownership workflows around it, using supported APIs and separate VOLT persistence. It does not write directly to DefectDojo's database tables. The name **VOLT** is provisional and subject to trademark clearance.

## Project status

This repository is under active development. It contains Python services, a React/TypeScript UI, database migrations, local fixtures and an evolving container packaging target. Current verification is limited to the commands and environments described below. G7 deployment and operations scenarios are proposed acceptance goals; their presence in OpenSpec does not mean they have been implemented or verified.

The design uses namespaced, source-native vulnerability identifiers as the primary grouping key. A shared CVE alone should not merge separate groups. Synthetic local suites currently exercise distinct source-native groups despite shared CVEs, retained identity and detection history across rebuilds, and ingestion completeness and freshness checks with replay and conflict handling. These suites do not establish live scanner, DefectDojo or deployment integration.

The current checkout does not provide an end-user installer or a documented checkout-to-running-application path. `Dockerfile.g7` is a development packaging target, not a supported deployment recipe. Do not treat DefectDojo's own installation instructions as a VOLT installation method.

## Architecture and dependencies

- **DefectDojo CE** provides the underlying finding engine and is accessed through its supported interfaces. See the [DefectDojo project](https://github.com/DefectDojo/django-DefectDojo) and its [official CE installation guide](https://docs.defectdojo.com/get_started/open_source/installation/) for information about DefectDojo itself.
- **VOLT services** are Python code in `uvm/`, with SQLAlchemy models and Alembic migrations. `uvm` remains the internal Python package name for compatibility.
- **Web UI** is in `ui/` and is built with React, TypeScript and Vite.
- **Development specification** uses OpenSpec changes and scenarios in `openspec/`; requirements and verification boundaries are in [REQUIREMENTS.md](REQUIREMENTS.md), [GATES.md](GATES.md) and [RUNBOOK.md](RUNBOOK.md).

## Development setup

These steps install development dependencies, build the UI and validate local specifications. They do not install or start a complete VOLT and DefectDojo service.

Prerequisites: Python 3.13.15 or later, [`uv`](https://docs.astral.sh/uv/) (CI pins 0.12.18), Node.js 24.21.0 and npm. Run from the repository root:

```sh
uv sync --locked
npm --prefix ui ci
npm --prefix ui run build
npm --prefix tools/g0_ci/openspec ci
tools/g0_ci/openspec/node_modules/.bin/openspec validate --all --strict
```

The local synthetic and in-process test suites are:

```sh
uv run python -m unittest discover -s tests/engine -v
uv run python -m unittest discover -s tests/identity -v
uv run python -m unittest tests.ingestion.test_run -v
```

These checks do not establish compatibility with live scanners, DefectDojo deployments, identity providers, GitHub, Slack, email, SIEM systems or cloud infrastructure. Report the exact commands and environment used; fixture results are not live integration evidence. See [CONTRIBUTING.md](CONTRIBUTING.md) for contribution guidance.

## Container packaging

`Dockerfile.g7` describes an optional development packaging target based on pinned DefectDojo CE and Valkey images. Its entrypoint requires external secret files and configuration, and the runbook treats it as a development target. There is no supported public `docker run` command, default login or complete end-user installation procedure in this repository. The image is not a production deployment recipe. Review [RUNBOOK.md](RUNBOOK.md) and [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md) before working with the packaging target; built-image redistribution notices are not yet complete.

## Data and security

Use synthetic data for local development. Do not commit credentials, raw vulnerability records, private environment identifiers, private reports or production exports. See [SECURITY.md](SECURITY.md) for the current vulnerability reporting status; a private reporting route is not active until the repository owner enables one.

VOLT is not production-ready. Local fixtures, builds and containers establish only the behaviours they actually exercise. Live integrations, operational recovery, security review and any release decision require separate evidence and approval.

## Project documents

- [Requirements](REQUIREMENTS.md)
- [Development and verification gates](GATES.md)
- [Development runbook](RUNBOOK.md)
- [Contributing](CONTRIBUTING.md)
- [Security policy](SECURITY.md)
- [Licence](LICENSE)
- [Third-party notices](THIRD-PARTY-NOTICES.md)
