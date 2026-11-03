<p align="center">
  <img src="docs/assets/volt-wordmark.svg" alt="VOLT — Vulnerability Ownership &amp; Lifecycle Tracking" width="480" />
</p>

# VOLT

**Vulnerability Ownership & Lifecycle Tracking**

**Connect vulnerability findings to accountable owners, governed decisions and measurable remediation.**

VOLT is an open-source vulnerability lifecycle application built around [DefectDojo Community Edition](https://github.com/DefectDojo/django-DefectDojo). It brings vulnerability identity, ownership, assessment and remediation workflows into a shared model for security teams, engineering teams and governance stakeholders.

Its focus is continuity and accountability: understanding which workloads are affected, who owns the outstanding work, which decisions apply and what evidence supports a change in status.

[Getting started](#getting-started) · [Architecture](#architecture) · [Documentation](#documentation) · [Contributing](CONTRIBUTING.md) · [Apache-2.0 licence](LICENSE)

> [!IMPORTANT]
> **Active development — not production-ready.** VOLT has a private local development preview using synthetic data. There is no end-user installer or supported production deployment. Capability descriptions below explain the product's scope; verification remains bounded to the environments recorded in [Development and verification](GATES.md).

## Why VOLT?

Vulnerability management involves more than collecting findings. Workloads are rebuilt, ownership changes, exceptions expire and remediation happens incrementally. Teams need to retain the history behind those changes without losing sight of the remaining exposure.

VOLT is being developed for organisations that need:

- **Security operations:** consistent finding identity and visibility into incomplete or stale source evidence.
- **Engineering teams:** accountable ownership and remediation of explicitly identified affected instances.
- **Governance stakeholders:** traceable assessments, approval boundaries and reporting that distinguishes accepted risk from completed remediation.
- **Platform teams:** a self-hosted application with explicit dependency, persistence and operational boundaries.

DefectDojo CE remains the finding engine. VOLT adds its own lifecycle and ownership model through supported interfaces and separate persistence.

## Core capabilities

The following areas describe the product and its development scope. See the linked contracts for requirements and the [verification status](#verification-and-deployment-status) for what the available evidence establishes.

| Area | Purpose | Further detail |
| --- | --- | --- |
| Vulnerability identity | Group by namespaced source-native identifiers; preserve CVE relationships without merging distinct vulnerabilities solely because they share a CVE. | [Identity requirements](REQUIREMENTS.md#cr-02--native-grouping) |
| Workload continuity | Retain logical workload identity, detection history and decision context across verified rebuilds; make ambiguous matches explicit. | [Continuity requirements](REQUIREMENTS.md#cr-03--rebuild-continuity) |
| Ownership and access | Associate work with people and teams while keeping accountable ownership separate from permission to approve or change a decision. | [Access and ownership contract](docs/g7-native-access-ownership-api-contract.md) |
| Assessment governance | Model severity overrides, time-bounded risk acceptance, approval limits and auditable changes against defined affected membership. | [Assessment requirements](REQUIREMENTS.md#fr-as-01--overrides) |
| Remediation workflows | Track partial remediation and coordinate GitHub issues with ownership and lifecycle state. | [GitHub requirements](REQUIREMENTS.md#fr-gh-01--single-issue) |
| Reporting and SLAs | Distinguish SLA coverage gaps, overdue exposure, accepted risk and remediation, with historical reporting context. | [Reporting requirements](REQUIREMENTS.md#fr-me-01--sla-coverage) |

The design treats **evidence, decisions and remediation as distinct concepts**. Missing or incomplete scanner results must not become evidence of remediation. Risk acceptance and exclusions must not count as patching. Scanner refreshes must preserve human decisions and audit history. These invariants are documented in [GATES.md](GATES.md).

## Getting started

### Evaluate the local preview

Start with the **[local preview guide](docs/local-preview.md)**. It covers prerequisites, initialisation, startup, synthetic sign-in, browser/API smoke checks, persistence and cleanup.

The preview:

- Builds from a committed, clean source revision using pinned dependencies.
- Publishes the application and synthetic OIDC provider on loopback only.
- Generates private local secrets and uses owned persistent volumes.
- Records smoke-test evidence and supports restart/readback checks.

Use synthetic data and disposable resources. Follow the guide's full sequence, including its one-time administrator linking step and cleanup instructions. The preview is a development evaluation environment, not a production installation recipe. Installing DefectDojo separately does not install VOLT.

### Set up for development

Prerequisites: Python 3.13.15 or later, [uv](https://docs.astral.sh/uv/) (CI pins 0.12.18), Node.js 24.21.0 and npm. From the repository root:

```sh
uv sync --locked
npm --prefix ui ci
npm --prefix ui run build
npm --prefix tools/g0_ci/openspec ci
tools/g0_ci/openspec/node_modules/.bin/openspec validate --all --strict
```

These commands install development dependencies, build the UI and validate specifications. They do not start the complete application.

Run the core synthetic and in-process checks:

```sh
uv run python -m unittest discover -s tests/engine -v
uv run python -m unittest discover -s tests/identity -v
uv run python -m unittest tests.ingestion.test_run -v
```

See the [development runbook](RUNBOOK.md) and [contribution guide](CONTRIBUTING.md) for the workflow and change-specific checks.

## Architecture

Logical application boundaries; this diagram does not prescribe separate containers or establish live integration compatibility.

```mermaid
flowchart TD
    UI["React / TypeScript UI"] --> VOLT["VOLT Python services"]
    VOLT --> CE["DefectDojo CE: finding engine"]
    VOLT --> STATE["VOLT persistence: identity, decisions and history"]
    VOLT --> GH["GitHub: remediation coordination"]
    IDP["OIDC identity provider"] --> VOLT
    classDef surface fill:#FFFFFF,stroke:#86818F,color:#252331
    classDef primary fill:#C4B5FD,stroke:#6442B5,color:#252331
    class UI,CE,STATE,GH,IDP surface
    class VOLT primary
```

**DefectDojo boundary.** VOLT uses supported interfaces and does not write directly to DefectDojo database tables. Upstream installation documentation describes DefectDojo itself.

**Application boundary.** Python services live in `uvm/`, with SQLAlchemy models and Alembic migrations. The internal package name remains `uvm` for compatibility. The React, TypeScript and Vite frontend lives in `ui/`.

**Identity and authority.** OIDC establishes identity; VOLT's access model governs application actions and scopes. Ownership-team membership is separate from access-group authority. The [native access contract](docs/g7-native-access-ownership-api-contract.md) details current authority checks, bounded grants and audited administration.

**Packaging.** `Dockerfile.g7` describes a development packaging target using pinned DefectDojo CE and Valkey images. Review the runbook and third-party notices before building or distributing an image.

## Verification and deployment status

| Area | Current position |
| --- | --- |
| Identity and ingestion | Synthetic local suites exercise source-native grouping, rebuild history, completeness, freshness, replay and conflict handling. |
| Local application preview | Documented loopback-only container evaluation with synthetic identity, smoke checks and persistent-state readback. |
| External integrations | Local tests do not establish compatibility with live scanners, enterprise identity providers, GitHub or other external services. |
| Enterprise deployment | No supported production deployment or end-user installer. Security, recovery, operational and integration qualification remain separate requirements. |
| G7 operational scenarios | Acceptance goals in OpenSpec; their presence does not establish implementation or successful execution. |

Evidence should identify the exact revision, commands, environment and result. A fixture result is **synthetic/local**; **integration verified** requires the named real service and version. **Production readiness** is a separate release decision. See [GATES.md](GATES.md) for these definitions and [REQUIREMENTS.md](REQUIREMENTS.md) for the target baseline.

## Documentation

| I want to… | Start here |
| --- | --- |
| Try the application locally | [Local preview](docs/local-preview.md) |
| Understand product scope and invariants | [Requirements](REQUIREMENTS.md) |
| Assess verification and maturity | [Development and verification](GATES.md) |
| Build and validate the project | [Development runbook](RUNBOOK.md) |
| Review permissions and ownership | [Native access and ownership contract](docs/g7-native-access-ownership-api-contract.md) |
| Contribute a change | [Contributing](CONTRIBUTING.md) |
| Report a security concern | [Security policy](SECURITY.md) |
| Review licensing and redistribution | [Licence](LICENSE) · [Third-party notices](THIRD-PARTY-NOTICES.md) |

## Security and responsible evaluation

Use synthetic data for development and evaluation. Keep credentials, raw vulnerability records, private environment identifiers, reports and production exports out of commits, issues and pull requests.

Read [SECURITY.md](SECURITY.md) before reporting a vulnerability. A private reporting route is not active until the repository owner enables it. Until then, arrange a secure route through an already-established private channel; do not disclose sensitive details in public issues. Security reports are handled on a best-effort basis, with no response-time or remediation SLA.

## Contributing

Contributions should be focused, reproducible and supported by evidence. Open an issue or discussion before starting a large change so its scope and interfaces can be reviewed. Include the rationale, relevant documentation changes and exact check results, identifying any services replaced by fixtures.

See [CONTRIBUTING.md](CONTRIBUTING.md) for the full workflow.

## Licence and acknowledgements

VOLT source is licensed under the [Apache License 2.0](LICENSE). DefectDojo CE and Valkey are upstream dependencies with their own licences; see [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md).

**Built-image redistribution notices are not yet complete.** Do not redistribute a built image until the package-level notices have been collected and included as described in that document.

The name **VOLT** is provisional and subject to trademark clearance.
