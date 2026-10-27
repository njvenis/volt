# Development runbook

## Prerequisites

- Python 3.13.15 or later and `uv`
- Node.js and npm
- Docker for the optional single-container packaging build
- The pinned DefectDojo CE and Valkey images when building the container

## Install and validate

From the repository root:

```sh
uv sync --locked
npm --prefix ui ci
npm --prefix ui run build
npm --prefix tools/g0_ci/openspec ci
tools/g0_ci/openspec/node_modules/.bin/openspec validate --all --strict
uv run python -m unittest discover -s tests/engine -v
uv run python -m unittest discover -s tests/identity -v
uv run python -m unittest tests.ingestion.test_run -v
```

The tests above use synthetic or in-process fixtures. They do not verify live scanner or external service behaviour.

## Container image

`Dockerfile.g7` describes a development packaging target. Review the image pins in `docker/g7/versions.lock` before building. The image is not a production deployment recipe: storage, ingress, identity, secrets, backups, monitoring and recovery require environment-specific configuration and verification.

Do not use production credentials or data in local runs. Use disposable resources and confirm cleanup before removing them.
