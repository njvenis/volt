# Changelog

## 0.1.0-rc.1 — 2026-11-04

[First public release candidate](https://github.com/njvenis/volt/releases/tag/v0.1.0-rc.1) of VOLT, for fresh Linux/amd64 evaluation installations with synthetic identity. Historical development volumes are not supported upgrade inputs; this is not a production-readiness claim.

- Published the versioned GHCR image and signed offline bundle; no `latest` tag.
- Included image-specific notices and source evidence, SBOMs, provenance, checksums and the complete vulnerability report.
- Passed the [release workflow](https://github.com/njvenis/volt/actions/runs/41804175229), including fresh startup, synthetic sign-in, an audited operation, ingress denial and restart persistence.
- Release notes record successful anonymous pull and exact-workflow signature verification. The scan retained 885 findings, including unfixed findings; the policy gate found zero fixable High/Critical findings and used no exceptions. This is not a vulnerability-free claim.

See [installation](docs/installation.md) for the published image and [release evidence](docs/releasing.md) for the exact source, artifact and verification boundaries.
