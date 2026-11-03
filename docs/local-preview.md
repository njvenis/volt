# Private G7 local preview

This is a local development image preview using the pinned CE/Valkey dependencies in `Dockerfile.g7`. It is not an Okta, AWS, production, or release-gate result. The identity provider and administrator identity below are explicitly synthetic. The helper publishes UVM and the synthetic OIDC provider on loopback only; recovery control stays private inside the container.

## Requirements

Use Docker with permission to build images and create containers/volumes, OpenSSL, Python 3.13+, Node/npm, and a Chromium installation supported by Playwright. Choose unused API and OIDC ports. Do not put production credentials or data in the preview. Use a committed, clean source revision: the image is tagged `volt:preview-<full-source-SHA>` and carries `org.opencontainers.image.revision` as metadata.

## Start a fresh preview

Run from the repository root:

```sh
python3 tools/g7_local_preview.py init demo --api-port 8180 --oidc-port 8190
python3 tools/g7_local_preview.py start demo
python3 tools/g7_local_preview.py wait demo
python3 tools/g7_local_preview.py status demo
```

`init` writes generated passwords, signing values, OIDC secrets, and locally generated recovery TLS material under `${XDG_STATE_HOME:-~/.local/state}/volt/g7-preview/demo`, with private directory and file modes. The synthetic login is `volt-local-preview-admin-subject`, linked to the local bootstrap principal `volt-local-preview-admin`; it has no identity outside this preview. The first policy and administrator account must still be established through the supported browser/API workflow.

Wait until Docker reports the container healthy, then create the initial subject link through the supported OIDC operator-link API:

```sh
python tools/g7_local_preview.py link-admin demo
```

Run the initial public browser/API journey with Playwright installed under `ui/` and a local Chromium executable:

```sh
python3 tools/g7_local_preview.py link-admin demo
python3 tools/g7_local_preview.py smoke demo --evidence evidence/g7-local-preview/demo
```

This opens the UI, follows **Sign in** through the synthetic provider at `http://127.0.0.1:8190/`, installs the initial assessment policy through `POST /api/v1/assessment/bootstrap-policy`, activates native authority through its audited command, creates a local access group through the public command API, reads it through the public access-groups API, verifies the audit history, and saves browser captures and public readback under the evidence path. The browser/API smoke does not write settled database state. Do not edit product tables directly. The native bootstrap principal is available only for the explicitly named synthetic local preview account and its source scope is local and synthetic.

Capture the exact commands and output, process exit codes, image ID and revision label, non-secret configuration/certificate fingerprints, browser screenshots, created public object and audit readback, and health state in an evidence directory outside the private instance directory. Keep that evidence when destroying the instance. Record that identity, container and data are local synthetic proof.

## Persistence and cleanup

The preview owns exactly three named volumes: PostgreSQL, DefectDojo media, and UVM state. `stop` and `restart` preserve the container and all volumes. After stopping, `start` does not recreate an existing container; use `restart` to resume it. Restart persistence can be checked by reading back the created access group and its audit history after restart.

```sh
python3 tools/g7_local_preview.py stop demo
python3 tools/g7_local_preview.py restart demo
python3 tools/g7_local_preview.py wait demo
python3 tools/g7_local_preview.py smoke demo --readback --evidence evidence/g7-local-preview/demo
python3 tools/g7_local_preview.py destroy demo
```

The `--readback` smoke logs in again in a fresh browser context and verifies that the same public access group and its audit event remain after restart.

`destroy` requires the exact ownership label on the container and each volume, then removes only those named resources and the instance's private configuration/secrets. It never prunes Docker resources. Save evidence before destroying. The image remains locally available and may be removed separately by its exact preview tag if desired.

## Limits

The helper does not use the G7 test clock, fault-injection flags, a production provider, remote registry, external deployment, or a recovery-control port mapping. Loopback publishing limits host exposure but does not make the local preview a production deployment. Starting the preview creates persistent local data until the explicitly scoped `destroy` command is run.
