# Ordinary signed LOCAL qualification on hosted native ARM

Prepared from approved draft37ac9fc66bc2b804689baa2dfc9f6f7adf1520d9, separate from
held Qualys/abb. No local ARM, service, key-generation, signing, deployment,
workflow dispatch, artifact upload or push has occurred. This is executable
preparation and public metadata compatibility evidence, not ARM lifecycle GO.

## Reproducible pieces

`hosted_arm_essential.py` provides three fixed stages, with no generic command or
signing/trust bypass. Each takes `--request OWNED_JSON` and an independently
provided `--expected-request-sha256 sha256:...`. `--plan-only` checks the closed
request and exact clean source checkout/U and emits a plan without Docker.
The selected source checkout may be the baseline37 checkout while this adapter
R is retained separately; its SHA is recorded separately from runtime P/U.
All source paths/commit/U must match, no installer overlay or image relabel.

`prepare-db-context` checks and copies ONLY the exact three canonical Trillian
v1.8.0 files, using pinned SHA256; it does not build. `build-q` first requires
actual uname aarch64 and Docker linux/arm64, then invokes the existing
`build_native_fixture_verifier.py --platform linux/arm64` with independently
provisioned PUBLIC three-file policy and expected inventory hash. All existing
stable FD/public-policy restage/source archive/CLI/witness rules remain intact.

`essential` requires the same native host+daemon and invokes maintained
`qualify_inventory_cause_fixture(platform='linux/arm64')`, then the original
externally authenticated public restored start, health and final stop. This
covers install/stop/cold backup/external verify-cache BEFORE extraction/import/
empty+corrupt inventory denials/valid restore-admit/start/health/stop, with no new
account/browser/scanner/SQL operations. The existing strict external admission
validator still authenticates Q and original launcher, runtime index, BOTH actual
children/configs, provenance, source and inclusion. No observation is a trust root.
This adapter retains uncertainty/private state; it does not auto-delete resources.

Example future invocations (NOT executed):

    PYTHONPATH=ADAPTER_CHECKOUT python3 ADAPTER_CHECKOUT/tools/release/hosted_arm_essential.py \
      prepare-db-context --request PRIVATE_DB_REQUEST --expected-request-sha256 EXPECTED_HASH
    PYTHONPATH=ADAPTER_CHECKOUT python3 ADAPTER_CHECKOUT/tools/release/hosted_arm_essential.py \
      build-q --request PRIVATE_Q_REQUEST --expected-request-sha256 EXPECTED_HASH
    PYTHONPATH=ADAPTER_CHECKOUT python3 ADAPTER_CHECKOUT/tools/release/hosted_arm_essential.py \
      essential --request PRIVATE_JOURNEY_REQUEST --expected-request-sha256 EXPECTED_HASH

All requests have exactly schema_version integer1, profile
hosted_native_arm_essential_v1, source_revision, source_snapshot,
source_checkout (exact clean checkout), evidence (new absolute directory).
DB preparation additionally has db_source_directory (canonical upstream source).
Q additionally has public_policy and public_policy_sha256. Essential additionally
has bundle, fixture, image_id and private (new owned directory). No platform
selector exists: ARM is fixed. An independently provisioned request hash is
required; not learned from untrusted artifact bytes. No inputs are provided yet.

## Exact native fixture stack path

The closed public component lock is `hosted-arm-fixture-components.json`.
All index/child/config bytes were fetched read-only from official registries and
hashed; retained response hashes identify evidence outside this source tree.
The existing three Sigstore parent pins already include ARM64/v8 children:
Rekor1662dc..., Trillian signerf86711..., Trillian servera23153.... They can use the
same immutable parent pins plus explicit --platform linux/arm64. No replacement
Rekor protocol or synthesized inclusion proof is introduced.

The existing db_server0bfefa... is an AMD64-only manifest. The canonical exact
v1.8.0 source commit0362d55869965067c9ffa276a78d18e95a596ca3 copies mysql.cnf and
storage.sql onto pinned mysql8.4 indexb3b90a... and adjusts file permissions. That
base already includes ARM childc9be23...; its MYSQL_VERSION8.4.11-1.el9 and
MYSQL_SHELL_VERSION8.4.10-1.el9 equal the existing AMD64 DB config versions.
Thus a truthful native ARM DB build can use this unchanged canonical recipe and
exact base index/schema/config. Its NEW built digest must be recorded and native
execution actually checked. Compatibility metadata is not a reproducible image
or runtime claim. Do not emulation-run the old AMD64 DB or switch DB versions.

After preparing canonical context, the future build is:

    docker build --platform linux/arm64 --pull=false --network=none \
      --file DB_CONTEXT/examples/deployment/docker/db_server/Dockerfile \
      --tag UNIQUE_EPHEMERAL_DB_TAG DB_CONTEXT

This command is not authorised/executed by the current preparation packet.
Public source references:
https://github.com/google/trillian/tree/0362d55869965067c9ffa276a78d18e95a596ca3/examples/deployment/docker/db_server
https://docs.sigstore.dev/logging/installation/
https://github.com/sigstore/rekor/blob/main/docker-compose.yml
The upstream compose's forced AMD64 DB is a recipe limitation, not a claim that
all official DB images lack ARM.

## Exact remaining hosted provisioning/job work

No complete hosted job exists yet. It must run on ubuntu-24.04-arm and consume
BOTH source-bound runtime children from the existing native matrix, verifying
ZIP/tar hashes and selected/checkedout P/U before any load. Native verifier/Q,
Cosign and registry must also resolve to actual ARM configs. No binfmt/QEMU.
A new owned loopback registry46150 can assemble the exact TWO-child ordinary
graph locally from those same-run archives. This avoids transporting already
signed/recompressed graph blobs between hosts. Fixed repos volt and
volt-installer-verifier are unchanged, with unique new subjects.

A genuine ephemeral Rekor+Trillian+DB stack must then be provisioned inside the
job, with the pinned ARM components above, exact owned containers/network/data
and cleanup guards, no external production endpoints. Generate a fresh signer
only in RUNNER_TEMP private custody and retain the genuine new log's public key /
ID in the existing closed trusted-root schema. Build native Q with that immutable
PUBLIC policy, then use the existing digest-pinned Cosign with the real signing
config and mandatory transparency to sign Q+SLSA, runtime index+BOTH children,
runtime provenance and original bundle/launcher. No private key in any artifact,
no tlog-upload=false, insecure-ignore flags, mocked log or proof synthesis.
The job coordinator, not a candidate manifest, provisions this fixture authority.

The missing implementation/approval point is that hosted ephemeral provisioning
and exact signing/job wiring. This preparation does not call an existing private
signer/log, upload keys, start services, generate roots or claim that gate met.
No new hosted production secrets are needed: all authority is disposable job-local,
provided its generation/provisioning is explicitly approved and reviewed.
Before external execution the exact job/controller must bind P/R/U, component
parents/children, public log/root identity and ownership. Online bootstrap can use
the genuine local log while signing/verification runs; offline outage verification
must still use original inclusion bundles, with no relaxed adapter.

Only `public-summary.json` (typed final outcome/P/U/platform) is an intended public
CI result from the adapter. Do NOT upload the raw evidence/private directories:
installer stdout, operation logs, host owner state, capability files and ephemeral
keys can be private. A reviewed explicit allowlist must select any additional
public proofs and scans; never upload RUNNER_TEMP recursively. Job-owned VM
teardown is not proof of exact cleanup; capture resource reconciliation separately.

600 seconds remains the approved clean-stop ACCEPTANCE cap and13-second reserve;
stock Docker may return later. Late result gives no clean proof/authority and
retains private evidence. This candidate does not add a hard host-return claim,
new timeout dependency, TLS/Qualys mode, production keyless acceptance or general
hardware claim. No native runtime evidence exists until the hosted signed journey
actually completes on those exact immutable bytes.
