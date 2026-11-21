# Native RC4 candidate execution boundary

The native CI runtime matrix builds on `ubuntu-24.04` and
`ubuntu-24.04-arm`. `native_runtime_probe.py` checks BOTH the host machine and
Docker server architecture before execution. It uses the existing maintained
`protected_launch_component.fd_diagnostic` only: protected root `-I -S` imports,
real UID/GID1800 FD-executed venv, same physical canonical module and required
pidfd syscalls. It does not call that historical component's broker main.
The probe is an unsigned source-build component, not signed LOCAL setup,
readiness, clean stop, backup, restoration or complete ARM qualification.

The container has no network, ports, instance/cache/key/socket mount or added
capability. Its fixed two read-only test-code mounts and bounded tmpfs mask the
unused image volumes. Default capabilities are needed for the existing root to
UID1800 transition; configuration is recorded, not claimed as a measured mask.
Exact registered full-CID/image/recipe checks gate cleanup. Raw result and source
binding are uploaded separately, including on a failed probe.

## Signed native ARM path and missing inputs

`qualify_inventory_cause_fixture` already takes `platform='linux/arm64'`; its
signed public essential path need not be replaced. The existing Portable demo
workflow runs checksum-only demo mode and cannot establish this LOCAL result.

A native ARM fixture verifier must first be built from the SAME selected source
with an independently provisioned public fixture context. The prepared command
is:

```
python3 tools/release/build_native_fixture_verifier.py \
  --platform linux/arm64 --source-commit EXACT_SHA --source-snapshot EXACT_U \
  --public-policy /independent/public-context \
  --expected-policy-sha256 INDEPENDENT_EXPECTED_POLICY_HASH \
  --evidence /private/native-arm-fixture-q
```

This build-only command rejects private material, unknown files, writable or
linked files and a changed expected hash. Its exact three-file context contains
only `fixture-trust.json`, `fixture.pub` and `trusted-root.json`, including the
fixed original loopback fixture log URL. It generates no signer or new root and
publishes nothing. No local trust material is committed here. Hosted provisioning
of that external context and expected hash is still a dependency; this command
is not silently enabled with a repository-provided or caller-selected root.

The ARM image, exact build/provenance inputs and its digest must return to the
existing independently controlled fixture signer. That signer must authenticate
ARM Q, runtime index and BOTH native subjects, runtime provenance and exact
bundle/launcher before a new signed native ARM essential run. Signing keys must
never be copied into a hosted artifact.

## Full graph transfer facts

The existing 48-file verification closure is intentionally metadata-only:
`offline_export.MetadataLayout.document` omits supported executable filesystem
edges. It cannot recreate a pullable full runtime registry. Docker save/load and
push is also not evidence of byte-identical compressed blobs or manifest IDs.

A portable replay requires a separately authenticated inventory of the exact
full OCI graph: runtime index, both subject manifests/configs/compressed layers,
ARM Q graph, every signature/provenance referrer index/manifest/proof layer and
original bundle/launcher bundles. A rehost must PUT exact blobs and manifests
and verify original SHA-256, sizes, media types and reference mapping on the
same loopback coordinates before executing Q. No recompression, resynthesis,
re-signing, missing attachment or learned trust is permitted. No such full graph
export/rehost controller is implemented by this change.

The offline adapter runs Cosign `verify-attestation --local-image` with the baked
public key/root and no Rekor URL or network. Existing offline proof acceptance
therefore does not need a live log. The ONLINE fixture adapter explicitly sets
`REKOR_SERVER=http://127.0.0.1:47280` and runs ordinary OCI verification. Static
inspection alone cannot prove that bootstrap makes no live Rekor request. The
initial launcher disallows creating a new installation from verification cache,
so an offline-new-install bypass is not an alternative. A frozen registry replay
must prove bootstrap with original inclusion proofs and absent live Rekor, or
supply the unchanged genuine fixture service; no verification flag is weakened.

## Alternative enrolled native host

A disposable native Linux ARM64 host with a local Unix-socket Docker Engine,
Compose v2, the existing minimal POSIX tools, and required pidfd/execveat/atomic
rename kernel support can execute the maintained controller natively. It must
support the ordinary default-capability UID1800 transition and fixed owned
private mounts, with adequate disk/RAM for the existing full runtime and cold
archives. Controller Python is separate from the minimal product PATH. Local
46150 registry and fixture47280 must be genuinely reachable by host-network
helpers; data ports46180/46181 must be free and owned. No Docker Desktop or
emulation result substitutes for this Linux native evidence.

If independently enrolled secure connectivity permits those exact loopback
fixture endpoints to reach the existing owned signer/registry services, Root can
provision that fixture outside the product without exporting signing secrets.
No tunnel, host enrollment or new endpoint is created by this source change.

## Remaining deadline qualification

The adopted terminal contract retains the original 600-second outer stop limit
and 13-second host observation reserve. Read-only acquisition enforces its
absolute cutoff, but synchronous physical Compose STOP startup remains explicitly
unqualified in the stopped-consumer contract. Native ARM success cannot close
that independent conformance gap. A candidate may retain these scoped development
results; full requirement-conformance/release readiness must not be inferred or
the deadline silently relaxed. No deadline architecture changes occur here.


## Input custody and byte binding

Policy input is opened through a canonical owned0700 directory FD. Directory and
named regular-file identities remain stable before/after bounded nonblocking
no-follow reads; FIFOs and other special files deny without waiting for writers.
Docker never receives that caller directory. The exact validated public bytes
are written/fsynced to a fresh owned private stage and checked before and after
the build. The stage contains only the fixed three public filenames.

Native CI now prepares its actual Docker build context from the clean selected
Git archive, checks its expected U and retains the file inventory. Probe and
fixture-Q scripts, Dockerfile/context bytes and mounted component code are
checked against the same archive before candidate actions. The probe's literal
private driver and component hashes are recorded before container creation and
rechecked after execution. The native build context is checked after build too.
A parent-index identity alone is insufficient: both selected and actual child
witnesses require a valid digest, supported manifest media type, positive exact
integer size and the exact requested native platform, then equality of all four.
No missing or equal-empty witness is accepted.

## Docker CLI portability

Retained b9 hosted AMD64 and ARM64 component records both establish native daemon
platform and then `image inspect --platform` exit125/unknown flag before any
container execution. They do not record a client version. Docker documents this
specific inspection flag as API1.49+: https://docs.docker.com/reference/cli/docker/image/inspect/.
The probe now records actual client/server versions and audits every fixed
Docker CLI command's help before candidate execution. Platform-specific inspect
is chosen only when the flag is advertised and both API versions support it.
This is preselection, never a catch/retry after a failed producer.

Without the flag, ordinary inspection is limited to the just-built single
native tag, one typed image with valid immutable ID, exact native OS/architecture
and source/version labels, and no ambiguous index descriptor. The second engine
inspection must be identical. Container creation still uses that immutable
selected ID and explicit supported native platform. Missing create options deny;
no daemon/default platform, emulation or parent-index-only witness is adopted.
The fixture-Q build uses the same inspected-image compatibility checks with its
existing verifier source/platform labels. Failed b9 artifacts remain unchanged.
