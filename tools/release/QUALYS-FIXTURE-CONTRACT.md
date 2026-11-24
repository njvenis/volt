# Qualys qualification artifact contract, version 1

This pins field spellings for the root-adopted
`openspec/changes/easy-compose-install/qualys-fixture-artifact-contract.md`.
It does not qualify a build or permit production fixture selection.

## Signed inventory F

F is UTF-8 JSON with sorted keys, compact separators and one trailing newline.
Duplicate or unknown members, noninteger schema versions, JSON floats and
noncanonical UUID/digest/reference spellings are rejected. No field contains a
private key, credential, cookie, authority proof or signing seed.

The exact top-level members are:

| Member | Exact type and meaning |
| --- | --- |
| `schema_version` | Integer `1`, never a boolean. |
| `profile` | String `qualys_vm_protocol_v1`. |
| `source_revision` | The exact 40-character committed code and recipe revision P. |
| `source_snapshot` | `sha256:` plus the 64 lowercase hex digest of complete code archive U. |
| `base_runtime_reference` | Admitted ordinary VOLT image/index reference ending `@sha256:<64 lowercase hex>`, from the fixed official repository or explicitly owned loopback repository. |
| `base_platform_children` | Object with exactly `linux/amd64` and `linux/arm64`; each value is its independently admitted manifest digest. |
| `build_context_sha256` | Digest of complete generated public build context B. |
| `public_ca_sha256` | Digest of the exact public PEM bytes baked into the derived runtime. |
| `recipe_files` | The exact path-to-digest object listed below. |
| `server_source_sha256` | Digest of committed `tests/scanners/packaged_qualys_fixture.py`. |
| `compose_delta` | The exact closed object below. |

`recipe_files` contains exactly these keys, each mapping to a `sha256:` digest:

- Proposed filename: "tools/release/build_qualys_fixture.py"
- Proposed filename: "tools/release/qualys-runtime.Dockerfile"
- Proposed filename: "tools/release/qualys-server.Dockerfile"
- `tools/build_compose_bundle.py`
- Proposed filename: "uvm/installer/qualys_fixture.py"

`compose_delta` contains exactly:

- `path`: string `deploy/compose/compose.yaml`.
- `network`: string `application`.
- `operation`: string `add_internal_true`.
- `source_sha256`: digest of the unchanged maintained Compose file in U.
- `rendered_sha256`: digest after inserting the single line `    internal: true`
  immediately after the application network's `    driver: bridge` line.

Rendering requires that the maintained application network has no `internal`
member and exactly one matching fixed block. All other bytes, files, mounts,
services, ownership labels, network names and settings stay byte-identical.
There is no caller-supplied patch, template, alternate network or source-root
exemption. Verification independently reproduces and compares the rendered
bytes against the maintained source in P/U.

## Acyclic build ordering

1. Commit code and every recipe in P, archive all code as U, and independently
   admit the ordinary base index and both native children.
2. Construct and archive B from U's exact code plus generated public CA and
   public base-image build inputs. B excludes F, signatures and private files.
3. Construct F from the identities above and sign its exact bytes with the
   independently pinned fixture key and mandatory transparency inclusion.
4. Build the real native derived children from the admitted base and B. Record
   F's digest in `org.volt.qualification.inventory-sha256`, B's digest in
   `org.volt.qualification.build-context-sha256`, and profile in
   `org.volt.qualification.profile`. Preserve P/U as code identities; derived
   digests are distinct from ordinary product digests.
5. Authenticate both derived manifests/configs, sign derived index J and its
   truthful provenance, then build/sign the bundle and exact launcher.

F contains no derived runtime, verifier, bundle, descriptor or launcher digest,
and neither B nor F includes its own identity. The existing closed runtime
provenance still binds J, P/U, both executable children and the exact bundle.
An additional authenticated F binds the build materials; ordinary product
signatures are never reused for derived images.

## Policy and bundle boundary

Only an independently selected fixture verifier whose baked policy explicitly
pins this profile, P/U and F may admit the fixture. The policy and pinned key
are provisioned outside the candidate. F and its signature remain separate
build-material artifacts, outside the closed host trust-root inventory.
A manifest cannot activate this policy or select another key/verifier.

The bundle keeps its existing closed path inventory and adds only the manifest
member `qualification_fixture`, an object with exactly `profile` and
`inventory_sha256`. The values must equal the independently pinned profile/F.
The ordinary builder and verifier reject that member and any derived fixture
image label. Existing local-admission-fixture mode alone does not authorize a
Qualys fixture profile. All source, config/selected-child identity, platform,
size, traversal, file inventory, signature and inclusion checks remain required
before any candidate execution.

The independent fixture verifier must have the exact maintained Compose source
from P/U and verify F's separately signed bytes. Delivery will pin its concrete
build-material input mechanism before executing this profile; no path is
silently added to the existing closed trust-root directory.

## Execution evidence

Use the unchanged Qualys hostname and production TLS transport with the public
CA baked into the distinct fixture image. Before transmitting synthetic
credentials, prove the API/server have exactly the declared isolated internal
network, the fixed alias resolves exclusively to the owned server, and external
egress is denied using owned negative peers. Never probe public Qualys.
Record zero provider requests for registration/save/upload, one for explicit
probe, still one after activation, and three after the two-page collection.
The positive data assertion is three observations, one native QID group, and
zero fabricated engineering occurrences. Parsed-request events are not proof
of completed body delivery. Full cold restore and host Ed25519 approval/public
apply/test/activate must use the maintained runner and accepted companions.
