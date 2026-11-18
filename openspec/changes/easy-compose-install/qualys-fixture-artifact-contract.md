# Qualification-only Qualys artifact binding

Root adopts this bounded extension to the already approved packaged fixture composition. It is not an unsigned Compose overlay or a production fixture mode. Ordinary bundle generation and verification remain unchanged and reject fixture metadata by default.

The fixture builder may deterministically render only the application network's `internal: true` delta from the maintained Compose source. Every other maintained file remains byte-identical, with the same closed path inventory, traversal/link/size protections, image/platform/source checks and private mounts. The fixture verifier independently reproduces that deterministic delta from the exact maintained source and compares bytes. There is no general source-root exemption or candidate-selected transform.

The fixture path requires the existing explicitly separate local-admission-fixture qualification invocation, an independently pinned fixture verifier and its fixed fixture signing authority. A candidate manifest cannot select this policy, another key, a relaxed verifier or a fixture profile for a production invocation. The production verifier/release path must reject these fixture bundles and images. All fixture graph artifacts and their inclusion proofs remain authenticated before candidate execution.

## Distinct source and build-material identities

Keep the ordinary `source_revision` as the exact committed application AND tracked fixture-builder recipe revision P, and `source_snapshot` as its complete code archive digest U. Do not overwrite U with a generated fixture build context or represent the derived image as the unmodified product. If the builder recipe is not committed in P, commit it before claiming that source identity.

The separate fixture build context B contains the exact code inputs and generated public CA/build inputs and is archived completely. Its digest is a separate build-material identity. The public CA, fixture Dockerfile/recipe, external server source and deterministic network delta have their own hashes. Private CA seeds, server keys, host keys and synthetic credentials are never part of B or the runtime image.

A closed signed qualification inventory F binds profile `qualys_vm_protocol_v1`, code P/U, base product image/index identity, B, public CA hash, builder/recipe hash, server source hash and the exact network delta. It is retained as a separately authenticated fixture artifact/build material, not smuggled into the closed trust-root directory. Its exact field spellings must be pinned by delivery before implementation/execution; no unknown fields or arbitrary transforms.

Avoid digest cycles: hash/archive B before constructing F; B excludes F and its signatures. F excludes derived runtime, bundle, descriptor and launcher digests. Build the real derived platform images from the admitted base and B with F's identity recorded as a build argument/label. Independently authenticate BOTH actual platform children/configs and sign derived index J and truthful provenance, whose materials bind P/U, base image, B, CA and F. Then construct the signed fixture bundle/descriptor/launcher through the existing acyclic artifact ordering. Neither F nor the runtime graph contains its own hash.

All expected source/platform/subject checks continue to apply to actual executable bytes. The fixture image may keep code P/U labels only because they identify unchanged code plus its tracked recipe; its distinct derived digest, fixture label/inventory and extra public-CA build material must be explicit. Do not reuse native product signatures or labels as evidence that the derived image is unmodified. The actual Docker selected-manifest/config identity rules remain strict and typed.

## Execution boundaries

Before sending synthetic credentials, prove actual network attachment exclusivity, fixture-only DNS resolution and denied external egress on the owned engine. Use owned negative peers, not public Qualys probing. Keep the unchanged allowlisted hostname and verified TLS with the baked public CA; no arbitrary provider URL, injected authority, disabled verification or production fixture switch. Server private keys stay outside API mounts, and logs remain redacted.

Delivery owns builder/verifier fixture deltas, artifact signing, network composition and maintained runner execution. The external test server and browser companions retain their existing owners. Three retained observations and one native QID group, with zero fabricated engineering occurrences, are the positive data assertion. This contract does not claim any build, signature, network or packaged journey has run.

## Adopted verifier material provisioning

Following the scoped design review of a31c86e and delivery b7484b0, root adopts the concrete provisioning mechanism: an independently admitted fixture-verifier image contains the exact signed F and its Sigstore inclusion bundle under `/usr/local/share/volt-fixture-materials`, separate from the unchanged closed host trust-root inventory. Its immutable baked policy pins the profile, P/U, F digest and fixture verification key. Authenticate that verifier image and its provenance before execution; it then verifies F's exact pinned digest, signature and transparency inclusion before candidate graph admission. There is no caller-selected material path, key or profile. Sign F before constructing the verifier image and derived graph; F excludes the verifier digest. The exact closed inventory schema and canonical encoding are pinned in `tools/release/QUALYS-FIXTURE-CONTRACT.md` at b7484b0. This is design acceptance, not execution evidence.

## Actual topology admission

The launcher creates the application network before Compose, so the signed Compose delta alone is insufficient. Root adopts the reviewed host-tool correction: the closed independently verified admission receipt contains `application_network_internal` exactly once as a strict boolean, bound to the verified bundle digest and fixed F policy. Ordinary bundles require false; only the separately admitted fixed fixture delta requires true. Cross-check that value against the exact bundled Compose derivation and journal `network_internal`. No environment input or observed network may select or repair the declared value.

Before workers or ingress release, actual Docker `Internal` must be a boolean equal to the journal. Include it in the resource projection/hash, resume validation, restore provisioning and restore admission; reject contradictory existing networks. Preserve ownership, subnet, exact attachments and crash-recovery checks. Pin the receipt and journal encoding in the helper contract before execution. This introduces no provider change or new trust root and does not replace actual DNS exclusivity and denied external-egress proof before synthetic credentials.
