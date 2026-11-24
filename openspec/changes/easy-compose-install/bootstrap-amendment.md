# Independent verifier amendment, 18 November 2026

## Evidence and decision

Delivery candidate25c3a2f executes its candidate runtime to parse the admission graph. Independent review correctly rejects that ordering. The delivery owner demonstrated that the pinned official Cosign image has neither the shell nor graph/archive parser needed to move those checks there. Candidate839865a retains focused corrections but cannot complete positive admission under the original Cosign-only design.

The primary adopts a **minimal independently trusted verification image**, replacing the Cosign-only bootstrap constraint. This is a focused correction under the user's authority to choose an installation design; the no-host-Python, signature/provenance and pre-execution admission requirements remain unchanged. It is not a service controller, identity service or decomposition of the supervised application. It never receives a Docker socket or controls host resources.

## Bootstrap trust root and responsibilities

The trusted project/release page or managed provisioning supplies the exact verifier OCI index digest, expected release, fixed publisher workflow identity and OIDC issuer. Downloaded installer metadata must not select or override any of them. The authenticated launcher must agree with those externally supplied pins before continuation. The verifier contains the reviewed graph/archive policy, minimal Python parsing code and pinned Cosign binary/trust dependencies. It has its own source/image provenance and publisher-authenticated release output. Its digest is an explicit independently provisioned bootstrap root, not an image chosen by an unverified bundle.

Run it read-only with dropped capabilities, no-new-privileges, non-root ownership, narrowly mounted package inputs and bounded ephemeral cache. Do not mount home, broad host state or Docker socket. The verifier may fetch only the approved release/registry/trust endpoints necessary for verification. User-provided artifact URLs, scripts, certificate identities or trust-policy files are not production configuration. Policy/root refresh must follow the versioned verified-bootstrap release path.

Before host extraction or application-helper execution, authenticate launcher/descriptor/bundle, inspect closed inventory and regular-file metadata, reject links/traversal/duplicates and bound both archive and extracted sizes. Verify expected source/release/contracts, index signature, provenance subject/type/source and complete index-to-platform-child graph. Preserve registry/index/platform/config identities distinctly. Pass verified admission data as data, never generated shell. Only then may the immutable admitted application runtime perform configuration/secret-generation helpers.

Docker/Compose and disclosed ordinary shell utilities remain the host prerequisites. Python/OpenSSL/Cosign run only inside trusted/admitted images. Report the verifier's measured compressed download size separately from the small installer and runtime images. Native amd64/arm64 builds and test evidence are required where infrastructure permits; no emulation is native proof.

## Acyclic artifact construction

The verification image/policy is built independently of the candidate application's artifact hashes. Build runtime/platform images, then their signed provenance. Build the installation data bundle without a rendered launcher self-hash dependency. The signed descriptor binds the bundle and runtime/provenance graph. The authenticated rendered launcher fixes that descriptor and bootstrap policy. Sign it last. A descriptor must not hash a launcher that embeds its descriptor hash; runtime provenance must not require a final launcher hash that already depends on that provenance. Source revision may bind the launcher template normally.

Keep the delivered launcher outside the descriptor-hashed payload bundle when necessary to preserve this dependency direction. Its independent signature and externally expected publisher/release authenticate it. After admission, journal its exact bytes/hash and verification result for safe offline lifecycle validation. Render the complete fixture artifact set before signing, never edit trusted launcher bytes afterwards or ignore its digest mismatch.

## Positive local transparency verification

The owner's pinned Cosign rejected locally signed fixture material without transparency inclusion proof. No TLog-ignore flag, changed production failure policy or public-log upload is authorised as a shortcut.

Authorise a disposable **local Rekor/Trillian and required database/signing fixture**, using reviewed pinned upstream images/code, within the existing delivery-owned development namespace. Expose only the necessary loopback Rekor endpoint (candidate47280 after checking availability); other services remain on an owned private network. No host network, privileged containers, Docker socket, global daemon/trust-root modifications or unrelated resource adoption. Capture exact component/config/root/key/image identities and actual inclusion/verification evidence, with bounded resource use and owned cleanup.

Provision the fixture signer and log trust root independently before generating candidate artifacts. A distinct immutable verifier fixture build bakes that authority; ordinary production setup cannot choose fixture trust or a local log. Exercise real Cosign signature and inclusion verification against the actual launcher/bundle/descriptor/runtime/provenance artifact set. Fixture checks prove the mechanism only, not public OIDC certificate identity, GHCR publication or production Sigstore acceptance. Production keeps its exact workflow identity/issuer and transparency/provenance policy.

## Ownership and acceptance

The existing delivery owner retains verifier image/launcher/release tooling, local log fixture, host lifecycle/qualification and docs. No new implementation owner or framework is needed for these coupled trust checks. Root owns this contract; the same Reviewer reviews the amended design and corrected fixed candidate/executed evidence. Backend and provider ownership are unchanged.

The next decisive independent outcome is a correctly signed fixture admitted outside the checkout with minimal host PATH and no candidate-runtime execution before graph admission. Wrong signer/root/hash/index/source/child, duplicate/oversized archive and mutated launcher fail before candidate effects. Then the complete owned/resumable installer/browser/restore journey executes against repaired backend/provider components. No release, PR merge, tenant contact or external deployment is authorised.
