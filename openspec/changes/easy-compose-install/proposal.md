# Easy Compose installation

## Why

RC3 is published at v0.1.0-rc.3 (2026-11-18), but main still describes it as planned. Its 25,273-byte Compose bundle depends on a signed approximately 1.4 GB platform archive for authentication. Installation also needs host Python/OpenSSL/Git, explicit identities, subject linking and a copied browser cookie. The password provider is a synthetic fixture. These are unsuitable defaults for a persistent end-user installation.

## Scope and authority

The user explicitly requested design, implementation, tests and documentation, authorised reasonable design choices, and prohibited merging, publication, historical-asset mutation and external deployment. This change targets the next conventional version, 0.1.0-rc.4, without publishing it. RC1/RC2/RC3 remain immutable.

Affected requirements: CR-01/08/09/10/11, FR-AS-03, FR-OP-01, FR-UI-01/02/03, NFR-01/03/04/05/06. Verified openspec/specs are not populated with proposed behaviour.

## Adopted design decision

The primary adopts dedicated persistent local accounts for new easy installations under the user's delegated choice authority. They reuse the existing supervised image, UVM PostgreSQL, native permissions, audit and recovery boundary. They require maintained password hashing, throttling, session revocation, password change and operator recovery. A bundled IdP would add another identity process, configuration and upgrade/recovery boundary; this scope does not justify that operational cost. This is an architecture judgement, not a measured resource comparison or production qualification.

The synthetic OIDC fixture is not the local-account implementation. Existing demo and external OIDC modes remain explicit and unchanged. No instance changes mode silently, and local mode does not fabricate provider membership or bypass OIDC's current provider/native intersection.

The primary adopts an independently digest-pinned verification image supplied by a trusted project/release page or managed provisioning, containing pinned Cosign and graph/archive checks. The [evidence-backed amendment](bootstrap-amendment.md) replaces the original Cosign-only choice because that image cannot perform the required parsing before candidate-runtime execution. The user has already downloaded and extracted the small package: no extra fetcher, host Git/Python/OpenSSL/Cosign, custom identity framework or Docker socket is needed. Configuration helpers run inside the runtime only after complete admission.

## Boundaries

No public registration, MFA, email recovery, authentication-mode migration, broad adapter redesign, service decomposition or automatic upgrade is included. Inspection disproved the assumption that existing adapters support scanner configuration. Following the user's explicit Qualys choice, the bounded [Qualys amendment](qualys-design.md) adds the first manual VM/VMDR source path and exact configuration/credential/ingestion contract. Actual live scanner/IdP, Docker Desktop/WSL, remote contexts, production and human visual decisions remain separately labelled. A successful packaged fixture proves only its named environment.
