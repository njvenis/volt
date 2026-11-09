## ADDED Requirements

### Requirement: Retained single-image release candidate
VOLT release preparation SHALL build one image from an exact clean main source revision and bind its immutable image ID, source archive digest, source revision, release version, platform, and Compose installation capability labels. Qualification, notices, SBOMs, full vulnerability scan, publication, signatures, provenance, and offline image archive SHALL refer to that same built image. Candidate preparation SHALL have no registry-write or OIDC permissions.

#### Scenario: Candidate preparation
- **WHEN** maintainers dispatch candidate preparation from main
- **THEN** the workflow builds one image, validates its labels against the exact source archive and commit, runs all required gates, and retains an immutable candidate artifact without publishing it

#### Scenario: Publication consumes retained candidate
- **WHEN** an explicitly approved publish dispatch names a candidate run
- **THEN** the workflow verifies that run is successful and belongs to this repository, workflow, main branch, and exact source SHA before downloading its candidate artifact
- **AND** publication does not rebuild the image and retains the required human reviewer environment guard

### Requirement: Digest-bound source-free Compose release bundle
The VOLT RC2 offline release SHALL include a verified, checksummed source-free Compose bundle whose version matches the release and whose consumer instructions bind the exact published registry digest. The signed manifest SHALL bind the bundle and source archive to the same release image and source snapshot.

#### Scenario: Offline bundle identity
- **WHEN** a consumer verifies the RC2 offline archive
- **THEN** the included Compose bundle checksum and file manifest validate, the bundle version matches the signed release, and its image reference equals the signed registry digest

### Requirement: Compose image qualification
The RC2 candidate SHALL be qualified through the source-free Compose installer using the exact release image ID and bundle. The journey SHALL capture synthetic demo identity, scoped audited operation and restart readback, cold store inventory, negative image-binding and corrupt-inventory checks, and restore admission/readback before application writers start.

#### Scenario: Synthetic cold restore
- **WHEN** the candidate is exercised in the loopback demo fixture
- **THEN** evidence binds the image, source snapshot and bundle, and records the operation receipt, restart persistence, restore rejection cases, successful same-image restore, and exact owned-resource cleanup
- **AND** the evidence SHALL NOT claim named-provider or production recovery verification
