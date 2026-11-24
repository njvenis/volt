## ADDED Requirements

### Requirement: Persistent local authentication
New easy installations SHALL offer supported persistent local accounts without an external IdP, independently of the synthetic demo provider. Existing instance modes SHALL remain unchanged.

#### Scenario: Durable credential and session lifecycle
- **WHEN** a local user signs in, restarts, changes a password, recovers access or is disabled
- **THEN** accounts and current authority survive restart
- **AND** credentials are securely hashed, attempts are throttled persistently and affected sessions are revoked on credential change, recovery or disable

#### Scenario: Purpose-bound enrolment and recovery
- **WHEN** a host-created pending account completes enrolment or an established account uses recovery
- **THEN** the capability is bound to its purpose, installation, account and generation and is consumed atomically with credential/audit changes
- **AND** cross-purpose or replayed tokens fail without assigning membership or bootstrap authority
- **AND** restore and credential changes revoke outstanding account capabilities

#### Scenario: Compatible identity modes
- **WHEN** an established external OIDC or demo instance starts
- **THEN** its existing documented authentication and authority rules remain active
- **AND** contradictory mode or incompatible state fails closed without conversion

### Requirement: Protected browser administrator setup
First-admin setup SHALL consume an expiring host-delivered capability once in the same transaction as identity, native authority, session, audit, receipt and intent.

#### Scenario: Concurrent claims and atomic failure
- **WHEN** real PostgreSQL transactions compete to claim an installation
- **THEN** exactly one administrator commits and replay is denied
- **AND** expired or rotated tokens fail
- **AND** audit, receipt or intent failure rolls back all account, authority, session and consumption changes

#### Scenario: Account details reach the dashboard
- **WHEN** a valid user submits the setup capability and human account details
- **THEN** the browser reaches a usable deployment dashboard without subject linking, internal identity IDs, manual authority commands or copied cookies
- **AND** an authenticated session alone never grants bootstrap powers

### Requirement: Supported scanner onboarding
A genuine protected administrator SHALL register supported scanner bindings through an audited browser workflow, receiving only explicit exact-source native grants.

#### Scenario: Register then configure
- **WHEN** the protected administrator registers a supported scanner using current revisions
- **THEN** stable IDs, disabled binding, exact envelope and explicit grants commit with audit and receipt
- **AND** normal configuration, credentials, validation and activation remain distinct permission-checked steps
- **AND** no assessment-write, approval or remediation power is granted implicitly

#### Scenario: Exact grantability before findings exist
- **WHEN** local setup or scanner registration creates administrative or connector permissions before findings exist
- **THEN** local-v2 typed deployment, connector and read-only source targets carry explicit exact ceilings
- **AND** grantability is distinct from effective grants with complete limits and separation-of-duties defaults
- **AND** no dummy finding/service IDs or wildcard source authority is introduced

#### Scenario: Denied or stale registration
- **WHEN** a non-bootstrap actor, stale command or actor with removed grants attempts registration or configuration
- **THEN** the server rejects the operation without partial authority or secret changes

#### Scenario: Resolve an uncertain registration
- **WHEN** an administrator explicitly requests disposition of an unchanged retained command
- **THEN** the service returns its actor and digest-bound committed receipt or atomically audits and permanently fences non-commit under the same command serialisation
- **AND** only definitive terminal non-commit permits a separately reviewed replacement with a new ID and current revisions
- **AND** network failure, absence and generic conflicts do not establish non-commit

### Requirement: Bounded Qualys VM source
The first supported scanner path SHALL provide permission-checked Qualys VM/VMDR configuration, encrypted credentials, explicit connection testing, activation and manual collection into retained source observations.

#### Scenario: Configure without internal identifiers or implicit contact
- **WHEN** an authorised administrator registers and saves a Qualys source and its credentials
- **THEN** stable account, scope and resource identifiers are generated automatically
- **AND** only reviewed regional platform origins and account-visible scope are accepted
- **AND** registration, save, secret submission and activation perform no external requests

#### Scenario: Trusted fixed rule and readable allocated slot
- **WHEN** the local installer prepares scanner services and the browser reads a newly allocated credential slot
- **THEN** a validated host maintenance operation initializes only the pinned source-only rule through the existing authorised repository
- **AND** identical initialization is repeat-safe while conflicting rules fail without overwrite or arbitrary authorizers
- **AND** metadata exposes the actual allocated secret revision so first submission requires no guessed fence or internal identifier

#### Scenario: Explicit bounded collection
- **WHEN** the user tests and activates an exact configuration and credential snapshot then requests collection
- **THEN** authenticated requests follow fixed-origin safe pagination with bounded time, bytes, pages and rows
- **AND** current exact-source authority, credential and restore fences are checked before each outbound attempt and final publication
- **AND** replay or restart does not silently duplicate external calls

#### Scenario: Honest persisted source results
- **WHEN** Qualys pages are retained and published
- **THEN** exact private page bytes, provenance, QID grouping and host-port-protocol distinctions survive durable readback
- **AND** a partial, failed or interrupted run remains visible without claiming complete retrieval
- **AND** unknown coverage or source freshness remains unknown, collection recency is separate, and unresolved workload identity remains explicit
- **AND** source Fixed, missing data and ignored results do not create assessment writes or engineering remediation confirmation

#### Scenario: Packaged source onboarding
- **WHEN** the actual packaged browser journey uses an isolated Qualys protocol fixture and PostgreSQL
- **THEN** registration, credentials, explicit test, activation, collection and populated source readback execute through public APIs
- **AND** the evidence identifies local protocol qualification separately from live Qualys validation

### Requirement: Supported local restore clearance
Local Qualys recovery SHALL preserve quarantine until a fresh encrypted credential, separately signed host approval and currently authorised browser application permit explicit test and activation.

#### Scenario: Separate local authorities
- **WHEN** a new local installation prepares recovery material
- **THEN** issuer and operator signing keys are distinct, generated once and preserved across resume and protected backup
- **AND** the API never mounts or receives the host operator private key
- **AND** local issuance is not claimed as external vendor identity or password-rotation proof

#### Scenario: Reject restored credential reuse
- **WHEN** a novel recovery credential is submitted
- **THEN** server-side semantic comparison rejects retained passwords despite different version IDs, usernames or JSON formatting
- **AND** revoked retained versions are included and undecryptable material fails closed
- **AND** no credential, comparison fingerprint or plaintext hash is exposed in public responses or ordinary logs

#### Scenario: Host approval and current browser authority
- **WHEN** the operator invokes the supported owned-host approval command and the user explicitly applies its proof
- **THEN** exact installation/source/slot/version/configuration/epoch/attestation and short-lived signature checks gate an audited atomic awaiting-activation transition
- **AND** no cookie copying, manual SQL, external IdP or implicit application grant is required
- **AND** only an explicit bounded test is permitted before exact current-proof activation clears the fence

#### Scenario: Replay, change and failure preserve the fence
- **WHEN** a proof expires, a credential/configuration/epoch changes, authority is revoked or audit/intent/receipt persistence fails
- **THEN** no unintended clearance, collection or activation occurs
- **AND** replay does not duplicate the transition and replacement requires a new explicit host approval
- **AND** external/demo authority semantics remain unchanged with no local fallback to fixture proofs

### Requirement: Independently authenticated small installation
Online setup SHALL authenticate a small installation package and immutable multi-platform runtime without requiring the offline image archive.

#### Scenario: Candidate cannot choose its verifier
- **WHEN** downloaded launcher, descriptor or bundle data proposes another verifier, identity, version, image, provenance or platform
- **THEN** independently provisioned trust and expected release govern admission
- **AND** wrong signatures, altered content and mismatched subjects fail before candidate execution or resource creation

#### Scenario: Minimal prerequisites outside checkout
- **WHEN** the actual authenticated package installs on a qualified host outside source checkout
- **THEN** Docker, Compose and disclosed ordinary shell utilities suffice without host Python, OpenSSL, Git, Cosign or source builds
- **AND** the Docker engine selects its supported platform from the authenticated index
- **AND** helpers never receive a Docker socket for convenience

### Requirement: Owned resumable lifecycle
Installation SHALL preserve established secrets, data and ownership across interruption, restart and coordinated restore.

#### Scenario: Resume and unrelated resources
- **WHEN** setup resumes after interruption or encounters existing resources
- **THEN** owned valid phases continue without secret regeneration
- **AND** unrelated or contradictory resources fail safely without adoption or data deletion

#### Scenario: Safe lifecycle and recovery
- **WHEN** a user stops, diagnoses, backs up or restores the instance
- **THEN** normal stop retains data and diagnostics redact secrets
- **AND** recovery covers all three stores, authentication and cryptographic state with existing fences and readback checks
- **AND** consumed setup never reopens and restored local sessions are revoked before ingress opens
- **AND** destructive removal and unsupported upgrades cannot occur implicitly

#### Scenario: Ordinary stop acceptance cutoff
- **WHEN** the original host ordinary-stop clock reaches 600 seconds before the same-incarnation stop and mandatory evidence are verified
- **THEN** the invocation returns nonzero and retains private failure evidence even if Docker subsequently completes its submitted stop
- **AND** any standalone cold backup requires independently verified current stopped evidence and the existing admission and custody checks

#### Scenario: Network and prerequisite failures
- **WHEN** ports, registry access, private-file permissions or required resources are unavailable
- **THEN** setup reports an actionable safe failure without foreign adoption
- **AND** loopback remains default while server access requires explicit HTTPS origin and ingress configuration
