## ADDED Requirements

### Requirement: Source-free Compose installation
VOLT SHALL provide a versioned, source-free Compose bundle that runs the existing application in one supervised image, stores PostgreSQL, DefectDojo media and application state persistently, and binds host listeners to loopback by default. Initialization SHALL generate private secrets and recovery TLS material without overwriting existing authority or adopting incompatible state. External OIDC SHALL use HTTPS issuer, discovery and callback origins and SHALL disable the synthetic provider and bearer bypass. The labelled local demo SHALL be opt-in and SHALL NOT be represented as a named-provider or production integration.

#### Scenario: Fresh demo installation and restart
- **WHEN** an operator initializes a new demo instance from the bundle and starts it
- **THEN** generated secret and TLS files have private permissions, the image is admitted by immutable identity, and all three persistent stores are created under the Compose project
- **AND** shutdown and restart preserve state and do not regenerate secrets
- **AND** demo identity is visibly labelled as synthetic

#### Scenario: External identity configuration
- **WHEN** an operator selects external OIDC mode with valid HTTPS provider configuration
- **THEN** VOLT authenticates only through that provider and current server-side permission checks remain in force
- **AND** synthetic-provider routes, fixture identities and bearer authentication are unavailable
- **AND** missing, contradictory or local/HTTP provider settings fail closed before readiness

#### Scenario: Incompatible or existing state
- **WHEN** initialization encounters an existing state directory, missing secrets, incompatible image metadata or an unrecognized schema
- **THEN** initialization fails without replacing authority, secrets or data

#### Scenario: Coordinated recovery
- **WHEN** an operator follows the documented backup and restore procedure
- **THEN** PostgreSQL, media, application state, secrets and cryptographic dependencies are captured consistently under effect fencing and read back together
- **AND** image rollback alone is not described as schema rollback


#### Scenario: Offline restore of established metadata and empty stores
- **WHEN** an operator restores captured established instance metadata onto absent project resources
- **THEN** explicit restore provisioning creates Compose-labelled volumes and a private network without a product runtime
- **AND** startup remains denied until imported content, ownership and permission inventories match the captured set, including stores recorded as empty
- **AND** PostgreSQL contains the captured PG_VERSION and the same admitted image is required

#### Scenario: Unsafe shutdown cannot authorize backup
- **WHEN** shutdown leaves a nonzero exit, OOM, forced termination or missing successful supervisor cleanup evidence from the current run
- **THEN** the installer rejects cold backup capture
- **AND** successful backup capture records all three offline store inventories

#### Scenario: Independent recovery credentials remain host-only
- **WHEN** Compose starts the application
- **THEN** only the recovery server identity and client CA are mounted for recovery TLS
- **AND** the independent host client's certificate and private key remain outside the application
