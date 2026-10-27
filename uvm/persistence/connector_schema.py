"""G7 connector settings, encrypted credential versions and durable outcomes."""
from sqlalchemy import (Boolean, CheckConstraint, Column, DateTime, ForeignKey, Index,
    Integer, JSON, LargeBinary, MetaData, String, Table, UniqueConstraint)

from uvm.persistence.schema import uvm_metadata

connectors = Table(
    "g7_connectors", uvm_metadata,
    Column("connector_id", String(36), primary_key=True),
    Column("source_id", String(36), nullable=False, unique=True),
    Column("source_family", String(128), nullable=False),
    Column("source_account_id", String(256), nullable=False),
    Column("scope_key", String(256), nullable=False),
    Column("source_revision", Integer, nullable=False, default=1),
    Column("secret_source_id", String(36)),
    Column("secret_source_revision", Integer, nullable=False, default=0),
    Column("connector_revision", Integer, nullable=False, default=1),
    Column("configuration_revision", Integer, nullable=False, default=0),
    Column("active_configuration_revision", Integer),
    # Survives disable and repeated staging to preserve rollback-only mode transitions.
    Column("last_activated_authentication_mode", String(32)),
    Column("lifecycle", String(16), nullable=False, default="disabled"),
    Column("validation", JSON, nullable=False),
    Column("recovery", JSON, nullable=False),
    Column("environment_label", String(128), nullable=False),
    Column("updated_at", DateTime(timezone=True), nullable=False),
    CheckConstraint("source_revision >= 0 AND secret_source_revision >= 0 AND connector_revision >= 0 AND configuration_revision >= 0", name="ck_g7_connector_revisions"),
    CheckConstraint("lifecycle IN ('staged','active','disabled')", name="ck_g7_connector_lifecycle"),
)

connector_secret_heads = Table(
    "g7_connector_secret_heads", uvm_metadata,
    Column("connector_id", String(36), ForeignKey("g7_connectors.connector_id", ondelete="CASCADE"), primary_key=True),
    Column("secret_id", String(36), primary_key=True),
    Column("purpose", String(32), nullable=False),
    Column("revision", Integer, nullable=False, default=0),
    CheckConstraint("revision >= 0", name="ck_g7_connector_secret_revision"),
)

connector_configurations = Table(
    "g7_connector_configurations", uvm_metadata,
    Column("connector_id", String(36), ForeignKey("g7_connectors.connector_id", ondelete="CASCADE"), primary_key=True),
    Column("configuration_revision", Integer, primary_key=True),
    Column("settings", JSON, nullable=False),
    Column("actor_id", String(256), nullable=False),
    Column("created_at", DateTime(timezone=True), nullable=False),
)

connector_secrets = Table(
    "g7_connector_secrets", uvm_metadata,
    Column("connector_id", String(36), ForeignKey("g7_connectors.connector_id", ondelete="CASCADE"), primary_key=True),
    Column("secret_id", String(36), primary_key=True),
    Column("version_id", String(36), primary_key=True),
    Column("purpose", String(32), nullable=False),
    Column("state", String(16), nullable=False),
    Column("algorithm", String(32)),
    Column("key_id", String(36)),
    Column("nonce", LargeBinary),
    Column("ciphertext", LargeBinary),
    Column("reference", String(2048)),
    Column("quarantine", String(32), nullable=False, default="clear"),
    Column("remote_revocation", JSON, nullable=False),
    Column("actor_id", String(256), nullable=False),
    Column("created_at", DateTime(timezone=True), nullable=False),
    CheckConstraint("state IN ('inactive','active','revoked')", name="ck_g7_connector_secret_state"),
    CheckConstraint("quarantine IN ('clear','restored_version')", name="ck_g7_connector_secret_quarantine"),
    CheckConstraint("(ciphertext IS NOT NULL AND nonce IS NOT NULL AND reference IS NULL) OR (ciphertext IS NULL AND nonce IS NULL)", name="ck_g7_connector_secret_storage"),
)
Index("ix_g7_connector_secrets_current", connector_secrets.c.connector_id, connector_secrets.c.secret_id, connector_secrets.c.state)

connector_receipts = Table(
    "g7_connector_receipts", uvm_metadata,
    Column("connector_id", String(36), ForeignKey("g7_connectors.connector_id", ondelete="CASCADE"), primary_key=True),
    Column("command_id", String(36), primary_key=True),
    Column("actor_id", String(256), nullable=False),
    Column("action", String(80), nullable=False),
    Column("request_digest", String(64), nullable=False),
    Column("receipt", JSON, nullable=False),
    Column("created_at", DateTime(timezone=True), nullable=False),
)

connector_intents = Table(
    "g7_connector_intents", uvm_metadata,
    Column("intent_id", String(36), primary_key=True),
    Column("connector_id", String(36), ForeignKey("g7_connectors.connector_id", ondelete="CASCADE"), nullable=False),
    Column("kind", String(40), nullable=False),
    Column("actor_id", String(256), nullable=False),
    Column("status", String(24), nullable=False),
    Column("attempts", Integer, nullable=False, default=0),
    Column("payload", JSON, nullable=False),
    Column("result", JSON),
    Column("created_at", DateTime(timezone=True), nullable=False),
    Column("updated_at", DateTime(timezone=True), nullable=False),
)
Index("ix_g7_connector_intents_pending", connector_intents.c.status, connector_intents.c.created_at)

connector_submissions = Table(
    "g7_connector_submissions", uvm_metadata,
    Column("submission_id", String(36), primary_key=True),
    Column("connector_id", String(36), nullable=False),
    Column("source_id", String(36), nullable=False),
    Column("secret_id", String(36), nullable=False),
    Column("version_id", String(36), nullable=False),
    Column("actor_id", String(256), nullable=False),
    Column("outcome", String(24), nullable=False),
    Column("retry_allowed", Boolean, nullable=False, default=False, server_default="false"),
    Column("receipt", JSON),
    Column("created_at", DateTime(timezone=True), nullable=False),
    UniqueConstraint("connector_id", "version_id", name="uq_g7_connector_submission_version"),
    CheckConstraint("(outcome = 'not_committed' AND retry_allowed) OR (outcome <> 'not_committed' AND NOT retry_allowed)", name="ck_g7_connector_submission_retry_state"),
)

connector_setup_flows = Table(
    "g7_connector_setup_flows", uvm_metadata,
    Column("flow_id", String(36), primary_key=True),
    Column("connector_id", String(36), ForeignKey("g7_connectors.connector_id", ondelete="CASCADE"), nullable=False),
    Column("actor_id", String(256), nullable=False),
    Column("session_id", String(36), nullable=False),
    Column("configuration_revision", Integer, nullable=False),
    Column("state_digest", String(64), nullable=False),
    Column("verifier_key_id", String(36), nullable=False),
    Column("verifier_nonce", LargeBinary, nullable=False),
    Column("verifier_ciphertext", LargeBinary, nullable=False),
    Column("status", String(32), nullable=False),
    Column("failure_reason", String(64)),
    Column("app", JSON, nullable=False),
    Column("credential_binding", JSON, nullable=True),
    Column("installation", JSON),
    Column("granted_permissions", JSON, nullable=False),
    Column("repositories", JSON, nullable=False),
    Column("repositories_complete", Boolean, nullable=False, default=False),
    Column("verification_receipt", JSON),
    Column("expires_at", DateTime(timezone=True), nullable=False),
    Column("consumed_at", DateTime(timezone=True)),
    Column("created_at", DateTime(timezone=True), nullable=False),
)
Index("ix_g7_connector_setup_flows_expiry", connector_setup_flows.c.expires_at)

# One database-wide reservation ledger covers both persisted secrets and the
# short-lived encrypted PKCE verifiers. AES-GCM nonces are never re-used for a
# key even when an API handler retries inside a transaction.
connector_nonce_reservations = Table(
    "g7_connector_nonce_reservations", uvm_metadata,
    Column("key_id", String(36), primary_key=True),
    Column("nonce", LargeBinary(12), primary_key=True),
    Column("purpose", String(32), nullable=False),
    Column("binding_id", String(36), nullable=False),
    Column("created_at", DateTime(timezone=True), nullable=False),
)

__all__ = ["connectors", "connector_secret_heads", "connector_configurations", "connector_secrets",
    "connector_receipts", "connector_intents", "connector_submissions", "connector_setup_flows",
    "connector_nonce_reservations"]
