"""Versioned OIDC authority and opaque session persistence for G7."""
from sqlalchemy import (Boolean, CheckConstraint, Column, DateTime, ForeignKey,
                        Index, Integer, JSON, String, Table, Text, Uuid,
                        UniqueConstraint)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.types import TypeDecorator

from uvm.persistence.schema import uvm_metadata


class _PortableJSON(TypeDecorator):
    impl = JSON
    cache_ok = True

    def load_dialect_impl(self, dialect):
        return dialect.type_descriptor(JSONB() if dialect.name == "postgresql" else JSON())


_ID = Uuid(as_uuid=False)
_TZ = DateTime(timezone=True)
_JSON = _PortableJSON()

auth_principals = Table(
    "auth_principals", uvm_metadata,
    Column("principal_id", String, primary_key=True),
    Column("display_label", String, nullable=False),
    Column("enabled", Boolean, nullable=False),
    Column("revision", Integer, nullable=False),
    Column("created_at", _TZ, nullable=False),
    CheckConstraint("revision > 0", name="auth_principal_revision_positive"),
)

oidc_subject_links = Table(
    "oidc_subject_links", uvm_metadata,
    Column("link_id", _ID, primary_key=True),
    Column("issuer", String, nullable=False),
    Column("subject", String, nullable=False),
    Column("principal_id", String, ForeignKey("auth_principals.principal_id"), nullable=False),
    Column("revision", Integer, nullable=False),
    Column("enabled", Boolean, nullable=False),
    Column("actor_id", String, nullable=False),
    Column("rationale", Text, nullable=False),
    Column("evidence_ref", Text, nullable=False),
    Column("created_at", _TZ, nullable=False),
    Column("updated_at", _TZ, nullable=False),
    UniqueConstraint("issuer", "subject", name="uq_oidc_subject_link"),
    CheckConstraint("revision > 0", name="oidc_link_revision_positive"),
    Index("ix_oidc_subject_link_principal", "principal_id", "enabled"),
)

oidc_subject_groups = Table(
    "oidc_subject_groups", uvm_metadata,
    Column("issuer", String, primary_key=True),
    Column("subject", String, primary_key=True),
    Column("group_id", String, primary_key=True),
    Column("provider_revision", Integer, nullable=False),
    Column("updated_at", _TZ, nullable=False),
)

auth_group_memberships = Table(
    "auth_group_memberships", uvm_metadata,
    Column("group_id", String, primary_key=True),
    Column("principal_id", String, ForeignKey("auth_principals.principal_id"), primary_key=True),
    Column("enabled", Boolean, nullable=False),
    Column("revision", Integer, nullable=False),
    Column("updated_at", _TZ, nullable=False),
    Column("provider_revision", Integer, nullable=False),
)

oidc_sessions = Table(
    "oidc_sessions", uvm_metadata,
    Column("session_hash", String(64), primary_key=True),
    Column("session_id", _ID, nullable=False, unique=True),
    Column("principal_id", String, ForeignKey("auth_principals.principal_id"), nullable=False),
    Column("link_id", _ID, ForeignKey("oidc_subject_links.link_id"), nullable=False),
    Column("link_revision", Integer, nullable=False),
    Column("revision", Integer, nullable=False),
    Column("csrf_hash", String(64), nullable=False),
    Column("created_at", _TZ, nullable=False),
    Column("expires_at", _TZ, nullable=False),
    Column("revoked_at", _TZ, nullable=True),
    Index("ix_oidc_sessions_principal", "principal_id", "revoked_at"),
)

oidc_authorization_states = Table(
    "oidc_authorization_states", uvm_metadata,
    Column("state_hash", String(64), primary_key=True),
    Column("nonce", String, nullable=False),
    Column("code_verifier", String, nullable=False),
    Column("browser_binding_hash", String(64), nullable=True),
    Column("created_at", _TZ, nullable=False),
    Column("expires_at", _TZ, nullable=False),
)

oidc_sync_state = Table(
    "oidc_sync_state", uvm_metadata,
    Column("provider_id", String, primary_key=True),
    Column("revision", Integer, nullable=False),
    Column("heartbeat_at", _TZ, nullable=False),
    Column("snapshot_digest", String(64), nullable=False),
)

auth_identity_events = Table(
    "auth_identity_events", uvm_metadata,
    Column("event_id", _ID, primary_key=True),
    Column("event_sequence", Integer, nullable=False, unique=True),
    Column("actor_id", String, nullable=False),
    Column("action", String, nullable=False),
    Column("subject_link_id", _ID, nullable=True),
    Column("revision", Integer, nullable=False),
    Column("before_value", _JSON, nullable=False),
    Column("after_value", _JSON, nullable=False),
    Column("rationale", Text, nullable=False),
    Column("evidence_ref", Text, nullable=False),
    Column("occurred_at", _TZ, nullable=False),
)

# Additive, installation-local credentials. Local browser sessions intentionally
# have no OIDC link and never borrow the synthetic provider's identity rows.
local_auth_installation = Table(
    "local_auth_installation", uvm_metadata,
    Column("singleton_id", Integer, primary_key=True),
    Column("installation_id", String(36), nullable=False, unique=True),
    Column("setup_generation", Integer, nullable=False),
    Column("claimed_at", _TZ),
    Column("created_at", _TZ, nullable=False),
    CheckConstraint("singleton_id = 1 AND setup_generation > 0", name="local_auth_installation_singleton"),
)

local_accounts = Table(
    "local_accounts", uvm_metadata,
    Column("principal_id", String, ForeignKey("auth_principals.principal_id"), primary_key=True),
    Column("username", String, nullable=False),
    Column("username_normalized", String, nullable=False, unique=True),
    Column("verifier", String),
    Column("credential_revision", Integer, nullable=False),
    Column("capability_generation", Integer, nullable=False),
    Column("status", String, nullable=False),
    Column("created_at", _TZ, nullable=False),
    Column("updated_at", _TZ, nullable=False),
    CheckConstraint("credential_revision > 0", name="local_account_credential_revision_positive"),
    CheckConstraint("capability_generation > 0", name="local_account_capability_generation_positive"),
    CheckConstraint("status IN ('pending', 'enabled', 'disabled')", name="local_account_status"),
)

local_sessions = Table(
    "local_sessions", uvm_metadata,
    Column("session_hash", String(64), primary_key=True),
    Column("session_id", _ID, nullable=False, unique=True),
    Column("principal_id", String, ForeignKey("local_accounts.principal_id"), nullable=False),
    Column("credential_revision", Integer, nullable=False),
    Column("revision", Integer, nullable=False),
    Column("csrf_hash", String(64), nullable=False),
    Column("created_at", _TZ, nullable=False),
    Column("expires_at", _TZ, nullable=False),
    Column("revoked_at", _TZ),
    Index("ix_local_sessions_principal", "principal_id", "revoked_at"),
)

local_capabilities = Table(
    "local_auth_capabilities", uvm_metadata,
    Column("capability_hash", String(64), primary_key=True),
    Column("capability_locator", String(32), nullable=False, unique=True),
    Column("purpose", String, nullable=False),
    Column("installation_id", String(36), nullable=False),
    Column("principal_id", String, ForeignKey("local_accounts.principal_id")),
    Column("generation", Integer, nullable=False),
    Column("credential_revision", Integer, nullable=False),
    Column("expires_at", _TZ, nullable=False),
    Column("consumed_at", _TZ),
    Column("created_at", _TZ, nullable=False),
    CheckConstraint("purpose IN ('setup', 'enrolment', 'recovery')", name="local_capability_purpose"),
)

local_login_throttles = Table(
    "local_login_throttles", uvm_metadata,
    Column("bucket_hash", String(64), primary_key=True),
    Column("window_started_at", _TZ, nullable=False),
    Column("attempts", Integer, nullable=False),
    Column("blocked_until", _TZ),
    Column("failure_times", _JSON, nullable=False, default=list),
    CheckConstraint("attempts >= 0", name="local_login_attempts_nonnegative"),
)

__all__ = ["auth_principals", "oidc_subject_links", "auth_group_memberships",
           "oidc_subject_groups", "oidc_sessions", "oidc_authorization_states", "oidc_sync_state",
           "auth_identity_events", "local_auth_installation", "local_accounts", "local_sessions",
           "local_capabilities", "local_login_throttles"]
