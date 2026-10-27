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

__all__ = ["auth_principals", "oidc_subject_links", "auth_group_memberships",
           "oidc_subject_groups", "oidc_sessions", "oidc_authorization_states", "oidc_sync_state",
           "auth_identity_events"]
