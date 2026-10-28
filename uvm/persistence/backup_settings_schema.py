"""Durable backup settings, host acknowledgements, recovery epochs and holds."""
from sqlalchemy import (BigInteger, CheckConstraint, Column, DateTime, Index,
    Integer, JSON, LargeBinary, String, Table, Text, UniqueConstraint)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.types import TypeDecorator

from uvm.persistence.schema import uvm_metadata


class _PortableJSON(TypeDecorator):
    impl = JSON
    cache_ok = True

    def load_dialect_impl(self, dialect):
        return dialect.type_descriptor(JSONB() if dialect.name == "postgresql" else JSON())


_JSON = _PortableJSON()

g7_backup_settings_revisions = Table(
    "g7_backup_settings_revisions", uvm_metadata,
    Column("deployment_id", String(256), primary_key=True),
    Column("revision", Integer, primary_key=True),
    Column("values", _JSON, nullable=False),
    Column("digest", String(64), nullable=False),
    Column("command_id", String(36), nullable=False),
    Column("actor_id", String(256), nullable=False),
    Column("action", String(64), nullable=False),
    Column("copied_from_revision", Integer),
    Column("rationale", Text, nullable=False),
    Column("evidence_ref", Text),
    Column("policy_revision", Integer, nullable=False),
    Column("authority_revision", Integer, nullable=False),
    Column("host_policy_revision", Integer, nullable=False),
    Column("created_at", DateTime(timezone=True), nullable=False),
    UniqueConstraint("deployment_id", "command_id", name="uq_g7_backup_revision_command"),
    CheckConstraint("revision > 0", name="ck_g7_backup_revision_positive"),
)

g7_backup_state = Table(
    "g7_backup_state", uvm_metadata,
    Column("deployment_id", String(256), primary_key=True),
    Column("effective_revision", Integer),
    Column("effective_digest", String(64)),
    Column("application_status", String(16)),
    Column("requested_revision", Integer),
    Column("requested_digest", String(64)),
    Column("application_intent_id", String(36)),
    Column("host_policy_revision", Integer),
    Column("host_policy_digest", String(64)),
    Column("host_policy_document", _JSON),
    Column("host_policy_key_id", String(128)),
    Column("host_policy_observed_at", DateTime(timezone=True)),
    Column("host_policy_max_age_seconds", Integer),
    Column("host_policy_future_skew_seconds", Integer),
    Column("latest_report_id", String(36)),
    Column("latest_sequence", BigInteger, nullable=False, default=0),
    Column("latest_report_at", DateTime(timezone=True)),
    Column("latest_failure_code", String(64)),
    Column("archive_id", String(36)),
    Column("archive_completed_at", DateTime(timezone=True)),
    Column("archive_manifest_digest", String(64)),
    Column("archive_outcome", String(16)),
    Column("freshness_state", String(16), nullable=False, default="unknown"),
    Column("freshness_age_seconds", BigInteger),
    Column("freshness_max_age_seconds", Integer),
    Column("recovery_epoch", BigInteger, nullable=False, default=0),
    Column("restore_state", String(16), nullable=False, default="unknown"),
    Column("restore_archive_id", String(36)),
    Column("restore_verified_at", DateTime(timezone=True)),
    Column("restore_failure_code", String(64)),
    Column("updated_at", DateTime(timezone=True)),
    CheckConstraint("latest_sequence >= 0", name="ck_g7_backup_sequence_nonnegative"),
    CheckConstraint("recovery_epoch >= 0", name="ck_g7_backup_epoch_nonnegative"),
)

g7_backup_host_records = Table(
    "g7_backup_host_records", uvm_metadata,
    Column("record_id", String(36), primary_key=True),
    Column("deployment_id", String(256), nullable=False),
    Column("record_kind", String(32), nullable=False),
    Column("sequence", BigInteger),
    Column("recovery_epoch", BigInteger),
    Column("record_digest", String(64), nullable=False),
    Column("signature", LargeBinary),
    Column("document", _JSON, nullable=False),
    Column("response", _JSON),
    Column("received_at", DateTime(timezone=True), nullable=False),
    UniqueConstraint("deployment_id", "record_kind", "sequence",
        name="uq_g7_backup_host_record_sequence"),
    CheckConstraint("record_kind IN ('policy','status','ack','recovery','resync','quarantine')",
        name="ck_g7_backup_record_kind"),
)

g7_backup_connector_quarantine = Table(
    "g7_backup_connector_quarantine", uvm_metadata,
    Column("deployment_id", String(256), primary_key=True),
    Column("intent_id", String(36), primary_key=True),
    Column("connector_id", String(256), nullable=False),
    Column("recovery_epoch", BigInteger, nullable=False),
    Column("connector_recovery_id", String(36), nullable=False),
    Column("event_id", String(36), nullable=False),
    Column("reason_code", String(64), nullable=False),
    Column("created_at", DateTime(timezone=True), nullable=False),
)


# Separate from the legacy state row so control-only restores can read that
# row before an explicitly authorized upgrade creates this additive table.
g7_backup_projection_evidence = Table(
    "g7_backup_projection_evidence", uvm_metadata,
    Column("deployment_id", String(256), primary_key=True),
    Column("application_evidence_record_id", String(36)),
    Column("effective_evidence_record_id", String(36)),
)
