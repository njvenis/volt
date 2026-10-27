"""Durable desired observer timing, independent application and host reports."""
from sqlalchemy import (BigInteger, CheckConstraint, Column, DateTime, Index,
    Integer, JSON, LargeBinary, String, Table, Text, UniqueConstraint)

from uvm.persistence.schema import uvm_metadata


g7_observer_settings_revisions = Table(
    "g7_observer_settings_revisions", uvm_metadata,
    Column("deployment_id", String(256), primary_key=True),
    Column("revision", Integer, primary_key=True),
    Column("values", JSON, nullable=False),
    Column("digest", String(64), nullable=False),
    Column("command_id", String(36), nullable=False),
    Column("actor_id", String(256), nullable=False),
    Column("action", String(64), nullable=False),
    Column("copied_from_revision", Integer),
    Column("rationale", Text, nullable=False),
    Column("evidence_ref", Text),
    Column("created_at", DateTime(timezone=True), nullable=False),
    UniqueConstraint("deployment_id", "command_id",
                     name="uq_g7_observer_revision_command"),
    CheckConstraint("revision > 0", name="ck_g7_observer_revision_positive"),
)

g7_observer_status = Table(
    "g7_observer_status", uvm_metadata,
    Column("deployment_id", String(256), primary_key=True),
    Column("effective_revision", Integer),
    Column("effective_digest", String(64)),
    Column("application_status", String(16), nullable=False),
    Column("latest_report_id", String(36)),
    Column("latest_report_sequence", BigInteger, nullable=False, default=0),
    Column("latest_report_at", DateTime(timezone=True)),
    Column("latest_failure_code", String(64)),
    Column("host_policy_revision", Integer),
    Column("host_policy_bounds", JSON),
    Column("host_policy_digest", String(64)),
    Column("host_policy_key_id", String(128)),
    Column("host_policy_observed_at", DateTime(timezone=True)),
    Column("host_policy_freshness_seconds", Integer),
    CheckConstraint("application_status IN ('pending','applied','failed','uncertain')",
                    name="ck_g7_observer_application_status"),
    CheckConstraint("latest_report_sequence >= 0", name="ck_g7_observer_report_sequence"),
)

g7_observer_host_reports = Table(
    "g7_observer_host_reports", uvm_metadata,
    Column("report_id", String(36), primary_key=True),
    Column("deployment_id", String(256), nullable=False),
    Column("sequence", BigInteger, nullable=False),
    Column("controller_instance", String(128), nullable=False),
    Column("requested_revision", Integer),
    Column("requested_digest", String(64)),
    Column("active_revision", Integer),
    Column("active_digest", String(64)),
    Column("policy_revision", Integer, nullable=False),
    Column("policy_bounds", JSON, nullable=False),
    Column("policy_digest", String(64), nullable=False),
    Column("policy_key_id", String(128), nullable=False),
    Column("policy_freshness_seconds", Integer, nullable=False),
    Column("observed_at", DateTime(timezone=True), nullable=False),
    Column("outcome", String(16), nullable=False),
    Column("failure_code", String(64)),
    Column("report_digest", String(64), nullable=False),
    Column("signature", LargeBinary, nullable=False),
    Column("report", JSON, nullable=False),
    Column("received_at", DateTime(timezone=True), nullable=False),
    UniqueConstraint("deployment_id", "sequence",
                     name="uq_g7_observer_report_sequence"),
    CheckConstraint("sequence > 0", name="ck_g7_observer_report_sequence_positive"),
    CheckConstraint("policy_revision > 0 AND policy_freshness_seconds > 0",
                    name="ck_g7_observer_policy_revision_valid"),
    CheckConstraint("outcome IN ('applied','failed','uncertain')",
                    name="ck_g7_observer_report_outcome"),
)

g7_observer_application_intents = Table(
    "g7_observer_application_intents", uvm_metadata,
    Column("intent_id", String(36), primary_key=True),
    Column("deployment_id", String(256), nullable=False),
    Column("command_id", String(36), nullable=False),
    Column("revision", Integer, nullable=False),
    Column("digest", String(64), nullable=False),
    Column("status", String(16), nullable=False),
    Column("result", JSON),
    Column("created_at", DateTime(timezone=True), nullable=False),
    Column("updated_at", DateTime(timezone=True), nullable=False),
    UniqueConstraint("deployment_id", "command_id",
                     name="uq_g7_observer_intent_command"),
    CheckConstraint("revision > 0", name="ck_g7_observer_intent_revision_positive"),
    CheckConstraint("status IN ('pending','applied','failed','uncertain')",
                    name="ck_g7_observer_intent_status"),
)
Index("uq_g7_observer_open_intent", g7_observer_application_intents.c.deployment_id,
    unique=True, postgresql_where=g7_observer_application_intents.c.status.in_(
        ("pending", "uncertain")), sqlite_where=g7_observer_application_intents.c.status.in_(
        ("pending", "uncertain")))
