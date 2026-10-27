"""Durable G5 SLA evaluations and immutable stakeholder reports."""
from sqlalchemy import (BigInteger, Boolean, CheckConstraint, Column, DateTime,
                        ForeignKey, Index, Integer, String, Table, Text, Uuid,
                        UniqueConstraint)
from sqlalchemy.types import TypeDecorator
from sqlalchemy import JSON
from sqlalchemy.dialects.postgresql import JSONB

from uvm.persistence.schema import groups, uvm_metadata


class _PortableJSON(TypeDecorator):
    impl = JSON
    cache_ok = True

    def load_dialect_impl(self, dialect):
        return dialect.type_descriptor(JSONB() if dialect.name == "postgresql" else JSON())


_ID = Uuid(as_uuid=False)
_TZ = DateTime(timezone=True)
_JSON = _PortableJSON()

sla_policy_heads = Table(
    "sla_policy_heads", uvm_metadata,
    Column("head_id", Integer, primary_key=True),
    Column("revision", Integer, nullable=False),
    Column("updated_at", _TZ, nullable=False),
    CheckConstraint("head_id = 1 AND revision >= 0", name="sla_policy_head_singleton"),
)

sla_policy_versions = Table(
    "sla_policy_versions", uvm_metadata,
    Column("policy_id", String, primary_key=True),
    Column("version", Integer, primary_key=True),
    Column("revision", Integer, nullable=False, unique=True),
    Column("document", _JSON, nullable=False),
    Column("created_at", _TZ, nullable=False),
    Column("created_by", String, nullable=False),
)

# Expected-estate configuration is versioned independently from SLA policy.
# Each document is retained verbatim so issued reports can reproduce the
# target/source mapping and freshness contract they evaluated.
inventory_policy_heads = Table(
    "inventory_policy_heads", uvm_metadata,
    Column("head_id", Integer, primary_key=True),
    Column("revision", Integer, nullable=False),
    Column("updated_at", _TZ, nullable=False),
    CheckConstraint("head_id = 1 AND revision >= 0", name="inventory_policy_head_singleton"),
)

inventory_policy_versions = Table(
    "inventory_policy_versions", uvm_metadata,
    Column("revision", Integer, primary_key=True),
    Column("command_id", _ID, nullable=False, unique=True),
    Column("document", _JSON, nullable=False),
    Column("created_at", _TZ, nullable=False),
    Column("created_by", String, nullable=False),
    Column("audit_event_id", _ID, nullable=False),
)

sla_evaluations = Table(
    "sla_evaluations", uvm_metadata,
    Column("evaluation_id", _ID, primary_key=True),
    Column("episode_id", _ID, nullable=False),
    Column("occurrence_id", _ID, nullable=False),
    Column("revision", Integer, nullable=False),
    Column("policy_id", String),
    Column("policy_version", Integer),
    Column("reference_binding_id", _ID),
    Column("started_at", _TZ),
    Column("original_deadline_at", _TZ),
    Column("current_deadline_at", _TZ),
    Column("deadline_basis", String, nullable=False),
    Column("gap_reasons", _JSON, nullable=False),
    Column("predecessor_evaluation_id", _ID),
    Column("head_decision_id", _ID),
    # Report-context derivations can be retained without replacing the
    # authorised, current decision chain for this member.
    Column("is_authoritative", Boolean, nullable=False, default=True, server_default="true"),
    # Origin and reset lineage are explicit facts: revisions alone cannot tell
    # a report branch from a command writer or whether a reset reached a writer.
    Column("derivation_kind", String, nullable=False, default="legacy", server_default="legacy"),
    Column("clock_reset_event_id", _ID),
    Column("clock_reset_absorbed", Boolean, nullable=False, default=True, server_default="true"),
    Column("effective_at", _TZ, nullable=False),
    Column("known_at", _TZ, nullable=False),
    UniqueConstraint("episode_id", "occurrence_id", "revision", name="uq_sla_evaluation_revision"),
    Index("ix_sla_evaluation_atom_head", "episode_id", "occurrence_id", "revision"),
)

# G7 ingestion-based clocks have a separate lineage. G5's report-derived and
# accepted heads remain byte-for-byte on the legacy table and keep their
# existing digest and replay semantics.
g7_sla_evaluations = Table(
    "g7_sla_evaluations", uvm_metadata,
    Column("evaluation_id", _ID, primary_key=True),
    Column("episode_id", _ID, nullable=False),
    Column("occurrence_id", _ID, nullable=False),
    Column("revision", Integer, nullable=False),
    Column("policy_id", String), Column("policy_version", Integer),
    Column("reference_binding_id", _ID), Column("started_at", _TZ),
    Column("original_deadline_at", _TZ), Column("current_deadline_at", _TZ),
    Column("deadline_basis", String, nullable=False),
    Column("gap_reasons", _JSON, nullable=False),
    Column("predecessor_evaluation_id", _ID), Column("head_decision_id", _ID),
    Column("is_authoritative", Boolean, nullable=False, default=True, server_default="true"),
    Column("derivation_kind", String, nullable=False, default="writer", server_default="writer"),
    Column("clock_reset_event_id", _ID),
    Column("clock_reset_absorbed", Boolean, nullable=False, default=True, server_default="true"),
    Column("effective_at", _TZ, nullable=False), Column("known_at", _TZ, nullable=False),
    UniqueConstraint("episode_id", "occurrence_id", "revision", name="uq_g7_sla_evaluation_revision"),
    Index("ix_g7_sla_evaluation_atom_head", "episode_id", "occurrence_id", "revision"),
)

g7_sla_deadline_decisions = Table(
    "g7_sla_deadline_decisions", uvm_metadata,
    Column("decision_id", _ID, primary_key=True),
    Column("episode_id", _ID, nullable=False),
    Column("occurrence_id", _ID, nullable=False),
    Column("evaluation_id", _ID, ForeignKey("g7_sla_evaluations.evaluation_id"), nullable=False),
    Column("predecessor_decision_id", _ID),
    Column("original_deadline_at", _TZ, nullable=False),
    Column("revised_deadline_at", _TZ, nullable=False),
    Column("actor_id", String, nullable=False),
    Column("rationale", Text, nullable=False),
    Column("evidence_ref", Text, nullable=False),
    Column("audit_event_id", _ID, nullable=False),
    Column("created_at", _TZ, nullable=False),
)

sla_deadline_decisions = Table(
    "sla_deadline_decisions", uvm_metadata,
    Column("decision_id", _ID, primary_key=True),
    Column("episode_id", _ID, nullable=False),
    Column("occurrence_id", _ID, nullable=False),
    Column("evaluation_id", _ID, ForeignKey("sla_evaluations.evaluation_id"), nullable=False),
    Column("predecessor_decision_id", _ID),
    Column("original_deadline_at", _TZ, nullable=False),
    Column("revised_deadline_at", _TZ, nullable=False),
    Column("actor_id", String, nullable=False),
    Column("rationale", Text, nullable=False),
    Column("evidence_ref", Text, nullable=False),
    Column("audit_event_id", _ID, nullable=False),
    Column("created_at", _TZ, nullable=False),
)

report_requests = Table(
    "metrics_report_requests", uvm_metadata,
    Column("report_id", _ID, primary_key=True),
    Column("command_id", _ID, nullable=False, unique=True),
    Column("principal_id", String, nullable=False),
    Column("request_digest", String(64), nullable=False),
    Column("mode", String, nullable=False),
    Column("as_of", _TZ, nullable=False),
    Column("known_at", _TZ, nullable=False),
    Column("period_start", _TZ),
    Column("period_end", _TZ),
    Column("display_timezone", String, nullable=False),
    Column("scope", _JSON, nullable=False),
    # Private immutable calculation authority captured with the report command.
    # It is not exposed verbatim; scoped owner/principal inputs are manifested.
    Column("assessment_policy_snapshot", _JSON),
    Column("definition_version", String, nullable=False),
    Column("predecessor_report_id", _ID),
    Column("snapshot_sequence", BigInteger, nullable=False),
    Column("identity_scalar_sequence", BigInteger, nullable=False, server_default="0"),
    Column("source_retention_watermark", BigInteger, nullable=False, server_default="0"),
    Column("input_manifest", _JSON, nullable=False),
    Column("status", String, nullable=False),
    Column("projection_intent_id", _ID),
    Column("result", _JSON),
    Column("error_code", String),
    Column("created_at", _TZ, nullable=False),
    Column("ready_at", _TZ),
    CheckConstraint("status IN ('pending','ready','failed')", name="metrics_report_status"),
    Index("ix_metrics_report_principal_created", "principal_id", "created_at"),
)

metrics_report_atoms = Table(
    "metrics_report_atoms", uvm_metadata,
    Column("report_id", _ID, ForeignKey("metrics_report_requests.report_id"), primary_key=True),
    Column("atom_id", String, primary_key=True),
    Column("group_id", _ID, ForeignKey("groups.group_id"), nullable=False),
    Column("episode_id", _ID, nullable=False),
    Column("occurrence_id", _ID, nullable=False),
    Column("ordinal", Integer, nullable=False),
    Column("document", _JSON, nullable=False),
    Index("ix_metrics_report_atom_page", "report_id", "ordinal"),
)

reporting_projection_intents = Table(
    "reporting_projection_intents", uvm_metadata,
    Column("intent_id", _ID, primary_key=True),
    Column("report_id", _ID, ForeignKey("metrics_report_requests.report_id"), nullable=True),
    Column("audit_event_id", _ID),
    Column("kind", String, nullable=False),
    Column("status", String, nullable=False),
    Column("attempts", Integer, nullable=False),
    Column("last_error", Text),
    Column("created_at", _TZ, nullable=False),
    Column("updated_at", _TZ, nullable=False),
    UniqueConstraint("report_id", "kind", name="uq_reporting_intent_report_kind"),
)
