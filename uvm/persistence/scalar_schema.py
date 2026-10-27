"""Additive H4 scalar supplier receipts; established correction rows stay intact."""
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB
from uvm.persistence.schema import uvm_metadata
from uvm.persistence import lineage_schema as _lineage  # noqa: F401
from uvm.persistence import assessment_schema as _assessment  # noqa: F401
from uvm.persistence import g4_schema as _g4, metrics_schema as _metrics  # noqa: F401
from uvm.persistence import exception_sla_schema as _exception_sla  # noqa: F401

identity_scalar_correction_receipts = sa.Table(
    "identity_scalar_correction_receipts", uvm_metadata,
    sa.Column("request_id", sa.Uuid(as_uuid=False), primary_key=True),
    sa.Column("schema_version", sa.Integer, nullable=False),
    sa.Column("request_digest", sa.String(64), nullable=False),
    sa.Column("canonical_request", sa.Text, nullable=False),
    sa.Column("principal_id", sa.String, nullable=False),
    sa.Column("action", sa.String, nullable=False),
    sa.Column("record_type", sa.String, nullable=False),
    sa.Column("record_id", sa.Uuid(as_uuid=False), nullable=False),
    sa.Column("field_name", sa.String, nullable=False),
    sa.Column("previous_revision", sa.Integer, nullable=False),
    sa.Column("new_revision", sa.Integer, nullable=False),
    sa.Column("correction_id", sa.Uuid(as_uuid=False),
              sa.ForeignKey("correction_records.correction_id"), nullable=False, unique=True),
    sa.Column("decision_id", sa.Uuid(as_uuid=False),
              sa.ForeignKey("identity_authorisation_decisions.decision_id"), nullable=False, unique=True),
    sa.Column("knowledge_sequence", sa.BigInteger, nullable=False, unique=True),
    sa.Column("recorded_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("scope_contexts", JSONB().with_variant(sa.JSON, "sqlite"), nullable=False),
    sa.Column("result", JSONB().with_variant(sa.JSON, "sqlite"), nullable=False),
    sa.UniqueConstraint("record_type", "record_id", "new_revision", name="uq_scalar_target_revision"),
    sa.CheckConstraint("schema_version = 1", name="scalar_receipt_version"),
    sa.CheckConstraint("previous_revision > 0 AND new_revision = previous_revision + 1", name="scalar_receipt_revision"),
    sa.CheckConstraint("knowledge_sequence > 0", name="scalar_receipt_sequence"),
    sa.CheckConstraint("(record_type = 'workload' AND action = 'identity.workload_field_correct') OR "
                       "(record_type = 'incarnation' AND action = 'identity.incarnation_locator_correct' "
                       "AND field_name = 'host_locator')", name="scalar_receipt_action"),
)
