"""Add G7 ingestion receipts, append-only SLA clock events and warning intents."""
from alembic import op
import sqlalchemy as sa

revision = "0038"
down_revision = "0037"
branch_labels = None
depends_on = None


def upgrade():
    uuid = sa.Uuid(as_uuid=False)
    timestamp = sa.DateTime(timezone=True)
    json_value = sa.JSON().with_variant(sa.dialects.postgresql.JSONB(), "postgresql")
    op.create_table("sla_ingest_receipts",
        sa.Column("receipt_id", uuid, primary_key=True),
        sa.Column("episode_id", uuid, nullable=False),
        sa.Column("occurrence_id", uuid, nullable=False),
        sa.Column("ingested_at", timestamp, nullable=False),
        sa.Column("source_observation_id", uuid),
        sa.Column("source_observed_at", timestamp),
        sa.Column("source_collected_at", timestamp),
        sa.Column("ingest_operation_id", uuid, nullable=False),
        sa.Column("policy_id", sa.String()),
        sa.Column("policy_version", sa.Integer()),
        sa.Column("created_at", timestamp, nullable=False),
        sa.UniqueConstraint("episode_id", "occurrence_id", name="uq_sla_ingest_receipt_atom"),
        sa.UniqueConstraint("ingest_operation_id", "occurrence_id", name="uq_sla_ingest_receipt_operation"))
    op.create_index("ix_sla_ingest_receipt_context", "sla_ingest_receipts", ["episode_id", "ingested_at"])
    op.create_table("sla_clock_events",
        sa.Column("event_id", uuid, primary_key=True),
        sa.Column("episode_id", uuid, nullable=False),
        sa.Column("occurrence_id", uuid, nullable=False),
        sa.Column("sequence", sa.BigInteger(), nullable=False),
        sa.Column("event_type", sa.String(), nullable=False),
        sa.Column("effective_at", timestamp, nullable=False),
        sa.Column("recorded_at", timestamp, nullable=False),
        sa.Column("ingest_receipt_id", uuid, sa.ForeignKey("sla_ingest_receipts.receipt_id")),
        sa.Column("decision_id", uuid),
        sa.Column("membership_ids", json_value, nullable=False),
        sa.Column("policy_id", sa.String()),
        sa.Column("policy_version", sa.Integer()),
        sa.Column("evaluation_revision", sa.Integer(), nullable=False),
        sa.Column("predecessor_event_id", uuid),
        sa.Column("data", json_value, nullable=False),
        sa.UniqueConstraint("episode_id", "occurrence_id", "sequence", name="uq_sla_clock_atom_sequence"),
        sa.CheckConstraint("event_type IN ('started','paused','resumed','revoked','suspended','completed')",
                           name="sla_clock_event_type"))
    op.create_index("ix_sla_clock_atom_time", "sla_clock_events",
        ["episode_id", "occurrence_id", "effective_at", "sequence"])
    op.create_table("exception_warning_intents",
        sa.Column("intent_id", uuid, primary_key=True), sa.Column("decision_id", uuid, nullable=False),
        sa.Column("expiry_revision", sa.Integer(), nullable=False), sa.Column("offset_seconds", sa.Integer(), nullable=False),
        sa.Column("channel", sa.String(), nullable=False), sa.Column("destination_ref", sa.Text(), nullable=False),
        sa.Column("status", sa.String(), nullable=False), sa.Column("suppression_reason", sa.String()),
        sa.Column("created_at", timestamp, nullable=False), sa.Column("updated_at", timestamp, nullable=False),
        sa.UniqueConstraint("decision_id", "expiry_revision", "offset_seconds", "channel", "destination_ref",
                            name="uq_exception_warning_key"),
        sa.CheckConstraint("channel IN ('slack','email')", name="exception_warning_channel"),
        sa.CheckConstraint("status IN ('pending','sent','failed','missed','suppressed')", name="exception_warning_status"))
    op.create_table("exception_warning_attempts",
        sa.Column("attempt_id", uuid, primary_key=True),
        sa.Column("intent_id", uuid, sa.ForeignKey("exception_warning_intents.intent_id"), nullable=False),
        sa.Column("attempt_number", sa.Integer(), nullable=False), sa.Column("attempted_at", timestamp, nullable=False),
        sa.Column("outcome", sa.String(), nullable=False), sa.Column("receipt", sa.Text()), sa.Column("error", sa.Text()),
        sa.UniqueConstraint("intent_id", "attempt_number", name="uq_exception_warning_attempt"))


def downgrade():
    bind = op.get_bind()
    for name in ("exception_warning_attempts", "exception_warning_intents", "sla_clock_events", "sla_ingest_receipts"):
        if bind.execute(sa.text(f'SELECT count(*) FROM "{name}"')).scalar_one():
            from alembic.util.exc import CommandError
            raise CommandError("refusing 0038 downgrade: retained exception/SLA history requires forward repair")
    op.drop_table("exception_warning_attempts")
    op.drop_table("exception_warning_intents")
    op.drop_index("ix_sla_clock_atom_time", table_name="sla_clock_events")
    op.drop_table("sla_clock_events")
    op.drop_index("ix_sla_ingest_receipt_context", table_name="sla_ingest_receipts")
    op.drop_table("sla_ingest_receipts")
