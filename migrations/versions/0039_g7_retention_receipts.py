"""Anchor G7 provenance at first durable source-observation retention."""
from alembic import op
import sqlalchemy as sa

revision = "0039"
down_revision = "0038"
branch_labels = None
depends_on = None


def upgrade():
    uuid = sa.Uuid(as_uuid=False)
    timestamp = sa.DateTime(timezone=True)
    op.create_table("source_observation_receipts",
        sa.Column("receipt_id", uuid, primary_key=True),
        sa.Column("source_observation_id", uuid,
            sa.ForeignKey("source_observations.observation_id"), nullable=False, unique=True),
        sa.Column("source_account_id", sa.String(), nullable=False),
        sa.Column("run_id", sa.String(), nullable=False),
        sa.Column("source_record_ordinal", sa.Integer(), nullable=False),
        sa.Column("retention_operation_id", uuid, nullable=False),
        sa.Column("retained_at", timestamp, nullable=False),
        sa.Column("source_observed_at", timestamp),
        sa.Column("source_collected_at", timestamp, nullable=False),
        sa.Column("created_at", timestamp, nullable=False),
        sa.UniqueConstraint("source_observation_id", "source_account_id", "run_id",
            "source_record_ordinal", name="uq_source_observation_receipt_position"))
    op.create_index("ix_source_observation_receipt_retained_at",
        "source_observation_receipts", ["retained_at"])
    op.add_column("sla_ingest_receipts", sa.Column("retention_receipt_id", uuid,
        sa.ForeignKey("source_observation_receipts.receipt_id"), unique=True))
    op.create_table("sla_episode_contracts",
        sa.Column("episode_id", uuid, primary_key=True),
        sa.Column("contract_version", sa.Integer(), nullable=False),
        sa.Column("start_source", sa.String(), nullable=False),
        sa.Column("retention_receipt_id", uuid,
            sa.ForeignKey("source_observation_receipts.receipt_id")),
        sa.Column("policy_id", sa.String()), sa.Column("policy_version", sa.Integer()),
        sa.Column("pinned_at", timestamp, nullable=False),
        sa.Column("created_at", timestamp, nullable=False),
        sa.CheckConstraint("contract_version IN (5,7)", name="sla_episode_contract_version"),
        sa.CheckConstraint("(contract_version = 7 AND start_source = 'uvm_ingest_commit_v1' AND policy_id IS NOT NULL AND policy_version IS NOT NULL) OR (contract_version = 5 AND start_source = 'source_observation_v1')",
            name="sla_episode_contract_consistency"))

    # Existing episodes are historical G5 contracts. No receipt or ingestion
    # instant is inferred for data retained before this feature existed.
    op.execute(sa.text("""INSERT INTO sla_episode_contracts
        (episode_id, contract_version, start_source, retention_receipt_id,
         policy_id, policy_version, pinned_at, created_at)
        SELECT episode_id, 5, 'source_observation_v1', NULL, NULL, NULL,
               created_at, created_at FROM assessment_exposure_episodes"""))


def downgrade():
    bind = op.get_bind()
    if bind.execute(sa.text("SELECT count(*) FROM source_observation_receipts")).scalar_one():
        from alembic.util.exc import CommandError
        raise CommandError("refusing 0039 downgrade: durable retention receipt history requires forward repair")
    op.drop_table("sla_episode_contracts")
    op.drop_column("sla_ingest_receipts", "retention_receipt_id")
    op.drop_index("ix_source_observation_receipt_retained_at", table_name="source_observation_receipts")
    op.drop_table("source_observation_receipts")
