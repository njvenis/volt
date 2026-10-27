"""Add the approved V2 grouped-unresolved durable identity boundary."""

from alembic import context, op
from alembic.util.exc import CommandError
from sqlalchemy import Boolean, CheckConstraint, Column, DateTime, ForeignKey, Integer, JSON, String, UniqueConstraint, Uuid, text
from sqlalchemy.dialects.postgresql import JSONB

revision = "0013"
down_revision = "0012"
branch_labels = None
depends_on = None

_NAME = "identity_resolutions_outcome_selection_consistent"
_KNOWN = "identity_resolutions_known_group_revision_consistent"


def _dialect():
    name = op.get_bind().dialect.name
    if name not in ("sqlite", "postgresql"):
        raise CommandError(f"0013 does not support {name}")
    return name


def _constraint():
    return CheckConstraint(
        "((outcome IN ('matched', 'new') AND group_id IS NOT NULL "
        "AND workload_id IS NOT NULL AND incarnation_id IS NOT NULL "
        "AND exposure_id IS NOT NULL AND occurrence_id IS NOT NULL "
        "AND known_group_revision IS NULL) "
        "OR (outcome = 'ambiguous' AND workload_id IS NULL "
        "AND incarnation_id IS NULL AND exposure_id IS NULL "
        "AND occurrence_id IS NULL AND known_group_revision IS NULL) "
        "OR (outcome = 'unresolved' "
        "AND ((schema_version = 1 AND known_group_revision IS NULL) "
        "OR (schema_version = 2 AND group_id IS NULL AND known_group_revision IS NULL) "
        "OR (schema_version = 2 AND group_id IS NOT NULL AND known_group_revision IS NOT NULL "
        "AND known_group_revision > 0)) "
        "AND workload_id IS NULL AND incarnation_id IS NULL "
        "AND exposure_id IS NULL AND occurrence_id IS NULL))",
        name=_NAME,
    )


def upgrade():
    if context.is_offline_mode():
        raise CommandError("0013 upgrade requires an online additive migration")
    dialect = _dialect()
    op.create_table("identity_authorisation_decisions",
        Column("decision_id", Uuid(as_uuid=False), primary_key=True),
        Column("action", String, nullable=False),
        Column("target_id", Uuid(as_uuid=False), nullable=False),
        Column("principal_id", String, nullable=False),
        Column("scope", String, nullable=False),
        Column("policy_revision", String, nullable=False),
        Column("reason", String, nullable=False),
        Column("evidence_ref", String, nullable=False),
        Column("correlation_id", String, nullable=False),
        Column("decided_at", DateTime(timezone=True), nullable=False),
        Column("decision_details", JSONB if dialect == "postgresql" else JSON, nullable=False))
    op.create_table("identity_rule_definitions",
        Column("rule_id", String, primary_key=True),
        Column("rule_version", Integer, primary_key=True),
        Column("workload_match_fields", JSONB if dialect == "postgresql" else JSON, nullable=False),
        Column("verified_asset_locator", Boolean, nullable=False),
        Column("definition_digest", String, nullable=False),
        Column("authorisation_decision_id", Uuid(as_uuid=False), ForeignKey("identity_authorisation_decisions.decision_id"), nullable=True),
        Column("created_at", DateTime(timezone=True), nullable=False),
        UniqueConstraint("rule_id", "rule_version", name="uq_identity_rule_definition"))
    op.create_table("identity_resolution_requests",
        Column("resolution_request_id", Uuid(as_uuid=False), primary_key=True),
        Column("observation_id", Uuid(as_uuid=False), ForeignKey("source_observations.observation_id"), nullable=False),
        Column("observation_revision", Integer, nullable=False),
        Column("request_fingerprint", String, nullable=False),
        Column("authorisation_decision_id", Uuid(as_uuid=False), ForeignKey("identity_authorisation_decisions.decision_id"), nullable=True),
        Column("resolution_id", Uuid(as_uuid=False), ForeignKey("identity_resolutions.resolution_id"), nullable=False),
        Column("resolution_revision", Integer, nullable=False),
        Column("created_at", DateTime(timezone=True), nullable=False),
        UniqueConstraint("resolution_request_id", name="uq_identity_resolution_request"))
    if dialect == "postgresql":
        op.add_column("identity_resolutions", Column("known_group_revision", Integer))
        op.drop_constraint(_NAME, "identity_resolutions", type_="check")
        op.create_check_constraint(_NAME, "identity_resolutions", _constraint().sqltext)
    else:
        # SQLite cannot drop a CHECK in place.  Alembic's batch recreation
        # preserves all reflected FKs/indexes while changing only this
        # additive column and the one approved outcome guard.
        with op.batch_alter_table("identity_resolutions", recreate="always") as batch:
            batch.add_column(Column("known_group_revision", Integer))
            batch.drop_constraint(_NAME, type_="check")
            batch.create_check_constraint(_NAME, _constraint().sqltext)


def downgrade():
    if context.is_offline_mode():
        raise CommandError("0013 downgrade requires online retained-row safety checks")
    dialect = _dialect()
    bind = op.get_bind()
    if bind.execute(text(
            "SELECT count(*) FROM identity_resolutions "
            "WHERE known_group_revision IS NOT NULL")).scalar_one():
        raise CommandError(
            "refusing 0013 downgrade: grouped-unresolved V2 rows are retained")
    if bind.execute(text("SELECT count(*) FROM identity_resolution_requests")).scalar_one():
        raise CommandError("refusing 0013 downgrade: resolution request ledger is retained")
    if bind.execute(text("SELECT count(*) FROM identity_authorisation_decisions")).scalar_one():
        raise CommandError("refusing 0013 downgrade: authorisation decisions are retained")
    if dialect == "postgresql":
        op.drop_constraint(_NAME, "identity_resolutions", type_="check")
        op.create_check_constraint(
            _NAME, "identity_resolutions",
            "((outcome IN ('matched', 'new') AND group_id IS NOT NULL "
            "AND workload_id IS NOT NULL AND incarnation_id IS NOT NULL "
            "AND exposure_id IS NOT NULL AND occurrence_id IS NOT NULL) "
            "OR (outcome IN ('ambiguous', 'unresolved') AND "
            "workload_id IS NULL AND incarnation_id IS NULL "
            "AND exposure_id IS NULL AND occurrence_id IS NULL))")
        op.drop_column("identity_resolutions", "known_group_revision")
    else:
        with op.batch_alter_table("identity_resolutions", recreate="always") as batch:
            batch.drop_constraint(_NAME, type_="check")
            batch.drop_column("known_group_revision")
            batch.create_check_constraint(
                _NAME,
                "((outcome IN ('matched', 'new') AND group_id IS NOT NULL "
                "AND workload_id IS NOT NULL AND incarnation_id IS NOT NULL "
                "AND exposure_id IS NOT NULL AND occurrence_id IS NOT NULL) "
                "OR (outcome IN ('ambiguous', 'unresolved') AND "
                "workload_id IS NULL AND incarnation_id IS NULL "
                "AND exposure_id IS NULL AND occurrence_id IS NULL))")
    op.drop_table("identity_resolution_requests")
    op.drop_table("identity_rule_definitions")
    op.drop_table("identity_authorisation_decisions")
