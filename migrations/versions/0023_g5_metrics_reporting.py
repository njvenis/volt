"""Persist versioned SLA evaluations and immutable metric report materialisation."""
from alembic import op
import sqlalchemy as sa

revision = "0023"
down_revision = "0022"
branch_labels = None
depends_on = None


def upgrade():
    # Keep this migration a literal 0023 schema snapshot. Importing current
    # metadata here would silently adopt columns introduced by later revisions.
    uuid = sa.Uuid(as_uuid=False)
    timestamp = sa.DateTime(timezone=True)
    json_value = sa.JSON().with_variant(sa.dialects.postgresql.JSONB(), "postgresql")
    op.create_table("sla_policy_heads",
        sa.Column("head_id", sa.Integer(), primary_key=True),
        sa.Column("revision", sa.Integer(), nullable=False),
        sa.Column("updated_at", timestamp, nullable=False),
        sa.CheckConstraint("head_id = 1 AND revision >= 0", name="sla_policy_head_singleton"))
    op.create_table("sla_policy_versions",
        sa.Column("policy_id", sa.String(), primary_key=True),
        sa.Column("version", sa.Integer(), primary_key=True),
        sa.Column("revision", sa.Integer(), nullable=False, unique=True),
        sa.Column("document", json_value, nullable=False),
        sa.Column("created_at", timestamp, nullable=False),
        sa.Column("created_by", sa.String(), nullable=False))
    op.create_table("sla_evaluations",
        sa.Column("evaluation_id", uuid, primary_key=True),
        sa.Column("episode_id", uuid, nullable=False),
        sa.Column("occurrence_id", uuid, nullable=False),
        sa.Column("revision", sa.Integer(), nullable=False),
        sa.Column("policy_id", sa.String()),
        sa.Column("policy_version", sa.Integer()),
        sa.Column("started_at", timestamp),
        sa.Column("original_deadline_at", timestamp),
        sa.Column("current_deadline_at", timestamp),
        sa.Column("deadline_basis", sa.String(), nullable=False),
        sa.Column("gap_reasons", json_value, nullable=False),
        sa.Column("predecessor_evaluation_id", uuid),
        sa.Column("head_decision_id", uuid),
        sa.Column("effective_at", timestamp, nullable=False),
        sa.Column("known_at", timestamp, nullable=False),
        sa.UniqueConstraint("episode_id", "occurrence_id", "revision", name="uq_sla_evaluation_revision"))
    op.create_index("ix_sla_evaluation_atom_head", "sla_evaluations",
        ["episode_id", "occurrence_id", "revision"])
    op.create_table("sla_deadline_decisions",
        sa.Column("decision_id", uuid, primary_key=True),
        sa.Column("episode_id", uuid, nullable=False),
        sa.Column("occurrence_id", uuid, nullable=False),
        sa.Column("evaluation_id", uuid, sa.ForeignKey("sla_evaluations.evaluation_id"), nullable=False),
        sa.Column("predecessor_decision_id", uuid),
        sa.Column("original_deadline_at", timestamp, nullable=False),
        sa.Column("revised_deadline_at", timestamp, nullable=False),
        sa.Column("actor_id", sa.String(), nullable=False),
        sa.Column("rationale", sa.Text(), nullable=False),
        sa.Column("evidence_ref", sa.Text(), nullable=False),
        sa.Column("audit_event_id", uuid, nullable=False),
        sa.Column("created_at", timestamp, nullable=False))
    op.create_table("metrics_report_requests",
        sa.Column("report_id", uuid, primary_key=True),
        sa.Column("command_id", uuid, nullable=False, unique=True),
        sa.Column("principal_id", sa.String(), nullable=False),
        sa.Column("request_digest", sa.String(64), nullable=False),
        sa.Column("mode", sa.String(), nullable=False),
        sa.Column("as_of", timestamp, nullable=False),
        sa.Column("known_at", timestamp, nullable=False),
        sa.Column("period_start", timestamp), sa.Column("period_end", timestamp),
        sa.Column("display_timezone", sa.String(), nullable=False),
        sa.Column("scope", json_value, nullable=False),
        sa.Column("definition_version", sa.String(), nullable=False),
        sa.Column("predecessor_report_id", uuid),
        sa.Column("snapshot_sequence", sa.BigInteger(), nullable=False),
        sa.Column("input_manifest", json_value, nullable=False),
        sa.Column("status", sa.String(), nullable=False),
        sa.Column("projection_intent_id", uuid), sa.Column("result", json_value),
        sa.Column("error_code", sa.String()), sa.Column("created_at", timestamp, nullable=False),
        sa.Column("ready_at", timestamp),
        sa.CheckConstraint("status IN ('pending','ready','failed')", name="metrics_report_status"))
    op.create_index("ix_metrics_report_principal_created", "metrics_report_requests",
        ["principal_id", "created_at"])
    op.create_table("metrics_report_atoms",
        sa.Column("report_id", uuid, sa.ForeignKey("metrics_report_requests.report_id"), primary_key=True),
        sa.Column("atom_id", sa.String(), primary_key=True),
        sa.Column("group_id", uuid, sa.ForeignKey("groups.group_id"), nullable=False),
        sa.Column("episode_id", uuid, nullable=False), sa.Column("occurrence_id", uuid, nullable=False),
        sa.Column("ordinal", sa.Integer(), nullable=False), sa.Column("document", json_value, nullable=False))
    op.create_index("ix_metrics_report_atom_page", "metrics_report_atoms", ["report_id", "ordinal"])
    op.create_table("reporting_projection_intents",
        sa.Column("intent_id", uuid, primary_key=True),
        sa.Column("report_id", uuid, sa.ForeignKey("metrics_report_requests.report_id")),
        sa.Column("kind", sa.String(), nullable=False), sa.Column("status", sa.String(), nullable=False),
        sa.Column("attempts", sa.Integer(), nullable=False), sa.Column("last_error", sa.Text()),
        sa.Column("created_at", timestamp, nullable=False), sa.Column("updated_at", timestamp, nullable=False),
        sa.UniqueConstraint("report_id", "kind", name="uq_reporting_intent_report_kind"))
    op.execute(sa.text("INSERT INTO sla_policy_heads (head_id, revision, updated_at) VALUES (1, 0, CURRENT_TIMESTAMP)"))


def downgrade():
    bind = op.get_bind()
    tables = ("metrics_report_atoms", "metrics_report_requests",
              "reporting_projection_intents", "sla_deadline_decisions",
              "sla_evaluations", "sla_policy_versions")
    inspector = sa.inspect(bind)
    for name in tables:
        if name in inspector.get_table_names() and bind.execute(
                sa.text(f'SELECT count(*) FROM "{name}"')).scalar_one():
            from alembic.util.exc import CommandError
            raise CommandError("refusing 0023 downgrade: retained G5 policy/report history requires forward repair")
    for name in ("metrics_report_atoms", "reporting_projection_intents",
                 "metrics_report_requests", "sla_deadline_decisions", "sla_evaluations",
                 "sla_policy_versions", "sla_policy_heads"):
        op.drop_table(name)
