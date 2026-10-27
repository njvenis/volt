"""Persist evaluation origin and causal reset absorption explicitly."""
from alembic import op
import sqlalchemy as sa

revision = "0031"
down_revision = "0030"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("sla_evaluations", sa.Column("derivation_kind", sa.String(),
        nullable=False, server_default="legacy"))
    op.add_column("sla_evaluations", sa.Column("clock_reset_event_id",
        sa.Uuid(as_uuid=False), nullable=True))
    op.add_column("sla_evaluations", sa.Column("clock_reset_absorbed",
        sa.Boolean(), nullable=False, server_default=sa.true()))
    # A retained deadline decision is unambiguous public-writer provenance for
    # pre-0031 rows. Preserve that reset absorption instead of rediscovering a
    # causal transition after adoption.
    op.execute(sa.text("""UPDATE sla_evaluations
        SET derivation_kind = 'writer', clock_reset_absorbed = true
        WHERE head_decision_id IS NOT NULL"""))
    # Severity writers record their exact evaluation IDs in the atomic audit.
    # Publication backfills retain exact targets and the transaction timestamp.
    # Recover only those established facts; unknown legacy origin stays legacy.
    bind = op.get_bind()
    metadata = sa.MetaData()
    evaluations = sa.Table("sla_evaluations", metadata, autoload_with=bind)
    audits = sa.Table("assessment_audit_events", metadata, autoload_with=bind)
    rows = list(bind.execute(sa.select(evaluations)).mappings())
    writer_ids = set()
    for audit in bind.execute(sa.select(audits).where(
            audits.c.action.in_(("severity.override", "policy.sla.publish")))).mappings():
        after = audit["after_value"]
        if audit["action"] == "severity.override":
            writer_ids.update(item["evaluation_id"] for item in after.get("sla_recalculations", [])
                if item.get("evaluation_id"))
        else:
            policy = after.get("sla_policy") or {}
            targets = policy.get("backfill", {}).get("targets", [])
            from datetime import datetime
            starts = datetime.fromisoformat(policy["effective_from"].replace("Z", "+00:00"))
            for row in rows:
                if (row["policy_id"] == policy.get("policy_id")
                        and row["policy_version"] == policy.get("version")
                        and row["known_at"] == audit["received_at"]
                        and row["effective_at"] == max(audit["occurred_at"], starts)
                        and any(str(row["episode_id"]) == target.get("episode_id")
                            and str(row["occurrence_id"]) == target.get("occurrence_id")
                            for target in targets)):
                    writer_ids.add(str(row["evaluation_id"]))
    for row in rows:
        if str(row["evaluation_id"]) in writer_ids:
            bind.execute(evaluations.update().where(
                evaluations.c.evaluation_id == row["evaluation_id"]).values(
                    derivation_kind="writer", clock_reset_absorbed=True))



def downgrade():
    bind = op.get_bind()
    if bind.execute(sa.text("""SELECT count(*) FROM sla_evaluations
            WHERE derivation_kind <> 'legacy' OR clock_reset_event_id IS NOT NULL
                OR clock_reset_absorbed = false""")).scalar_one():
        from alembic.util.exc import CommandError
        raise CommandError("refusing 0031 downgrade: evaluation origin/reset lineage is retained")
    op.drop_column("sla_evaluations", "clock_reset_absorbed")
    op.drop_column("sla_evaluations", "clock_reset_event_id")
    op.drop_column("sla_evaluations", "derivation_kind")
