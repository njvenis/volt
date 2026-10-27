"""Add atomic G3 assessment command, event, intent and receipt records."""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "0016"
down_revision = "0015"
branch_labels = None
depends_on = None

_ID = sa.Uuid(as_uuid=False)
_JSON = sa.JSON().with_variant(postgresql.JSONB(), "postgresql")
_TZ = sa.DateTime(timezone=True)


def upgrade():
    op.create_table(
        "assessment_policy",
        sa.Column("policy_id", sa.Integer(), primary_key=True),
        sa.Column("revision", sa.Integer(), nullable=False),
        sa.Column("document", _JSON, nullable=False),
        sa.Column("updated_at", _TZ, nullable=False),
        sa.Column("updated_by", sa.String(), nullable=False),
    )
    op.create_table(
        "assessment_group_state",
        sa.Column("group_id", _ID, sa.ForeignKey("groups.group_id"), primary_key=True),
        sa.Column("revision", sa.Integer(), nullable=False),
        sa.Column("document", _JSON, nullable=False),
        sa.Column("updated_at", _TZ, nullable=False),
    )
    op.create_table(
        "assessment_audit_events",
        sa.Column("event_id", _ID, primary_key=True),
        sa.Column("event_sequence", sa.BigInteger(), nullable=False, unique=True),
        sa.Column("actor_id", sa.String(), nullable=False),
        sa.Column("actor_kind", sa.String(), nullable=False),
        sa.Column("origin", sa.String(), nullable=False),
        sa.Column("action", sa.String(), nullable=False),
        sa.Column("target_id", _ID, nullable=False),
        sa.Column("before_value", _JSON, nullable=False),
        sa.Column("after_value", _JSON, nullable=False),
        sa.Column("membership_ids", _JSON, nullable=False),
        sa.Column("membership_revision", sa.Integer(), nullable=False),
        sa.Column("rationale", sa.Text(), nullable=False),
        sa.Column("evidence_ref", sa.Text(), nullable=False),
        sa.Column("policy_revision", sa.Integer(), nullable=False),
        sa.Column("identity_revision", sa.Integer(), nullable=False),
        sa.Column("occurred_at", _TZ, nullable=False),
        sa.Column("received_at", _TZ, nullable=False),
        sa.Column("correlation_id", _ID, nullable=False),
        sa.Column("command_id", _ID, nullable=False),
    )
    op.create_index("ix_assessment_audit_target_sequence", "assessment_audit_events",
                    ["target_id", "event_sequence"])
    op.create_table(
        "assessment_command_receipts",
        sa.Column("command_id", _ID, primary_key=True),
        sa.Column("principal_id", sa.String(), nullable=False),
        sa.Column("action", sa.String(), nullable=False),
        sa.Column("target_id", _ID, nullable=False),
        sa.Column("request_digest", sa.String(64), nullable=False),
        sa.Column("decision_id", _ID, nullable=False),
        sa.Column("audit_event_id", _ID,
                  sa.ForeignKey("assessment_audit_events.event_id"), nullable=False),
        sa.Column("intent_id", _ID, nullable=True),
        sa.Column("result", _JSON, nullable=False),
        sa.Column("created_at", _TZ, nullable=False),
    )
    op.create_table(
        "assessment_projection_intents",
        sa.Column("intent_id", _ID, primary_key=True),
        sa.Column("event_id", _ID,
                  sa.ForeignKey("assessment_audit_events.event_id"), nullable=False),
        sa.Column("target_id", _ID, nullable=False),
        sa.Column("membership_ids", _JSON, nullable=False),
        sa.Column("status", sa.String(), nullable=False),
        sa.Column("created_at", _TZ, nullable=False),
        sa.UniqueConstraint("event_id", name="uq_assessment_intent_event"),
    )
    op.create_table(
        "assessment_export_acknowledgements",
        sa.Column("event_id", _ID,
                  sa.ForeignKey("assessment_audit_events.event_id"), primary_key=True),
        sa.Column("sink_receipt", sa.String(), nullable=False),
        sa.Column("acknowledged_at", _TZ, nullable=False),
    )


def downgrade():
    bind = op.get_bind()
    receipts = bind.execute(sa.text("SELECT count(*) FROM assessment_command_receipts")).scalar_one()
    if receipts:
        from alembic.util.exc import CommandError
        raise CommandError("refusing 0016 downgrade: assessment decisions exist")
    op.drop_table("assessment_export_acknowledgements")
    op.drop_table("assessment_projection_intents")
    op.drop_table("assessment_command_receipts")
    op.drop_index("ix_assessment_audit_target_sequence", table_name="assessment_audit_events")
    op.drop_table("assessment_audit_events")
    op.drop_table("assessment_group_state")
    op.drop_table("assessment_policy")
