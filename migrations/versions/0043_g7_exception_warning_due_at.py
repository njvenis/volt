"""Persist each exception warning's scheduled eligibility time."""
from alembic import op
import sqlalchemy as sa

revision = "0043"
down_revision = "0042"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("exception_warning_intents", sa.Column("due_at", sa.DateTime(timezone=True)))
    op.execute(sa.text("""
        UPDATE exception_warning_intents AS intent
        SET due_at = (decision.value->>'expires_at')::timestamptz
                     - intent.offset_seconds * interval '1 second'
        FROM assessment_group_state AS state
        CROSS JOIN LATERAL jsonb_array_elements(
            COALESCE(state.document->'acceptances', '[]'::jsonb)) AS decision(value)
        WHERE decision.value->>'acceptance_id' = intent.decision_id::text
          AND decision.value->>'expires_at' IS NOT NULL
    """))
    # A retained orphan must remain visible but cannot be dispatched without a
    # trustworthy expiry-derived due time.
    op.execute(sa.text("""
        UPDATE exception_warning_intents
        SET due_at = created_at,
            status = CASE WHEN status IN ('pending', 'failed') THEN 'suppressed' ELSE status END,
            suppression_reason = CASE WHEN status IN ('pending', 'failed')
                THEN 'due_time_unavailable' ELSE suppression_reason END
        WHERE due_at IS NULL
    """))
    op.alter_column("exception_warning_intents", "due_at", nullable=False)
    op.drop_index("ix_exception_warning_due", table_name="exception_warning_intents")
    op.create_index("ix_exception_warning_due", "exception_warning_intents",
        ["status", "due_at", "next_attempt_at"])


def downgrade():
    op.drop_index("ix_exception_warning_due", table_name="exception_warning_intents")
    op.create_index("ix_exception_warning_due", "exception_warning_intents",
        ["status", "next_attempt_at"])
    op.drop_column("exception_warning_intents", "due_at")
