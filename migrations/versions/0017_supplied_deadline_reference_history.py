"""Append-only G3 supplied references; no SLA calculation or identity change."""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

revision = '0017'
down_revision = '0016'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table('identity_deadline_reference_evidence',
        sa.Column('sha256', sa.String(64), primary_key=True),
        sa.Column('content', sa.LargeBinary, nullable=False),
        sa.CheckConstraint('length(sha256) = 64', name='deadline_evidence_sha_length'))
    op.create_table('identity_deadline_references',
        sa.Column('reference_id', sa.Uuid(as_uuid=False), primary_key=True),
        sa.Column('schema_version', sa.Integer, nullable=False),
        sa.Column('occurrence_id', sa.Uuid(as_uuid=False), sa.ForeignKey('occurrences.occurrence_id'), nullable=False),
        sa.Column('revision', sa.Integer, nullable=False),
        sa.Column('deadline_at', sa.DateTime(timezone=True)),
        sa.Column('policy_ref', sa.String),
        sa.Column('evidence_ref', sa.Text, nullable=False),
        sa.Column('evidence_sha256', sa.String(64), sa.ForeignKey('identity_deadline_reference_evidence.sha256'), nullable=False),
        sa.Column('supersedes_reference_id', sa.Uuid(as_uuid=False), unique=True),
        sa.Column('rationale', sa.Text, nullable=False),
        sa.Column('expected_occurrence_revision', sa.Integer, nullable=False),
        sa.Column('expected_reference_revision', sa.Integer, nullable=False),
        sa.Column('request_canonical', sa.Text, nullable=False),
        sa.Column('identity_snapshot', sa.JSON().with_variant(JSONB, 'postgresql'), nullable=False),
        sa.Column('authorisation_decision_id', sa.Uuid(as_uuid=False), sa.ForeignKey('identity_authorisation_decisions.decision_id'), nullable=False),
        sa.Column('recorded_at', sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint('reference_id', 'occurrence_id', name='deadline_reference_subject_unique'),
        sa.UniqueConstraint('occurrence_id', 'revision', name='deadline_reference_revision_unique'),
        sa.ForeignKeyConstraint(['supersedes_reference_id', 'occurrence_id'],
            ['identity_deadline_references.reference_id', 'identity_deadline_references.occurrence_id'], name='deadline_reference_same_subject'),
        sa.CheckConstraint('schema_version = 1', name='deadline_reference_version'),
        sa.CheckConstraint('revision > 0 AND expected_reference_revision = revision - 1 AND expected_occurrence_revision > 0', name='deadline_reference_heads'),
        sa.CheckConstraint('(revision = 1 AND supersedes_reference_id IS NULL) OR (revision > 1 AND supersedes_reference_id IS NOT NULL)', name='deadline_reference_chain'))


def downgrade():
    if op.get_bind().execute(sa.text('SELECT count(*) FROM identity_deadline_references')).scalar_one():
        from alembic.util.exc import CommandError
        raise CommandError('refusing 0017 downgrade: supplied reference history exists')
    op.drop_table('identity_deadline_references')
    op.drop_table('identity_deadline_reference_evidence')
