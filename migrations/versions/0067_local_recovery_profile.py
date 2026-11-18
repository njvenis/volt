"""Private local recovery profile binding and signed workflow provenance."""
from alembic import op
import sqlalchemy as sa
revision = '0067'
down_revision = '0066'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table('local_recovery_installation',
        sa.Column('installation_id',sa.String(36),primary_key=True),
        sa.Column('configuration_digest',sa.String(64),nullable=False),
        sa.Column('key_fingerprints',sa.JSON(),nullable=False),
        sa.Column('journal_id',sa.String(36),nullable=False),
        sa.Column('applied_restore_generation',sa.Integer(),nullable=False),
        sa.Column('applied_recovery_epoch_id',sa.String(36)),
        sa.Column('applied_at',sa.DateTime(timezone=True),nullable=False))
    op.create_table('local_recovery_attestations',
        sa.Column('attestation_id',sa.String(36),primary_key=True),
        sa.Column('installation_id',sa.String(36),nullable=False),
        sa.Column('connector_id',sa.String(36),nullable=False),
        sa.Column('secret_id',sa.String(36),nullable=False),
        sa.Column('version_id',sa.String(36),nullable=False),
        sa.Column('recovery_epoch_id',sa.String(36),nullable=False),
        sa.Column('document',sa.JSON(),nullable=False),
        sa.Column('issued_at',sa.DateTime(timezone=True),nullable=False),
        sa.UniqueConstraint('connector_id','secret_id','version_id','recovery_epoch_id',name='local_recovery_attestation_version_epoch'))
    op.create_table('local_recovery_approvals',
        sa.Column('approval_id',sa.String(36),primary_key=True),
        sa.Column('installation_id',sa.String(36),nullable=False),
        sa.Column('connector_id',sa.String(36),nullable=False),
        sa.Column('document',sa.JSON(),nullable=False),
        sa.Column('acknowledgement',sa.JSON(),nullable=False),
        sa.Column('consumed_command_id',sa.String(36),unique=True),
        sa.Column('superseded_at',sa.DateTime(timezone=True)),
        sa.Column('issued_at',sa.DateTime(timezone=True),nullable=False),
        sa.Column('expires_at',sa.DateTime(timezone=True),nullable=False))


def downgrade():
    op.drop_table('local_recovery_approvals')
    op.drop_table('local_recovery_attestations')
    op.drop_table('local_recovery_installation')
