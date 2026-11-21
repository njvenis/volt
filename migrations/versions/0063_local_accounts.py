"""Add persistent local accounts, sessions, throttles and one-use capabilities."""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

revision = "0063"
down_revision = "0062"
branch_labels = None
depends_on = None


def _tz():
    return sa.DateTime(timezone=True)


def upgrade():
    op.create_table("local_auth_installation",
        sa.Column("singleton_id", sa.Integer(), primary_key=True),
        sa.Column("installation_id", sa.String(36), nullable=False, unique=True),
        sa.Column("setup_generation", sa.Integer(), nullable=False),
        sa.Column("claimed_at", _tz()), sa.Column("created_at", _tz(), nullable=False),
        sa.CheckConstraint("singleton_id = 1 AND setup_generation > 0", name="local_auth_installation_singleton"))
    op.create_table("local_accounts",
        sa.Column("principal_id", sa.String(), sa.ForeignKey("auth_principals.principal_id"), primary_key=True),
        sa.Column("username", sa.String(), nullable=False),
        sa.Column("username_normalized", sa.String(), nullable=False, unique=True),
        sa.Column("verifier", sa.String()), sa.Column("credential_revision", sa.Integer(), nullable=False),
        sa.Column("capability_generation", sa.Integer(), nullable=False),
        sa.Column("status", sa.String(), nullable=False), sa.Column("created_at", _tz(), nullable=False),
        sa.Column("updated_at", _tz(), nullable=False),
        sa.CheckConstraint("credential_revision > 0", name="local_account_credential_revision_positive"),
        sa.CheckConstraint("capability_generation > 0", name="local_account_capability_generation_positive"),
        sa.CheckConstraint("status IN ('pending', 'enabled', 'disabled')", name="local_account_status"))
    op.create_table("local_sessions",
        sa.Column("session_hash", sa.String(64), primary_key=True),
        sa.Column("session_id", sa.Uuid(as_uuid=False), nullable=False, unique=True),
        sa.Column("principal_id", sa.String(), sa.ForeignKey("local_accounts.principal_id"), nullable=False),
        sa.Column("credential_revision", sa.Integer(), nullable=False), sa.Column("revision", sa.Integer(), nullable=False),
        sa.Column("csrf_hash", sa.String(64), nullable=False), sa.Column("created_at", _tz(), nullable=False),
        sa.Column("expires_at", _tz(), nullable=False), sa.Column("revoked_at", _tz()))
    op.create_index("ix_local_sessions_principal", "local_sessions", ["principal_id", "revoked_at"])
    op.create_table("local_auth_capabilities",
        sa.Column("capability_hash", sa.String(64), primary_key=True),
        sa.Column("capability_locator", sa.String(32), nullable=False, unique=True),
        sa.Column("purpose", sa.String(), nullable=False),
        sa.Column("installation_id", sa.String(36), nullable=False),
        sa.Column("principal_id", sa.String(), sa.ForeignKey("local_accounts.principal_id")),
        sa.Column("generation", sa.Integer(), nullable=False), sa.Column("credential_revision", sa.Integer(), nullable=False),
        sa.Column("expires_at", _tz(), nullable=False), sa.Column("consumed_at", _tz()), sa.Column("created_at", _tz(), nullable=False),
        sa.CheckConstraint("purpose IN ('setup', 'enrolment', 'recovery')", name="local_capability_purpose"))
    op.create_table("local_login_throttles",
        sa.Column("bucket_hash", sa.String(64), primary_key=True), sa.Column("window_started_at", _tz(), nullable=False),
        sa.Column("attempts", sa.Integer(), nullable=False), sa.Column("blocked_until", _tz()),
        sa.Column("failure_times", JSONB(), nullable=False, server_default=sa.text("'[]'::jsonb")),
        sa.CheckConstraint("attempts >= 0", name="local_login_attempts_nonnegative"))


def downgrade():
    bind = op.get_bind()
    if bind.execute(sa.text("SELECT count(*) FROM local_accounts")).scalar_one():
        raise RuntimeError("refusing 0063 downgrade: local accounts are retained")
    op.drop_table("local_login_throttles")
    op.drop_table("local_auth_capabilities")
    op.drop_index("ix_local_sessions_principal", table_name="local_sessions")
    op.drop_table("local_sessions")
    op.drop_table("local_accounts")
    op.drop_table("local_auth_installation")
