"""Durable OIDC links, group memberships, sessions and evaluated authority."""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB


revision = "0034"
down_revision = "0033"
branch_labels = None
depends_on = None


def _json():
    return JSONB().with_variant(sa.JSON(), "sqlite")


def upgrade():
    identifier = sa.Uuid(as_uuid=False)
    instant = sa.DateTime(timezone=True)
    op.create_table(
        "auth_principals",
        sa.Column("principal_id", sa.String(), primary_key=True),
        sa.Column("display_label", sa.String(), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("revision", sa.Integer(), nullable=False),
        sa.Column("created_at", instant, nullable=False),
        sa.CheckConstraint("revision > 0", name="auth_principal_revision_positive"),
    )
    op.create_table(
        "oidc_subject_links",
        sa.Column("link_id", identifier, primary_key=True),
        sa.Column("issuer", sa.String(), nullable=False),
        sa.Column("subject", sa.String(), nullable=False),
        sa.Column("principal_id", sa.String(), sa.ForeignKey("auth_principals.principal_id"), nullable=False),
        sa.Column("revision", sa.Integer(), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("actor_id", sa.String(), nullable=False),
        sa.Column("rationale", sa.Text(), nullable=False),
        sa.Column("evidence_ref", sa.Text(), nullable=False),
        sa.Column("created_at", instant, nullable=False),
        sa.Column("updated_at", instant, nullable=False),
        sa.UniqueConstraint("issuer", "subject", name="uq_oidc_subject_link"),
        sa.CheckConstraint("revision > 0", name="oidc_link_revision_positive"),
    )
    op.create_index("ix_oidc_subject_link_principal", "oidc_subject_links", ["principal_id", "enabled"])
    op.create_table(
        "oidc_subject_groups",
        sa.Column("issuer", sa.String(), primary_key=True),
        sa.Column("subject", sa.String(), primary_key=True),
        sa.Column("group_id", sa.String(), primary_key=True),
        sa.Column("provider_revision", sa.Integer(), nullable=False),
        sa.Column("updated_at", instant, nullable=False),
    )
    op.create_table(
        "auth_group_memberships",
        sa.Column("group_id", sa.String(), primary_key=True),
        sa.Column("principal_id", sa.String(), sa.ForeignKey("auth_principals.principal_id"), primary_key=True),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("revision", sa.Integer(), nullable=False),
        sa.Column("updated_at", instant, nullable=False),
        sa.Column("provider_revision", sa.Integer(), nullable=False),
    )
    op.create_table(
        "oidc_sessions",
        sa.Column("session_hash", sa.String(64), primary_key=True),
        sa.Column("session_id", identifier, nullable=False, unique=True),
        sa.Column("principal_id", sa.String(), sa.ForeignKey("auth_principals.principal_id"), nullable=False),
        sa.Column("link_id", identifier, sa.ForeignKey("oidc_subject_links.link_id"), nullable=False),
        sa.Column("link_revision", sa.Integer(), nullable=False),
        sa.Column("revision", sa.Integer(), nullable=False),
        sa.Column("csrf_hash", sa.String(64), nullable=False),
        sa.Column("created_at", instant, nullable=False),
        sa.Column("expires_at", instant, nullable=False),
        sa.Column("revoked_at", instant, nullable=True),
    )
    op.create_index("ix_oidc_sessions_principal", "oidc_sessions", ["principal_id", "revoked_at"])
    op.create_table(
        "oidc_authorization_states",
        sa.Column("state_hash", sa.String(64), primary_key=True),
        sa.Column("nonce", sa.String(), nullable=False),
        sa.Column("code_verifier", sa.String(), nullable=False),
        sa.Column("created_at", instant, nullable=False),
        sa.Column("expires_at", instant, nullable=False),
    )
    op.create_table(
        "oidc_sync_state",
        sa.Column("provider_id", sa.String(), primary_key=True),
        sa.Column("revision", sa.Integer(), nullable=False),
        sa.Column("heartbeat_at", instant, nullable=False),
        sa.Column("snapshot_digest", sa.String(64), nullable=False),
    )
    op.create_table(
        "auth_identity_events",
        sa.Column("event_id", identifier, primary_key=True),
        sa.Column("event_sequence", sa.Integer(), nullable=False, unique=True),
        sa.Column("actor_id", sa.String(), nullable=False),
        sa.Column("action", sa.String(), nullable=False),
        sa.Column("subject_link_id", identifier, nullable=True),
        sa.Column("revision", sa.Integer(), nullable=False),
        sa.Column("before_value", _json(), nullable=False),
        sa.Column("after_value", _json(), nullable=False),
        sa.Column("rationale", sa.Text(), nullable=False),
        sa.Column("evidence_ref", sa.Text(), nullable=False),
        sa.Column("occurred_at", instant, nullable=False),
    )
    # Existing assessment decisions remain readable. New writers populate this
    # with the separately evaluated OIDC/session/group revisions.
    op.add_column("assessment_audit_events", sa.Column("authorization_context", _json(), nullable=True))
    op.add_column("assessment_command_receipts", sa.Column("authorization_context", _json(), nullable=True))


def downgrade():
    bind = op.get_bind()
    for table in ("assessment_audit_events", "assessment_command_receipts"):
        if bind.execute(sa.text(
                f"SELECT count(*) FROM {table} WHERE authorization_context IS NOT NULL "
                "AND CAST(authorization_context AS TEXT) NOT IN ('null', '\"null\"')")).scalar_one():
            from alembic.util.exc import CommandError
            raise CommandError(f"refusing 0034 downgrade: evaluated identity authority is retained in {table}")
    for table in ("oidc_sessions", "oidc_subject_links", "oidc_subject_groups", "auth_group_memberships",
                  "auth_identity_events", "oidc_sync_state", "oidc_authorization_states",
                  "auth_principals"):
        if bind.execute(sa.text(f"SELECT count(*) FROM {table}")).scalar_one():
            from alembic.util.exc import CommandError
            raise CommandError(f"refusing 0034 downgrade: retained G7 identity rows exist in {table}")
    op.drop_column("assessment_command_receipts", "authorization_context")
    op.drop_column("assessment_audit_events", "authorization_context")
    op.drop_table("auth_identity_events")
    op.drop_table("oidc_sync_state")
    op.drop_table("oidc_authorization_states")
    op.drop_index("ix_oidc_sessions_principal", table_name="oidc_sessions")
    op.drop_table("oidc_sessions")
    op.drop_table("oidc_subject_groups")
    op.drop_table("auth_group_memberships")
    op.drop_index("ix_oidc_subject_link_principal", table_name="oidc_subject_links")
    op.drop_table("oidc_subject_links")
    op.drop_table("auth_principals")
