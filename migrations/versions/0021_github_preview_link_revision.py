"""Bind signed previews to the exact audited GitHub identity-link revision."""

from alembic import op
import sqlalchemy as sa

revision = "0021"
down_revision = "0020"
branch_labels = None
depends_on = None


def upgrade():
    existing = {column["name"] for column in sa.inspect(op.get_bind()).get_columns(
        "github_command_previews")}
    if "link_revision" not in existing:
        op.add_column("github_command_previews",
            sa.Column("link_revision", sa.Integer(), nullable=True))
    op.execute(sa.text("""
        UPDATE github_command_previews AS preview
        SET link_revision = link.revision
        FROM github_identity_links AS link
        WHERE link.link_id = preview.link_id
    """))
    op.alter_column("github_command_previews", "link_revision",
        existing_type=sa.Integer(), nullable=False)


def downgrade():
    op.drop_column("github_command_previews", "link_revision")
