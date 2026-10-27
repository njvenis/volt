"""Persist external projection step outcomes and safe inbox references."""

from alembic import op
import sqlalchemy as sa

revision = "0022"
down_revision = "0021"
branch_labels = None
depends_on = None


def upgrade():
    inspector = sa.inspect(op.get_bind())
    tables = set(inspector.get_table_names())
    projection_columns = {column["name"] for column in inspector.get_columns(
        "github_projection_intents")}
    if "in_flight_step" not in projection_columns:
        op.add_column("github_projection_intents", sa.Column("in_flight_step", sa.String()))
    inbox_columns = {column["name"] for column in inspector.get_columns(
        "github_inbox_commands")}
    if "preview_reference" not in inbox_columns:
        op.add_column("github_inbox_commands", sa.Column("preview_reference", sa.String()))
    if "connector_command_id" not in inbox_columns:
        op.add_column("github_inbox_commands", sa.Column("connector_command_id", sa.Uuid()))
    if "github_projection_steps" not in tables:
        op.create_table(
        "github_projection_steps",
        sa.Column("step_id", sa.Uuid(), nullable=False),
        sa.Column("projection_id", sa.Uuid(), sa.ForeignKey("github_projection_intents.projection_id"), nullable=False),
        sa.Column("group_id", sa.Uuid(), sa.ForeignKey("groups.group_id"), nullable=False),
        sa.Column("step_key", sa.String(), nullable=False),
        sa.Column("request_digest", sa.String(length=64), nullable=False),
        sa.Column("request", sa.JSON(), nullable=False),
        sa.Column("state", sa.String(), nullable=False),
        sa.Column("response", sa.JSON()),
        sa.Column("attempted_at", sa.DateTime(timezone=True)),
        sa.Column("settled_at", sa.DateTime(timezone=True)),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("state IN ('dispatching','applied','uncertain','failed')",
            name="github_projection_step_state"),
        sa.PrimaryKeyConstraint("step_id"),
        sa.UniqueConstraint("projection_id", "step_key", name="uq_github_projection_step"),
        )
    if "ix_github_projection_step_group" not in {
            item["name"] for item in inspector.get_indexes("github_projection_steps")}:
        op.create_index("ix_github_projection_step_group", "github_projection_steps",
            ["group_id", "state"], unique=False)


def downgrade():
    bind = op.get_bind()
    # G4 lifecycle records are retained history. Once populated, disabling the
    # worker and forward-repairing is the supported rollback path; dropping
    # captured external outcomes or command bindings would make recovery
    # ambiguous. This is deliberately a no-op refusal even when only unrelated
    # G4 history is present.
    retained_tables = (
        "assessment_exposure_episodes", "assessment_exposure_episode_members",
        "assessment_exposure_episode_events", "github_repositories",
        "github_identity_links", "github_identity_link_events",
        "github_group_issues", "github_create_reservations",
        "github_projection_intents", "github_projection_steps",
        "github_command_previews", "github_inbox_commands", "github_poll_state",
        "github_repository_events", "github_external_events",
    )
    inspector = sa.inspect(bind)
    present = set(inspector.get_table_names())
    for table in retained_tables:
        if table in present and bind.execute(sa.text(
                f'SELECT count(*) FROM "{table}"')).scalar_one():
            from alembic.util.exc import CommandError
            raise CommandError("refusing 0022 downgrade: retained G4 lifecycle data "
                "requires worker disablement and forward repair")
    op.drop_index("ix_github_projection_step_group", table_name="github_projection_steps")
    op.drop_table("github_projection_steps")
    op.drop_column("github_inbox_commands", "connector_command_id")
    op.drop_column("github_inbox_commands", "preview_reference")
    op.drop_column("github_projection_intents", "in_flight_step")
