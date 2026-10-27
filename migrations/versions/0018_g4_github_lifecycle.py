"""Add exposure episode history and recoverable GitHub lifecycle records."""

from alembic import op
import sqlalchemy as sa

revision = "0018"
down_revision = "0017"
branch_labels = None
depends_on = None


def upgrade():
    # Keep table metadata in the persistence schema so portable SQLite fixtures
    # and the production PostgreSQL migration render the same constraints.
    from uvm.persistence.g4_schema import uvm_metadata

    # Frozen revision-0018 table set. Later migrations add repository events,
    # external events and projection steps; this migration must not grow when
    # current metadata evolves.
    table_names = (
        "assessment_exposure_episodes", "assessment_exposure_episode_members",
        "assessment_exposure_episode_events", "github_repositories",
        "github_identity_links", "github_identity_link_events",
        "github_group_issues", "github_create_reservations",
        "github_projection_intents", "github_command_previews",
        "github_inbox_commands", "github_poll_state",
    )

    bind = op.get_bind()
    for name in table_names:
        table = uvm_metadata.tables[name]
        table.create(bind=bind, checkfirst=False)


def downgrade():
    from uvm.persistence.g4_schema import uvm_metadata

    table_names = (
        "assessment_exposure_episodes", "assessment_exposure_episode_members",
        "assessment_exposure_episode_events", "github_repositories",
        "github_identity_links", "github_identity_link_events",
        "github_group_issues", "github_create_reservations",
        "github_projection_intents", "github_command_previews",
        "github_inbox_commands", "github_poll_state",
    )

    bind = op.get_bind()
    for name in table_names:
        table = uvm_metadata.tables[name]
        if bind.execute(sa.text(f'SELECT count(*) FROM "{table.name}"')).scalar_one():
            from alembic.util.exc import CommandError
            raise CommandError(f"refusing 0018 downgrade: {table.name} contains retained G4 data")
    for name in reversed(table_names):
        uvm_metadata.tables[name].drop(bind=bind, checkfirst=False)
