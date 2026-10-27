"""0007 durable DefectDojo CE context registrations (G1, CR-01/04).

The registration is UVM-owned metadata only.  Existing 0005/0006 rows remain
readable and untrusted: their nullable foreign key is intentionally not
backfilled.  Cross-context Product/Engagement/Test relationship validation is
reserved for the later writer/read-back contract.
"""

from alembic import context, op
from alembic.util.exc import CommandError
from sqlalchemy import CheckConstraint, Column, ForeignKey, Integer, String, UniqueConstraint, Uuid, text

revision = "0007"
down_revision = "0006"
branch_labels = None
depends_on = None

_ID = Uuid(as_uuid=False)


def _dialect() -> str:
    name = op.get_bind().dialect.name
    if name not in ("sqlite", "postgresql"):
        raise CommandError(f"0007 does not support {name}")
    return name


def sa_check(sql: str, name: str):
    return CheckConstraint(sql, name=name)


def upgrade() -> None:
    if context.is_offline_mode():
        raise CommandError("0007 upgrade requires online CE registration preflight")
    _dialect()
    op.create_table(
        "ce_context_registrations",
        Column("registration_id", _ID, primary_key=True),
        Column("schema_version", Integer, nullable=False),
        Column("deployment_key", String, nullable=False),
        Column("context_key", String, nullable=False),
        Column("product_id", Integer, nullable=False),
        Column("engagement_id", Integer, nullable=False),
        Column("test_id", Integer, nullable=True),
        sa_check("schema_version = 1", "ce_context_registrations_schema_version_v1"),
        sa_check("length(deployment_key) > 0", "ce_context_registrations_deployment_non_empty"),
        sa_check("length(context_key) > 0", "ce_context_registrations_context_non_empty"),
        sa_check("product_id > 0", "ce_context_registrations_product_positive"),
        sa_check("engagement_id > 0", "ce_context_registrations_engagement_positive"),
        sa_check("test_id IS NULL OR test_id > 0", "ce_context_registrations_test_positive"),
        UniqueConstraint("deployment_key", "context_key",
                         name="uq_ce_context_registrations_deployment_context"),
    )
    op.create_index(
        "uq_ce_context_registrations_deployment_test", "ce_context_registrations",
        ["deployment_key", "test_id"],
        unique=True, sqlite_where=text("test_id IS NOT NULL"),
        postgresql_where=text("test_id IS NOT NULL"),
    )
    # SQLite cannot ALTER TABLE ADD COLUMN with a foreign-key constraint;
    # Alembic's batch operation uses the same copy-and-move DDL on SQLite and
    # emits a normal ADD COLUMN plus FK on PostgreSQL.
    with op.batch_alter_table("engine_operation_requests") as batch:
        batch.add_column(
            Column("registration_id", _ID,
                   ForeignKey("ce_context_registrations.registration_id"), nullable=True)
        )


def _downgrade_guard() -> None:
    registration_count = op.get_bind().execute(
        text("SELECT count(*) FROM ce_context_registrations")
    ).scalar_one()
    reference_count = op.get_bind().execute(
        text("SELECT count(*) FROM engine_operation_requests WHERE registration_id IS NOT NULL")
    ).scalar_one()
    if registration_count or reference_count:
        raise CommandError(
            "refusing 0007 downgrade: CE registrations or operation references exist"
        )


def downgrade() -> None:
    if context.is_offline_mode():
        raise CommandError("0007 downgrade requires online CE registration safety checks")
    _dialect()
    _downgrade_guard()
    with op.batch_alter_table("engine_operation_requests") as batch:
        batch.drop_column("registration_id")
    op.drop_index("uq_ce_context_registrations_deployment_test", table_name="ce_context_registrations")
    op.drop_table("ce_context_registrations")
