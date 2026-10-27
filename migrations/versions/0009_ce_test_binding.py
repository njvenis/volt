"""0009 durable supported-API CE Test binding (G1, CR-01/04).

The binding records the once-only result of the first import's supported API
Test creation/read-back.  It is additive metadata: the initial registration
history remains nullable and no DefectDojo tables are touched.  Append-only
behaviour is a writer obligation; these constraints enforce identity and
cross-table pairing only.
"""

from alembic import context, op
from alembic.util.exc import CommandError
from sqlalchemy import CheckConstraint, Column, DateTime, ForeignKeyConstraint, Integer, String, UniqueConstraint, Uuid, text

revision = "0009"
down_revision = "0008"
branch_labels = None
depends_on = None

_ID = Uuid(as_uuid=False)
_TZ = DateTime(timezone=True)


def _dialect() -> str:
    name = op.get_bind().dialect.name
    if name not in ("sqlite", "postgresql"):
        raise CommandError(f"0009 does not support {name}")
    return name


def _check(sql: str, name: str) -> CheckConstraint:
    return CheckConstraint(sql, name=name)


def _hex64(column: str, name: str) -> CheckConstraint:
    if op.get_bind().dialect.name == "postgresql":
        return _check(f"{column} ~ '^[0-9A-Fa-f]{{64}}$'", name)
    return _check(f"length({column}) = 64 AND {column} NOT GLOB '*[^0-9A-Fa-f]*'", name)


def upgrade() -> None:
    if context.is_offline_mode():
        raise CommandError("0009 upgrade requires online CE Test binding preflight")
    _dialect()

    # The operation primary key is already unique, but this explicit target
    # lets SQLite enforce operation↔registration pairing in a composite FK.
    with op.batch_alter_table("engine_operation_requests") as batch:
        batch.create_unique_constraint(
            "uq_engine_operation_requests_operation_registration",
            ["operation_id", "registration_id"],
        )

    op.create_table(
        "ce_context_test_bindings",
        Column("binding_id", _ID, primary_key=True),
        Column("schema_version", Integer, nullable=False),
        Column("registration_id", _ID, nullable=False),
        Column("originating_operation_id", _ID, nullable=False),
        Column("deployment_key", String, nullable=False),
        Column("test_id", Integer, nullable=False),
        Column("test_body_ref", String, nullable=False),
        Column("test_body_sha256", String, nullable=False),
        Column("deployment_config_revision", Integer, nullable=False),
        Column("bound_at", _TZ, nullable=False),
        ForeignKeyConstraint(
            ["registration_id", "deployment_key"],
            ["ce_context_registrations.registration_id", "ce_context_registrations.deployment_key"],
            name="fk_ce_context_test_bindings_registration_deployment",
        ),
        ForeignKeyConstraint(
            ["originating_operation_id", "registration_id"],
            ["engine_operation_requests.operation_id", "engine_operation_requests.registration_id"],
            name="fk_ce_context_test_bindings_operation_registration",
        ),
        ForeignKeyConstraint(
            ["deployment_key", "deployment_config_revision"],
            ["ce_deployment_configurations.deployment_key", "ce_deployment_configurations.revision"],
            name="fk_ce_context_test_bindings_deployment_configuration",
        ),
        UniqueConstraint("registration_id", name="uq_ce_context_test_bindings_registration"),
        UniqueConstraint("originating_operation_id", name="uq_ce_context_test_bindings_operation"),
        UniqueConstraint("deployment_key", "test_id",
                         name="uq_ce_context_test_bindings_deployment_test"),
        _check("schema_version = 1", "ce_context_test_bindings_schema_version_v1"),
        _check("length(deployment_key) > 0", "ce_context_test_bindings_deployment_non_empty"),
        _check("test_id > 0", "ce_context_test_bindings_test_positive"),
        _check("deployment_config_revision > 0", "ce_context_test_bindings_config_revision_positive"),
        _check("length(test_body_ref) > 0", "ce_context_test_bindings_test_ref_non_empty"),
        _hex64("test_body_sha256", "ce_context_test_bindings_test_digest_sha256"),
    )


def _downgrade_guard() -> None:
    bind = op.get_bind()
    count = bind.execute(text("SELECT count(*) FROM ce_context_test_bindings")).scalar_one()
    if count:
        raise CommandError("refusing 0009 downgrade: CE Test bindings exist")


def downgrade() -> None:
    if context.is_offline_mode():
        raise CommandError("0009 downgrade requires online CE Test binding safety checks")
    _dialect()
    _downgrade_guard()
    op.drop_table("ce_context_test_bindings")
    with op.batch_alter_table("engine_operation_requests") as batch:
        batch.drop_constraint(
            "uq_engine_operation_requests_operation_registration", type_="unique"
        )
