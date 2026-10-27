"""0008 durable CE deployment configuration and GET evidence (G1).

This is additive metadata only.  It stores references and SHA-256 digests of
the exact Product/Engagement/optional Test GET bodies; it never stores bodies,
credentials, or authentication headers.  Legacy operation requests remain
valid with a NULL verification_id.
"""

from alembic import context, op
from alembic.util.exc import CommandError
from sqlalchemy import CheckConstraint, Column, DateTime, ForeignKeyConstraint, Integer, String, UniqueConstraint, Uuid, text

revision = "0008"
down_revision = "0007"
branch_labels = None
depends_on = None

_ID = Uuid(as_uuid=False)
_TZ = DateTime(timezone=True)


def _dialect() -> str:
    name = op.get_bind().dialect.name
    if name not in ("sqlite", "postgresql"):
        raise CommandError(f"0008 does not support {name}")
    return name


def _check(sql: str, name: str) -> CheckConstraint:
    return CheckConstraint(sql, name=name)


def _hex64(column: str, name: str) -> CheckConstraint:
    if op.get_bind().dialect.name == "postgresql":
        return _check(f"{column} ~ '^[0-9A-Fa-f]{{64}}$'", name)
    return _check(f"length({column}) = 64 AND {column} NOT GLOB '*[^0-9A-Fa-f]*'", name)


def upgrade() -> None:
    if context.is_offline_mode():
        raise CommandError("0008 upgrade requires online CE evidence preflight")
    _dialect()

    # SQLite needs the parent key to be explicitly UNIQUE for the composite
    # registration/deployment foreign key below.  The batch operation keeps
    # 0007 column bytes and rows intact while adding only this key.
    with op.batch_alter_table("ce_context_registrations") as batch:
        batch.create_unique_constraint(
            "uq_ce_context_registrations_id_deployment",
            ["registration_id", "deployment_key"],
        )

    op.create_table(
        "ce_deployment_configurations",
        Column("configuration_id", _ID, primary_key=True),
        Column("schema_version", Integer, nullable=False),
        Column("deployment_key", String, nullable=False),
        Column("revision", Integer, nullable=False),
        Column("ce_base_url", String, nullable=False),
        Column("ce_release", String, nullable=False),
        Column("config_ref", String, nullable=False),
        Column("config_sha256", String, nullable=False),
        Column("recorded_at", _TZ, nullable=False),
        UniqueConstraint("deployment_key", "revision",
                         name="uq_ce_deployment_configurations_deployment_revision"),
        _check("schema_version = 1", "ce_deployment_configurations_schema_version_v1"),
        _check("length(deployment_key) > 0", "ce_deployment_configurations_deployment_non_empty"),
        _check("revision > 0", "ce_deployment_configurations_revision_positive"),
        _check("length(ce_base_url) > 0", "ce_deployment_configurations_base_url_non_empty"),
        _check("length(ce_release) > 0", "ce_deployment_configurations_release_non_empty"),
        _check("length(config_ref) > 0", "ce_deployment_configurations_ref_non_empty"),
        _hex64("config_sha256", "ce_deployment_configurations_digest_sha256"),
    )
    op.create_table(
        "ce_context_verifications",
        Column("verification_id", _ID, primary_key=True),
        Column("schema_version", Integer, nullable=False),
        Column("registration_id", _ID, nullable=False),
        Column("deployment_key", String, nullable=False),
        Column("deployment_config_revision", Integer, nullable=False),
        Column("product_body_ref", String, nullable=False),
        Column("product_body_sha256", String, nullable=False),
        Column("engagement_body_ref", String, nullable=False),
        Column("engagement_body_sha256", String, nullable=False),
        Column("test_body_ref", String, nullable=True),
        Column("test_body_sha256", String, nullable=True),
        Column("verified_at", _TZ, nullable=False),
        ForeignKeyConstraint(
            ["registration_id", "deployment_key"],
            ["ce_context_registrations.registration_id", "ce_context_registrations.deployment_key"],
            name="fk_ce_context_verifications_registration_deployment",
        ),
        ForeignKeyConstraint(
            ["deployment_key", "deployment_config_revision"],
            ["ce_deployment_configurations.deployment_key", "ce_deployment_configurations.revision"],
            name="fk_ce_context_verifications_deployment_configuration",
        ),
        UniqueConstraint("registration_id", "deployment_config_revision",
                         name="uq_ce_context_verifications_registration_revision"),
        UniqueConstraint("registration_id", "verification_id",
                         name="uq_ce_context_verifications_registration_verification"),
        _check("schema_version = 1", "ce_context_verifications_schema_version_v1"),
        _check("length(deployment_key) > 0", "ce_context_verifications_deployment_non_empty"),
        _check("deployment_config_revision > 0", "ce_context_verifications_config_revision_positive"),
        _check("length(product_body_ref) > 0 AND length(engagement_body_ref) > 0",
               "ce_context_verifications_required_refs_non_empty"),
        _hex64("product_body_sha256", "ce_context_verifications_product_digest_sha256"),
        _hex64("engagement_body_sha256", "ce_context_verifications_engagement_digest_sha256"),
        _check("(test_body_ref IS NULL) = (test_body_sha256 IS NULL)",
               "ce_context_verifications_test_ref_digest_pair"),
        _check("test_body_ref IS NULL OR length(test_body_ref) > 0",
               "ce_context_verifications_test_ref_non_empty"),
        _hex64("test_body_sha256", "ce_context_verifications_test_digest_sha256") if _dialect() == "postgresql"
        else _check("test_body_sha256 IS NULL OR (length(test_body_sha256) = 64 AND test_body_sha256 NOT GLOB '*[^0-9A-Fa-f]*')",
                    "ce_context_verifications_test_digest_sha256"),
    )
    with op.batch_alter_table("engine_operation_requests") as batch:
        batch.add_column(Column("verification_id", _ID, nullable=True))
        batch.create_check_constraint(
            "engine_operation_requests_verification_registration_pair",
            "verification_id IS NULL OR registration_id IS NOT NULL",
        )
        batch.create_foreign_key(
            "fk_engine_operation_requests_registration_verification",
            "ce_context_verifications", ["registration_id", "verification_id"],
            ["registration_id", "verification_id"],
        )


def _downgrade_guard() -> None:
    bind = op.get_bind()
    refs = bind.execute(text(
        "SELECT count(*) FROM engine_operation_requests WHERE verification_id IS NOT NULL"
    )).scalar_one()
    verifications = bind.execute(text("SELECT count(*) FROM ce_context_verifications")).scalar_one()
    configurations = bind.execute(text("SELECT count(*) FROM ce_deployment_configurations")).scalar_one()
    if refs or verifications or configurations:
        raise CommandError("refusing 0008 downgrade: CE configurations, verifications or request references exist")


def downgrade() -> None:
    if context.is_offline_mode():
        raise CommandError("0008 downgrade requires online CE evidence safety checks")
    _dialect()
    _downgrade_guard()
    with op.batch_alter_table("engine_operation_requests") as batch:
        batch.drop_constraint("fk_engine_operation_requests_registration_verification", type_="foreignkey")
        batch.drop_constraint("engine_operation_requests_verification_registration_pair", type_="check")
        batch.drop_column("verification_id")
    op.drop_table("ce_context_verifications")
    op.drop_table("ce_deployment_configurations")
    with op.batch_alter_table("ce_context_registrations") as batch:
        batch.drop_constraint("uq_ce_context_registrations_id_deployment", type_="unique")
