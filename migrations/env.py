"""Alembic environment for the UVM separate-database metadata (G1).

Single target metadata: the 13-table ``uvm_metadata`` shared by
``uvm/persistence/{schema,observation_schema,lineage_schema,
alias_schema}.py``. No DefectDojo CE tables (CR-01). The import of
``alias_schema`` pulls the whole registration
chain (core -> observation -> lineage -> alias). This import is
reserved for future autogenerate of LATER revisions: the frozen
revision 0001 carries its own self-contained DDL and never uses
``target_metadata`` at run time. Revision 0002 backfills retained
membership pairs. SQLite migrations use one explicit
transaction with foreign keys disabled before BEGIN for the 0002
resolution-table rebuild; foreign_key_check runs before commit.

URL resolution: ``sqlalchemy.url`` in alembic.ini (intentionally blank
in the committed file) wins; otherwise the ``UVM_DB_URL`` environment
variable. Both blank is a clear error, online or offline (offline SQL
rendering needs a URL for the dialect even though it makes no
connection).
"""

import os
import sys
from pathlib import Path

from alembic import context
from sqlalchemy import engine_from_config, pool

# Make the project root importable regardless of alembic's launch directory.
PROJECT_ROOT = str(Path(__file__).resolve().parent.parent)
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

import uvm.persistence.alias_schema  # noqa: F401  registers all 13 tables
import uvm.persistence.assessment_schema  # noqa: F401 registers additive G3 metadata
import uvm.persistence.deadline_reference_schema  # noqa: F401 supplied history companion
import uvm.persistence.auth_schema  # noqa: F401 registers G7 OIDC authority metadata
import uvm.persistence.native_authority_schema  # noqa: F401 registers native authority reconciliation metadata
import uvm.persistence.connector_schema  # noqa: F401 registers G7 connector metadata
import uvm.persistence.incident_schema  # noqa: F401 registers additive G7 incident projection
import uvm.persistence.observer_settings_schema  # noqa: F401 registers G7 observer settings
from uvm.persistence.schema import uvm_metadata  # noqa: E402

config = context.config
target_metadata = uvm_metadata


def _migration_fault_callbacks():
    """Allow disposable PostgreSQL tests to fail inside a named revision txn."""
    target = os.environ.get("UVM_G7_TEST_FAIL_AFTER_REVISION")
    if target is None:
        return []
    if target not in {"0059", "0060", "0061", "0062"}:
        raise RuntimeError("unsupported G7 migration test fault boundary")

    def fail_after_revision(*, ctx, step, heads, run_args):
        if target in step.up_revision_ids:
            raise RuntimeError("G7_TEST_MIGRATION_BOUNDARY_FAILURE revision=" + target)

    return [fail_after_revision]


_MIGRATION_FAULT_CALLBACKS = _migration_fault_callbacks()


def _resolve_url() -> str:
    """Committed alembic.ini keeps the URL blank; per-environment it
    comes from ``sqlalchemy.url`` or the ``UVM_DB_URL`` environment
    variable."""
    # Alembic's ConfigParser interpolation treats a URL-encoded password
    # marker such as ``%40`` as an interpolation directive. Read this one
    # value raw so SQLAlchemy receives the exact URL configured in the INI.
    url = (config.file_config.get("alembic", "sqlalchemy.url", raw=True)
           or "").strip()
    if not url:
        url = os.environ.get("UVM_DB_URL", "").strip()
    if not url:
        raise RuntimeError(
            "UVM database URL is not set: put it in sqlalchemy.url in "
            "alembic.ini or export UVM_DB_URL (see alembic.ini header)")
    return url


def run_migrations_offline() -> None:
    context.configure(
        url=_resolve_url(),
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    url = _resolve_url()
    connectable = engine_from_config(
        {"sqlalchemy.url": url},
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    with connectable.connect() as connection:
        if connection.dialect.name == "sqlite":
            # PRAGMA foreign_keys cannot change inside a transaction.
            connection.exec_driver_sql("PRAGMA foreign_keys=OFF")
            connection.commit()
            context.configure(connection=connection,
                              target_metadata=target_metadata,
                              on_version_apply=_MIGRATION_FAULT_CALLBACKS,
                              transactional_ddl=True)
            try:
                with context.begin_transaction():
                    # pysqlite defers its actual BEGIN for DDL. An explicit
                    # BEGIN makes the table rebuild and stamp atomic.
                    connection.exec_driver_sql("BEGIN")
                    context.run_migrations()
                    violations = connection.exec_driver_sql(
                        "PRAGMA foreign_key_check").fetchall()
                    if violations:
                        raise RuntimeError(
                            f"migration foreign_key_check failed: "
                            f"{violations[:3]}")
            finally:
                connection.exec_driver_sql("PRAGMA foreign_keys=ON")
                connection.commit()
        else:
            context.configure(connection=connection,
                              target_metadata=target_metadata,
                              on_version_apply=_MIGRATION_FAULT_CALLBACKS)
            with context.begin_transaction():
                context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
