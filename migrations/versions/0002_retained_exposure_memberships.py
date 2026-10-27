"""Second additive G1 migration (FR-ID-02/CR-03 amendment): the
retained exposure/workload pair table
``exposure_workload_memberships`` (docs/g1-membership-correction-
schema-amendment.md).

Revision ID: 0002
Revises: 0001
Create Date: 2026-09-28

Data-preserving revision; self-contained frozen DDL in the 0001
pattern — no ``uvm/persistence`` metadata import. Revision 0001 stays
frozen and byte-identical.

This revision implements the retained historical key:

* CREATE ``exposure_workload_memberships(exposure_id, workload_id)``
  with a named composite PK and STABLE-ID single-column FKs to
  ``exposures.exposure_id`` and ``workloads.workload_id`` — never the
  exposure's current (exposure_id, workload_id) composite pair, so an
  old pair stays valid after a correction moves the exposure.
* Backfill each exposure's current pair from ``exposures`` (each
  exposure_id is a primary key, so the pairs are unique; no conflict
  path).
* Refuse inconsistent legacy resolution chains before backfill, then
  move only the historical resolution composite FK to the retained pair.
  SQLite rebuilds that table inside one migration transaction; PostgreSQL
  replaces the named constraint.
* Safe downgrade to 0001: refuse (CommandError, nothing dropped) if
  any retained pair differs from the exposure's current pair — after a
  correction, rolling back 0001 would discard corrected historical
  evidence.

* On PostgreSQL, re-emit the current-membership occurrence FK
  ``fk_occurrences_exposure_id_workload_id_exposures`` as ``DEFERRABLE
  INITIALLY IMMEDIATE`` (0001 created it immediate): a guarded correction
  transaction may defer it only for its transient move, everything else
  stays immediate. The downgrade restores the immediate form. The head
  metadata renders this same dialect-specific form (``
  _DeferrableOnPostgresFK`` in uvm/persistence/schema.py renders the
  deferral keywords on PostgreSQL only), so the create_all head and the
  migrated head agree. SQLite renders the immediate form in the head
  metadata and defers via the correction-transaction
  ``PRAGMA defer_foreign_keys=ON`` route, so no SQLite DDL is emitted for
  it here (the writer owns that pragma; it is not a DDL change).
* An offline 0001 -> 0002 upgrade is refused (CommandError): rendered SQL
  cannot execute the pre-backfill history guard, so it must not be emitted
  without that guard.

PostgreSQL execution remains integration-unverified.
"""

import re

from alembic import context, op
from alembic.util.exc import CommandError
from sqlalchemy import (
    Column,
    ForeignKey,
    MetaData,
    Table,
    Uuid,
    text,
)
from sqlalchemy.schema import CreateTable, DropTable

# Same ID rendering and naming convention as the frozen 0001 DDL.
_ID = Uuid(as_uuid=False)

uvm_metadata_0002 = MetaData(
    naming_convention={
        "pk": "pk_%(table_name)s",
        "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
        "uq": "uq_%(table_name)s_%(column_0_name)s",
        "ix": "ix_%(table_name)s_%(column_0_name)s",
        "ck": "ck_%(table_name)s",
    }
)

# Reference-only stubs so the stable-ID FK strings resolve inside THIS
# revision's metadata (the 0001 pattern keeps every revision
# self-contained: it never imports product metadata). 0001 owns these
# tables' DDL; 0002 emits nothing for them.
_exposures_stub = Table(
    "exposures", uvm_metadata_0002,
    Column("exposure_id", _ID, primary_key=True),
)
_workloads_stub = Table(
    "workloads", uvm_metadata_0002,
    Column("workload_id", _ID, primary_key=True),
)

# Historical pair key: stable-ID FKs (not the exposure's current
# composite pair), so a retained pair remains valid after the exposure
# moves.
exposure_workload_memberships = Table(
    "exposure_workload_memberships",
    uvm_metadata_0002,
    Column("exposure_id", _ID, ForeignKey("exposures.exposure_id"),
           primary_key=True),
    Column("workload_id", _ID, ForeignKey("workloads.workload_id"),
           primary_key=True),
)

# revision identifiers, used by Alembic.
revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None

_OLD_FK = "fk_identity_resolutions_exposure_id_workload_id_exposures"
_NEW_FK = "fk_identity_resolutions_exposure_memberships"
# Frozen 0001 name for the current-membership occurrence composite FK.
_OCCURRENCE_FK = "fk_occurrences_exposure_id_workload_id_exposures"


def _pg_occurrence_fk_sql(*, deferrable: bool) -> str:
    """PostgreSQL DDL replacing the current-membership occurrence FK.

    ``DEFERRABLE INITIALLY IMMEDIATE`` lets a guarded correction
    transaction defer this one FK for its transient exposure move; the
    default stays immediate, and the downgrade restores 0001's immediate
    form (``NOT DEFERRABLE`` is the PostgreSQL default).
    """
    deferral = ("DEFERRABLE INITIALLY IMMEDIATE" if deferrable
                else "NOT DEFERRABLE INITIALLY IMMEDIATE")
    return (
        f"ALTER TABLE occurrences "
        f"DROP CONSTRAINT {_OCCURRENCE_FK}, "
        f"ADD CONSTRAINT {_OCCURRENCE_FK} "
        f"FOREIGN KEY (exposure_id, workload_id) "
        f"REFERENCES exposures (exposure_id, workload_id) {deferral}"
    )


def _replace_occurrence_fk(*, deferrable: bool) -> None:
    """PostgreSQL only: make the current-membership occurrence FK
    deferrable (upgrade) or restore its immediate form (downgrade).
    SQLite defers via the correction-transaction pragma instead and needs
    no DDL change; any other dialect is unsupported by this revision.
    """
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        op.execute(text(_pg_occurrence_fk_sql(deferrable=deferrable)))
    elif bind.dialect.name != "sqlite":
        raise CommandError(
            f"0002 occurrence FK deferral does not support "
            f"{bind.dialect.name}")


def _check_existing_history() -> None:
    """Do not backfill a current pair over an incoherent legacy selection.
    Online only: upgrade() refuses offline rendering before reaching
    this guard, so a guarded database inspection always runs here."""
    bind = op.get_bind()
    if bind.dialect.name == "sqlite":
        # FK enforcement was disabled before BEGIN for the rebuild. Detect
        # any already-broken 0001 references before creating the pair table.
        violations = bind.exec_driver_sql(
            "PRAGMA foreign_key_check").fetchall()
        if violations:
            raise CommandError(
                "refusing to upgrade 0001 -> 0002: existing foreign key "
                f"violations: {violations[:3]}")
    bad = bind.execute(text(
        "SELECT COUNT(*) FROM identity_resolutions AS r "
        "LEFT JOIN exposures AS e ON e.exposure_id = r.exposure_id "
        "LEFT JOIN incarnations AS i ON i.incarnation_id = r.incarnation_id "
        "LEFT JOIN occurrences AS o ON o.occurrence_id = r.occurrence_id "
        "WHERE r.outcome IN ('matched', 'new') AND ("
        "e.exposure_id IS NULL OR e.workload_id <> r.workload_id "
        "OR e.group_id <> r.group_id "
        "OR i.incarnation_id IS NULL OR i.workload_id <> r.workload_id "
        "OR o.occurrence_id IS NULL OR o.exposure_id <> r.exposure_id "
        "OR o.incarnation_id <> r.incarnation_id "
        "OR o.workload_id <> r.workload_id)"
    )).scalar_one()
    if bad:
        raise CommandError(
            f"refusing to upgrade 0001 -> 0002: {bad} existing "
            "identity resolution(s) have an inconsistent selected chain")


def _sqlite_rebuild_resolution(old_fk: str, new_fk: str,
                               old_target: str, new_target: str) -> None:
    """Replace only the historical FK, retaining frozen 0001 DDL verbatim.

    The env disables SQLite FK enforcement before its explicit migration
    transaction. Rebuild with a temporary self-reference so rename updates
    that reference to the final table name.
    """
    bind = op.get_bind()
    row = bind.execute(text(
        "SELECT sql FROM sqlite_master WHERE type = 'table' "
        "AND name = 'identity_resolutions'"
    )).scalar_one()
    indexes = [r[0] for r in bind.execute(text(
        "SELECT sql FROM sqlite_master WHERE type = 'index' "
        "AND tbl_name = 'identity_resolutions' AND sql IS NOT NULL "
        "ORDER BY name"
    ))]
    temp = "identity_resolutions__0002"
    ddl, create_count = re.subn(
        r'CREATE TABLE "?identity_resolutions"? \(',
        f"CREATE TABLE {temp} (", row, count=1)
    if create_count != 1:
        raise CommandError("unexpected identity_resolutions table DDL")
    old_clause = (
        f"CONSTRAINT {old_fk} FOREIGN KEY(exposure_id, workload_id) "
        f"REFERENCES {old_target} (exposure_id, workload_id)"
    )
    new_clause = (
        f"CONSTRAINT {new_fk} FOREIGN KEY(exposure_id, workload_id) "
        f"REFERENCES {new_target} (exposure_id, workload_id)"
    )
    if ddl.count(old_clause) != 1:
        raise CommandError("unexpected identity_resolutions composite FK DDL")
    ddl = ddl.replace(old_clause, new_clause, 1)
    ddl, self_ref_count = re.subn(
        r'REFERENCES "?identity_resolutions"? \(resolution_id\)',
        f"REFERENCES {temp} (resolution_id)", ddl, count=1)
    if self_ref_count != 1:
        raise CommandError("unexpected identity_resolutions self-FK DDL")
    columns = [r[1] for r in bind.exec_driver_sql(
        "PRAGMA table_info(identity_resolutions)")]
    if not columns:
        raise CommandError("identity_resolutions has no columns")
    names = ", ".join(columns)
    bind.exec_driver_sql(ddl)
    bind.exec_driver_sql(
        f"INSERT INTO {temp} ({names}) SELECT {names} "
        "FROM identity_resolutions")
    bind.exec_driver_sql("DROP TABLE identity_resolutions")
    bind.exec_driver_sql(
        f"ALTER TABLE {temp} RENAME TO identity_resolutions")
    for index_sql in indexes:
        bind.exec_driver_sql(index_sql)
    violations = bind.exec_driver_sql("PRAGMA foreign_key_check").fetchall()
    if violations:
        raise CommandError(
            "identity_resolutions rebuild failed foreign_key_check: "
            f"{violations[:3]}")


def _replace_resolution_fk(*, forward: bool) -> None:
    bind = op.get_bind()
    old_fk, new_fk = (_OLD_FK, _NEW_FK) if forward else (_NEW_FK, _OLD_FK)
    old_target, new_target = (
        ("exposures", "exposure_workload_memberships") if forward
        else ("exposure_workload_memberships", "exposures")
    )
    if bind.dialect.name == "sqlite":
        _sqlite_rebuild_resolution(old_fk, new_fk, old_target, new_target)
    elif bind.dialect.name == "postgresql":
        op.execute(text(
            "ALTER TABLE identity_resolutions "
            f"DROP CONSTRAINT {old_fk}, "
            f"ADD CONSTRAINT {new_fk} "
            "FOREIGN KEY (exposure_id, workload_id) "
            f"REFERENCES {new_target} (exposure_id, workload_id)"
        ))
    else:
        raise CommandError(
            f"0002 identity resolution FK migration does not support "
            f"{bind.dialect.name}")


def upgrade() -> None:
    if context.is_offline_mode():
        raise CommandError(
            "refusing an offline 0001 -> 0002 upgrade: this revision "
            "inspects existing identity resolution history before "
            "backfilling and rebuilds identity_resolutions, which "
            "rendered SQL cannot guard or verify. Run the upgrade "
            "online.")
    _check_existing_history()
    op.execute(CreateTable(exposure_workload_memberships))
    # Backfill the current pair from exposures. exposure_id is the
    # exposures primary key, so each emitted (exposure_id, workload_id)
    # pair is unique — no conflict path.
    op.execute(text(
        "INSERT INTO exposure_workload_memberships "
        "(exposure_id, workload_id) "
        "SELECT exposure_id, workload_id FROM exposures"))
    _replace_resolution_fk(forward=True)
    _replace_occurrence_fk(deferrable=True)


def downgrade() -> None:
    if context.is_offline_mode():
        raise CommandError(
            "0002 -> 0001 downgrade requires an online database "
            "to verify retained pairs before dropping history")
    bind = op.get_bind()
    divergent = bind.execute(text(
        "SELECT COUNT(*) "
        "FROM exposure_workload_memberships AS m "
        "LEFT JOIN exposures AS e ON e.exposure_id = m.exposure_id "
        "WHERE e.exposure_id IS NULL "
        "OR m.workload_id <> e.workload_id")).scalar()
    if divergent:
        raise CommandError(
            "refusing to downgrade 0002 -> 0001: "
            f"{divergent} retained exposure_workload_memberships pair(s) "
            "differ from the exposure's current workload; a correction "
            "has run, so dropping the pair table would discard "
            "historical evidence. Retain the 0002 reader or apply a "
            "forward fix instead.")
    _replace_resolution_fk(forward=False)
    _replace_occurrence_fk(deferrable=False)
    op.execute(DropTable(exposure_workload_memberships))
