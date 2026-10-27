"""Store occurrence component-locator birth proof (G1 amendment).

This is an additive, self-contained revision.  Existing 0003 occurrences
retain the explicit ``recorded = false`` absence marker: no observation,
timestamp, UUID or current locator is treated as creation proof.
"""

import re

from alembic import context, op
from alembic.util.exc import CommandError
from sqlalchemy import Boolean, column, func, select, table, text, true


revision = "0004"
down_revision = "0003"
branch_labels = None
depends_on = None

_LOCATOR = "birth_component_locator"
_RECORDED = "birth_component_locator_recorded"
_CHECK = "occurrences_birth_component_locator_consistent"


def _dialect() -> str:
    name = op.get_bind().dialect.name
    if name not in ("sqlite", "postgresql"):
        raise CommandError(f"0004 does not support {name}")
    return name


def _sqlite_rebuild(*, forward: bool) -> None:
    """Rebuild occurrences while retaining its complete pre-0004 shape."""
    bind = op.get_bind()
    ddl = bind.execute(text(
        "SELECT sql FROM sqlite_master WHERE type='table' "
        "AND name='occurrences'"
    )).scalar_one_or_none()
    if not ddl:
        raise CommandError("0004 could not find occurrences table")
    indexes = [row[0] for row in bind.execute(text(
        "SELECT sql FROM sqlite_master WHERE type='index' "
        "AND tbl_name='occurrences' AND sql IS NOT NULL ORDER BY name"
    ))]
    temp = "occurrences__0004"
    ddl, count = re.subn(
        r'CREATE TABLE "?occurrences"? \(',
        f"CREATE TABLE {temp} (", ddl, count=1)
    if count != 1:
        raise CommandError("unexpected occurrences DDL")

    if forward:
        marker = (
            f"{_LOCATOR} VARCHAR, {_RECORDED} BOOLEAN NOT NULL DEFAULT 0,"
        )
        first_constraint = ddl.index("CONSTRAINT pk_occurrences")
        ddl = (ddl[:first_constraint] + marker + "\n\t" +
               ddl[first_constraint:])
        ddl = ddl[:ddl.rfind(")")] + \
            f",\n\tCONSTRAINT {_CHECK} CHECK ("
        ddl += (
            f"{_RECORDED} IN (0, 1) AND (({_RECORDED} = 0 AND "
            f"{_LOCATOR} IS NULL) OR {_RECORDED} = 1))\n)"
        )
    else:
        start = re.search(rf',\s*CONSTRAINT {re.escape(_CHECK)} CHECK \(', ddl)
        if start is None:
            raise CommandError(f"missing 0004 constraint {_CHECK}")
        pos, depth = start.end() - 1, 0
        for end in range(pos, len(ddl)):
            if ddl[end] == "(":
                depth += 1
            elif ddl[end] == ")":
                depth -= 1
                if depth == 0:
                    ddl = ddl[:start.start()] + ddl[end + 1:]
                    break
        else:
            raise CommandError("unbalanced 0004 CHECK")
        # Remove the two columns from the column list.  They are adjacent and
        # have no commas in their definitions.
        ddl, removed = re.subn(
            rf'\s*{re.escape(_LOCATOR)}\s+[^,]+,\s*'
            rf'{re.escape(_RECORDED)}\s+[^,]+,', "", ddl, count=1)
        if removed != 1:
            raise CommandError("missing 0004 birth-locator columns")

    columns = [row[1] for row in bind.exec_driver_sql(
        "PRAGMA table_info(occurrences)")]
    if not forward:
        columns = [c for c in columns if c not in (_LOCATOR, _RECORDED)]
    names = ", ".join(columns)
    bind.exec_driver_sql(ddl)
    bind.exec_driver_sql(
        f"INSERT INTO {temp} ({names}) SELECT {names} FROM occurrences")
    bind.exec_driver_sql("DROP TABLE occurrences")
    bind.exec_driver_sql(f"ALTER TABLE {temp} RENAME TO occurrences")
    for index_sql in indexes:
        bind.exec_driver_sql(index_sql)
    violations = bind.exec_driver_sql("PRAGMA foreign_key_check").fetchall()
    if violations:
        raise CommandError(
            f"0004 occurrences rebuild failed foreign_key_check: "
            f"{violations[:3]}")


def _pg_upgrade() -> None:
    op.execute(text(
        "ALTER TABLE occurrences "
        f"ADD COLUMN {_LOCATOR} VARCHAR, "
        f"ADD COLUMN {_RECORDED} BOOLEAN NOT NULL DEFAULT FALSE, "
        f"ADD CONSTRAINT {_CHECK} CHECK ("
        f"{_RECORDED} IN (FALSE, TRUE) AND (({_RECORDED} = FALSE AND "
        f"{_LOCATOR} IS NULL) OR {_RECORDED} = TRUE))"
    ))


def _pg_downgrade() -> None:
    op.execute(text(
        "ALTER TABLE occurrences "
        f"DROP CONSTRAINT {_CHECK}, "
        f"DROP COLUMN {_RECORDED}, DROP COLUMN {_LOCATOR}"
    ))


def _downgrade_guard_statement():
    occurrences_table = table(
        "occurrences", column(_RECORDED, Boolean()))
    return select(func.count()).select_from(occurrences_table).where(
        column(_RECORDED, Boolean()) == true())


def _downgrade_guard() -> None:
    count = op.get_bind().execute(_downgrade_guard_statement()).scalar_one()
    if count:
        raise CommandError(
            f"refusing 0004 downgrade: {count} captured birth proof row(s) "
            "would be lost")


def upgrade() -> None:
    if context.is_offline_mode():
        raise CommandError(
            "0004 upgrade requires online quiescence/preflight and cannot "
            "render safe backfill SQL offline")
    if _dialect() == "sqlite":
        _sqlite_rebuild(forward=True)
    else:
        _pg_upgrade()


def downgrade() -> None:
    if context.is_offline_mode():
        raise CommandError(
            "0004 downgrade requires online safety checks for captured proof")
    _downgrade_guard()
    if _dialect() == "sqlite":
        _sqlite_rebuild(forward=False)
    else:
        _pg_downgrade()
