"""Transaction-scoped coordination for assessment policy readers and writers."""

from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy.engine import Connection

# Readers use the shared form; policy mutations take the exclusive form.
_LOCK_KEY = (0x55564D, 0x475033)


def lock_policy(connection: Connection, *, shared: bool = False) -> None:
    """Coordinate PostgreSQL policy reads/writes without granting UPDATE to readers."""
    if connection.dialect.name != "postgresql":
        return
    function = "pg_advisory_xact_lock_shared" if shared else "pg_advisory_xact_lock"
    connection.execute(sa.text(f"SELECT {function}(:key1, :key2)"),
                       {"key1": _LOCK_KEY[0], "key2": _LOCK_KEY[1]})
