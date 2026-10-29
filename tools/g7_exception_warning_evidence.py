"""Read-only evidence export for callback inbox outcomes in disposable G7 runs."""
from __future__ import annotations

import json
import os
from pathlib import Path
import sys

import sqlalchemy as sa

from uvm.persistence.exception_sla_schema import exception_warning_callback_inbox


def main() -> None:
    if os.environ.get("UVM_G7_DISPOSABLE_MODE") != "1":
        raise SystemExit("callback evidence export is restricted to disposable mode")
    ids = [value for value in sys.argv[1:] if value]
    if not ids:
        raise SystemExit("callback inbox IDs are required")
    engine = sa.create_engine(sa.URL.create("postgresql+psycopg", username="uvm_app",
        password=Path("/run/secrets/uvm_db_password").read_text().strip(),
        host="127.0.0.1", port=5432, database="uvm"))
    with engine.connect() as connection:
        rows = connection.execute(sa.select(exception_warning_callback_inbox).where(
            exception_warning_callback_inbox.c.inbox_id.in_(ids)).order_by(
                exception_warning_callback_inbox.c.received_at)).mappings().all()
    print(json.dumps([{"inbox_id": row["inbox_id"], "state": row["state"],
        "result": row["result"], "attempt_count": row["attempt_count"]} for row in rows],
        sort_keys=True, separators=(",", ":")))


if __name__ == "__main__":
    main()
