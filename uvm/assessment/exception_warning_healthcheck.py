"""Independent, read-only database health check for warning backlog integrity."""
from __future__ import annotations

import json
import os
from pathlib import Path

import sqlalchemy as sa
from sqlalchemy.engine import URL

from uvm.assessment.exception_warning_dispatcher import warning_health_snapshot


def main() -> int:
    password_path = Path(os.environ.get("UVM_DB_PASSWORD_FILE", "/run/secrets/uvm_db_password"))
    password = password_path.read_text(encoding="utf-8").strip()
    url = URL.create("postgresql+psycopg", username="uvm_app", password=password,
        host="127.0.0.1", port=5432, database="uvm")
    engine = sa.create_engine(url, pool_pre_ping=True)
    try:
        snapshot = warning_health_snapshot(engine)
    finally:
        engine.dispose()
    print(json.dumps(snapshot, sort_keys=True, separators=(",", ":")))
    return 0 if snapshot["status"] == "healthy" else 1


if __name__ == "__main__":
    raise SystemExit(main())
