"""Long-running exporter process, independently supervised from its watchdog."""

from __future__ import annotations

import json
import os
import signal
import time
from datetime import datetime, timezone

from .exporter import AuditExporter, AuditSinkConnectionError
from .integrity import AuditAnchorAuthority
from .process_config import load_factory, required
from .watchdog import record_heartbeat


def main() -> int:
    source = load_factory("G3_AUDIT_SOURCE_FACTORY")()
    exporter = AuditExporter(required("G3_EXPORT_DB_URL"), source,
        anchor_authority=AuditAnchorAuthority(required("G7_AUDIT_ANCHOR_DSN")))
    health_dsn = required("G3_EXPORT_HEALTH_DB_URL")
    exporter_id = required("G3_EXPORTER_ID")
    interval = float(os.environ.get("G3_EXPORT_POLL_SECONDS", "5"))
    limit = int(os.environ.get("G3_EXPORT_BATCH_LIMIT", "100"))
    if interval < 0.1:
        raise ValueError("G3_EXPORT_POLL_SECONDS must be at least 0.1")
    if not 1 <= limit <= 5000:
        raise ValueError("G3_EXPORT_BATCH_LIMIT must be between 1 and 5000")
    stopping = False

    def stop(_signum, _frame):
        nonlocal stopping
        stopping = True

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    while not stopping:
        try:
            result = exporter.export_once(limit)
        except AuditSinkConnectionError as exc:
            # Identify failures raised specifically by psycopg.connect to the
            # sink, without misclassifying source-reader failures as sink outage.
            print(json.dumps({"event": "audit_export_poll_failed",
                              "stage": "sink_connect",
                              "sqlstate": exc.sqlstate,
                              "error_type": exc.error_type}), flush=True)
            raise
        record_heartbeat(health_dsn, exporter_id)
        print(json.dumps({"at": datetime.now(timezone.utc).isoformat(), "export": result.__dict__}), flush=True)
        if not stopping:
            time.sleep(interval)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
