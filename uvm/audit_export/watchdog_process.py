"""Independent watchdog process with an optional external notifier command."""

from __future__ import annotations

import json
import os
import subprocess
import time
from datetime import datetime, timezone

from .process_config import load_factory, required
from .watchdog import check_watchdog


def _notify(alert: str) -> None:
    raw = os.environ.get("G3_NOTIFY_COMMAND")
    if not raw:
        print(json.dumps({"notification": alert}), flush=True)
        return
    # JSON argv avoids shell interpolation and allows a controlled local notifier
    # executable (or a deliberate /bin/false failure fixture).
    argv = json.loads(raw)
    if not isinstance(argv, list) or not argv or not all(isinstance(x, str) for x in argv):
        raise ValueError("G3_NOTIFY_COMMAND must be a non-empty JSON string array")
    completed = subprocess.run([*argv, alert], check=False, timeout=10, capture_output=True, text=True)
    if completed.returncode:
        detail = completed.stderr.strip() or f"exit {completed.returncode}"
        raise RuntimeError(f"notifier failed: {detail}")


def main() -> int:
    backlog_count = load_factory("G3_BACKLOG_COUNT_FACTORY")()
    health_dsn = required("G3_EXPORT_HEALTH_DB_URL")
    stale_after = int(os.environ.get("G3_WATCHDOG_STALE_SECONDS", "15"))
    interval = float(os.environ.get("G3_WATCHDOG_INTERVAL_SECONDS", "5"))
    once = os.environ.get("G3_WATCHDOG_ONCE") == "1"
    if interval < 0.1:
        raise ValueError("G3_WATCHDOG_INTERVAL_SECONDS must be at least 0.1")
    while True:
        result = check_watchdog(health_dsn, stale_after_seconds=stale_after,
                                backlog_count=backlog_count, notify=_notify)
        print(json.dumps({"at": datetime.now(timezone.utc).isoformat(), **result}), flush=True)
        if once:
            return 2 if result["heartbeat_error"] or result["backlog_error"] else 0
        time.sleep(interval)


if __name__ == "__main__":
    raise SystemExit(main())
