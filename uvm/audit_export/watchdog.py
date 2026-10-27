"""Independent sink-backed exporter heartbeat and notification watchdog."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Callable

import psycopg


def record_heartbeat(health_dsn: str, exporter_id: str, *, connect=psycopg.connect) -> None:
    """Called by the separately supervised exporter process after a completed poll."""
    with connect(health_dsn) as conn:
        conn.execute(
            """INSERT INTO uvm_audit_export.heartbeats(exporter_id, seen_at)
               VALUES (%s, %s) ON CONFLICT (exporter_id) DO UPDATE SET seen_at=EXCLUDED.seen_at""",
            (exporter_id, datetime.now(timezone.utc)),
        )


def check_watchdog(health_dsn: str, *, stale_after_seconds: int = 15,
                   backlog_count: Callable[[], int], notify: Callable[[str], None],
                   connect=psycopg.connect) -> dict[str, object]:
    """Read health using its own credential; report notification errors separately."""
    if stale_after_seconds <= 0:
        raise ValueError("stale_after_seconds must be positive")
    heartbeat_error = None
    try:
        with connect(health_dsn) as conn:
            row = conn.execute(
                "SELECT seen_at FROM uvm_audit_export.heartbeats ORDER BY seen_at DESC LIMIT 1"
            ).fetchone()
    except Exception as exc:  # health and source/backlog dimensions must fail independently
        row = None
        heartbeat_error = {"error_type": type(exc).__name__, "sqlstate": getattr(exc, "sqlstate", None)}
    now = datetime.now(timezone.utc)
    heartbeat = row[0] if row else None
    age = None if heartbeat is None else max(0.0, (now - heartbeat).total_seconds())
    try:
        backlog = backlog_count()
        backlog_error = None
    except Exception as exc:  # health dimensions remain independent
        backlog, backlog_error = None, {"error_type": type(exc).__name__,
                                         "sqlstate": getattr(exc, "sqlstate", None)}
    alerts = []
    if heartbeat_error is not None:
        alerts.append("exporter_heartbeat_unavailable")
    elif age is None or age > stale_after_seconds:
        alerts.append("exporter_heartbeat_stale")
    if backlog is None or backlog > 0:
        alerts.append("audit_export_backlog")
    notification_error = None
    if alerts:
        try:
            notify(",".join(alerts))
        except Exception as exc:
            notification_error = {"error_type": type(exc).__name__,
                                  "sqlstate": getattr(exc, "sqlstate", None)}
    return {"heartbeat_age_seconds": age, "heartbeat_error": heartbeat_error, "backlog": backlog,
            "backlog_error": backlog_error, "alerts": alerts,
            "notification_error": notification_error}
