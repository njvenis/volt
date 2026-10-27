"""Polling process entry point for bounded exception warning dispatch."""
from __future__ import annotations

import json
import logging
import os
import signal
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import sqlalchemy as sa

from uvm.assessment.exception_warning_dispatcher import (dispatch_due,
    mark_orphaned_sends_uncertain, warning_health_snapshot)
from uvm.assessment.exception_warning_callbacks import process_received_slack_callbacks
from uvm.assessment.exception_warning_transports import FixtureAdapter, HttpAdapter

LOG = logging.getLogger("uvm.exception_warning_worker")
STOP = False


def _stop(*_):
    global STOP
    STOP = True


def _authority_resolver(engine):
    if os.environ.get("UVM_AUTH_MODE") != "oidc":
        return None
    try:
        raw_principals = json.loads(os.environ.get("UVM_EXCEPTION_WARNING_PRINCIPALS", "{}"))
        if not isinstance(raw_principals, dict):
            raise ValueError("principal map must be an object")
        principals = {}
        for principal_id, record in raw_principals.items():
            if not isinstance(principal_id, str) or not isinstance(record, dict):
                raise ValueError("principal record is invalid")
            scopes = []
            for scope in record.get("scopes", []):
                if isinstance(scope, dict):
                    scope = [scope.get(key) for key in
                        ("source_family", "source_account_id", "scope_key")]
                if (not isinstance(scope, (list, tuple)) or len(scope) != 3
                        or not all(isinstance(value, str) and value for value in scope)):
                    raise ValueError("principal scope is invalid")
                scopes.append(list(scope))
            principals[principal_id] = {"actor_kind": record.get("actor_kind"),
                "role_ids": list(record.get("role_ids", [])), "scopes": scopes}
        from uvm.auth.service import OIDCAuth
        auth = OIDCAuth(engine, principals)
    except Exception as exc:
        raise RuntimeError("current warning recipient authority configuration is unavailable") from exc

    def resolve(connection, principal_id):
        configured = principals.get(principal_id, {})
        if configured.get("actor_kind") == "service":
            context = auth.service_context_for_principal(principal_id)
        else:
            context = auth.linked_actor_context(connection, principal_id)
        if context is None or context.principal_id != principal_id:
            raise RuntimeError("current warning recipient authority is unavailable")
        return context

    return resolve


def _worker_now():
    clock_file = os.environ.get("UVM_G7_TEST_CLOCK_FILE")
    if os.environ.get("UVM_G7_DISPOSABLE_MODE") == "1" and clock_file:
        try:
            value = datetime.fromisoformat(Path(clock_file).read_text(encoding="utf-8").strip().replace("Z", "+00:00"))
            return value.astimezone(timezone.utc)
        except (OSError, ValueError):
            raise RuntimeError("disposable warning worker clock is unavailable") from None
    return datetime.now(timezone.utc)


def main():
    logging.basicConfig(level=os.environ.get("UVM_EXCEPTION_WARNING_LOG_LEVEL", "INFO"))
    database_url = os.environ.get("UVM_DB_URL")
    if not database_url:
        raise SystemExit("UVM_DB_URL is required")
    interval = int(os.environ.get("UVM_EXCEPTION_WARNING_POLL_SECONDS", "15"))
    batch_size = int(os.environ.get("UVM_EXCEPTION_WARNING_BATCH_SIZE", "20"))
    start_delay = int(os.environ.get("UVM_EXCEPTION_WARNING_START_DELAY_SECONDS", "0"))
    if not 1 <= interval <= 300 or not 1 <= batch_size <= 100 or not 0 <= start_delay <= 3600:
        raise SystemExit("warning worker bounds are invalid")
    orphan_threshold = int(os.environ.get("UVM_EXCEPTION_WARNING_ORPHAN_SECONDS", "30"))
    if not 1 <= orphan_threshold <= 3600:
        raise SystemExit("warning worker orphan threshold is invalid")
    engine = sa.create_engine(database_url, pool_pre_ping=True)
    authority_resolver = _authority_resolver(engine)
    LOG.info("worker_ready callback_installation_configured=%s callback_app_configured=%s",
        bool(os.environ.get("UVM_EXCEPTION_WARNING_INSTALLATION_ID")),
        bool(os.environ.get("UVM_EXCEPTION_WARNING_APP_ID")))
    fixture = None
    HttpAdapter.from_environment()  # validate routes and secret references without opening sockets
    if os.environ.get("UVM_G7_DISPOSABLE_MODE") == "1":
        plan = json.loads(os.environ.get("UVM_EXCEPTION_WARNING_FIXTURE_PLAN", "{}"))
        if not isinstance(plan, dict):
            raise SystemExit("warning fixture plan is invalid")
        if os.environ.get("UVM_EXCEPTION_WARNING_USE_LOOPBACK_HTTP") != "1":
            fixture = FixtureAdapter(plan)
    elif os.environ.get("UVM_EXCEPTION_WARNING_USE_LOOPBACK_HTTP") == "1":
        raise SystemExit("loopback HTTP transport is disposable-only")
    intent_ids = None
    raw_intent_ids = os.environ.get("UVM_EXCEPTION_WARNING_TEST_INTENT_IDS")
    if raw_intent_ids:
        if os.environ.get("UVM_G7_DISPOSABLE_MODE") != "1":
            raise SystemExit("warning test intent filter is disposable-only")
        try:
            intent_ids = json.loads(raw_intent_ids)
        except json.JSONDecodeError:
            raise SystemExit("warning test intent filter is invalid") from None
        if (not isinstance(intent_ids, list) or not intent_ids
                or any(not isinstance(item, str) or len(item) != 36 for item in intent_ids)):
            raise SystemExit("warning test intent filter is invalid")
    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)
    for _ in range(start_delay * 10):
        if STOP:
            return
        time.sleep(0.1)
    while not STOP:
        try:
            pause_file = os.environ.get("UVM_EXCEPTION_WARNING_PAUSE_FILE")
            if not pause_file or not Path(pause_file).exists():
                installation_id = os.environ.get("UVM_EXCEPTION_WARNING_INSTALLATION_ID")
                app_id = os.environ.get("UVM_EXCEPTION_WARNING_APP_ID")
                if installation_id and app_id:
                    callbacks = process_received_slack_callbacks(engine, authority_resolver=authority_resolver,
                        installation_id=installation_id, app_id=app_id, now=_worker_now(),
                        limit=batch_size)
                    if callbacks:
                        LOG.info("exception_warning_callbacks_processed count=%s states=%s",
                            len(callbacks), ",".join(sorted({item["state"] for item in callbacks})))
                mark_orphaned_sends_uncertain(engine,
                    before=_worker_now() - timedelta(seconds=orphan_threshold))
                health = warning_health_snapshot(engine, now=_worker_now(),
                    overdue_after_seconds=max(60, interval * 4),
                    abandoned_after_seconds=orphan_threshold)
                if health["status"] != "healthy":
                    LOG.error("exception_warning_worker_health status=%s overdue=%s abandoned=%s missing_alerts=%s",
                        health["status"], health["overdue_intents"],
                        health["abandoned_attempts"], health["missing_failure_alerts"])
                result = dispatch_due(engine, now=_worker_now(), limit=batch_size,
                    fixture_adapter=fixture, authority_resolver=authority_resolver,
                    intent_ids=intent_ids)
                for item in result:
                    # Do not log recipient, secret reference, payload, or receipt.
                    LOG.info("exception_warning_dispatch intent=%s status=%s", item["intent_id"], item["status"])
        except Exception:
            LOG.exception("exception_warning_dispatch_cycle_failed")
        for _ in range(interval * 10):
            if STOP:
                break
            time.sleep(0.1)


if __name__ == "__main__":
    main()
