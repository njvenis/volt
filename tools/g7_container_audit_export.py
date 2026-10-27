#!/usr/bin/env python3
"""Narrow host-invoked bridge to the existing committed audit export contract."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
from urllib.parse import quote
from uuid import UUID

from uvm.assessment.audit_export import make_audit_export_source


def configure_source():
    observer_dsn = os.environ.get("G7_AUDIT_READ_DSN")
    if observer_dsn:
        os.environ["UVM_DB_URL"] = observer_dsn
        os.environ["UVM_G3_EXPORT_PRINCIPAL"] = os.environ.get("UVM_G7_EXPORT_PRINCIPAL", "g3-exporter")
        return make_audit_export_source()
    password_file = Path("/run/uvm-g7-secrets/uvm_db_password")
    # The baseline image predates the runtime's narrowed secret copy. During
    # rollback/upgrade rehearsal its disposable secret is still supplied by
    # the existing read-only /run/secrets mount.
    if not password_file.is_file():
        password_file = Path("/run/secrets/uvm_db_password")
    if not password_file.is_file():
        raise RuntimeError("dedicated UVM exporter credential is unavailable")
    password = quote(password_file.read_text().strip(), safe="")
    os.environ["UVM_DB_URL"] = f"postgresql+psycopg://uvm_app:{password}@127.0.0.1:5432/uvm"
    os.environ["UVM_G3_EXPORT_PRINCIPAL"] = os.environ.get("UVM_G7_EXPORT_PRINCIPAL", "g3-exporter")
    return make_audit_export_source()


def main() -> int:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    pending = sub.add_parser("pending")
    pending.add_argument("--limit", type=int, default=100)
    backlog = sub.add_parser("backlog")
    event = sub.add_parser("event")
    event.add_argument("event_id")
    history = sub.add_parser("history")
    history.add_argument("--sink-id", default="g7-siem")
    ack = sub.add_parser("ack")
    ack.add_argument("event_id")
    ack.add_argument("receipt")
    siem = sub.add_parser("siem-export")
    siem.add_argument("--limit", type=int, default=100)
    siem.add_argument("--sink-id", default="g7-siem")
    siem_backlog = sub.add_parser("siem-backlog")
    siem_backlog.add_argument("--sink-id", default="g7-siem")
    args = parser.parse_args()
    source = configure_source()
    if args.command == "pending":
        events = source.list_unexported_audit_events(args.limit)
        print(json.dumps(events, sort_keys=True, separators=(",", ":"), default=lambda x: x.isoformat()))
    elif args.command == "backlog":
        print(json.dumps({"backlog": source.backlog_count()}, sort_keys=True))
    elif args.command == "event":
        event_id = str(UUID(args.event_id))
        rows, found, after = [], None, 0
        total = source.count_authorised_audit_events()
        while len(rows) < total:
            page = source.list_authorised_audit_page(5000, after)
            if not page:
                raise RuntimeError("authorised audit event lookup stalled during pagination")
            for row in page:
                after = int(row["event_sequence"])
                rows.append(row)
                if str(row["event_id"]) == event_id:
                    found = row
        if found is None:
            raise PermissionError("audit event is outside the export principal's current scope")
        print(json.dumps(found, sort_keys=True, separators=(",", ":"), default=lambda x: x.isoformat()))
    elif args.command == "history":
        from uvm.audit_export.exporter import EVENT_FIELDS, _event_payload
        from uvm.persistence.assessment_schema import assessment_audit_events, assessment_sink_export_receipts
        import sqlalchemy as sa
        rows = []
        receipt = assessment_sink_export_receipts
        event = assessment_audit_events
        with source.engine.connect() as connection:
            total = int(connection.execute(sa.select(sa.func.count()).select_from(event)).scalar_one())
        after = 0
        fixture_fail_after = os.environ.get("G7_AUDIT_FIXTURE_FAIL_PAGE_AFTER")
        if fixture_fail_after is not None:
            if os.environ.get("UVM_G7_DISPOSABLE_MODE") != "1":
                raise RuntimeError("fixture pagination fault is available only in disposable mode")
            fixture_fail_after = int(fixture_fail_after)
            if fixture_fail_after < 0:
                raise RuntimeError("fixture pagination fault count must be non-negative")
        pages_read = 0
        while len(rows) < total:
            if fixture_fail_after is not None and pages_read >= fixture_fail_after:
                raise RuntimeError("fixture-injected audit history pagination interruption")
            query = (sa.select(*(event.c[name] for name in EVENT_FIELDS), receipt.c.sink_receipt)
                .select_from(event.outerjoin(receipt, sa.and_(
                    receipt.c.event_id == event.c.event_id,
                    receipt.c.sink_id == args.sink_id)))
                .where(event.c.event_sequence > after)
                .order_by(event.c.event_sequence).limit(5000))
            with source.engine.connect() as connection:
                page = connection.execute(query).mappings().all()
            if not page:
                raise RuntimeError(f"independent source pagination stalled at {len(rows)}/{total}")
            for row in page:
                item = {key: row[key] for key in EVENT_FIELDS}
                item = _event_payload(item)
                after = int(item["event_sequence"])
                rows.append({"event": item, "sink_receipt": row["sink_receipt"]})
            if after <= 0:
                raise RuntimeError("independent source pagination cursor did not advance")
            pages_read += 1
        with source.engine.connect() as connection:
            final_total = int(connection.execute(sa.select(sa.func.count()).select_from(event)).scalar_one())
        if len(rows) != total or final_total != total:
            raise RuntimeError(f"independent source total changed during pagination: {total}/{len(rows)}/{final_total}")
        print(json.dumps({"schema_version": 1, "items": rows, "count": total},
            sort_keys=True, separators=(",", ":"), default=lambda x: x.isoformat()))
    elif args.command == "ack":
        event_id = str(UUID(args.event_id))
        inserted = source.acknowledge_export(event_id, args.receipt, datetime.now(timezone.utc))
        print(json.dumps({"event_id": event_id, "acknowledged": inserted}, sort_keys=True))
    elif args.command == "siem-backlog":
        print(json.dumps({"sink_id": args.sink_id,
                          "backlog": source.sink_backlog_count(args.sink_id)}, sort_keys=True))
    else:
        from uvm.audit_export.exporter import AuditExporter
        from uvm.audit_export.integrity import AuditAnchorAuthority
        dsn = os.environ.get("G7_SIEM_DSN")
        if not dsn:
            raise RuntimeError("G7_SIEM_DSN is required for the independently credentialled SIEM sink")
        anchor_dsn = os.environ.get("G7_AUDIT_ANCHOR_DSN")
        if not anchor_dsn:
            raise RuntimeError("G7_AUDIT_ANCHOR_DSN is required; export fails closed without the independent inventory")
        result = AuditExporter(dsn, source,
            anchor_authority=AuditAnchorAuthority(anchor_dsn)).export_authorised_history_once(
                args.limit, sink_id=args.sink_id)
        print(json.dumps({"sink": "labelled-disposable-postgresql-siem-contract-fixture",
                          "sink_id": args.sink_id,
                          **result.__dict__}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
