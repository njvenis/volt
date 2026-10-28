#!/usr/bin/env python3
"""Narrow host-invoked bridge to the existing committed audit export contract."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
from urllib.parse import quote
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen
from uuid import UUID

from uvm.assessment.audit_export import make_audit_export_source


def audit_union_state(*, changed: bool, unexpected: bool, pending_receipts: int) -> str:
    if changed or unexpected:
        return "gap"
    if pending_receipts > 0:
        return "unknown"
    return "verified"


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
    database_url = f"postgresql+psycopg://uvm_app:{password}@127.0.0.1:5432/uvm"
    if os.environ.get("G7_DEPLOYMENT_AUDIT_TOKEN"):
        import sqlalchemy as sa
        from uvm.assessment.audit_export import DeploymentAuditExportSource
        engine = sa.create_engine(database_url, pool_pre_ping=True)
        scope = {key: os.environ.get(env, "") for key, env in (
            ("source_family", "G7_AUDIT_SOURCE_FAMILY"),
            ("source_account_id", "G7_AUDIT_SOURCE_ACCOUNT"),
            ("scope_key", "G7_AUDIT_SCOPE_KEY"))}
        if any(not value for value in scope.values()):
            raise RuntimeError("deployment audit scope is unavailable")
        origin = os.environ.get("G7_AUDIT_AUTH_ORIGIN", "http://127.0.0.1:8000")
        token = os.environ["G7_DEPLOYMENT_AUDIT_TOKEN"]
        def authorize():
            body = json.dumps({"schema_version": 1, "scope": scope,
                "class_ids": ["product.source_evidence", "product.audit_history",
                    "operational.scanner_collection"]}, sort_keys=True,
                separators=(",", ":")).encode()
            request = Request(origin.rstrip("/") + "/internal/g7/preservation/source-snapshot",
                data=body, method="POST", headers={"Authorization": "Bearer " + token,
                    "Content-Type": "application/json", "Accept": "application/json"})
            try:
                with urlopen(request, timeout=20) as response:
                    if response.status != 200:
                        raise RuntimeError("deployment audit authority unavailable")
                    response.read(1024 * 1024)
            except (HTTPError, URLError, OSError):
                raise RuntimeError("deployment audit authority unavailable") from None
        authorize()
        return DeploymentAuditExportSource(engine, authorize)
    os.environ["UVM_DB_URL"] = database_url
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
    anchor_history = sub.add_parser("anchor-history")
    anchor_history.add_argument("--limit", type=int, default=5000)
    anchor_history.add_argument("--sink-id", default="g7-siem")
    audit_state = sub.add_parser("audit-state")
    audit_state.add_argument("--limit", type=int, default=5000)
    audit_state.add_argument("--sink-id", default="g7-siem")
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
    elif args.command == "anchor-history":
        import psycopg
        from uvm.audit_export.exporter import _event_payload
        from uvm.audit_export.integrity import AuditAnchorAuthority, anchor_payload
        sink_dsn = os.environ.get("G7_SIEM_DSN")
        anchor_dsn = os.environ.get("G7_AUDIT_ANCHOR_SIGNER_DSN")
        if not sink_dsn or not anchor_dsn:
            raise RuntimeError("independent sink and anchor signer credentials are required")
        authority = AuditAnchorAuthority(anchor_dsn, deployment_id=os.environ.get(
            "G7_AUDIT_DEPLOYMENT_ID", "g7-local"))
        expected_total = source.count_authorised_audit_events()
        scanned = anchored = existing = 0
        after = 0
        while scanned < expected_total:
            events = source.list_authorised_audit_page(args.limit, after)
            if not events:
                raise RuntimeError("deployment audit source pagination stalled")
            for raw_event in events:
                event = _event_payload(dict(raw_event))
                after = int(event["event_sequence"])
                receipt = source.get_sink_receipt(event["event_id"], args.sink_id)
                if receipt is None:
                    raise RuntimeError("deployment audit sink receipt is missing")
                with psycopg.connect(sink_dsn) as connection:
                    row = connection.execute("SELECT payload FROM uvm_audit_export.events WHERE event_id=%s",
                        (event["event_id"],)).fetchone()
                if row is None:
                    raise RuntimeError("deployment audit sink record is missing")
                sink_payload = row[0]
                result = anchor_payload(authority, sink_id=args.sink_id, event=event,
                    sink_receipt=receipt, sink_payload=sink_payload,
                    affected_scope="deployment")
                anchored += result["status"] == "anchored"
                existing += result["status"] == "already-anchored"
                scanned += 1
            if after <= 0:
                raise RuntimeError("deployment audit anchor cursor did not advance")
        if scanned != expected_total or source.count_authorised_audit_events() != expected_total:
            raise RuntimeError("deployment audit source total changed during anchoring")
        print(json.dumps({"deployment_id": authority.deployment_id, "sink_id": args.sink_id,
            "events": scanned, "anchored": anchored, "already_anchored": existing},
            sort_keys=True, separators=(",", ":")))
    elif args.command == "audit-state":
        import hashlib
        import psycopg
        import sqlalchemy as sa
        from uvm.audit_export.exporter import EVENT_FIELDS, _event_payload
        from uvm.audit_export.integrity import AuditAnchorAuthority, event_digest
        from uvm.operations.preservation import canonical_json, utc_timestamp
        from uvm.persistence.assessment_schema import assessment_audit_events, assessment_sink_export_receipts
        sink_dsn = os.environ.get("G7_SIEM_DSN")
        anchor_dsn = os.environ.get("G7_AUDIT_ANCHOR_SIGNER_DSN")
        deployment_id = os.environ.get("G7_AUDIT_DEPLOYMENT_ID", "g7-local")
        if not sink_dsn or not anchor_dsn:
            raise RuntimeError("independent sink and anchor credentials are required")
        authority = AuditAnchorAuthority(anchor_dsn, deployment_id=deployment_id)
        total = source.count_authorised_audit_events()
        source_events, after = [], 0
        while len(source_events) < total:
            page = source.list_authorised_audit_page(args.limit, after)
            if not page:
                raise RuntimeError("deployment audit source pagination stalled")
            source_events.extend(_event_payload(dict(row)) for row in page)
            after = int(source_events[-1]["event_sequence"])
        source_map = {event["event_id"]: event for event in source_events}
        def text_value(value):
            return value.decode("utf-8", errors="strict") if isinstance(value, bytes) else value
        source.authorize()
        with source.engine.connect() as connection:
            receipts = {str(row.event_id): text_value(row.sink_receipt) for row in connection.execute(
                sa.select(assessment_sink_export_receipts.c.event_id,
                    assessment_sink_export_receipts.c.sink_receipt).where(
                    assessment_sink_export_receipts.c.sink_id == args.sink_id)).all()}
            final_total = int(connection.execute(sa.select(sa.func.count()).select_from(
                assessment_audit_events)).scalar_one())
        if final_total != total:
            raise RuntimeError("deployment audit source changed during reconciliation")
        with psycopg.connect(sink_dsn) as connection:
            sink_rows = connection.execute("SELECT event_id,payload FROM uvm_audit_export.events").fetchall()
        sink_map = {str(text_value(event_id)): payload for event_id, payload in sink_rows}
        anchor_rows = authority.inventory(args.sink_id)
        anchor_map = {str(text_value(row["event_id"])):
            {key: text_value(value) for key, value in row.items()} for row in anchor_rows}
        union_ids = sorted(set(source_map) | set(sink_map) | set(anchor_map) | set(receipts))
        members = []
        matching_events = missing_events = changed_events = unexpected_events = 0
        expected_receipts = matching_receipts = missing_receipts = changed_receipts = 0
        pending_receipts = 0
        unexpected_receipts = 0

        def member(kind, key, retained_at, state, reasons, *, legacy=None, version=None, representation=None):
            retained_at = utc_timestamp(retained_at) if retained_at is not None else None
            metadata = {"legacy_payload_sha256": legacy,
                "canonicalization_version": version,
                "representation_metadata": representation}
            preimage = {"record_kind": kind, "record_key": key, "retained_at": retained_at,
                "state": state, "reasons": reasons, **metadata}
            record_sha = hashlib.sha256(b"VOLT-G7-RECORD\0product.audit_history\0"
                + canonical_json(preimage)).hexdigest()
            members.append({"record_key": key, "record_kind": kind, "retained_at": retained_at,
                "state": state, "reasons": reasons, "expected_sha256": None,
                "actual_sha256": None, "record_sha256": None if state == "missing" else record_sha,
                "byte_bearing": False, "evidence_id": None, **metadata})

        changed_any = unexpected_any = False
        for event_id in union_ids:
            source_event = source_map.get(event_id)
            sink_event = sink_map.get(event_id)
            anchor = anchor_map.get(event_id)
            source_digest = event_digest(source_event) if source_event is not None else None
            sink_digest = event_digest(sink_event) if sink_event is not None else None
            anchor_digest = anchor.get("payload_sha256") if anchor else None
            sequence = int((source_event or sink_event or {}).get("event_sequence",
                anchor.get("event_sequence", 0) if anchor else 0))
            event_key = f"audit_event:{event_id}:{sequence}"
            retained_at = ((source_event or {}).get("received_at") or
                ((sink_event or {}).get("received_at")) or
                (anchor.get("anchored_at").isoformat().replace("+00:00", "Z") if anchor else None))
            reasons, state = [], "verified"
            if source_event is None:
                state, reasons = "unexpected", ["unexpected_member"]
                unexpected_events += 1; unexpected_any = True
            elif sink_event is None:
                state, reasons = "missing", ["sink_record_missing"]
                missing_events += 1
            elif source_digest != sink_digest or (anchor is not None and source_digest != anchor_digest):
                state, reasons = "changed", ["sink_record_changed"]
                changed_events += 1; changed_any = True
            else:
                matching_events += 1
            representation = {"source_time_values": {"occurred_at": "datetime", "received_at": "datetime"},
                "sink_time_values": {"occurred_at": "string", "received_at": "string"}}
            member("audit_event", event_key, retained_at, state, reasons,
                legacy=source_digest or sink_digest or anchor_digest,
                version=(anchor.get("contract_version") if anchor else "g7-audit-anchor/v1"),
                representation=representation)
            member("audit_attribution", f"audit_attribution:{event_id}:deployment-v1",
                retained_at, "verified", [])
            source_receipt = receipts.get(event_id)
            anchor_receipt = anchor.get("sink_receipt") if anchor else None
            if source_receipt is not None or anchor_receipt is not None:
                if source_event is not None or anchor_receipt is not None:
                    expected_receipts += 1
                receipt_value = source_receipt or anchor_receipt
                receipt_digest = hashlib.sha256(receipt_value.encode()).hexdigest()
                receipt_state, receipt_reasons = "verified", []
                if source_receipt is None and anchor_receipt is not None:
                    receipt_state, receipt_reasons = "missing", ["receipt_missing"]
                    missing_receipts += 1; changed_any = True
                elif source_event is None:
                    receipt_state, receipt_reasons = "unexpected", ["unexpected_member"]
                    unexpected_receipts += 1; unexpected_any = True
                elif anchor_receipt is not None and source_receipt != anchor_receipt:
                    receipt_state, receipt_reasons = "changed", ["receipt_changed"]
                    changed_receipts += 1; changed_any = True
                elif source_receipt is not None and anchor_receipt is None:
                    receipt_state, receipt_reasons = "missing", ["receipt_missing"]
                    missing_receipts += 1; changed_any = True
                else:
                    matching_receipts += 1
                member("audit_copy_receipt_established",
                    f"audit_copy_receipt_established:{event_id}:g7-siem:{receipt_digest}",
                    retained_at, receipt_state, receipt_reasons)
            elif sink_event is not None:
                pending_receipts += 1
            if anchor is not None:
                anchor_time = anchor["anchored_at"].isoformat().replace("+00:00", "Z")
                anchor_preimage_digest = hashlib.sha256(canonical_json({
                    "deployment_id": anchor["deployment_id"], "sink_id": anchor["sink_id"],
                    "event_id": event_id, "event_sequence": int(anchor["event_sequence"]),
                    "payload_sha256": anchor_digest,
                    "sink_receipt_sha256": hashlib.sha256(anchor_receipt.encode()).hexdigest(),
                    "affected_scope": anchor["affected_scope"], "anchored_at": anchor_time,
                    "contract_version": anchor["contract_version"]})).hexdigest()
                anchor_state, anchor_reasons = "verified", []
                if source_event is None:
                    anchor_state, anchor_reasons = "unexpected", ["unexpected_member"]
                elif sink_event is None or source_digest != anchor_digest or sink_digest != anchor_digest:
                    anchor_state, anchor_reasons = "changed", ["sink_record_changed"]
                member("audit_anchor", f"audit_anchor:{event_id}:g7-siem:{sequence}", anchor_time,
                    anchor_state, anchor_reasons, legacy=anchor_digest,
                    version=anchor["contract_version"], representation=representation)
        members.sort(key=lambda item: (item["record_kind"].encode(), item["record_key"].encode()))
        state = audit_union_state(changed=changed_any, unexpected=unexpected_any,
            pending_receipts=pending_receipts)
        reasons = sorted(set(reason for item in members for reason in item["reasons"]))
        if state == "unknown":
            reasons = sorted(set(reasons) | {"source_checkpoint_missing"})
        checked_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        verified = sum(item["state"] == "verified" for item in members)
        missing = sum(item["state"] == "missing" for item in members)
        changed = sum(item["state"] == "changed" for item in members)
        unreadable = sum(item["state"] == "unreadable" for item in members)
        unexpected = sum(item["state"] == "unexpected" for item in members)
        baseline_digest = hashlib.sha256(canonical_json([[item["record_key"],
            item["record_kind"], item["record_sha256"], item["expected_sha256"]]
            for item in members])).hexdigest()
        dto = {"class_id": "product.audit_history", "minimum_period": "P1Y",
            "state": state, "reasons": reasons, "expected_records": verified + missing + changed + unreadable,
            "verified_records": verified, "missing_records": missing, "changed_records": changed,
            "unreadable_records": unreadable, "unexpected_records": unexpected,
            "oldest_retained_at": min((item["retained_at"] for item in members if item["retained_at"]), default=None),
            "baseline_digest": "sha256:" + baseline_digest,
            "audit_copy": {"state": state, "reasons": reasons,
                "expected_events": len(source_map), "matching_events": matching_events,
                "missing_events": missing_events, "changed_events": changed_events,
                "unexpected_events": unexpected_events, "expected_receipts": expected_receipts,
                "matching_receipts": matching_receipts, "missing_receipts": missing_receipts,
                "changed_receipts": changed_receipts, "unexpected_receipts": unexpected_receipts,
                "pending_receipts": pending_receipts, "checked_at": checked_at}}
        print(json.dumps({"schema_version": 1, "class_id": "product.audit_history",
            "audit_targets": [{"kind": "deployment"}], "dto": dto, "members": members},
            sort_keys=True, separators=(",", ":")))
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
