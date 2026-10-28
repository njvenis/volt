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
    copied_url = os.environ.get("G7_DEPLOYMENT_AUDIT_DATABASE_URL")
    if copied_url:
        import sqlalchemy as sa
        url = sa.engine.make_url(copied_url)
        import re
        if os.environ.get("UVM_G7_DISPOSABLE_MODE") != "1" or not re.fullmatch(r"g7_copy_[a-z0-9_]+", url.database or ""):
            raise RuntimeError("copied audit database is outside the disposable namespace")
    password_file = Path("/run/uvm-g7-secrets/uvm_db_password")
    # The baseline image predates the runtime's narrowed secret copy. During
    # rollback/upgrade rehearsal its disposable secret is still supplied by
    # the existing read-only /run/secrets mount.
    if not password_file.is_file():
        password_file = Path("/run/secrets/uvm_db_password")
    if not password_file.is_file() and not copied_url:
        raise RuntimeError("dedicated UVM exporter credential is unavailable")
    password = quote(password_file.read_text().strip(), safe="") if not copied_url else ""
    database_url = copied_url or f"postgresql+psycopg://uvm_app:{password}@127.0.0.1:5432/uvm"
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
        import hmac
        import hashlib
        from uvm.api.app import _decode_config
        from uvm.auth.schema import AuthorityContext
        from uvm.operations.preservation_api import _authority
        from uvm.persistence.assessment_schema import assessment_policy
        deployment_id = os.environ.get("G7_AUDIT_DEPLOYMENT_ID", "")
        source_scope = tuple(scope[k] for k in ("source_family", "source_account_id", "scope_key"))
        service_id = os.environ.get("UVM_G7_SOURCE_ADAPTER_PRINCIPAL", "")
        def authorize(connection):
            # Credential validation and native policy evaluation share this
            # operation's connection/lock. No cross-connection HTTP lock cycle.
            configured = _decode_config(os.environ.get("UVM_API_PRINCIPALS")).get(service_id)
            if (not configured or configured.get("actor_kind") != "service"
                    or not hmac.compare_digest(token, configured["token"])):
                raise PermissionError("deployment export credential is unavailable")
            revision = connection.execute(sa.select(assessment_policy.c.revision).where(
                assessment_policy.c.policy_id == 1)).scalar_one_or_none()
            context = AuthorityContext(service_id, "service_bearer", None, None, None, None,
                None, None, (), 0, 0, revision or 0, configured["scopes"],
                configured["role_ids"], datetime.now(timezone.utc))
            principal = {"name": service_id, "context": context, "scopes": configured["scopes"],
                "service_grants": configured["service_grants"]}
            fingerprints = []
            for action in ("preservation.read", "audit.read.deployment", "audit.export.deployment"):
                allowed, fingerprint = _authority(engine, principal, source_scope, action,
                    deployment_id=deployment_id if action.endswith(".deployment") else None,
                    connection=connection, service_adapter=True)
                if not allowed:
                    raise PermissionError("deployment export authority is unavailable")
                fingerprints.append(fingerprint)
            return hashlib.sha256(json.dumps([deployment_id, source_scope, service_id,
                "g7-data-preservation/v1", fingerprints], separators=(",", ":")).encode()).hexdigest()
        source = DeploymentAuditExportSource(engine, authorize, authorize_on_connection=True,
            deployment_id=deployment_id, source_scope=source_scope, service_id=service_id)
        def legacy_metadata(event_id):
            from uvm.operations.preservation_streams import read_stream,namespace,INVENTORY
            from uvm.audit_export.integrity import LegacyPreimageUnavailable
            try:
                inventory,_=read_stream(os.environ['UVM_G7_PRESERVATION_TRUST_DIR'],
                    os.environ['UVM_G7_PRESERVATION_PUBLIC_KEY_FILE'],namespace(deployment_id,INVENTORY,source_scope,'product.audit_history'),key_id=os.environ.get('UVM_G7_PRESERVATION_KEY_ID'))
                found=[item['member']['representation_metadata'] for item in inventory['content']['members']
                    if item['member']['record_kind']=='audit_event' and item['member']['record_key'].split(':')[1]==str(event_id)]
                if len(found)!=1:raise LegacyPreimageUnavailable()
                return found[0]
            except (KeyError,OSError,ValueError):raise LegacyPreimageUnavailable() from None
        source.preservation_legacy_metadata=legacy_metadata
        return source
    os.environ["UVM_DB_URL"] = database_url
    os.environ["UVM_G3_EXPORT_PRINCIPAL"] = os.environ.get("UVM_G7_EXPORT_PRINCIPAL", "g3-exporter")
    return make_audit_export_source()


def event_attribution(connection, event, scope):
    """Resolve source targets from retained linkage; never infer them as deployment."""
    import sqlalchemy as sa
    from uvm.persistence.schema import groups
    from uvm.persistence.observation_schema import source_observations
    from uvm.persistence.lineage_schema import identity_resolutions
    from uvm.persistence.ingestion_schema import collection_runs
    target = str(event["target_id"])
    group = connection.execute(sa.select(groups.c.group_id).where(groups.c.group_id == target)).first()
    if group is not None or event.get("membership_ids"):
        query = (sa.select(identity_resolutions.c.occurrence_id,
            source_observations.c.source_family, source_observations.c.source_account_id,
            collection_runs.c.scope_key).select_from(identity_resolutions
                .outerjoin(source_observations, identity_resolutions.c.observation_id == source_observations.c.observation_id)
                .outerjoin(collection_runs, sa.and_(sa.cast(collection_runs.c.run_id, sa.String) == source_observations.c.run_id,
                    collection_runs.c.source_family == source_observations.c.source_family,
                    collection_runs.c.source_account_id == source_observations.c.source_account_id)))
            .where(identity_resolutions.c.group_id == target))
        membership = set(map(str, event.get("membership_ids") or []))
        if membership: query = query.where(identity_resolutions.c.occurrence_id.in_(membership))
        rows = connection.execute(query).all()
        if (not rows or any(any(value is None for value in row[1:]) for row in rows)
                or membership and not membership.issubset({str(row[0]) for row in rows})):
            return None
        tuples = {tuple(row[1:]) for row in rows}
        if scope not in tuples:
            return {"kind": "foreign_source", "target_id": target}
        return {"kind": "source", "target_id": target, "scope": list(scope)}
    action = event.get("action", "")
    prefixes = ("native.authority.", "access_group.", "ownership.team.", "policy.",
        "principal.", "observer.", "backup.", "recovery.", "scanner.", "connector.")
    if target == "00000000-0000-0000-0000-000000000000" or action.startswith(prefixes):
        return {"kind": "deployment"}
    return None


def captured_attribution(event, inventory, scope):
    """Restore only attribution already admitted for this unchanged event."""
    if inventory is None: return None
    from uvm.audit_export.integrity import event_digest
    key=f"audit_event:{event['event_id']}:{int(event['event_sequence'])}"
    expected=next((item['member'] for item in inventory['members']
        if item['member']['record_kind']=='audit_event' and item['member']['record_key']==key),None)
    if expected is None:return None
    try:
        from uvm.audit_export.integrity import legacy_event_digest
        observed=(legacy_event_digest(event,expected.get('representation_metadata'))
            if expected['canonicalization_version']=='g7-audit-anchor/v1' else event_digest(event,expected['canonicalization_version']))
    except (ValueError,KeyError,TypeError):return None
    if observed != expected['legacy_payload_sha256']:return None
    matches=[target for target in inventory['audit_targets'] if target.get('kind')=='source'
        and target.get('target_id')==str(event['target_id']) and target.get('scope')==list(scope)]
    return matches[0] if len(matches)==1 else None


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
    audit_state.add_argument("--admit-new-members", action="store_true")
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
        scope = tuple(os.environ.get(name) for name in (
            "G7_AUDIT_SOURCE_FAMILY", "G7_AUDIT_SOURCE_ACCOUNT", "G7_AUDIT_SCOPE_KEY"))
        from uvm.operations.preservation_streams import read_stream, namespace, INVENTORY, reconcile_members
        expected_inventory = None
        try:
            baseline, baseline_digest = read_stream(os.environ["UVM_G7_PRESERVATION_TRUST_DIR"],
                os.environ["UVM_G7_PRESERVATION_PUBLIC_KEY_FILE"],
                namespace(deployment_id, INVENTORY, scope, "product.audit_history"), key_id=os.environ.get("UVM_G7_PRESERVATION_KEY_ID"))
            expected_inventory = baseline["content"]
        except (KeyError, FileNotFoundError):
            pass
        with source.engine.begin() as connection:
            attributions = {event_id: captured_attribution(event, expected_inventory, scope)
                or event_attribution(connection, event, scope) for event_id, event in source_map.items()}
        expected_event_ids = {item["member"]["record_key"].split(":")[1]
            for item in (expected_inventory or {}).get("members", [])
            if item["member"]["record_kind"] == "audit_event"}
        foreign = {event_id for event_id, attribution in attributions.items()
            if attribution and attribution["kind"] == "foreign_source" and event_id not in expected_event_ids}
        # A new event proven to belong only to another tuple is outside this
        # namespace. Never filter a previously admitted expected identity away.
        for event_id in foreign:
            for mapping in (source_map, sink_map, anchor_map, receipts, attributions): mapping.pop(event_id, None)
        attribution_complete = all(item is not None and item["kind"] != "foreign_source" for item in attributions.values())
        audit_targets = sorted({json.dumps(item, sort_keys=True) for item in attributions.values()
            if item is not None and item["kind"] != "foreign_source"})
        audit_targets = [json.loads(item) for item in audit_targets]
        union_ids = sorted(set(source_map) | set(sink_map) | set(anchor_map) | set(receipts))
        members = []
        matching_events = missing_events = changed_events = unexpected_events = 0
        expected_receipts = matching_receipts = missing_receipts = changed_receipts = 0
        pending_receipts = 0
        unexpected_receipts = 0

        def member(kind, key, retained_at, state, reasons, *, legacy=None, version=None, representation=None, fact_digest=None):
            retained_at = utc_timestamp(retained_at) if retained_at is not None else None
            metadata = {"legacy_payload_sha256": legacy,
                "canonicalization_version": version,
                "representation_metadata": representation}
            preimage = {"record_kind": kind, "record_key": key, "retained_at": retained_at,
                "fact_digest": fact_digest, **metadata}
            record_sha = hashlib.sha256(b"VOLT-G7-RECORD\0product.audit_history\0"
                + canonical_json(preimage)).hexdigest()
            members.append({"record_key": key, "record_kind": kind, "retained_at": retained_at,
                "state": state, "reasons": reasons, "expected_sha256": None,
                "actual_sha256": None, "record_sha256": None if state == "missing" else record_sha,
                "byte_bearing": False, "evidence_id": None, **metadata})

        changed_any = unexpected_any = False
        legacy_unknown_reason = None
        for event_id in union_ids:
            source_event = source_map.get(event_id)
            sink_event = sink_map.get(event_id)
            anchor = anchor_map.get(event_id)
            version = anchor.get("contract_version") if anchor else "g7-audit-anchor/v2"
            representation = {"source_time_values": {"occurred_at": "string", "received_at": "string"},
                "sink_time_values": {"occurred_at": "string", "received_at": "string"}}
            if version == "g7-audit-anchor/v1":
                from uvm.audit_export.integrity import legacy_event_digest, LegacyPreimageUnavailable
                expected_event = next((item["member"] for item in (expected_inventory or {}).get("members", [])
                    if item["member"]["record_kind"] == "audit_event" and item["member"]["record_key"].split(":")[1] == event_id), None)
                representation = expected_event.get("representation_metadata") if expected_event else None
                try:
                    # Either readable authorized copy supplies values. No raw
                    # preimage is retained and no old anchor is rewritten.
                    if source_event is None and sink_event is None:raise LegacyPreimageUnavailable()
                    source_digest = legacy_event_digest(source_event, representation) if source_event is not None else None
                    sink_digest = legacy_event_digest(sink_event, representation) if sink_event is not None else None
                except LegacyPreimageUnavailable:
                    legacy_unknown_reason = "legacy_preimage_unavailable"
                    source_digest = sink_digest = None
            else:
                source_digest = event_digest(source_event, version) if source_event is not None else None
                sink_digest = event_digest(sink_event, version) if sink_event is not None else None
            anchor_digest = anchor.get("payload_sha256") if anchor else None
            sequence = int((source_event or sink_event or {}).get("event_sequence",
                anchor.get("event_sequence", 0) if anchor else 0))
            event_key = f"audit_event:{event_id}:{sequence}"
            retained_at = ((source_event or {}).get("received_at") or
                ((sink_event or {}).get("received_at")) or
                (anchor.get("anchored_at").isoformat().replace("+00:00", "Z") if anchor else None))
            reasons, state = [], "verified"
            if source_event is None:
                state, reasons = "missing", ["record_missing"]
                missing_events += 1; changed_any = True
            elif sink_event is None:
                state, reasons = "missing", ["sink_record_missing"]
                missing_events += 1
            elif source_digest != sink_digest or (anchor is not None and source_digest != anchor_digest):
                state, reasons = "changed", ["sink_record_changed"]
                changed_events += 1; changed_any = True
            else:
                matching_events += 1
            member("audit_event", event_key, retained_at, state, reasons,
                legacy=source_digest or sink_digest or anchor_digest,
                version=(anchor.get("contract_version") if anchor else "g7-audit-anchor/v2"),
                representation=representation)
            attribution = attributions.get(event_id)
            member("audit_attribution", f"audit_attribution:{event_id}:attribution-v1",
                retained_at, "verified" if attribution else "missing",
                [] if attribution else ["record_missing"],
                fact_digest=hashlib.sha256(canonical_json(attribution)).hexdigest())
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
            elif sink_event is not None and source_event is not None:
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
                member("audit_anchor", f"audit_anchor:{event_id}:g7-siem:{sequence}", anchor_time,
                    anchor_state, anchor_reasons, legacy=anchor_digest,
                    version=anchor["contract_version"], representation=representation, fact_digest=anchor_preimage_digest)
        if expected_inventory is not None:
            expected_members = expected_inventory["members"]
            if args.admit_new_members:
                # Admission is explicit and additive. Only independently read,
                # source-attributed canonical matches qualify; existing expected
                # members remain byte-for-byte unchanged.
                keys = {item["member"]["record_key"] for item in expected_members}
                expected_members = expected_members + [{"member": item, "byte_size": None}
                    for item in members if item["state"] == "verified" and item["record_key"] not in keys]
                audit_targets = [json.loads(item) for item in sorted({json.dumps(item, sort_keys=True)
                    for item in [*expected_inventory["audit_targets"], *audit_targets]})]
            else:
                audit_targets = expected_inventory["audit_targets"]
            members = reconcile_members(expected_members, members)
        # Current store rows cannot redefine expectation after a loss.
        for kind, suffix in (("audit_event", "events"), ("audit_copy_receipt_established", "receipts")):
            selected = [item for item in members if item["record_kind"] == kind]
            values = {state: sum(item["state"] == state for item in selected)
                for state in ("verified", "missing", "changed", "unexpected")}
            if kind == "audit_event":
                matching_events, missing_events, changed_events, unexpected_events = (values[s] for s in ("verified", "missing", "changed", "unexpected"))
            else:
                matching_receipts, missing_receipts, changed_receipts, unexpected_receipts = (values[s] for s in ("verified", "missing", "changed", "unexpected"))
                expected_receipts = matching_receipts + missing_receipts + changed_receipts
        if expected_inventory is not None:
            for item in members:
                if legacy_unknown_reason or item["state"] not in {"missing", "changed"}:
                    continue
                event_id = item["record_key"].split(":")[1]
                with authority.locked(args.sink_id, event_id) as lease:
                    lease.anomaly("source_integrity" if "receipt" in item["record_kind"] or "record_missing" in item["reasons"]
                        else "siem_integrity", {"record_kind": item["record_kind"],
                            "reasons": item["reasons"], "baseline_digest": baseline_digest})
        members.sort(key=lambda item: (item["record_kind"].encode(), item["record_key"].encode()))
        changed_any = changed_any or any(item["state"] in {"missing", "changed", "unreadable"} for item in members)
        unexpected_any = unexpected_any or any(item["state"] == "unexpected" for item in members)
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
                "expected_events": matching_events + missing_events + changed_events, "matching_events": matching_events,
                "missing_events": missing_events, "changed_events": changed_events,
                "unexpected_events": unexpected_events, "expected_receipts": expected_receipts,
                "matching_receipts": matching_receipts, "missing_receipts": missing_receipts,
                "changed_receipts": changed_receipts, "unexpected_receipts": unexpected_receipts,
                "pending_receipts": pending_receipts, "checked_at": checked_at}}
        if legacy_unknown_reason:
            from uvm.operations.preservation import unknown_class
            dto = unknown_class("product.audit_history", "P1Y", legacy_unknown_reason)
            members = []
        elif not attribution_complete:
            from uvm.operations.preservation import unknown_class
            dto = unknown_class("product.audit_history", "P1Y", "audit_scope_incomplete")
            members = []
        print(json.dumps({"schema_version": 1, "class_id": "product.audit_history",
            "context": {"deployment_id": deployment_id, "checked_at": checked_at,
                "storage_generation": os.environ.get("UVM_G7_STORAGE_GENERATION"),
                "recovery_epoch": int(os.environ["UVM_G7_RECOVERY_EPOCH"]),
                "volume_set_digest": os.environ.get("UVM_G7_VOLUME_SET_DIGEST"),
                "scope": [os.environ.get(name) for name in ("G7_AUDIT_SOURCE_FAMILY", "G7_AUDIT_SOURCE_ACCOUNT", "G7_AUDIT_SCOPE_KEY")],
                "source_watermark": getattr(source, "watermark", max((int(e["event_sequence"]) for e in source_events), default=0)),
                "export_context_id": getattr(source, "context_id", None),
                "sink_watermark": max((int(e["event_sequence"]) for e in sink_map.values()), default=0),
                "anchor_watermark": max((int(e["event_sequence"]) for e in anchor_map.values()), default=0)},
            "audit_targets": audit_targets, "dto": dto, "members": members},
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
