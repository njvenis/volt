"""Transfer complete UVM audit event JSON records into an isolated sink.

The SIEM ingest contract is one JSON object per stable ``event_id`` with every
field in :data:`EVENT_FIELDS`; sinks must commit the complete object before the
source acknowledgement is appended. PostgreSQL is only the disposable G7
contract fixture, not a claim of integration with a production SIEM.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import os
import time
from typing import Any, Protocol, Sequence
from uuid import UUID

import psycopg
from psycopg.types.json import Jsonb
from .integrity import AuditAnchorAuthority, event_digest


EVENT_FIELDS = (
    "event_id", "event_sequence", "actor_id", "actor_kind", "origin", "action", "target_id",
    "before_value", "after_value", "membership_ids", "membership_revision",
    "rationale", "evidence_ref", "policy_revision", "identity_revision",
    "occurred_at", "received_at", "correlation_id", "command_id", "authorization_context",
)


class AuditSource(Protocol):
    def list_unexported_audit_events(self, limit: int) -> Sequence[dict[str, Any]]: ...
    def list_authorised_audit_events(self, limit: int) -> Sequence[dict[str, Any]]: ...
    def list_authorised_audit_page(self, limit: int, after_sequence: int = 0) -> Sequence[dict[str, Any]]: ...
    def count_authorised_audit_events(self) -> int: ...
    def list_unreceipted_audit_page(self, sink_id: str, limit: int,
                                    after_sequence: int = 0) -> Sequence[dict[str, Any]]: ...
    def acknowledge_sink_export(self, event_id: UUID, sink_id: str, sink_receipt: str,
                                acknowledged_at: datetime) -> Any: ...
    def get_sink_receipt(self, event_id: UUID, sink_id: str) -> str | None: ...
    def acknowledge_export(self, event_id: UUID, sink_receipt: str, acknowledged_at: datetime) -> Any: ...


class AuditSinkConnectionError(RuntimeError):
    """A psycopg failure raised specifically while opening the export sink."""

    def __init__(self, error: psycopg.Error):
        super().__init__("unable to connect to audit export sink")
        self.sqlstate = error.sqlstate
        self.error_type = type(error).__name__


@dataclass(frozen=True)
class ExportResult:
    read: int
    inserted: int
    deduplicated: int
    acknowledged: int


def _event_payload(event: dict[str, Any]) -> dict[str, Any]:
    missing = set(EVENT_FIELDS) - event.keys()
    if missing:
        raise ValueError(f"audit event is missing required fields: {', '.join(sorted(missing))}")
    payload = {key: event[key] for key in EVENT_FIELDS}
    payload["event_id"] = str(UUID(str(payload["event_id"])))
    payload["membership_ids"] = [str(x) for x in payload["membership_ids"]]
    for key in ("occurred_at", "received_at"):
        value = payload[key]
        if isinstance(value, datetime):
            if value.tzinfo is None:
                raise ValueError(f"{key} must be timezone-aware")
            payload[key] = value.astimezone(timezone.utc).isoformat()
    return payload


class AuditExporter:
    """At-least-once source reader; unique sink IDs make recovery exactly-once visible."""

    def __init__(self, sink_dsn: str, source: AuditSource, *,
                 anchor_authority: AuditAnchorAuthority | None = None,
                 sink_connect=psycopg.connect):
        self._sink_dsn = sink_dsn
        self._source = source
        self._anchors = anchor_authority
        self._connect = sink_connect

    def export_once(self, limit: int = 100) -> ExportResult:
        if not 1 <= limit <= 5000:
            raise ValueError("limit must be between 1 and 5000")
        # Compatibility entry point: use the same anchored sink-specific path.
        return self.export_authorised_history_once(limit)

    def export_authorised_history_once(self, limit: int = 5000, *, sink_id: str = "g7-siem") -> ExportResult:
        """Reconcile the full currently authorised source history into a new sink.

        Existing source acknowledgements may refer to the earlier host archive.
        They are preserved; only events that remain pending receive a source
        acknowledgement, and only after the independent sink has committed.
        """
        if not 1 <= limit <= 5000:
            raise ValueError("limit must be between 1 and 5000")
        if not sink_id or len(sink_id) > 100:
            raise ValueError("sink_id must be between 1 and 100 characters")
        if self._anchors is None:
            raise RuntimeError("normal SIEM export is blocked: independent audit inventory is unavailable")
        expected_total = self._source.count_authorised_audit_events()
        inserted = deduplicated = acknowledged = 0
        scanned = 0
        after_sequence = 0
        while scanned < expected_total:
            events = self._source.list_authorised_audit_page(limit, after_sequence)
            if not events:
                raise RuntimeError(f"authorised source pagination stalled at {scanned}/{expected_total}")
            previous_sequence = after_sequence
            for event in events:
                payload = _event_payload(event)
                sequence = int(payload["event_sequence"])
                if sequence <= previous_sequence:
                    raise RuntimeError("authorised source cursor did not advance monotonically")
                previous_sequence = sequence
                result = self._export_one(payload, sink_id)
                inserted += result == "inserted"
                deduplicated += result == "deduplicated"
                acknowledged += result in {"inserted", "acknowledged"}
            if previous_sequence <= after_sequence:
                raise RuntimeError("authorised source cursor failed to advance")
            after_sequence = previous_sequence
            scanned += len(events)
        final_total = self._source.count_authorised_audit_events()
        if scanned != expected_total or final_total != expected_total:
            raise RuntimeError(f"authorised source total changed during SIEM reconciliation: "
                               f"start={expected_total} scanned={scanned} end={final_total}")
        backlog = self._source.sink_backlog_count(sink_id)
        if backlog:
            raise RuntimeError(f"SIEM sink receipt backlog remains: {backlog}")
        return ExportResult(scanned, inserted, deduplicated, acknowledged)

    def _export_one(self, payload: dict[str, Any], sink_id: str) -> str:
        if self._anchors is None:
            raise RuntimeError("normal SIEM export is blocked: independent audit inventory is unavailable")
        event_id = payload["event_id"]
        with self._anchors.locked(sink_id, event_id) as lease:
            # The labelled disposable journey uses this delay to hold the
            # same per-event lock while the independent observer anchors.
            if os.environ.get("G7_AUDIT_FIXTURE_EXPORT_LOCK_DELAY"):
                marker = os.environ.get("G7_AUDIT_FIXTURE_EXPORT_LOCK_READY_FILE")
                if marker:
                    with open(marker, "w", encoding="ascii") as handle:
                        handle.write(event_id)
                time.sleep(float(os.environ["G7_AUDIT_FIXTURE_EXPORT_LOCK_DELAY"]))
            anchor = lease.get()
            receipt = self._source.get_sink_receipt(UUID(event_id), sink_id)
            if anchor is not None:
                sink_payload = self._read_sink_record(event_id)
                mismatch = []
                if event_digest(payload) != anchor["payload_sha256"]:
                    mismatch.append("source_content_changed")
                if receipt != anchor["sink_receipt"]:
                    mismatch.append("source_receipt_missing_or_changed")
                if sink_payload is None:
                    mismatch.append("siem_record_missing")
                elif event_digest(sink_payload) != anchor["payload_sha256"]:
                    mismatch.append("siem_content_changed")
                if mismatch:
                    condition = ("source_integrity" if any(reason in mismatch for reason in
                        ("source_content_changed", "source_receipt_missing_or_changed"))
                        else "siem_integrity")
                    incident_id = lease.anomaly(condition, {
                        "event_id": event_id, "reasons": mismatch,
                        "anchor_sha256": anchor["payload_sha256"],
                        "affected_scope": anchor["affected_scope"],
                        "vulnerability_group_id": anchor["affected_scope"],
                        "source_receipt_present": receipt is not None,
                        "sink_record_present": sink_payload is not None})
                    raise RuntimeError(f"SIEM integrity anomaly {incident_id}: {','.join(mismatch)}")
                return "deduplicated"
            if receipt is not None:
                # Pre-inventory receipts remain unchanged for the independent
                # observer to compare and anchor.
                self._verify_receipted_sink_record(payload)
                return "deduplicated"
            was_inserted = self._persist(payload)
            receipt_value = f"postgres:uvm_audit_export.events:{event_id}"
            self._source.acknowledge_sink_export(UUID(event_id), sink_id,
                receipt_value, datetime.now(timezone.utc))
            return "inserted" if was_inserted else "acknowledged"

    def _read_sink_record(self, event_id: str) -> dict[str, Any] | None:
        try:
            connection = self._connect(self._sink_dsn)
        except psycopg.Error as exc:
            raise AuditSinkConnectionError(exc) from exc
        with connection as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT payload FROM uvm_audit_export.events WHERE event_id=%s",
                            (event_id,))
                row = cur.fetchone()
        return row[0] if row is not None else None

    def _verify_receipted_sink_record(self, payload: dict[str, Any]) -> None:
        try:
            sink_connection = self._connect(self._sink_dsn)
        except psycopg.Error as exc:
            raise AuditSinkConnectionError(exc) from exc
        with sink_connection as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT payload FROM uvm_audit_export.events WHERE event_id=%s",
                            (payload["event_id"],))
                row = cur.fetchone()
        if row is None:
            raise RuntimeError(
                f"SIEM integrity anomaly: source receipt exists but sink record is missing: {payload['event_id']}"
            )
        if row[0] != payload:
            raise ValueError(f"event ID {payload['event_id']} was reused with different content")

    def _persist(self, payload: dict[str, Any]) -> bool:
        try:
            sink_connection = self._connect(self._sink_dsn)
        except psycopg.Error as exc:
            raise AuditSinkConnectionError(exc) from exc
        with sink_connection as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """INSERT INTO uvm_audit_export.events(event_id, payload, committed_at)
                       VALUES (%s, %s, clock_timestamp()) ON CONFLICT (event_id) DO NOTHING
                       RETURNING event_id""",
                    (payload["event_id"], Jsonb(payload)),
                )
                was_inserted = cur.fetchone() is not None
                # Read back under the sink transaction. A reused UUID with altered bytes
                # is corruption, not a successful retry.
                cur.execute("SELECT payload FROM uvm_audit_export.events WHERE event_id=%s",
                            (payload["event_id"],))
                stored = cur.fetchone()[0]
                if stored != payload:
                    raise ValueError(f"event ID {payload['event_id']} was reused with different content")
            # Context manager commits before the source is acknowledged.
        return was_inserted
