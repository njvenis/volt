"""Independent G7 audit anchors and append-only integrity observations.

The local disposable fixture stores this inventory in the separately
credentialled SIEM PostgreSQL service.  The application exporter has read
access to anchors and insert-only access to anomaly observations; it cannot
change the retained inventory.
"""
from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timezone, timedelta
import hashlib
import json
from typing import Any, Iterator
from uuid import UUID, uuid4

import psycopg
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb


ANCHOR_VERSION = "g7-audit-anchor/v2"
INCIDENT_VERSION = "g7-operations-incident/v1"
DEPLOYMENT_ID = "uvm-local-disposable-v1"


def canonical_event(event: dict[str, Any], version: str = "g7-audit-anchor/v1") -> bytes:
    """Return the versioned complete-event representation used by anchors."""
    if version not in {"g7-audit-anchor/v1", "g7-audit-anchor/v2"}:
        raise ValueError("unsupported audit canonicalization version")
    if version == "g7-audit-anchor/v2":
        from uvm.operations.preservation import utc_timestamp
        event = dict(event)
        for field in ("occurred_at", "received_at"):
            if field in event:
                value = event[field]
                if isinstance(value, str):
                    value = datetime.fromisoformat(value.replace("Z", "+00:00"))
                event[field] = utc_timestamp(value)
    def normalise(value):
        if isinstance(value, datetime):
            if value.tzinfo is None or value.utcoffset() is None:
                raise ValueError("audit timestamps must include a timezone")
            return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
        if isinstance(value, UUID):
            return str(value)
        if isinstance(value, dict):
            return {str(key): normalise(item) for key, item in value.items()}
        if isinstance(value, (tuple, list)):
            return [normalise(item) for item in value]
        return value
    return json.dumps(normalise(event), ensure_ascii=False, sort_keys=True,
        separators=(",", ":"), allow_nan=False).encode("utf-8")


def event_digest(event: dict[str, Any], version: str = "g7-audit-anchor/v1") -> str:
    return hashlib.sha256(canonical_event(event, version)).hexdigest()


class LegacyPreimageUnavailable(ValueError):
    def __init__(self): super().__init__('legacy_preimage_unavailable')


def legacy_event_digest(event: dict[str, Any], metadata: dict | None) -> str:
    """Reconstruct v1 input types/format from independently retained safe facts.

    Never infer the original representation by trying candidate digests. Values
    come from the authorized current payload; metadata contains no time values.
    """
    if not isinstance(metadata, dict) or not isinstance(metadata.get('legacy_time_preimage'), dict):
        raise LegacyPreimageUnavailable()
    modes = metadata['legacy_time_preimage']
    if set(modes) != {'occurred_at', 'received_at'}: raise LegacyPreimageUnavailable()
    reconstructed = dict(event)
    for field in ('occurred_at', 'received_at'):
        mode = modes[field]; value = event.get(field)
        try:
            if isinstance(value, str): value = datetime.fromisoformat(value.replace('Z', '+00:00'))
            if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
                raise LegacyPreimageUnavailable()
            if mode == {'kind': 'datetime'}:
                reconstructed[field] = value
            elif (isinstance(mode, dict) and set(mode) == {'kind','timespec','offset_minutes','zone'}
                    and mode['kind']=='string' and mode['timespec'] in {'auto','seconds','milliseconds','microseconds'}
                    and type(mode['offset_minutes']) is int and -1439 <= mode['offset_minutes'] <= 1439
                    and mode['zone'] in {'Z','offset'} and (mode['zone']!='Z' or mode['offset_minutes']==0)):
                if (mode['timespec']=='seconds' and value.microsecond
                        or mode['timespec']=='milliseconds' and value.microsecond % 1000):
                    raise LegacyPreimageUnavailable()
                rendered=value.astimezone(timezone(timedelta(minutes=mode['offset_minutes']))).isoformat(timespec=mode['timespec'])
                reconstructed[field]=rendered.replace('+00:00','Z') if mode['zone']=='Z' else rendered
            else: raise LegacyPreimageUnavailable()
        except (KeyError, TypeError, ValueError):
            raise LegacyPreimageUnavailable() from None
    return event_digest(reconstructed, 'g7-audit-anchor/v1')


def advisory_key(deployment_id: str, sink_id: str, event_id: str) -> int:
    raw = f"{deployment_id}\0{sink_id}\0{event_id}".encode()
    return int.from_bytes(hashlib.sha256(raw).digest()[:8], "big", signed=True)


class AuditAnchorAuthority:
    """Client for the independent inventory and its per-event serialisation."""

    def __init__(self, dsn: str, *, connect=psycopg.connect,
                 deployment_id: str = DEPLOYMENT_ID):
        if not dsn:
            raise ValueError("independent audit anchor DSN is required")
        self.dsn, self._connect, self.deployment_id = dsn, connect, deployment_id

    @contextmanager
    def locked(self, sink_id: str, event_id: str) -> Iterator["AnchorLease"]:
        conn = self._connect(self.dsn, autocommit=True, row_factory=dict_row)
        key = advisory_key(self.deployment_id, sink_id, str(event_id))
        try:
            conn.execute("SELECT pg_advisory_lock(%s)", (key,))
            yield AnchorLease(conn, self.deployment_id, sink_id, str(event_id))
        finally:
            try:
                conn.execute("SELECT pg_advisory_unlock(%s)", (key,))
            finally:
                conn.close()

    def inventory(self, sink_id: str | None = None, *, watermark: int | None = None,
                  expected_event_ids=()) -> list[dict[str, Any]]:
        query = """SELECT deployment_id, sink_id, event_id, event_sequence,
                   payload_sha256, sink_receipt, affected_scope, anchored_at,
                   contract_version FROM uvm_audit_anchor.inventory
                   WHERE deployment_id=%s"""
        params: tuple[Any, ...] = (self.deployment_id,)
        if sink_id is not None:
            query += " AND sink_id=%s"
            params += (sink_id,)
        if watermark is not None:
            if type(watermark) is not int or watermark < 0:
                raise ValueError("invalid audit inventory watermark")
            query += " AND (event_sequence<=%s OR event_id=ANY(%s::uuid[]))"
            params += (watermark, list(expected_event_ids))
        query += " ORDER BY event_sequence, event_id"
        with self._connect(self.dsn, row_factory=dict_row) as conn:
            return [dict(row) for row in conn.execute(query, params).fetchall()]


class AnchorLease:
    def __init__(self, connection, deployment_id: str, sink_id: str, event_id: str):
        self.connection = connection
        self.deployment_id, self.sink_id, self.event_id = deployment_id, sink_id, event_id

    def get(self) -> dict[str, Any] | None:
        row = self.connection.execute("""SELECT deployment_id, sink_id, event_id,
            event_sequence, payload_sha256, sink_receipt, affected_scope,
            anchored_at, contract_version FROM uvm_audit_anchor.inventory
            WHERE deployment_id=%s AND sink_id=%s AND event_id=%s""",
            (self.deployment_id, self.sink_id, self.event_id)).fetchone()
        return dict(row) if row is not None else None

    def anomaly(self, condition: str, evidence: dict[str, Any], *, detected_at=None) -> str:
        """Durably record a stable open integrity episode before returning."""
        incident_id = str(uuid4())
        self.connection.execute("""INSERT INTO uvm_audit_anchor.incidents
            (incident_id, deployment_id, sink_id, event_id, condition, detected_at,
             observed_at, state, evidence, contract_version)
            VALUES (%s,%s,%s,%s,%s,%s,%s,'open',%s,%s)""",
            (incident_id, self.deployment_id, self.sink_id, self.event_id, condition,
             detected_at or datetime.now(timezone.utc), datetime.now(timezone.utc),
             Jsonb(evidence), INCIDENT_VERSION))
        return incident_id


def anchor_payload(authority: AuditAnchorAuthority, *, sink_id: str,
                   event: dict[str, Any], sink_receipt: str,
                   sink_payload: dict[str, Any], affected_scope: str,
                   anchored_at: datetime | None = None) -> dict[str, Any]:
    """Observer-only insertion helper; the exporter must never call this."""
    event_id = str(event["event_id"])
    with authority.locked(sink_id, event_id) as lease:
        if lease.get() is not None:
            return {"status": "already-anchored", "event_id": event_id}
        if event_digest(event, ANCHOR_VERSION) != event_digest(sink_payload, ANCHOR_VERSION):
            lease.anomaly("siem_integrity", {"reason": "source_sink_mismatch"})
            raise RuntimeError("source and SIEM differ; event was not anchored")
        conn = lease.connection
        conn.execute("""INSERT INTO uvm_audit_anchor.inventory
            (deployment_id,sink_id,event_id,event_sequence,payload_sha256,
             sink_receipt,affected_scope,anchored_at,contract_version)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
            (authority.deployment_id, sink_id, event_id, int(event["event_sequence"]),
             event_digest(event, ANCHOR_VERSION), sink_receipt, affected_scope,
             anchored_at or datetime.now(timezone.utc), ANCHOR_VERSION))
    return {"status": "anchored", "event_id": event_id}
