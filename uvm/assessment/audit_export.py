"""Read and acknowledge G3 audit events for the separately owned exporter."""

from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Iterator

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.engine import Connection, Engine
from uvm.assessment.policy_lock import lock_policy as acquire_policy_lock

from uvm.persistence.assessment_schema import (
    assessment_audit_events,
    assessment_export_acknowledgements,
    assessment_policy,
    assessment_sink_export_receipts,
)
from uvm.persistence.schema import groups


@contextmanager
def _connection(source: Engine | Connection) -> Iterator[tuple[Connection, bool]]:
    if isinstance(source, Engine):
        with source.connect() as connection:
            yield connection, True
    else:
        yield source, False


def _instant(value):
    if value is None:
        return None
    try:
        parsed = value if isinstance(value, datetime) else datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None or parsed.utcoffset() is None:
            return None
        return parsed.astimezone(timezone.utc)
    except (ValueError, AttributeError, TypeError):
        return None


def _scope_allows(scope: dict, target_id: str, source_family: str) -> bool:
    """Fail closed whenever the event lacks context needed by a selector."""
    groups_allowed = scope.get("group_ids") or []
    mode = scope.get("membership_mode", "explicit")
    if groups_allowed and "*" not in groups_allowed and target_id not in groups_allowed:
        return False
    if not groups_allowed and mode != "all_current":
        return False
    sources = scope.get("source_families") or []
    if sources and "*" not in sources and source_family not in sources:
        return False
    # The current durable group/audit contract has no environment or service
    # identity. A selector cannot be proven from absent context, so deny it.
    if scope.get("environments") or scope.get("service_ids"):
        return False
    return True


def _export_authorised_targets(source: Engine | Connection, principal_id: str,
                               *, lock_policy: bool = False) -> set[str]:
    """Evaluate current principal/grant policy against durable group context.

    Export is deliberately narrower than a general assessment command: a
    non-empty environment/service restriction fails closed because those
    attributes are not stored on the current group/audit read model.
    """
    with _connection(source) as (connection, _owned):
        query = sa.select(assessment_policy.c.document).where(assessment_policy.c.policy_id == 1)
        if lock_policy:
            acquire_policy_lock(connection, shared=True)
        policy = connection.execute(query).scalar_one_or_none()
        group_rows = connection.execute(sa.select(groups.c.group_id, groups.c.source_family)).all()
    if not isinstance(policy, dict):
        return set()
    now = datetime.now(timezone.utc)
    principal = policy.get("principals", {}).get(principal_id, {})
    def active(record):
        start, end = record.get("effective_from"), record.get("effective_until")
        start_at = _instant(start) if start else None
        end_at = _instant(end) if end else None
        if start and (start_at is None or start_at > now):
            return False
        if end and (end_at is None or end_at <= now):
            return False
        return True

    if principal.get("enabled") is False or not active(principal):
        return set()

    directory = {item.get("owner_id"): item for item in policy.get("owner_directory", [])
        if isinstance(item, dict) and item.get("owner_id")}
    authority_ids = {principal_id}
    for team_id in principal.get("team_ids", []):
        team = directory.get(team_id)
        if (team and team.get("owner_type") == "team"
                and team.get("enabled", True) is not False and active(team)):
            authority_ids.add(team_id)

    def has_action(actions):
        return "*" in (actions or []) or "audit.export" in (actions or [])

    roles = policy.get("roles", {})
    authorised = set()
    for group_id, source_family in group_rows:
        target_id = str(group_id)
        denied = False
        for rule in policy.get("denies", []):
            if (rule.get("principal_id") in authority_ids | {"*"}
                    and has_action(rule.get("actions"))
                    and ("*" in (rule.get("target_ids") or [])
                         or target_id in (rule.get("target_ids") or []))):
                denied = True
                break
        if denied:
            continue
        for grant in policy.get("grants", []):
            if grant.get("principal_id") not in authority_ids or not active(grant):
                continue
            role = roles.get(grant.get("role_id")) if grant.get("role_id") else None
            actions = role.get("actions", []) if role else grant.get("actions", [])
            if not has_action(actions):
                continue
            if role:
                scope = role.get("target_scope", {})
                if not _scope_allows(scope, target_id, source_family):
                    continue
                # An assignment-level explicit target list can only narrow a role.
                assignment_targets = grant.get("target_ids")
                if assignment_targets and "*" not in assignment_targets and target_id not in assignment_targets:
                    continue
                limits = role.get("limits", {})
            else:
                direct_targets = grant.get("target_ids", [])
                scope = grant.get("target_scope")
                if scope is None:
                    scope = {"group_ids": direct_targets, "membership_mode": "explicit",
                             "source_families": [], "environments": [], "service_ids": []}
                if not _scope_allows(scope, target_id, source_family):
                    continue
                limits = grant.get("limits", {})
            allowed_envs = limits.get("allowed_environments") or []
            allowed_services = limits.get("allowed_service_ids") or []
            if allowed_envs or allowed_services:
                continue
            authorised.add(target_id)
            break
    return authorised


def list_unexported_audit_events(source: Engine | Connection, limit: int = 100,
                                 *, principal_id: str | None = None) -> list[dict]:
    """Return oldest unacknowledged events with the complete stable event shape."""
    if isinstance(limit, bool) or not 1 <= limit <= 5000:
        raise ValueError("limit must be between 1 and 5000")
    event = assessment_audit_events
    ack = assessment_export_acknowledgements
    query = (sa.select(*(event.c[name] for name in (
        "event_id", "event_sequence", "actor_id", "actor_kind", "origin", "action",
        "target_id", "before_value", "after_value", "membership_ids",
        "membership_revision", "rationale", "evidence_ref", "policy_revision",
        "identity_revision", "occurred_at", "received_at", "correlation_id", "command_id",
        "authorization_context",
    )))
        .select_from(event.outerjoin(ack, ack.c.event_id == event.c.event_id))
        .where(ack.c.event_id.is_(None))
        .order_by(event.c.event_sequence)
        .limit(limit))
    with _connection(source) as (connection, _owned):
        if principal_id is not None:
            targets = _export_authorised_targets(connection, principal_id, lock_policy=True)
            query = query.where(event.c.target_id.in_(targets)) if targets else query.where(sa.false())
        rows = connection.execute(query).mappings().all()
    return [dict(row) for row in rows]


def list_authorised_audit_events(source: Engine | Connection, limit: int = 100,
                                 *, principal_id: str, after_sequence: int = 0) -> list[dict]:
    """Return all currently authorised durable events, including acknowledged rows.

    This is a reconciliation/readback seam, not an export queue. Requiring the
    current service principal prevents it from becoming an unscoped audit dump.
    """
    if isinstance(limit, bool) or not 1 <= limit <= 5000:
        raise ValueError("limit must be between 1 and 5000")
    event = assessment_audit_events
    query = (sa.select(*(event.c[name] for name in (
        "event_id", "event_sequence", "actor_id", "actor_kind", "origin", "action",
        "target_id", "before_value", "after_value", "membership_ids",
        "membership_revision", "rationale", "evidence_ref", "policy_revision",
        "identity_revision", "occurred_at", "received_at", "correlation_id", "command_id",
        "authorization_context",
    )))
        .where(event.c.event_sequence > after_sequence)
        .order_by(event.c.event_sequence)
        .limit(limit))
    with _connection(source) as (connection, _owned):
        targets = _export_authorised_targets(connection, principal_id, lock_policy=True)
        query = query.where(event.c.target_id.in_(targets)) if targets else query.where(sa.false())
        rows = connection.execute(query).mappings().all()
    return [dict(row) for row in rows]


def count_authorised_audit_events(source: Engine | Connection, *, principal_id: str) -> int:
    event = assessment_audit_events
    with _connection(source) as (connection, _owned):
        targets = _export_authorised_targets(connection, principal_id, lock_policy=True)
        query = sa.select(sa.func.count()).select_from(event)
        query = query.where(event.c.target_id.in_(targets)) if targets else query.where(sa.false())
        return int(connection.execute(query).scalar_one())


def list_unreceipted_audit_events(source: Engine | Connection, limit: int, *,
                                  principal_id: str, sink_id: str,
                                  after_sequence: int = 0) -> list[dict]:
    if isinstance(limit, bool) or not 1 <= limit <= 5000:
        raise ValueError("limit must be between 1 and 5000")
    event, receipt = assessment_audit_events, assessment_sink_export_receipts
    fields = [event.c[name] for name in (
        "event_id", "event_sequence", "actor_id", "actor_kind", "origin", "action",
        "target_id", "before_value", "after_value", "membership_ids", "membership_revision",
        "rationale", "evidence_ref", "policy_revision", "identity_revision", "occurred_at",
        "received_at", "correlation_id", "command_id", "authorization_context")]
    query = (sa.select(*fields).select_from(event.outerjoin(
        receipt, sa.and_(receipt.c.event_id == event.c.event_id, receipt.c.sink_id == sink_id)))
        .where(receipt.c.event_id.is_(None), event.c.event_sequence > after_sequence)
        .order_by(event.c.event_sequence).limit(limit))
    with _connection(source) as (connection, _owned):
        targets = _export_authorised_targets(connection, principal_id, lock_policy=True)
        query = query.where(event.c.target_id.in_(targets)) if targets else query.where(sa.false())
        return [dict(row) for row in connection.execute(query).mappings().all()]


def acknowledge_sink_export(source: Engine | Connection, event_id: str, sink_id: str,
                            sink_receipt: str, acknowledged_at: datetime | None = None, *,
                            principal_id: str) -> bool:
    if not sink_id.strip() or not sink_receipt.strip():
        raise ValueError("sink_id and sink_receipt must be non-empty")
    acknowledged_at = acknowledged_at or datetime.now(timezone.utc)
    table = assessment_sink_export_receipts
    def apply(connection: Connection) -> bool:
        target = connection.execute(sa.select(assessment_audit_events.c.target_id)
            .where(assessment_audit_events.c.event_id == event_id)).scalar_one_or_none()
        targets = _export_authorised_targets(connection, principal_id, lock_policy=True)
        if target is None or target not in targets:
            raise PermissionError("export principal is not authorised for this audit event")
        inserted = connection.execute(pg_insert(table).values(
            event_id=event_id, sink_id=sink_id, sink_receipt=sink_receipt,
            acknowledged_at=acknowledged_at.astimezone(timezone.utc)
        ).on_conflict_do_nothing(index_elements=[table.c.event_id, table.c.sink_id])
         .returning(table.c.event_id)).scalar_one_or_none()
        if inserted is not None:
            return True
        existing = connection.execute(sa.select(table.c.sink_receipt).where(
            table.c.event_id == event_id, table.c.sink_id == sink_id)).scalar_one_or_none()
        if existing != sink_receipt:
            raise ValueError("event already acknowledged by this sink with a different receipt")
        return False
    if isinstance(source, Engine):
        with source.begin() as connection:
            return apply(connection)
    if source.in_transaction():
        return apply(source)
    with source.begin():
        return apply(source)


def get_sink_export_receipt(source: Engine | Connection, event_id: str, sink_id: str,
                            *, principal_id: str) -> str | None:
    """Read the current sink receipt under the export principal's live scope."""
    with _connection(source) as (connection, _owned):
        target_id = connection.execute(sa.select(assessment_audit_events.c.target_id)
            .where(assessment_audit_events.c.event_id == str(event_id))).scalar_one_or_none()
        targets = _export_authorised_targets(connection, principal_id, lock_policy=True)
        if target_id is None or target_id not in targets:
            raise PermissionError("export principal is not authorised for this audit event")
        return connection.execute(sa.select(assessment_sink_export_receipts.c.sink_receipt)
            .where(assessment_sink_export_receipts.c.event_id == str(event_id),
                   assessment_sink_export_receipts.c.sink_id == sink_id)).scalar_one_or_none()


def count_unreceipted_audit_events(source: Engine | Connection, *, principal_id: str,
                                   sink_id: str) -> int:
    event, receipt = assessment_audit_events, assessment_sink_export_receipts
    query = (sa.select(sa.func.count()).select_from(event.outerjoin(
        receipt, sa.and_(receipt.c.event_id == event.c.event_id, receipt.c.sink_id == sink_id)))
        .where(receipt.c.event_id.is_(None)))
    with _connection(source) as (connection, _owned):
        targets = _export_authorised_targets(connection, principal_id, lock_policy=True)
        query = query.where(event.c.target_id.in_(targets)) if targets else query.where(sa.false())
        return int(connection.execute(query).scalar_one())


def count_unexported_audit_events(source: Engine | Connection,
                                  *, principal_id: str | None = None) -> int:
    """Return the number of durable source events awaiting sink acknowledgement."""
    event = assessment_audit_events
    ack = assessment_export_acknowledgements
    query = (sa.select(sa.func.count())
        .select_from(event.outerjoin(ack, ack.c.event_id == event.c.event_id))
        .where(ack.c.event_id.is_(None)))
    with _connection(source) as (connection, _owned):
        if principal_id is not None:
            targets = _export_authorised_targets(connection, principal_id, lock_policy=True)
            query = query.where(event.c.target_id.in_(targets)) if targets else query.where(sa.false())
        return int(connection.execute(query).scalar_one())


def get_audit_event(source: Engine | Connection, event_id: str) -> dict | None:
    """Read one audit event by its stable event UUID."""
    with _connection(source) as (connection, _owned):
        row = connection.execute(sa.select(assessment_audit_events)
                                 .where(assessment_audit_events.c.event_id == event_id))\
            .mappings().first()
    return dict(row) if row is not None else None


def acknowledge_export(source: Engine | Connection, event_id: str, sink_receipt: str,
                       acknowledged_at: datetime | None = None, *,
                       principal_id: str | None = None) -> bool:
    """Append the source acknowledgement after the exporter commits its sink row.

    Returns True when a row was inserted and False for an identical replay.
    Reuse with a different sink receipt is rejected.
    """
    if not isinstance(sink_receipt, str) or not sink_receipt.strip():
        raise ValueError("sink_receipt must be non-empty")
    acknowledged_at = acknowledged_at or datetime.now(timezone.utc)
    if acknowledged_at.tzinfo is None or acknowledged_at.utcoffset() is None:
        raise ValueError("acknowledged_at must be timezone-aware")

    def apply(connection: Connection) -> bool:
        table = assessment_export_acknowledgements
        if principal_id is not None:
            target_id = connection.execute(sa.select(assessment_audit_events.c.target_id)
                .where(assessment_audit_events.c.event_id == event_id)).scalar_one_or_none()
            targets = _export_authorised_targets(connection, principal_id, lock_policy=True)
            if target_id is None or target_id not in targets:
                raise PermissionError("export principal is not authorised for this audit event")
        inserted = connection.execute(pg_insert(table).values(
            event_id=event_id, sink_receipt=sink_receipt,
            acknowledged_at=acknowledged_at.astimezone(timezone.utc)
        ).on_conflict_do_nothing(index_elements=[table.c.event_id])
         .returning(table.c.event_id)).scalar_one_or_none()
        if inserted is not None:
            return True
        existing = connection.execute(sa.select(table.c.sink_receipt)
                                      .where(table.c.event_id == event_id)).scalar_one_or_none()
        if existing is not None:
            if existing != sink_receipt:
                raise ValueError("event already acknowledged with a different sink receipt")
            return False
        raise RuntimeError("acknowledgement conflict completed without a readable source row")

    if isinstance(source, Engine):
        with source.begin() as connection:
            return apply(connection)
    if source.in_transaction():
        return apply(source)
    with source.begin():
        return apply(source)


class AuditExportSource:
    """O3-compatible reader/acknowledger backed by the O1 source database."""

    def __init__(self, engine: Engine, principal_id: str):
        self.engine = engine
        self.principal_id = principal_id

    def list_unexported_audit_events(self, limit: int = 100) -> list[dict]:
        return list_unexported_audit_events(self.engine, limit, principal_id=self.principal_id)

    def list_authorised_audit_events(self, limit: int = 100) -> list[dict]:
        return list_authorised_audit_events(self.engine, limit, principal_id=self.principal_id)

    def list_authorised_audit_page(self, limit: int, after_sequence: int = 0) -> list[dict]:
        return list_authorised_audit_events(self.engine, limit, principal_id=self.principal_id,
                                            after_sequence=after_sequence)

    def count_authorised_audit_events(self) -> int:
        return count_authorised_audit_events(self.engine, principal_id=self.principal_id)

    def list_unreceipted_audit_page(self, sink_id: str, limit: int,
                                    after_sequence: int = 0) -> list[dict]:
        return list_unreceipted_audit_events(self.engine, limit, principal_id=self.principal_id,
                                             sink_id=sink_id, after_sequence=after_sequence)

    def acknowledge_sink_export(self, event_id, sink_id, sink_receipt, acknowledged_at):
        return acknowledge_sink_export(self.engine, str(event_id), sink_id, sink_receipt,
                                       acknowledged_at, principal_id=self.principal_id)

    def get_sink_receipt(self, event_id, sink_id):
        return get_sink_export_receipt(self.engine, str(event_id), sink_id,
                                       principal_id=self.principal_id)

    def sink_backlog_count(self, sink_id: str) -> int:
        return count_unreceipted_audit_events(self.engine, principal_id=self.principal_id,
                                              sink_id=sink_id)

    def acknowledge_export(self, event_id, sink_receipt: str, acknowledged_at: datetime) -> bool:
        return acknowledge_export(self.engine, str(event_id), sink_receipt, acknowledged_at,
                                 principal_id=self.principal_id)

    def backlog_count(self) -> int:
        return count_unexported_audit_events(self.engine, principal_id=self.principal_id)


def _source_engine(database_url: str) -> Engine:
    """Use the project's pinned psycopg3 driver for scheme-only PostgreSQL DSNs."""
    url = sa.engine.make_url(database_url)
    if url.drivername in {"postgresql", "postgres"}:
        url = url.set(drivername="postgresql+psycopg")
    return sa.create_engine(url, pool_pre_ping=True)


def make_audit_export_source() -> AuditExportSource:
    """O3 factory: construct an adapter from the runner's UVM_DB_URL only."""
    import os

    database_url = os.environ.get("UVM_DB_URL")
    if not database_url:
        raise RuntimeError("UVM_DB_URL is required for the O1 audit source")
    principal_id = os.environ.get("UVM_G3_EXPORT_PRINCIPAL", "g3-exporter")
    return AuditExportSource(_source_engine(database_url), principal_id)


def make_audit_backlog_counter():
    """Return O3 watchdog's no-argument backlog callback from UVM_DB_URL."""
    source = make_audit_export_source()
    return source.backlog_count
