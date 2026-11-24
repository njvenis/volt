"""Durable idempotency and attempt ledger for Qualys scanner operations.

All mutators accept the caller's live SQLAlchemy Connection; none owns an outer
transaction, opens another connection or commits. Coordinator admission, local
configuration and final publication pass ScannerTransaction.connection so shared
authority locks, intent/audit/receipt and provider state share one commit/rollback.
The begin_nested() in admit is an integrity-error SAVEPOINT only; it never commits
the enclosing transaction. HTTP, evidence writes and independently committing
observation/identity repositories run outside the short shared transaction.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any
import uuid

import sqlalchemy as sa
from sqlalchemy.engine import Connection
from sqlalchemy.exc import IntegrityError

_metadata = sa.MetaData()
operations = sa.Table("qualys_vm_operations", _metadata,
    sa.Column("operation_id", sa.Uuid(as_uuid=False), primary_key=True),
    sa.Column("connector_id", sa.String(36), nullable=False),
    sa.Column("source_id", sa.String(36), nullable=False),
    sa.Column("command_id", sa.String(36), nullable=False),
    sa.Column("principal_id", sa.String(256), nullable=False),
    sa.Column("action", sa.String(32), nullable=False),
    sa.Column("request_digest", sa.String(64), nullable=False),
    sa.Column("status", sa.String(16), nullable=False),
    sa.Column("configuration_revision", sa.Integer(), nullable=False),
    sa.Column("credential_version_id", sa.String(36), nullable=False),
    sa.Column("restore_epoch_id", sa.String(36), nullable=False),
    sa.Column("run_id", sa.Uuid(as_uuid=False)),
    sa.Column("finalization_stage", sa.String(24), nullable=False),
    sa.Column("intent_id", sa.String(36)),
    sa.Column("receipt_id", sa.String(36)),
    sa.Column("error_code", sa.String(64)),
    sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("finished_at", sa.DateTime(timezone=True)))
attempts = sa.Table("qualys_vm_http_attempts", _metadata,
    sa.Column("operation_id", sa.Uuid(as_uuid=False), primary_key=True),
    sa.Column("attempt_no", sa.Integer(), primary_key=True),
    sa.Column("page_ordinal", sa.Integer(), nullable=False),
    sa.Column("request_identity_sha256", sa.String(64), nullable=False),
    sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("finished_at", sa.DateTime(timezone=True)),
    sa.Column("response_class", sa.String(32)),
    sa.Column("http_status", sa.Integer()),
    sa.Column("success", sa.Boolean()),
    sa.Column("error_code", sa.String(64)),
    sa.Column("retry_after_seconds", sa.Float()))
pages = sa.Table("qualys_vm_operation_pages", _metadata,
    sa.Column("operation_id", sa.Uuid(as_uuid=False), primary_key=True),
    sa.Column("page_ordinal", sa.Integer(), primary_key=True),
    sa.Column("request_identity_sha256", sa.String(64), nullable=False),
    sa.Column("continuation_sha256", sa.String(64)),
    sa.Column("evidence_ref", sa.String(256)),
    sa.Column("response_sha256", sa.String(64)),
    sa.Column("byte_count", sa.Integer(), nullable=False),
    sa.Column("host_count", sa.Integer(), nullable=False),
    sa.Column("detection_count", sa.Integer(), nullable=False),
    sa.Column("response_class", sa.String(32), nullable=False),
    sa.Column("attempt_count", sa.Integer(), nullable=False),
    sa.Column("recorded_at", sa.DateTime(timezone=True), nullable=False))


class OperationError(RuntimeError):
    """Safe operation admission or transition error."""

    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


@dataclass(frozen=True)
class OperationAdmission:
    connector_id: str
    source_id: str
    command_id: str
    principal_id: str
    action: str
    request_digest: str
    configuration_revision: int
    credential_version_id: str
    restore_epoch_id: str
    run_id: str | None


def command_digest(principal_id: str, command: dict[str, Any]) -> str:
    body = json.dumps({"principal_id": principal_id, "command": command},
        sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    return hashlib.sha256(body).hexdigest()


def admit(connection: Connection, request: OperationAdmission, *,
          now: datetime | None = None) -> tuple[dict[str, Any], bool]:
    """Persist operation before HTTP; returns (row, replayed). Caller locks authority."""
    if request.action not in {"test", "collect"}:
        raise OperationError("invalid_action")
    if not _digest(request.request_digest) or request.configuration_revision < 0:
        raise OperationError("invalid_request")
    now = _aware(now or datetime.now(timezone.utc))
    existing = connection.execute(sa.select(operations).where(
        operations.c.connector_id == request.connector_id,
        operations.c.command_id == request.command_id)).mappings().first()
    if existing is not None:
        if (existing["principal_id"] != request.principal_id
                or existing["action"] != request.action
                or existing["request_digest"] != request.request_digest):
            raise OperationError("command_id_reused")
        return dict(existing), True
    operation_id = str(uuid.uuid4())
    values = {"operation_id": operation_id, "connector_id": request.connector_id,
        "source_id": request.source_id, "command_id": request.command_id,
        "principal_id": request.principal_id, "action": request.action,
        "request_digest": request.request_digest, "status": "running",
        "configuration_revision": request.configuration_revision,
        "credential_version_id": request.credential_version_id,
        "restore_epoch_id": request.restore_epoch_id, "run_id": request.run_id,
        "finalization_stage": "admitted", "error_code": None,
        "started_at": now, "finished_at": None}
    try:
        with connection.begin_nested():
            connection.execute(operations.insert().values(**values))
    except IntegrityError:
        # In particular, the partial unique running-connector index ensures
        # there is one external operation at a time per connector.
        raise OperationError("operation_in_progress") from None
    return values, False


def reserve_attempt(connection: Connection, operation_id: str, *, page_ordinal: int,
                    request_identity_sha256: str, now: datetime | None = None) -> int:
    """Durably reserve outbound request before dispatch; replay cannot reserve twice."""
    _require_running(connection, operation_id)
    if page_ordinal < 1 or not _digest(request_identity_sha256):
        raise OperationError("invalid_request")
    attempt_no = int(connection.execute(sa.select(sa.func.coalesce(
        sa.func.max(attempts.c.attempt_no), 0) + 1).where(
            attempts.c.operation_id == operation_id)).scalar_one())
    connection.execute(attempts.insert().values(operation_id=operation_id,
        attempt_no=attempt_no, page_ordinal=page_ordinal,
        request_identity_sha256=request_identity_sha256,
        started_at=_aware(now or datetime.now(timezone.utc)), finished_at=None,
        response_class=None, http_status=None, success=None, error_code=None,
        retry_after_seconds=None))
    return attempt_no


def finish_attempt(connection: Connection, operation_id: str, attempt_no: int, *,
                   response_class: str, success: bool, http_status: int | None = None,
                   error_code: str | None = None, retry_after_seconds: float | None = None,
                   now: datetime | None = None) -> None:
    _require_running(connection, operation_id)
    result = connection.execute(attempts.update().where(
        attempts.c.operation_id == operation_id,
        attempts.c.attempt_no == attempt_no,
        attempts.c.finished_at.is_(None)).values(
            finished_at=_aware(now or datetime.now(timezone.utc)),
            response_class=response_class, http_status=http_status, success=success,
            error_code=error_code, retry_after_seconds=retry_after_seconds))
    if result.rowcount != 1:
        raise OperationError("attempt_not_pending")


def record_page(connection: Connection, operation_id: str, *, page_ordinal: int,
                request_identity_sha256: str, continuation_sha256: str | None,
                evidence_ref: str, response_sha256: str, byte_count: int,
                host_count: int, detection_count: int, attempt_count: int,
                now: datetime | None = None) -> None:
    _require_running(connection, operation_id)
    if (page_ordinal < 1 or min(byte_count, host_count, detection_count) < 0
            or attempt_count < 1 or not all(_digest(value) for value in
                (request_identity_sha256, response_sha256))
            or (continuation_sha256 is not None and not _digest(continuation_sha256))):
        raise OperationError("invalid_page")
    values = {"operation_id": operation_id, "page_ordinal": page_ordinal,
        "request_identity_sha256": request_identity_sha256,
        "continuation_sha256": continuation_sha256, "evidence_ref": evidence_ref,
        "response_sha256": response_sha256, "byte_count": byte_count,
        "host_count": host_count, "detection_count": detection_count,
        "response_class": "xml", "attempt_count": attempt_count}
    prior = connection.execute(sa.select(pages).where(
        pages.c.operation_id == operation_id,
        pages.c.page_ordinal == page_ordinal)).mappings().first()
    if prior is not None:
        if any(prior[name] != value for name, value in values.items()):
            raise OperationError("page_replay_conflict")
        return
    connection.execute(pages.insert().values(**values,
        recorded_at=_aware(now or datetime.now(timezone.utc))))


def advance_finalization(connection: Connection, operation_id: str, stage: str) -> None:
    _advance_checkpoint(connection, operation_id, stage, allow_interrupted=False)


def reconcile_interrupted_finalization(connection: Connection, operation_id: str,
                                        stage: str) -> None:
    """Record local-only replay progress after reauthorising an interrupted run.

    This never changes status or reserves/sends HTTP. The caller must perform
    the backend's current exact-source authorization fence before reconciliation.
    """
    _advance_checkpoint(connection, operation_id, stage, allow_interrupted=True)


def _advance_checkpoint(connection: Connection, operation_id: str, stage: str,
                        *, allow_interrupted: bool) -> None:
    order = {name: index for index, name in enumerate(
        ("admitted", "evidence", "observations", "resolution", "published"))}
    if stage not in order:
        raise OperationError("invalid_finalization_stage")
    row = connection.execute(sa.select(operations).where(
        operations.c.operation_id == operation_id).with_for_update()).mappings().first()
    if row is None:
        raise OperationError("operation_missing")
    allowed_status = {"running", "interrupted"} if allow_interrupted else {"running"}
    if row["status"] not in allowed_status:
        raise OperationError("operation_not_running")
    if order[stage] == order[row["finalization_stage"]]:
        return
    if order[stage] != order[row["finalization_stage"]] + 1:
        raise OperationError("finalization_stage_conflict")
    connection.execute(operations.update().where(
        operations.c.operation_id == operation_id,
        operations.c.status == row["status"]).values(finalization_stage=stage))


def finish(connection: Connection, operation_id: str, *, status: str,
           error_code: str | None = None, now: datetime | None = None) -> None:
    if status not in {"succeeded", "partial", "failed", "interrupted"}:
        raise OperationError("invalid_terminal_status")
    row = connection.execute(sa.select(operations).where(
        operations.c.operation_id == operation_id).with_for_update()).mappings().first()
    if row is None:
        raise OperationError("operation_missing")
    if row["status"] != "running":
        if row["status"] == status and row["error_code"] == error_code:
            return
        raise OperationError("operation_terminal_conflict")
    if status == "succeeded" and row["finalization_stage"] != "published" and row["action"] == "collect":
        raise OperationError("publication_incomplete")
    connection.execute(operations.update().where(
        operations.c.operation_id == operation_id,
        operations.c.status == "running").values(status=status,
            error_code=error_code, finished_at=_aware(now or datetime.now(timezone.utc))))


def interrupt_running(connection: Connection, *, now: datetime | None = None) -> int:
    """Mark process-lost work interrupted; never reissue its reserved requests."""
    now = _aware(now or datetime.now(timezone.utc))
    running_ids = sa.select(operations.c.operation_id).where(
        operations.c.status == "running")
    connection.execute(attempts.update().where(
        attempts.c.operation_id.in_(running_ids),
        attempts.c.finished_at.is_(None)).values(finished_at=now,
            response_class="interrupted", success=False,
            error_code="process_interrupted"))
    result = connection.execute(operations.update().where(
        operations.c.status == "running").values(status="interrupted",
            error_code="process_interrupted",
            finished_at=now))
    return int(result.rowcount or 0)


def read_operation(connection: Connection, operation_id: str) -> dict[str, Any] | None:
    row = connection.execute(sa.select(operations).where(
        operations.c.operation_id == operation_id)).mappings().first()
    return dict(row) if row is not None else None


def _require_running(connection: Connection, operation_id: str) -> dict[str, Any]:
    row = connection.execute(sa.select(operations).where(
        operations.c.operation_id == operation_id).with_for_update()).mappings().first()
    if row is None:
        raise OperationError("operation_missing")
    if row["status"] != "running":
        raise OperationError("operation_not_running")
    return dict(row)


def _aware(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise OperationError("timestamp_must_be_aware")
    return value.astimezone(timezone.utc)


def _digest(value: str) -> bool:
    return (isinstance(value, str) and len(value) == 64 and
            all(char in "0123456789abcdef" for char in value))

# Isolated provider projections. Shared auth, connectors, crypto and audits remain
# accessible only through ScannerRuntimeAdapters/established repositories.
configurations = sa.Table('qualys_vm_configurations', _metadata,
    sa.Column('connector_id', sa.String(36), primary_key=True),
    sa.Column('source_id', sa.String(36), nullable=False),
    sa.Column('configuration_revision', sa.Integer(), nullable=False),
    sa.Column('settings', sa.JSON(), nullable=False),
    sa.Column('validation', sa.JSON()),
    sa.Column('active_snapshot', sa.JSON()),
    sa.Column('latest_attempt_run_id', sa.String(36)),
    sa.Column('latest_complete_run_id', sa.String(36)))
detections = sa.Table('qualys_vm_detections', _metadata,
    sa.Column('operation_id', sa.Uuid(as_uuid=False), primary_key=True),
    sa.Column('ordinal', sa.Integer(), primary_key=True),
    sa.Column('observation_id', sa.String(36), nullable=False),
    sa.Column('payload', sa.JSON(), nullable=False))
publications = sa.Table('qualys_vm_publications', _metadata,
    sa.Column('run_id', sa.Uuid(as_uuid=False), primary_key=True),
    sa.Column('operation_id', sa.Uuid(as_uuid=False), nullable=False),
    sa.Column('connector_id', sa.String(36), nullable=False),
    sa.Column('source_id', sa.String(36), nullable=False),
    sa.Column('published_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('retrieval', sa.JSON(), nullable=False),
    sa.Column('coverage', sa.JSON(), nullable=False),
    sa.Column('source_freshness', sa.JSON(), nullable=False))
cursors = sa.Table('qualys_vm_read_cursors', _metadata,
    sa.Column('token_hash', sa.String(64), primary_key=True),
    sa.Column('binding_hash', sa.String(64), nullable=False),
    sa.Column('run_id', sa.Uuid(as_uuid=False), nullable=False),
    sa.Column('after_ordinal', sa.Integer(), nullable=False),
    sa.Column('expires_at', sa.DateTime(timezone=True), nullable=False))


def read_configuration(connection, connector_id, source_id):
    row = connection.execute(sa.select(configurations).where(
        configurations.c.connector_id == connector_id,
        configurations.c.source_id == source_id)).mappings().first()
    return dict(row) if row else None


def save_configuration(connection, connector_id, source_id, *, revision, settings):
    current = read_configuration(connection, connector_id, source_id)
    values = dict(configuration_revision=revision, settings=settings,
        validation=None, active_snapshot=None)
    if current:
        connection.execute(configurations.update().where(
            configurations.c.connector_id == connector_id,
            configurations.c.source_id == source_id).values(**values))
    else:
        connection.execute(configurations.insert().values(connector_id=connector_id,
            source_id=source_id, **values))


def update_configuration(connection, connector_id, source_id, **values):
    allowed = {'validation', 'active_snapshot', 'latest_attempt_run_id',
        'latest_complete_run_id'}
    if not values or set(values) - allowed:
        raise OperationError('invalid_configuration_update')
    result = connection.execute(configurations.update().where(
        configurations.c.connector_id == connector_id,
        configurations.c.source_id == source_id).values(**values))
    if result.rowcount != 1:
        raise OperationError('configuration_missing')


def record_detection(connection, operation_id, ordinal, observation_id, payload):
    _require_running(connection, operation_id)
    current = connection.execute(sa.select(detections).where(
        detections.c.operation_id == operation_id,
        detections.c.ordinal == ordinal)).mappings().first()
    if current:
        if current['observation_id'] != observation_id or current['payload'] != payload:
            raise OperationError('detection_replay_conflict')
        return
    connection.execute(detections.insert().values(operation_id=operation_id,
        ordinal=ordinal, observation_id=observation_id, payload=payload))


def resolve_detection(connection, operation_id, ordinal, *, group_id, state):
    _require_running(connection, operation_id)
    row = connection.execute(sa.select(detections).where(
        detections.c.operation_id == operation_id,
        detections.c.ordinal == ordinal)).mappings().one()
    payload = dict(row['payload'], group_id=group_id, identity_resolution=state)
    connection.execute(detections.update().where(
        detections.c.operation_id == operation_id, detections.c.ordinal == ordinal
        ).values(payload=payload))


def publish(connection, operation, *, published_at, retrieval, coverage, freshness):
    _require_running(connection, operation['operation_id'])
    connection.execute(publications.insert().values(run_id=operation['run_id'],
        operation_id=operation['operation_id'], connector_id=operation['connector_id'],
        source_id=operation['source_id'], published_at=published_at,
        retrieval=retrieval, coverage=coverage, source_freshness=freshness))


def scoped_operation(connection, connector_id, source_id, operation_id):
    row = connection.execute(sa.select(operations).where(
        operations.c.operation_id == operation_id,
        operations.c.connector_id == connector_id,
        operations.c.source_id == source_id)).mappings().first()
    if row is None:
        raise OperationError('not_found')
    return dict(row)


def command_operation(connection, connector_id, command_id):
    """Provider admission evidence, used only inside current-authorized lookup."""
    row = connection.execute(sa.select(operations).where(
        operations.c.connector_id == connector_id,
        operations.c.command_id == command_id)).mappings().first()
    return dict(row) if row else None
