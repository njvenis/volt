"""Durable G1 reservation writer for CE import operations.

This module owns UVM's reservation ledger only.  It never calls DefectDojo or
stores authoritative source payload bytes.  The complete structured manifest
needed to reconstruct the registration is persisted in the ledger; its
digests/references bind that reconstruction to the request and external
evidence, while authoritative snapshots and payload bytes remain outside this
store.
"""

from __future__ import annotations

import uuid
import hashlib
import base64
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional

import sqlalchemy as sa
from sqlalchemy.exc import IntegrityError

from uvm.engine.manifest import (
    InventorySealV1, ManifestBindingRegistry, OccurrenceManifestV1,
    PayloadRecordV1, RowDispositionV1,
)
from uvm.engine.operation import (
    EngineImportOperationV1, REQUEST_IMPORT, REQUEST_REIMPORT,
    STATUS_PENDING,
)
from uvm.engine.api_codec import parse_response
from uvm.engine.ce_read_client import RawResponse
from uvm.engine.occurrence_readback import build_occurrence_finding_links
from uvm.engine.readback_builder import (
    ReadbackBundleV1, rebuild_readback_from_responses,
    validate_readback_bundle,
)
from uvm.persistence.engine_operation_schema import (
    ce_context_registrations, ce_context_verifications,
    ce_deployment_configurations,
    engine_operation_manifests, engine_operation_requests,
    engine_operation_states, engine_operation_transitions,
    ce_import_request_bindings,
    manifest_ledger_headers, manifest_ledger_rows, manifest_payload_memberships,
    manifest_payload_records,
    ce_context_test_bindings,
    engine_occurrence_links,
)


class OperationStoreError(ValueError):
    """Base class for rejected or malformed durable reservations."""


class OperationConflictError(OperationStoreError):
    """An ID, context, or Test is already bound to different data."""


class OperationNotFoundError(OperationStoreError):
    pass


class OperationReadError(OperationStoreError):
    """Persisted rows cannot be safely represented as an operation."""


@dataclass(frozen=True)
class DurableOperation:
    operation: EngineImportOperationV1
    manifest_sha256: str
    manifest_ref: str
    history: tuple
    manifest: OccurrenceManifestV1
    registration_id: Optional[str] = None
    verification_id: Optional[str] = None


@dataclass(frozen=True)
class OperationWriteResult:
    status: str
    record: DurableOperation


@dataclass(frozen=True)
class DurableOccurrenceLink:
    link_id: str
    operation_id: str
    manifest_id: str
    mapping_revision: int
    occurrence_id: str
    test_id: int
    finding_id: int
    endpoint_id: int | None
    component_name: str | None
    component_version: str | None
    readback_ref: str
    readback_sha256: str
    recorded_at: datetime


_REQUEST_COLUMNS = (
    "schema_version", "operation_id", "context_key", "source_run_id",
    "scan_type", "payload_sha256", "parser_config_version", "engine_release",
    "request_kind", "requested_at", "close_old_findings", "test_id",
)
_STATE_COLUMNS = tuple(c.name for c in engine_operation_states.columns)


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        # SQLite's DateTime type drops the offset on round-trip; persisted
        # rows are defined as UTC by the store contract.
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


class EngineOperationStore:
    """Transactional writer/read-back over an already migrated 0006 engine ledger."""

    def __init__(self, engine, context_store=None):
        self.engine = engine
        self.context_store = context_store

    def _transaction(self):
        conn = self.engine.connect()
        try:
            if conn.dialect.name == "sqlite":
                # Acquire the write reservation before any SELECT.  This is
                # essential because context/Test collision checks are coupled.
                conn.exec_driver_sql("BEGIN IMMEDIATE")
            else:
                conn.begin()
            return conn
        except Exception:
            conn.close()
            raise

    @staticmethod
    def _close(conn, ok):
        try:
            (conn.commit if ok else conn.rollback)()
        finally:
            conn.close()

    @staticmethod
    def _lock(select, conn):
        return select.with_for_update() if conn.dialect.name == "postgresql" else select

    @staticmethod
    def _lock_configuration_table(conn):
        """Serialise configuration-head validation for this transaction.

        PostgreSQL row-level FOR SHARE does not conflict with an INSERT of a
        new configuration revision.  A table-level SHARE lock does conflict
        with the INSERT's ROW EXCLUSIVE lock and is held until commit.  On
        SQLite, BEGIN IMMEDIATE in ``_transaction`` already serialises the
        database writer; neither behaviour proves anything about a live CE
        deployment outside this local database.
        """
        if conn.dialect.name == "postgresql":
            conn.exec_driver_sql(
                "LOCK TABLE ce_deployment_configurations IN SHARE MODE"
            )

    def register(self, operation: EngineImportOperationV1,
                 manifest: OccurrenceManifestV1,
                 manifest_ref: Optional[str] = None,
                 *, registration_id: Optional[str] = None,
                 verification_id: Optional[str] = None,
                 cli_request_binding: Optional[dict] = None) -> OperationWriteResult:
        self._validate_new(operation, manifest, manifest_ref)
        # ManifestBindingRegistry is intentionally the gate for builder-issued
        # objects.  It rejects directly forged DTOs and does not claim that the
        # manifest body is durable.
        try:
            self._validate_manifest_integrity(manifest)
            ManifestBindingRegistry().bind(manifest)
        except Exception as exc:
            raise OperationStoreError(f"manifest is not an approved builder-issued binding: {exc}") from exc
        ref = manifest_ref or f"manifest://{manifest.manifest_id}"
        canonical_cli_request = None
        cli_digest = None
        if cli_request_binding is not None:
            if not isinstance(cli_request_binding, dict) or set(cli_request_binding) != {"request", "binding"}:
                raise OperationStoreError("CLI request binding must contain exact request and binding objects")
            canonical_cli_request = json.dumps(
                cli_request_binding["request"], sort_keys=True, ensure_ascii=False,
                separators=(",", ":"), allow_nan=False)
            cli_digest = hashlib.sha256(canonical_cli_request.encode("utf-8")).hexdigest()
        now = _utc(operation.requested_at)
        conn = self._transaction()
        try:
            self._lock_configuration_table(conn)
            req = conn.execute(self._lock(sa.select(engine_operation_requests).where(
                engine_operation_requests.c.operation_id == operation.operation_id), conn)).mappings().first()
            if req is not None:
                existing = self._load_locked(conn, operation.operation_id)
                prior_cli_binding = conn.execute(sa.select(ce_import_request_bindings).where(
                    ce_import_request_bindings.c.operation_id == operation.operation_id
                )).mappings().first()
                same_cli_binding = (
                    (prior_cli_binding is None and cli_request_binding is None)
                    or (prior_cli_binding is not None and cli_request_binding is not None
                        and prior_cli_binding["request_sha256"] == cli_digest
                        and prior_cli_binding["canonical_request"] == canonical_cli_request
                        and prior_cli_binding["binding"] == cli_request_binding["binding"])
                )
                if same_cli_binding and self._same_request(existing, operation, manifest, ref,
                                      registration_id, verification_id):
                    self._close(conn, True)
                    return OperationWriteResult("duplicate", existing)
                raise OperationConflictError("operation ID is already bound to different request or manifest")

            context = self._validate_verified_context(
                conn, operation, registration_id, verification_id)

            collisions = conn.execute(self._lock(sa.select(
                engine_operation_states.c.operation_id,
                engine_operation_states.c.context_key,
                engine_operation_states.c.test_id,
                engine_operation_states.c.bound_test_id,
                engine_operation_states.c.response_test_id,
                engine_operation_states.c.status,
                engine_operation_states.c.post_issued,
            ).where(
                sa.and_(
                    sa.or_(engine_operation_states.c.context_key == operation.context_key,
                           *[column == operation.test_id for column in (
                               engine_operation_states.c.test_id,
                               engine_operation_states.c.bound_test_id,
                               engine_operation_states.c.response_test_id,
                           ) if operation.test_id is not None]),
                    engine_operation_states.c.status.in_(("pending", "quarantined", "conflict")),
                )), conn)).mappings().all()
            for collision in collisions:
                # A reservation tied to an older configuration remains
                # immutable and will fail its own issue guard, but must not
                # strand the context after a guarded rotation. Only an
                # exact current verification keeps an active reservation.
                request = conn.execute(sa.select(
                    engine_operation_requests.c.registration_id,
                    engine_operation_requests.c.verification_id,
                ).where(engine_operation_requests.c.operation_id ==
                        collision["operation_id"])).mappings().one_or_none()
                verification = None
                if request is not None and request["registration_id"] is not None:
                    verification = conn.execute(sa.select(
                        ce_context_verifications.c.deployment_key,
                        ce_context_verifications.c.deployment_config_revision,
                    ).where(
                        ce_context_verifications.c.registration_id == request["registration_id"],
                        ce_context_verifications.c.verification_id == request["verification_id"],
                    )).mappings().one_or_none()
                head = None
                if verification is not None:
                    head = conn.execute(sa.select(
                        sa.func.max(ce_deployment_configurations.c.revision)
                    ).where(ce_deployment_configurations.c.deployment_key ==
                            verification["deployment_key"])).scalar_one()
                if (collision["status"] != STATUS_PENDING
                        or collision["post_issued"]
                        or verification is None or head is None
                        or verification["deployment_config_revision"] == head):
                    raise OperationConflictError(
                        "active context or Test is already reserved")

            # Settled mappings are durable ownership, not active write locks.
            # A first import may not replace one, and a reimport may only
            # target the Test settled for its own context.  Inspect the whole
            # settled set while holding the transaction so contradictory
            # historical mappings fail closed rather than being guessed at.
            settled = conn.execute(self._lock(sa.select(engine_operation_states).where(
                engine_operation_states.c.status == "settled"), conn)).mappings().all()
            settled_by_context, settled_by_test = \
                self._validate_settled_ownership(settled)
            context_mapping = settled_by_context.get(operation.context_key, set())
            context_is_mapped = bool(context_mapping)
            if operation.request_kind == REQUEST_IMPORT and operation.test_id is not None:
                raise OperationConflictError(
                    "first import must auto-create a Test; test_id must be null")
            if operation.request_kind == REQUEST_IMPORT and operation.prior_mapping_revision is not None:
                raise OperationConflictError(
                    "first import cannot provide a prior mapping revision")
            if operation.request_kind == REQUEST_REIMPORT:
                self._validate_reimport_binding(
                    conn, operation, registration_id, verification_id)
                self._require_settled_reimport_mapping(operation, settled)
            elif context_is_mapped:
                raise OperationConflictError("settled context or Test is already bound")

            foreign_test_contexts = settled_by_test.get(operation.test_id, set())
            if foreign_test_contexts and operation.context_key not in foreign_test_contexts:
                raise OperationConflictError("Test is already settled for a different context")

            for row in settled:
                bound_test = row["bound_test_id"]
                same_context = row["context_key"] == operation.context_key
                claims_test = (operation.request_kind == REQUEST_REIMPORT
                               and operation.test_id == bound_test)
                mapped = bound_test is not None
                if (same_context and mapped and operation.request_kind == REQUEST_IMPORT) or (
                    same_context and mapped and not claims_test) or (
                    not same_context and operation.request_kind == REQUEST_REIMPORT
                    and mapped and operation.test_id == bound_test
                ):
                    raise OperationConflictError("settled context or Test is already bound")

            values = {k: getattr(operation, k) for k in _REQUEST_COLUMNS}
            values["requested_at"] = now
            values["registration_id"] = registration_id
            values["verification_id"] = verification_id
            conn.execute(engine_operation_requests.insert().values(values))
            conn.execute(engine_operation_manifests.insert().values(
                operation_id=operation.operation_id,
                manifest_sha256=manifest.manifest_sha256, manifest_ref=ref, bound_at=now))
            self._insert_manifest_ledger(conn, manifest, operation, now)
            state = self._state_values(operation, revision=1, changed_at=now)
            conn.execute(engine_operation_states.insert().values(state))
            conn.execute(engine_operation_transitions.insert().values(
                transition_id=str(uuid.uuid4()), operation_id=operation.operation_id,
                from_revision=None, to_revision=1, from_status=None,
                to_status=STATUS_PENDING, evidence_ref=ref,
                occurred_at=now, transition_reason="reservation registered"))
            if cli_request_binding is not None:
                conn.execute(ce_import_request_bindings.insert().values(
                    operation_id=operation.operation_id, schema_version=1,
                    request_sha256=cli_digest,
                    canonical_request=canonical_cli_request,
                    binding=cli_request_binding["binding"], recorded_at=now))
            # Validate the complete persisted projection while the write
            # transaction is still open.  A malformed state must never be
            # committed merely because the post-insert reader rejected it.
            registered = self._load_locked(conn, operation.operation_id)
            conn.commit()
            return OperationWriteResult("registered", registered)
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def read_cli_request_binding(self, operation_id: str) -> dict:
        try:
            with self.engine.connect() as conn:
                row = conn.execute(sa.select(ce_import_request_bindings).where(
                    ce_import_request_bindings.c.operation_id == operation_id
                )).mappings().one_or_none()
        except Exception as exc:
            raise OperationReadError("CLI request binding could not be read") from exc
        if row is None:
            raise OperationNotFoundError(operation_id)
        canonical = row["canonical_request"]
        if hashlib.sha256(canonical.encode("utf-8")).hexdigest() != row["request_sha256"]:
            raise OperationReadError("CLI request binding digest is corrupt")
        try:
            request = json.loads(canonical)
        except (TypeError, json.JSONDecodeError) as exc:
            raise OperationReadError("CLI canonical request is corrupt") from exc
        return {"request": request, "binding": row["binding"],
                "request_sha256": row["request_sha256"]}

    def mark_issued(self, operation_id: str, evidence_ref: str) -> OperationWriteResult:
        if not evidence_ref:
            raise OperationStoreError("issue evidence reference is required")
        conn = self._transaction()
        try:
            self._lock_configuration_table(conn)
            current = self._load_locked(conn, operation_id)
            op = current.operation
            req = conn.execute(sa.select(engine_operation_requests).where(
                engine_operation_requests.c.operation_id == operation_id)).mappings().one()
            self._validate_verified_context(
                conn, op, req["registration_id"], req["verification_id"])
            expected_revision = (
                2 if op.request_kind == REQUEST_IMPORT
                and op.first_import_baseline_ref is not None else 1
            )
            if (op.status != STATUS_PENDING or op.post_issued
                    or op.revision != expected_revision):
                raise OperationConflictError("operation is not clean pending and cannot be issued")
            settled = conn.execute(self._lock(sa.select(
                engine_operation_states).where(
                    engine_operation_states.c.status == "settled"), conn
            )).mappings().all()
            settled_by_context, _ = self._validate_settled_ownership(settled)
            if op.request_kind == REQUEST_REIMPORT:
                self._validate_reimport_binding(
                    conn, op, req["registration_id"], req["verification_id"])
                self._require_settled_reimport_mapping(op, settled)
            elif settled_by_context.get(op.context_key):
                raise OperationConflictError("settled context or Test is already bound")
            now = datetime.now(timezone.utc)
            next_revision = op.revision + 1
            values = self._state_values(op, revision=next_revision, changed_at=now)
            values.update(post_issued=True)
            conn.execute(engine_operation_states.update().where(
                engine_operation_states.c.operation_id == operation_id).values(values))
            conn.execute(engine_operation_transitions.insert().values(
                transition_id=str(uuid.uuid4()), operation_id=operation_id,
                from_revision=op.revision, to_revision=next_revision, from_status=STATUS_PENDING,
                to_status=STATUS_PENDING, evidence_ref=evidence_ref,
                occurred_at=now, transition_reason="POST issued"))
            conn.commit()
            return OperationWriteResult("issued", self.load(operation_id))
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def retire_stale_configuration_reservation(
        self, operation_id: str, *, evidence_ref: str
    ) -> OperationWriteResult:
        """Retire an unissued pending reservation after configuration rotation.

        The stale issue attempt is a read-only rejection and changes no
        history. This explicit follow-up terminally records that the same
        reserved operation cannot be reused, releasing its active-context
        uniqueness claim while preserving its request and manifest history.
        """
        if not isinstance(evidence_ref, str) or not evidence_ref.strip():
            raise OperationStoreError("stale reservation evidence reference is required")
        conn = self._transaction()
        try:
            self._lock_configuration_table(conn)
            current = self._load_locked(conn, operation_id)
            op = current.operation
            if op.status == "failed" and op.error_code == "stale_configuration":
                if op.error_detail_ref == evidence_ref:
                    self._close(conn, True)
                    return OperationWriteResult("duplicate", current)
                raise OperationConflictError(
                    "stale configuration reservation has different retirement evidence")
            if op.status != STATUS_PENDING or op.post_issued:
                raise OperationConflictError(
                    "only an unissued pending operation can be retired as configuration-stale")
            request = conn.execute(sa.select(
                engine_operation_requests.c.registration_id,
                engine_operation_requests.c.verification_id,
            ).where(engine_operation_requests.c.operation_id == operation_id)).mappings().one()
            verification = conn.execute(sa.select(
                ce_context_verifications.c.deployment_key,
                ce_context_verifications.c.deployment_config_revision,
            ).where(
                ce_context_verifications.c.registration_id == request["registration_id"],
                ce_context_verifications.c.verification_id == request["verification_id"],
            )).mappings().one_or_none()
            if verification is None:
                raise OperationReadError("stale reservation verification is missing")
            latest = conn.execute(sa.select(
                sa.func.max(ce_deployment_configurations.c.revision)
            ).where(ce_deployment_configurations.c.deployment_key ==
                    verification["deployment_key"])).scalar_one()
            if (latest is None
                    or verification["deployment_config_revision"] == latest):
                raise OperationConflictError(
                    "reservation is not stale against the current configuration")
            now = datetime.now(timezone.utc)
            next_revision = op.revision + 1
            values = self._state_values(op, revision=next_revision, changed_at=now)
            values.update(status="failed", error_code="stale_configuration",
                          error_detail_ref=evidence_ref)
            conn.execute(engine_operation_states.update().where(
                sa.and_(engine_operation_states.c.operation_id == operation_id,
                        engine_operation_states.c.revision == op.revision,
                        engine_operation_states.c.status == STATUS_PENDING,
                        engine_operation_states.c.post_issued.is_(False)),
            ).values(values))
            conn.execute(engine_operation_transitions.insert().values(
                transition_id=str(uuid.uuid4()), operation_id=operation_id,
                from_revision=op.revision, to_revision=next_revision,
                from_status=STATUS_PENDING, to_status="failed",
                evidence_ref=evidence_ref, occurred_at=now,
                transition_reason="unissued reservation retired after configuration rotation"))
            result = self._load_locked(conn, operation_id)
            conn.commit()
            return OperationWriteResult("failed", result)
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def capture_first_import_baseline(self, operation_id: str, reader) -> OperationWriteResult:
        """Capture and durably bind verified-empty CE inventory before first POST.

        The reader is a configured ``CEReadClient`` capability supplied by the
        repository/application boundary.  The context store performs the
        scoped GET and retains its exact response page bytes before this
        transaction publishes the content reference.
        """
        capture = getattr(self.context_store, "capture_first_import_baseline", None)
        if not callable(capture):
            raise OperationStoreError("durable first-import baseline capture is unavailable")
        baseline = capture(operation_id, reader)
        conn = self._transaction()
        try:
            current = self._load_locked(conn, operation_id)
            op = current.operation
            req = conn.execute(sa.select(engine_operation_requests).where(
                engine_operation_requests.c.operation_id == operation_id
            )).mappings().one()
            if (op.request_kind != REQUEST_IMPORT or op.status != STATUS_PENDING
                    or op.post_issued or op.revision != 1
                    or op.first_import_baseline_ref is not None):
                raise OperationConflictError(
                    "operation changed or already has an immutable first-import baseline"
                )
            if (baseline.context_key != op.context_key
                    or baseline.registration_id != req["registration_id"]
                    or baseline.verification_id != req["verification_id"]
                    or baseline.candidate_test_ids or baseline.count != 0
                    or not baseline.pages):
                raise OperationConflictError(
                    "captured baseline does not prove an empty inventory for this registration"
                )
            now = datetime.now(timezone.utc)
            values = self._state_values(op, revision=2, changed_at=now)
            values["first_import_baseline_ref"] = baseline.baseline_ref
            updated = conn.execute(engine_operation_states.update().where(
                sa.and_(
                    engine_operation_states.c.operation_id == operation_id,
                    engine_operation_states.c.revision == 1,
                    engine_operation_states.c.post_issued.is_(False),
                    engine_operation_states.c.first_import_baseline_ref.is_(None),
                )).values(values))
            if updated.rowcount != 1:
                raise OperationConflictError(
                    "operation changed before first-import baseline was recorded"
                )
            conn.execute(engine_operation_transitions.insert().values(
                transition_id=str(uuid.uuid4()), operation_id=operation_id,
                from_revision=1, to_revision=2, from_status=STATUS_PENDING,
                to_status=STATUS_PENDING, evidence_ref=baseline.baseline_ref,
                occurred_at=now, transition_reason="first-import baseline recorded"))
            conn.commit()
            conn.close()
            return OperationWriteResult("baseline_recorded", self.load(operation_id))
        except Exception:
            conn.rollback()
            conn.close()
            raise

    def mark_uncertain(self, operation_id: str, *, evidence_ref: str,
                       reason: str) -> OperationWriteResult:
        """Quarantine an issued POST whose response outcome is uncertain.

        The transition is durable and blocks another POST.  Retrying the exact
        same call is idempotent; a different uncertainty report cannot rewrite
        the original evidence.
        """
        if not isinstance(evidence_ref, str) or not evidence_ref.strip():
            raise OperationStoreError("uncertainty evidence reference is required")
        if not isinstance(reason, str) or not reason.strip():
            raise OperationStoreError("uncertainty reason is required")
        transition_reason = f"uncertain response: {reason}"
        conn = self._transaction()
        try:
            self._lock_configuration_table(conn)
            current = self._load_locked(conn, operation_id)
            op = current.operation
            if op.status == "quarantined":
                last = current.history[-1]
                if (op.error_detail_ref == evidence_ref
                        and last["evidence_ref"] == evidence_ref
                        and last["transition_reason"] == transition_reason
                        and last["to_status"] == "quarantined"):
                    self._close(conn, True)
                    return OperationWriteResult("duplicate", current)
                raise OperationConflictError(
                    "quarantined operation has different uncertainty evidence")
            if op.status != STATUS_PENDING or not op.post_issued:
                raise OperationConflictError(
                    "only an issued pending operation can be marked uncertain")

            now = datetime.now(timezone.utc)
            next_revision = op.revision + 1
            values = self._state_values(op, revision=next_revision, changed_at=now)
            values.update(status="quarantined", error_detail_ref=evidence_ref)
            updated = conn.execute(engine_operation_states.update().where(
                sa.and_(
                    engine_operation_states.c.operation_id == operation_id,
                    engine_operation_states.c.revision == op.revision,
                    engine_operation_states.c.status == STATUS_PENDING,
                    engine_operation_states.c.post_issued.is_(True),
                )).values(values))
            if updated.rowcount != 1:
                raise OperationConflictError(
                    "operation revision changed before uncertainty was recorded")
            conn.execute(engine_operation_transitions.insert().values(
                transition_id=str(uuid.uuid4()), operation_id=operation_id,
                from_revision=op.revision, to_revision=next_revision,
                from_status=op.status, to_status="quarantined",
                evidence_ref=evidence_ref, occurred_at=now,
                transition_reason=transition_reason))
            result = self._load_locked(conn, operation_id)
            conn.commit()
            return OperationWriteResult("quarantined", result)
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def capture_first_import_reconciliation(
        self, operation_id: str, reader
    ) -> OperationWriteResult:
        """Persist one complete supported Test inventory for a lost first POST response.

        Every measured inventory remains quarantined.  In particular, zero
        candidates do not prove that the POST did not execute, and this method
        never authorises another POST or binds a candidate Test.
        """
        capture = getattr(self.context_store, "capture_first_import_reconciliation", None)
        read_back = getattr(self.context_store, "read_first_import_reconciliation", None)
        if not callable(capture) or not callable(read_back):
            raise OperationStoreError("durable first-import reconciliation is unavailable")

        # A published checkpoint is immutable. Exact replay reads and verifies
        # the same artifact without another GET or state revision.
        before = self.load(operation_id)
        if before.operation.reconciliation_evidence_ref is not None:
            try:
                evidence = read_back(
                    operation_id, before.operation.reconciliation_evidence_ref
                )
            except Exception as exc:
                raise OperationReadError(
                    "first-import reconciliation artifact is invalid"
                ) from exc
            return OperationWriteResult("duplicate", before)

        reconciliation = capture(operation_id, reader)
        conn = self._transaction()
        try:
            self._lock_configuration_table(conn)
            current = self._load_locked(conn, operation_id)
            op = current.operation
            req = conn.execute(sa.select(engine_operation_requests).where(
                engine_operation_requests.c.operation_id == operation_id
            )).mappings().one()
            if (op.request_kind != REQUEST_IMPORT or op.status != "quarantined"
                    or not op.post_issued or op.response_ref is not None
                    or op.first_import_baseline_ref is None
                    or op.reconciliation_evidence_ref is not None):
                raise OperationConflictError(
                    "only an uncertain quarantined first import without a checkpoint can reconcile"
                )
            if (reconciliation.operation_id != operation_id
                    or reconciliation.context_key != op.context_key
                    or reconciliation.registration_id != req["registration_id"]
                    or reconciliation.verification_id != req["verification_id"]
                    or reconciliation.baseline_ref != op.first_import_baseline_ref
                    or len(reconciliation.candidate_test_ids) != reconciliation.count):
                raise OperationConflictError(
                    "captured reconciliation inventory does not match the exact operation binding"
                )
            now = datetime.now(timezone.utc)
            next_revision = op.revision + 1
            values = self._state_values(op, revision=next_revision, changed_at=now)
            values["reconciliation_evidence_ref"] = reconciliation.reconciliation_ref
            updated = conn.execute(engine_operation_states.update().where(
                sa.and_(
                    engine_operation_states.c.operation_id == operation_id,
                    engine_operation_states.c.revision == op.revision,
                    engine_operation_states.c.status == "quarantined",
                    engine_operation_states.c.post_issued.is_(True),
                    engine_operation_states.c.first_import_baseline_ref ==
                    reconciliation.baseline_ref,
                    engine_operation_states.c.reconciliation_evidence_ref.is_(None),
                )).values(values))
            if updated.rowcount != 1:
                raise OperationConflictError(
                    "operation changed before first-import reconciliation was checkpointed"
                )
            conn.execute(engine_operation_transitions.insert().values(
                transition_id=str(uuid.uuid4()), operation_id=operation_id,
                from_revision=op.revision, to_revision=next_revision,
                from_status="quarantined", to_status="quarantined",
                evidence_ref=reconciliation.reconciliation_ref, occurred_at=now,
                transition_reason="reconciliation inventory recorded"))
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()
        return OperationWriteResult("reconciled", self.load(operation_id))

    def record_response(self, operation_id: str, raw_response_bytes: bytes) -> OperationWriteResult:
        """Durably capture the exact supported-API response body.

        The response is accepted only after the reservation's POST has been
        issued.  Parsing happens before publication, and the immutable body is
        stored by digest before its reference and parsed projection are
        committed together with the revision transition.  A later identical
        body is an idempotent replay; a different body quarantines the
        operation while retaining the first response projection.
        """
        if not isinstance(raw_response_bytes, bytes):
            raise OperationStoreError("response body must be bytes")
        try:
            parsed = parse_response(raw_response_bytes)
        except Exception as exc:
            raise OperationStoreError(f"response body is malformed: {exc}") from exc
        artifact_store = getattr(self.context_store, "artifact_store", None)
        if artifact_store is None:
            raise OperationStoreError("response artifact store is required")
        digest = hashlib.sha256(raw_response_bytes).hexdigest()
        ref = artifact_store.reference_for_digest(digest)
        conn = self._transaction()
        try:
            current = self._load_locked(conn, operation_id)
            op = current.operation
            if op.status != STATUS_PENDING or not op.post_issued:
                raise OperationConflictError("operation is not an issued pending operation")
            if op.response_ref is not None:
                stored_digest = op.response_ref.rsplit(":", 1)[-1]
                stored_body = artifact_store.get(op.response_ref, stored_digest)
                if stored_body == raw_response_bytes:
                    if (op.response_test_id != parsed.test_id or
                            op.response_deduplication_complete != parsed.deduplication_complete):
                        raise OperationReadError("stored response projection does not match its artifact")
                    self._close(conn, True)
                    return OperationWriteResult("duplicate", current)
                # Quarantine evidence is immutable too.  Publish the exact
                # conflicting body before recording its reference so a
                # transition can never point at an unstored artifact.
                conflict_ref, conflict_digest = artifact_store.put(raw_response_bytes)
                if conflict_ref != ref or conflict_digest != digest:
                    raise OperationStoreError("response artifact digest mismatch")
                now = datetime.now(timezone.utc)
                values = self._state_values(op, revision=op.revision + 1, changed_at=now)
                values["status"] = "quarantined"
                values["error_detail_ref"] = f"conflicting-response:{ref}"
                conn.execute(engine_operation_states.update().where(
                    engine_operation_states.c.operation_id == operation_id).values(values))
                conn.execute(engine_operation_transitions.insert().values(
                    transition_id=str(uuid.uuid4()), operation_id=operation_id,
                    from_revision=op.revision, to_revision=op.revision + 1,
                    from_status=op.status, to_status="quarantined", evidence_ref=ref,
                    occurred_at=now, transition_reason="conflicting response"))
                result = self._load_locked(conn, operation_id)
                self._close(conn, True)
                return OperationWriteResult("quarantined", result)
            response_ref, stored_digest = artifact_store.put(raw_response_bytes)
            if response_ref != ref or stored_digest != digest:
                raise OperationStoreError("response artifact digest mismatch")
            now = datetime.now(timezone.utc)
            values = self._state_values(op, revision=op.revision + 1, changed_at=now)
            values.update(response_ref=ref, response_test_id=parsed.test_id,
                          response_deduplication_complete=parsed.deduplication_complete,
                          deduplication_complete=parsed.deduplication_complete)
            conn.execute(engine_operation_states.update().where(
                engine_operation_states.c.operation_id == operation_id).values(values))
            conn.execute(engine_operation_transitions.insert().values(
                transition_id=str(uuid.uuid4()), operation_id=operation_id,
                from_revision=op.revision, to_revision=op.revision + 1,
                from_status=op.status, to_status=op.status, evidence_ref=ref,
                occurred_at=now, transition_reason="response recorded"))
            result = self._load_locked(conn, operation_id)
            self._close(conn, True)
            return OperationWriteResult("recorded", result)
        except Exception:
            conn.rollback()
            conn.close()
            raise

    def load(self, operation_id: str) -> DurableOperation:
        conn = self.engine.connect()
        try:
            return self._load_locked(conn, operation_id)
        finally:
            conn.close()

    def read_settled_readback(self, operation_id: str) -> ReadbackBundleV1:
        """Reconstruct and verify a settled read-back in a fresh process."""
        durable = self.load(operation_id)
        op = durable.operation
        if op.status != "settled" or not op.settle_readback_ref:
            raise OperationConflictError("operation has no settled read-back artifact")
        artifact_store = getattr(self.context_store, "artifact_store", None)
        if artifact_store is None:
            raise OperationStoreError("durable read-back artifact store is required")
        try:
            digest = op.settle_readback_ref.rsplit(":", 1)[-1]
            raw_document = artifact_store.get(op.settle_readback_ref, digest)
            document = json.loads(
                raw_document.decode("utf-8"),
                object_pairs_hook=self._reject_duplicate_json_keys,
            )
            if (not isinstance(document, dict)
                    or document.get("schema_version") != 1
                    or document.get("operation_id") != op.operation_id
                    or document.get("manifest_id") != durable.manifest.manifest_id
                    or document.get("context_key") != op.context_key
                    or document.get("test_id") != int(op.bound_test_id)
                    or document.get("engine_release") != op.engine_release):
                raise ValueError("settlement envelope does not match durable operation")

            def response(item):
                if not isinstance(item, dict):
                    raise ValueError("settlement response envelope is not an object")
                body = base64.b64decode(item["body_base64"], validate=True)
                response_value = RawResponse(
                    item["status"], item["headers"], body, item["url"])
                if item["body_sha256"] != response_value.sha256:
                    raise ValueError("settlement response body digest mismatch")
                return response_value

            responses = [response(document["test"])]
            for key in ("finding_pages", "finding_details", "endpoint_details"):
                values = document[key]
                if not isinstance(values, list):
                    raise ValueError(f"settlement {key} must be a list")
                responses.extend(response(item) for item in values)
        except Exception as exc:
            raise OperationReadError(
                "settled read-back artifact is missing or invalid") from exc

        if (self.context_store is None or durable.registration_id is None
                or durable.verification_id is None):
            raise OperationStoreError("verified deployment context is required for read-back replay")
        evidence = self.context_store.read_verified_context(
            durable.registration_id, durable.verification_id)
        configured = self.context_store.read(
            evidence.deployment_key, evidence.deployment_config_revision
        ).snapshot.configured
        if configured.ce_release != op.engine_release:
            raise OperationReadError("settled read-back CE release differs from configuration")
        try:
            bundle = rebuild_readback_from_responses(
                responses, op, durable.manifest,
                ce_release=configured.ce_release,
                expected_ce_base_url=configured.ce_base_url,
                engagement_id=evidence.engagement_id,
                evidence_ref=f"settled-artifact://{op.settle_readback_ref}",
                source_kind="retained-artifact")
            if self._readback_document(op, durable.manifest, bundle) != raw_document:
                raise ValueError("reconstructed settlement envelope is not byte-exact")
            validate_readback_bundle(
                bundle, op, durable.manifest,
                ce_release=configured.ce_release,
                expected_ce_base_url=configured.ce_base_url,
                engagement_id=evidence.engagement_id)
        except Exception as exc:
            raise OperationReadError(
                "settled read-back artifact cannot be reconstructed from its exact responses") from exc
        return bundle

    @staticmethod
    def _reject_duplicate_json_keys(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("settled read-back envelope contains duplicate keys")
            result[key] = value
        return result

    @staticmethod
    def _readback_document(operation, manifest, readback: ReadbackBundleV1) -> bytes:
        def response(item):
            return {
                "status": item.status,
                "url": item.url,
                "headers": dict(item.headers),
                "body_base64": base64.b64encode(item.body).decode("ascii"),
                "body_sha256": item.sha256,
            }

        document = {
            "schema_version": 1,
            "operation_id": operation.operation_id,
            "manifest_id": manifest.manifest_id,
            "context_key": operation.context_key,
            "test_id": readback.test_id,
            "engine_release": operation.engine_release,
            "test": response(readback.test_response),
            "finding_pages": [response(item) for item in readback.finding_pages],
            "finding_details": [response(item) for item in readback.finding_details],
            "endpoint_details": [response(item) for item in readback.endpoint_details],
        }
        return json.dumps(document, sort_keys=True, separators=(",", ":")).encode()

    def settle_readback(
        self,
        operation_id: str,
        readback: ReadbackBundleV1,
        *,
        fail_before_commit: bool = False,
    ) -> OperationWriteResult:
        """Atomically settle a complete supported-API read-back and its occurrence links.

        A response-backed operation needs explicit response deduplication
        completion. A lost first-import response may settle only after the
        pre-POST empty baseline, a complete one-candidate reconciliation, a
        durable Test binding and a complete read-back that associates every
        included payload record. Lost reimports remain quarantined because a
        stale Test read-back cannot prove that uncertain write executed.
        """
        if not isinstance(readback, ReadbackBundleV1):
            raise OperationStoreError("settlement requires a complete ReadbackBundleV1")
        before = self.load(operation_id)
        op = before.operation
        manifest = before.manifest
        if readback.operation_id != operation_id:
            raise OperationConflictError("read-back belongs to a different operation")
        if (self.context_store is None or before.registration_id is None
                or before.verification_id is None):
            raise OperationStoreError("verified deployment context is required for read-back settlement")
        verified_context = self.context_store.read_verified_context(
            before.registration_id, before.verification_id)
        configuration = self.context_store.read(
            verified_context.deployment_key,
            verified_context.deployment_config_revision)
        configured = configuration.snapshot.configured
        if configured.ce_release != op.engine_release:
            raise OperationConflictError(
                "read-back CE release does not match the verified deployment")
        recovered = (
            op.status == "quarantined" and op.request_kind == REQUEST_IMPORT
            and op.response_ref is None and op.reconciliation_evidence_ref is not None
        )
        accepted_test_ids = {
            str(value) for value in (op.test_id, op.response_test_id, op.bound_test_id)
            if value is not None
        }
        if recovered:
            reconciliation = self.context_store.read_first_import_reconciliation(
                operation_id, op.reconciliation_evidence_ref
            )
            accepted_test_ids.update(map(str, reconciliation.candidate_test_ids))
        if (readback.context_key != op.context_key
                or str(readback.test_id) not in accepted_test_ids):
            raise OperationConflictError("read-back context or Test does not match operation")
        replay_operation = op
        if not (op.test_id or op.response_test_id or op.bound_test_id):
            from dataclasses import replace
            replay_operation = replace(op, bound_test_id=str(readback.test_id))
        readback = validate_readback_bundle(
            readback, replay_operation, manifest,
            ce_release=configured.ce_release,
            expected_ce_base_url=configured.ce_base_url,
            engagement_id=verified_context.engagement_id)
        links = build_occurrence_finding_links(manifest, readback)
        if not links:
            raise OperationConflictError("settlement read-back has no included occurrence associations")
        if op.status == "settled":
            artifact = self._readback_document(op, manifest, readback)
            digest = hashlib.sha256(artifact).hexdigest()
            artifact_store = getattr(self.context_store, "artifact_store", None)
            if artifact_store is None:
                raise OperationStoreError("durable read-back artifact store is required")
            expected_ref = artifact_store.reference_for_digest(digest)
            if op.settle_readback_ref != expected_ref:
                raise OperationConflictError("settled operation has different read-back evidence")
            if artifact_store.get(expected_ref, digest) != artifact:
                raise OperationReadError("settlement artifact differs from its retained bytes")
            return OperationWriteResult("duplicate", before)
        if recovered:
            if op.first_import_baseline_ref is None:
                raise OperationConflictError("recovered first import lacks its empty pre-POST baseline")
            reconciliation = self.context_store.read_first_import_reconciliation(
                operation_id, op.reconciliation_evidence_ref
            )
            if (reconciliation.count != 1
                    or reconciliation.candidate_test_ids != (readback.test_id,)
                    or reconciliation.candidate_test_ids[0] in
                    self.context_store.read_first_import_baseline(
                        operation_id
                    ).candidate_test_ids):
                raise OperationConflictError(
                    "read-back Test is not the sole fresh reconciliation candidate"
                )
        elif op.status != STATUS_PENDING:
            raise OperationConflictError(
                "only a pending response-backed operation or recovered first import can settle"
            )
        elif not op.post_issued or op.response_ref is None:
            raise OperationConflictError("settlement requires the issued POST and captured response")
        elif (op.response_deduplication_complete is not True
              or op.deduplication_complete is not True):
            raise OperationConflictError(
                "incomplete or unknown response deduplication cannot settle"
            )
        elif op.response_test_id != str(readback.test_id):
            raise OperationConflictError("read-back Test does not match the captured response")

        if op.request_kind == REQUEST_IMPORT and op.first_import_baseline_ref is None:
            raise OperationConflictError("first import requires a verified empty pre-POST baseline")
        if op.request_kind == REQUEST_REIMPORT and str(readback.test_id) != str(op.test_id):
            raise OperationConflictError("reimport read-back does not match its registered Test")

        # The durable immutable binding is the Test ownership authority for
        # both the first import and all subsequent same-Test reimports.
        if self.context_store is None or before.registration_id is None:
            raise OperationStoreError("registered context binding is required for settlement")
        with self.engine.connect() as connection:
            binding = connection.execute(sa.select(ce_context_test_bindings).where(
                ce_context_test_bindings.c.registration_id == before.registration_id,
                ce_context_test_bindings.c.deployment_key ==
                connection.execute(sa.select(ce_context_registrations.c.deployment_key).where(
                    ce_context_registrations.c.registration_id == before.registration_id
                )).scalar_one(),
                ce_context_test_bindings.c.test_id == readback.test_id,
            )).mappings().one_or_none()
        if binding is None:
            raise OperationConflictError("read-back Test has no durable registration binding")
        if op.request_kind == REQUEST_IMPORT and binding["originating_operation_id"] != operation_id:
            raise OperationConflictError("first-import Test binding belongs to another operation")

        artifact_store = getattr(self.context_store, "artifact_store", None)
        if artifact_store is None:
            raise OperationStoreError("durable read-back artifact store is required")
        artifact = self._readback_document(op, manifest, readback)
        readback_ref, digest = artifact_store.put(artifact)
        if (digest != hashlib.sha256(artifact).hexdigest()
                or artifact_store.get(readback_ref, digest) != artifact):
            raise OperationStoreError("complete read-back artifact failed digest read-back")

        conn = self._transaction()
        try:
            self._lock_configuration_table(conn)
            current = self._load_locked(conn, operation_id)
            op = current.operation
            if op.status == "settled":
                if op.settle_readback_ref == readback_ref:
                    self._close(conn, True)
                    return OperationWriteResult("duplicate", current)
                raise OperationConflictError("settled operation has different read-back evidence")
            if recovered:
                if (op.status != "quarantined" or op.request_kind != REQUEST_IMPORT
                        or op.response_ref is not None
                        or op.reconciliation_evidence_ref !=
                        before.operation.reconciliation_evidence_ref):
                    raise OperationConflictError("recovered operation changed before settlement")
            elif op.status != STATUS_PENDING or op.response_ref != before.operation.response_ref:
                raise OperationConflictError("response-backed operation changed before settlement")

            settled = conn.execute(sa.select(engine_operation_states).where(
                engine_operation_states.c.status == "settled").with_for_update()
            ).mappings().all()
            settled_by_context, _ = self._validate_settled_ownership(settled)
            prior_rows = [row for row in settled if row["context_key"] == op.context_key]
            prior_revision = max((row["mapping_revision"] for row in prior_rows), default=None)
            if op.request_kind == REQUEST_IMPORT and prior_revision is not None:
                raise OperationConflictError("first import context already has a settled mapping")
            if op.request_kind == REQUEST_REIMPORT:
                self._require_settled_reimport_mapping(op, settled)
                if op.prior_mapping_revision != prior_revision:
                    raise OperationConflictError("reimport prior mapping revision is stale")
            mapping_revision = 1 if prior_revision is None else prior_revision + 1
            now = datetime.now(timezone.utc)
            revision = op.revision + 1
            values = self._state_values(op, revision=revision, changed_at=now)
            values.update(
                status="settled", bound_test_id=str(readback.test_id),
                response_test_id=(op.response_test_id if not recovered else None),
                deduplication_complete=(op.deduplication_complete
                                        if not recovered else None),
                deduplication_evidence_ref=(op.deduplication_evidence_ref
                                            if not recovered else None),
                settle_readback_ref=readback_ref,
                finding_ids=list(readback.finding_ids),
                endpoint_ids=list(readback.endpoint_ids),
                mapping_revision=mapping_revision,
                prior_mapping_revision=prior_revision,
                reconciled=recovered,
            )
            result = conn.execute(engine_operation_states.update().where(
                sa.and_(
                    engine_operation_states.c.operation_id == operation_id,
                    engine_operation_states.c.revision == op.revision,
                    engine_operation_states.c.status == op.status,
                )).values(values))
            if result.rowcount != 1:
                raise OperationConflictError("operation changed before settlement commit")
            conn.execute(engine_operation_transitions.insert().values(
                transition_id=str(uuid.uuid4()), operation_id=operation_id,
                from_revision=op.revision, to_revision=revision,
                from_status=op.status, to_status="settled",
                evidence_ref=readback_ref, occurred_at=now,
                transition_reason=("reconciliation read-back settled" if recovered
                                   else "complete CE read-back settled"),
            ))
            for link in links:
                conn.execute(engine_occurrence_links.insert().values(
                    link_id=str(uuid.uuid4()), operation_id=operation_id,
                    manifest_id=manifest.manifest_id,
                    mapping_revision=mapping_revision,
                    occurrence_id=link.occurrence_id,
                    test_id=readback.test_id, finding_id=link.finding_id,
                    endpoint_id=link.endpoint_id,
                    component_name=link.component_name,
                    component_version=link.component_version,
                    readback_ref=readback_ref, readback_sha256=digest,
                    recorded_at=now,
                ))
            if fail_before_commit:
                raise RuntimeError("injected settlement rollback before commit")
            updated = self._load_locked(conn, operation_id)
            self._close(conn, True)
            return OperationWriteResult("settled", updated)
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def read_occurrence_links(self, operation_id: str) -> tuple[DurableOccurrenceLink, ...]:
        with self.engine.connect() as connection:
            rows = connection.execute(sa.select(engine_occurrence_links).where(
                engine_occurrence_links.c.operation_id == operation_id
            ).order_by(
                engine_occurrence_links.c.occurrence_id,
                engine_occurrence_links.c.finding_id,
                engine_occurrence_links.c.endpoint_id,
            )).mappings().all()
        return tuple(DurableOccurrenceLink(**dict(row)) for row in rows)

    def _load_locked(self, conn, operation_id: str) -> DurableOperation:
        req = conn.execute(self._lock(sa.select(engine_operation_requests).where(
            engine_operation_requests.c.operation_id == operation_id), conn)).mappings().first()
        if req is None:
            raise OperationNotFoundError(operation_id)
        man = conn.execute(sa.select(engine_operation_manifests).where(
            engine_operation_manifests.c.operation_id == operation_id)).mappings().first()
        state = conn.execute(self._lock(sa.select(engine_operation_states).where(
            engine_operation_states.c.operation_id == operation_id), conn)).mappings().first()
        history = conn.execute(sa.select(engine_operation_transitions).where(
            engine_operation_transitions.c.operation_id == operation_id).order_by(
                engine_operation_transitions.c.to_revision)).mappings().all()
        if man is None or state is None or not history:
            raise OperationReadError("reservation is missing manifest, state, or history")
        self._validate_persisted(req, man, state, history)
        if state["first_import_baseline_ref"] is not None:
            try:
                self.context_store.read_first_import_baseline(operation_id)
            except Exception as exc:
                raise OperationReadError("first-import baseline artifact is invalid") from exc
        if state["reconciliation_evidence_ref"] is not None:
            try:
                self.context_store.read_first_import_reconciliation(
                    operation_id, state["reconciliation_evidence_ref"]
                )
            except Exception as exc:
                raise OperationReadError(
                    "first-import reconciliation artifact is invalid"
                ) from exc
        self._validate_response_artifact(state, history)
        try:
            manifest = self._load_manifest_ledger(conn, req, state, man)
        except OperationReadError:
            raise
        except Exception as exc:
            raise OperationReadError(f"manifest ledger content is invalid: {exc}") from exc
        op_fields = {
            "bound_test_id", "response_deduplication_complete", "response_ref",
            "response_test_id", "deduplication_complete", "deduplication_evidence_ref",
            "settle_readback_ref", "reconciliation_evidence_ref", "first_import_baseline_ref",
            "finding_ids", "endpoint_ids", "mapping_revision", "prior_mapping_revision",
            "error_code", "error_detail_ref", "supersedes_operation_id", "post_issued",
            "reconciled",
        }
        request_values = {k: req[k] for k in _REQUEST_COLUMNS}
        request_values["requested_at"] = _utc(request_values["requested_at"])
        state_values = {k: state[k] for k in op_fields}
        state_values["finding_ids"] = tuple(state_values["finding_ids"] or ())
        state_values["endpoint_ids"] = tuple(state_values["endpoint_ids"] or ())
        request_values.update(
            revision=state["revision"], status=state["status"],
            context_key=state["context_key"], test_id=state["test_id"],
            **state_values)
        op = EngineImportOperationV1(**request_values)
        return DurableOperation(
            op, man["manifest_sha256"], man["manifest_ref"], tuple(history), manifest,
            req["registration_id"], req["verification_id"])

    def _validate_response_artifact(self, state, history):
        """Validate response bytes and their parsed projection on every read."""
        fields = (state["response_ref"], state["response_test_id"],
                  state["response_deduplication_complete"])
        if state["response_ref"] is None:
            if any(value is not None for value in fields[1:]):
                raise OperationReadError("response projection exists without response artifact")
            return
        artifact_store = getattr(self.context_store, "artifact_store", None)
        if artifact_store is None:
            raise OperationReadError("response artifact store is required to read response evidence")
        try:
            digest = state["response_ref"].rsplit(":", 1)[-1]
            body = artifact_store.get(state["response_ref"], digest)
            parsed = parse_response(body)
        except Exception as exc:
            raise OperationReadError("stored response artifact is missing or malformed") from exc
        if (parsed.test_id != state["response_test_id"] or
                parsed.deduplication_complete != state["response_deduplication_complete"]):
            raise OperationReadError("stored response artifact does not match persisted projection")
        for transition in history:
            if transition["transition_reason"] != "conflicting response":
                continue
            if state["error_detail_ref"] != (
                    f"conflicting-response:{transition['evidence_ref']}"):
                raise OperationReadError(
                    "conflicting response transition does not match error detail")
            try:
                digest = transition["evidence_ref"].rsplit(":", 1)[-1]
                body = artifact_store.get(transition["evidence_ref"], digest)
                parse_response(body)
            except Exception as exc:
                raise OperationReadError(
                    "conflicting response artifact is missing or malformed") from exc

    @staticmethod
    def _row_id(manifest_id, observation_id):
        return str(uuid.uuid5(uuid.NAMESPACE_URL, f"uvm:manifest-row:{manifest_id}:{observation_id}"))

    @classmethod
    def _insert_manifest_ledger(cls, conn, manifest, operation, now):
        seal = manifest.inventory_seal
        conn.execute(manifest_ledger_headers.insert().values(
            manifest_id=manifest.manifest_id, operation_id=operation.operation_id,
            schema_version=manifest.schema_version, source_family=manifest.source_family,
            source_account_id=manifest.source_account_id, run_id=manifest.run_id,
            context_key=manifest.context_key, bound_test_id=manifest.bound_test_id,
            inventory_seal_ref=seal.seal_ref,
            inventory_high_watermark=seal.retention_high_watermark,
            retained_row_count=seal.retained_row_count,
            conflict_holder_count=seal.conflict_holder_count,
            payload_sha256=manifest.payload_sha256,
            manifest_sha256=manifest.manifest_sha256, sealed_at=now))
        row_ids = {}
        for ordinal, disposition in enumerate(manifest.dispositions):
            row_id = cls._row_id(manifest.manifest_id, disposition.observation_id)
            row_ids[disposition.observation_id] = row_id
            conn.execute(manifest_ledger_rows.insert().values(
                manifest_row_id=row_id, manifest_id=manifest.manifest_id,
                observation_id=disposition.observation_id,
                source_account_id=manifest.source_account_id, run_id=manifest.run_id,
                source_record_ordinal=disposition.source_record_ordinal,
                disposition_ordinal=ordinal,
                retained_evidence_sha256=disposition.raw_evidence_sha256,
                disposition=disposition.disposition,
                resolution_id=disposition.resolution_id,
                resolution_revision=disposition.resolution_revision,
                occurrence_id=disposition.occurrence_id,
                exclusion_rule_id=disposition.exclusion_rule_id,
                exclusion_rule_version=disposition.exclusion_rule_version,
                exclusion_evidence_ref=disposition.exclusion_evidence_ref,
                exclusion_reason=disposition.exclusion_reason,
                excluded_by_actor_id=disposition.exclusion_actor,
                blocked_reason=disposition.blocked_reason))
        for ordinal, record in enumerate(manifest.payload_records):
            conn.execute(manifest_payload_records.insert().values(
                payload_record_id=record.payload_record_id,
                manifest_id=manifest.manifest_id, payload_ordinal=ordinal,
                transformation_version=record.transformation_version))
            for membership_ordinal, observation_id in enumerate(record.source_observation_ids):
                conn.execute(manifest_payload_memberships.insert().values(
                    manifest_id=manifest.manifest_id,
                    payload_record_id=record.payload_record_id,
                    manifest_row_id=row_ids[observation_id],
                    membership_ordinal=membership_ordinal))

    @classmethod
    def _load_manifest_ledger(cls, conn, req, state, man):
        header = conn.execute(sa.select(manifest_ledger_headers).where(
            manifest_ledger_headers.c.operation_id == req["operation_id"])).mappings().first()
        if header is None:
            raise OperationReadError("0005-only reservation has no durable manifest body")
        if (header["manifest_sha256"] != man["manifest_sha256"]
                or header["operation_id"] != req["operation_id"]
                or header["context_key"] != req["context_key"]
                or header["context_key"] != state["context_key"]
                or header["bound_test_id"] != (
                    req["test_id"] if req["request_kind"] == REQUEST_REIMPORT
                    else None)
                or header["run_id"] != req["source_run_id"]
                or header["payload_sha256"] != req["payload_sha256"]):
            raise OperationReadError("manifest ledger header is not bound to the request")
        rows = conn.execute(sa.select(manifest_ledger_rows).where(
            manifest_ledger_rows.c.manifest_id == header["manifest_id"]).order_by(
                manifest_ledger_rows.c.disposition_ordinal)).mappings().all()
        records = conn.execute(sa.select(manifest_payload_records).where(
            manifest_payload_records.c.manifest_id == header["manifest_id"]).order_by(
                manifest_payload_records.c.payload_ordinal)).mappings().all()
        memberships = conn.execute(sa.select(manifest_payload_memberships).where(
            manifest_payload_memberships.c.manifest_id == header["manifest_id"]).order_by(
                manifest_payload_memberships.c.payload_record_id,
                manifest_payload_memberships.c.membership_ordinal)).mappings().all()
        if len(rows) != header["retained_row_count"]:
            raise OperationReadError("manifest ledger disposition coverage is incomplete")
        if any(row["source_account_id"] != header["source_account_id"]
               or row["run_id"] != header["run_id"] for row in rows):
            raise OperationReadError("manifest ledger row scope is not bound to its header")
        if [row["disposition_ordinal"] for row in rows] != list(range(len(rows))):
            raise OperationReadError("manifest disposition ordinals are incomplete")
        row_by_id = {row["manifest_row_id"]: row for row in rows}
        if len(row_by_id) != len(rows) or len({row["observation_id"] for row in rows}) != len(rows):
            raise OperationReadError("manifest ledger contains duplicate observations")
        dispositions = tuple(RowDispositionV1(
            1, row["observation_id"], row["source_record_ordinal"],
            row["retained_evidence_sha256"], row["disposition"],
            row["occurrence_id"], row["resolution_id"], row["resolution_revision"],
            row["exclusion_rule_id"], row["exclusion_rule_version"],
            row["exclusion_evidence_ref"], row["exclusion_reason"],
            row["excluded_by_actor_id"], row["blocked_reason"])
            for row in rows)
        members_by_record = {}
        for membership in memberships:
            row = row_by_id.get(membership["manifest_row_id"])
            if row is None:
                raise OperationReadError("manifest membership references an unknown row")
            members_by_record.setdefault(membership["payload_record_id"], []).append(
                (membership["membership_ordinal"], row["observation_id"]))
        payload_records = []
        for record in records:
            members = members_by_record.get(record["payload_record_id"], [])
            if [ordinal for ordinal, _ in members] != list(range(len(members))):
                raise OperationReadError("manifest membership ordinals are incomplete")
            payload_records.append(PayloadRecordV1(
                1, record["payload_record_id"],
                tuple(observation_id for _, observation_id in members),
                record["transformation_version"]))
        if set(members_by_record) != {record["payload_record_id"] for record in records}:
            raise OperationReadError("manifest membership has an unknown payload record")
        if [record["payload_ordinal"] for record in records] != list(range(len(records))):
            raise OperationReadError("manifest payload ordinals are incomplete")
        manifest = OccurrenceManifestV1(
            header["schema_version"], header["manifest_id"], header["manifest_sha256"],
            header["operation_id"], header["context_key"], header["bound_test_id"],
            header["source_family"], header["source_account_id"], header["run_id"],
            header["payload_sha256"], InventorySealV1(
                1, header["source_family"], header["source_account_id"], header["run_id"],
                header["inventory_high_watermark"], header["retained_row_count"],
                header["conflict_holder_count"], header["inventory_seal_ref"]),
            dispositions, tuple(payload_records))
        try:
            manifest.__post_init__()
        except Exception as exc:
            raise OperationReadError(f"manifest ledger content is invalid: {exc}") from exc
        return manifest

    @staticmethod
    def _validate_new(op, manifest, ref):
        if not isinstance(op, EngineImportOperationV1) or not isinstance(manifest, OccurrenceManifestV1):
            raise OperationStoreError("operation and manifest DTO types are required")
        if op.status != STATUS_PENDING or op.revision != 1 or op.post_issued:
            raise OperationStoreError("registration requires clean revision-1 pending operation")
        if op.close_old_findings is not False or op.first_import_baseline_ref is not None:
            raise OperationStoreError("registration requires explicit clean pre-POST operation")
        if manifest.operation_id != op.operation_id or manifest.context_key != op.context_key:
            raise OperationConflictError("manifest operation/context binding is not exact")
        if manifest.payload_sha256 != op.payload_sha256:
            raise OperationConflictError("manifest Test or payload binding is not exact")
        expected_manifest_test = (
            op.test_id if op.request_kind == REQUEST_REIMPORT else None)
        if manifest.bound_test_id != expected_manifest_test:
            raise OperationConflictError(
                "manifest Test or request Test binding is not exact")
        if manifest.run_id != op.source_run_id:
            raise OperationConflictError("manifest run is not bound to operation source_run_id")
        clean_fields = {
            "bound_test_id": None,
            "response_deduplication_complete": None,
            "response_ref": None,
            "response_test_id": None,
            "deduplication_complete": None,
            "deduplication_evidence_ref": None,
            "settle_readback_ref": None,
            "reconciliation_evidence_ref": None,
            "finding_ids": (),
            "endpoint_ids": (),
            "mapping_revision": None,
            "error_code": None,
            "error_detail_ref": None,
            "supersedes_operation_id": None,
            "reconciled": False,
        }
        for field, expected in clean_fields.items():
            if getattr(op, field) != expected:
                raise OperationStoreError(
                    f"registration requires clean pre-POST field {field}")
        if ref is not None and not ref:
            raise OperationStoreError("manifest reference must be non-empty")

    @staticmethod
    def _validate_manifest_integrity(manifest):
        """Re-run frozen DTO validation at the durable registration boundary.

        ``OccurrenceManifestV1`` is frozen only by convention at runtime:
        callers can still mutate it with ``object.__setattr__``.  The
        persisted ledger reconstructs the complete structured manifest, while
        its digests/references bind that reconstruction to the request and
        external evidence; registration must still re-derive the canonical
        digest and repeat the builder's shape checks before any database
        mutation.
        """
        try:
            manifest.__post_init__()
        except Exception as exc:
            raise OperationStoreError(
                f"manifest content or membership integrity failed: {exc}") from exc

    @staticmethod
    def _state_values(op, revision, changed_at):
        return {"operation_id": op.operation_id, "context_key": op.context_key,
                "test_id": op.test_id, "bound_test_id": op.bound_test_id,
                "revision": revision, "status": op.status,
                "response_deduplication_complete": op.response_deduplication_complete,
                "response_ref": op.response_ref, "response_test_id": op.response_test_id,
                "deduplication_complete": op.deduplication_complete,
                "deduplication_evidence_ref": op.deduplication_evidence_ref,
                "settle_readback_ref": op.settle_readback_ref,
                "reconciliation_evidence_ref": op.reconciliation_evidence_ref,
                "first_import_baseline_ref": op.first_import_baseline_ref,
                "finding_ids": list(op.finding_ids), "endpoint_ids": list(op.endpoint_ids),
                "mapping_revision": op.mapping_revision, "prior_mapping_revision": op.prior_mapping_revision,
                "error_code": op.error_code, "error_detail_ref": op.error_detail_ref,
                "supersedes_operation_id": op.supersedes_operation_id,
                "post_issued": op.post_issued, "reconciled": op.reconciled,
                "changed_at": _utc(changed_at)}

    def _validate_verified_context(self, conn, op, registration_id, verification_id):
        """Validate the immutable CE pair while the reservation transaction is open."""
        if not registration_id or not verification_id or self.context_store is None:
            raise OperationStoreError(
                "new engine reservations require a verified registration and verification pair"
            )
        # Read the verification first only to discover its deployment key.  The
        # configuration head is then locked before any operation rows are locked.
        verification = conn.execute(sa.select(ce_context_verifications).where(
            ce_context_verifications.c.verification_id == verification_id)).mappings().one_or_none()
        if verification is None:
            raise OperationConflictError("verification_id is missing or unknown")
        deployment_key = verification["deployment_key"]
        configurations = conn.execute(sa.select(ce_deployment_configurations).where(
            ce_deployment_configurations.c.deployment_key == deployment_key
        ).order_by(ce_deployment_configurations.c.revision.asc())).mappings().all()
        if not configurations:
            raise OperationConflictError("verified context has no deployment configuration")
        revisions = [row["revision"] for row in configurations]
        if revisions != list(range(1, len(configurations) + 1)):
            raise OperationReadError("verified context configuration history is not contiguous")
        try:
            snapshots = [self.context_store._snapshot_from_row(row)
                         for row in configurations]
        except Exception as exc:
            raise OperationReadError(
                "verified context configuration history is invalid") from exc
        latest = configurations[-1]
        configured = snapshots[-1].configured
        registration = conn.execute(sa.select(ce_context_registrations).where(
            ce_context_registrations.c.registration_id == registration_id)).mappings().one_or_none()
        exact = conn.execute(sa.select(ce_context_verifications).where(
            ce_context_verifications.c.registration_id == registration_id,
            ce_context_verifications.c.verification_id == verification_id)).mappings().one_or_none()
        if registration is None or exact is None:
            raise OperationConflictError("registration_id and verification_id are not an exact pair")
        if exact["deployment_key"] != registration["deployment_key"]:
            raise OperationReadError("verified context deployment binding is inconsistent")
        if exact["deployment_config_revision"] != latest["revision"]:
            raise OperationConflictError("verified context references a stale configuration revision")
        if registration["context_key"] != op.context_key:
            raise OperationConflictError("operation context does not match verified registration")
        if configured.ce_release != op.engine_release:
            raise OperationConflictError("operation engine release does not match configuration")
        expected_test = op.test_id if op.request_kind == REQUEST_REIMPORT else None
        registration_test_matches = (
            (registration["test_id"] is None) == (expected_test is None)
            and (registration["test_id"] is None
                 or str(registration["test_id"]) == str(expected_test)))
        if not registration_test_matches and not (
                op.request_kind == REQUEST_REIMPORT
                and registration["test_id"] is None
                and self._validate_reimport_binding(
                    conn, op, registration_id, verification_id)):
            raise OperationConflictError("operation import/reimport Test does not match registration")
        # Verify the retained evidence references and parent relationships. The
        # context store owns the artifact bytes and canonical JSON checks.
        if (exact["test_body_ref"] is None) != (exact["test_body_sha256"] is None):
            raise OperationReadError("verified Test evidence reference and digest are not paired")
        binding = conn.execute(sa.select(ce_context_test_bindings).where(
            ce_context_test_bindings.c.registration_id == registration_id
        )).mappings().one_or_none()
        effective_test_id = registration["test_id"]
        if binding is not None:
            if (binding["deployment_key"] != registration["deployment_key"]
                    or (effective_test_id is not None
                        and effective_test_id != binding["test_id"])):
                raise OperationReadError("first-import Test binding disagrees with registration")
            effective_test_id = binding["test_id"]
        if effective_test_id is None and exact["test_body_ref"] is not None:
            raise OperationReadError("import verification unexpectedly contains Test evidence")
        if effective_test_id is not None and exact["test_body_ref"] is None and exact["verification_id"] != (
                binding and conn.execute(sa.select(engine_operation_requests.c.verification_id).where(
                    engine_operation_requests.c.operation_id == binding["originating_operation_id"]
                )).scalar_one_or_none()):
            raise OperationReadError("reimport verification is missing Test evidence")
        for resource, ref_key, digest_key in (
            ("product", "product_body_ref", "product_body_sha256"),
            ("engagement", "engagement_body_ref", "engagement_body_sha256"),
        ):
            body = self.context_store.artifact_store.get(exact[ref_key], exact[digest_key])
            document = self.context_store._json_object(body, resource)
            if self.context_store._related_id(document.get("id"), f"{resource}.id") != registration[f"{resource}_id"]:
                raise OperationReadError(f"verified {resource} evidence does not match registration")
            if resource == "engagement" and self.context_store._related_id(
                    document.get("product"), "engagement.product") != registration["product_id"]:
                raise OperationReadError("verified engagement parent does not match registration")
        if exact["test_body_ref"] is not None:
            body = self.context_store.artifact_store.get(exact["test_body_ref"], exact["test_body_sha256"])
            document = self.context_store._json_object(body, "test")
            if self.context_store._related_id(document.get("id"), "test.id") != effective_test_id:
                raise OperationReadError("verified Test evidence does not match registration")
            if self.context_store._related_id(
                    document.get("engagement"), "test.engagement") != registration["engagement_id"]:
                raise OperationReadError("verified Test parent does not match registration")
        return exact

    def _validate_reimport_binding(self, conn, op, registration_id, verification_id):
        """Validate the immutable 0009 first-import Test binding in-transaction.

        A 0009 binding intentionally does not update the 0007 registration's
        nullable Test column.  The originating operation and its recorded
        response are therefore part of the binding proof for every reimport
        reservation; a missing binding returns False so legacy settled mapping
        validation remains available.
        """
        if op.request_kind != REQUEST_REIMPORT:
            return False
        binding = conn.execute(self._lock(sa.select(ce_context_test_bindings).where(
            ce_context_test_bindings.c.registration_id == registration_id), conn
        )).mappings().one_or_none()
        if binding is None:
            return False
        if str(binding["test_id"]) != str(op.test_id):
            raise OperationConflictError("0009 Test binding does not match reimport Test")
        if binding["deployment_config_revision"] <= 0:
            raise OperationReadError("0009 Test binding has invalid configuration revision")

        # The origin's parsed fields alone are insufficient: a different body
        # with the same fields must not replace the originally recorded POST
        # response.  The normal reader verifies the exact artifact reference,
        # its parsed projection, and its single response-recorded transition.
        originating = self._load_locked(conn, binding["originating_operation_id"])

        request = conn.execute(sa.select(engine_operation_requests).where(
            engine_operation_requests.c.operation_id == binding["originating_operation_id"]
        )).mappings().one_or_none()
        state = conn.execute(sa.select(engine_operation_states).where(
            engine_operation_states.c.operation_id == binding["originating_operation_id"]
        )).mappings().one_or_none()
        if (request is None or state is None
                or request["registration_id"] != registration_id
                or request["verification_id"] is None
                or request["request_kind"] != REQUEST_IMPORT
                or request["test_id"] is not None
                or request["context_key"] != op.context_key
                or state["context_key"] != op.context_key
                or not state["post_issued"]):
            raise OperationConflictError(
                "0009 Test binding has no matching originating import response")
        recovered_response = (
            state["response_ref"] is None
            and state["response_test_id"] is None
            and state["reconciled"]
            and state["status"] == "settled"
            and str(state["bound_test_id"]) == str(op.test_id)
            and bool(state["reconciliation_evidence_ref"]))
        response_backed = (
            state["response_ref"] is not None
            and str(state["response_test_id"]) == str(op.test_id))
        if not (recovered_response or response_backed):
            raise OperationConflictError(
                "0009 Test binding has no matching originating import response or settled reconciliation")
        if recovered_response:
            reconciliation = self.context_store.read_first_import_reconciliation(
                binding["originating_operation_id"],
                state["reconciliation_evidence_ref"])
            if (reconciliation.count != 1
                    or reconciliation.candidate_test_ids != (int(op.test_id),)
                    or originating.operation.status != "settled"
                    or not originating.operation.reconciled):
                raise OperationConflictError(
                    "0009 Test binding has no exact settled reconciliation candidate")
        verification = conn.execute(sa.select(ce_context_verifications).where(
            ce_context_verifications.c.verification_id == verification_id)).mappings().one()
        origin_verification = conn.execute(sa.select(ce_context_verifications).where(
            ce_context_verifications.c.registration_id == registration_id,
            ce_context_verifications.c.verification_id == request["verification_id"]
        )).mappings().one_or_none()
        registration = conn.execute(sa.select(ce_context_registrations).where(
            ce_context_registrations.c.registration_id == registration_id
        )).mappings().one()
        if (origin_verification is None
                or binding["deployment_key"] != verification["deployment_key"]
                or binding["deployment_key"] != origin_verification["deployment_key"]
                or binding["deployment_config_revision"] !=
                origin_verification["deployment_config_revision"]
                or registration["deployment_key"] != binding["deployment_key"]
                or registration["context_key"] != op.context_key):
            raise OperationConflictError(
                "0009 Test binding deployment or verification does not match")

        artifact_store = getattr(self.context_store, "artifact_store", None)
        if artifact_store is None:
            raise OperationReadError("Test binding artifact store is required")
        try:
            if response_backed:
                response_digest = state["response_ref"].rsplit(":", 1)[-1]
                response_body = artifact_store.get(state["response_ref"], response_digest)
                parsed_response = parse_response(response_body)
            test_digest = binding["test_body_ref"].rsplit(":", 1)[-1]
            test_body = artifact_store.get(binding["test_body_ref"], test_digest)
            if test_digest != binding["test_body_sha256"]:
                raise ValueError("Test binding digest does not match reference")
            test_document = self.context_store._json_object(test_body, "test")
        except Exception as exc:
            raise OperationReadError(
                "0009 Test binding or originating response evidence is invalid") from exc
        if ((response_backed and (
                parsed_response.test_id != str(op.test_id)
                or parsed_response.test_id != str(binding["test_id"])
                or parsed_response.deduplication_complete !=
                state["response_deduplication_complete"]))
                or self.context_store._related_id(test_document.get("id"), "test.id")
                != int(binding["test_id"])
                or self.context_store._related_id(
                    test_document.get("engagement"), "test.engagement")
                != registration["engagement_id"]):
            raise OperationConflictError(
                "0009 Test binding does not match durable response evidence")
        return True

    @staticmethod
    def _same_request(existing, op, manifest, manifest_ref,
                      registration_id, verification_id):
        e = existing.operation
        immutable = all(
            (_utc(getattr(e, field)) if field == "requested_at" else getattr(e, field))
            == (_utc(getattr(op, field)) if field == "requested_at" else getattr(op, field))
            for field in _REQUEST_COLUMNS
        )
        return (immutable
                and existing.registration_id == registration_id
                and existing.verification_id == verification_id
                and existing.manifest_sha256 == manifest.manifest_sha256
                and existing.manifest_ref == manifest_ref
                and existing.operation.prior_mapping_revision
                == op.prior_mapping_revision)

    @staticmethod
    def _validate_persisted(req, man, state, history):
        if (req["registration_id"] is None) != (req["verification_id"] is None):
            raise OperationReadError("registration and verification IDs must be paired")
        if req["operation_id"] != state["operation_id"] or req["context_key"] != state["context_key"]:
            raise OperationReadError("request/state identity mismatch")
        if req["test_id"] != state["test_id"] or req["close_old_findings"] is not False:
            raise OperationReadError("request/state Test or close_old_findings mismatch")
        allowed_bound_ids = {None, state["test_id"], state["response_test_id"]}
        if state["reconciled"]:
            allowed_bound_ids.add(state["bound_test_id"])
        if state["bound_test_id"] not in allowed_bound_ids:
            raise OperationReadError("inconsistent bound Test history")
        if (state["bound_test_id"] is not None
                and state["response_test_id"] is not None
                and state["bound_test_id"] != state["response_test_id"]):
            raise OperationReadError("bound and response Test IDs disagree")
        if (state["bound_test_id"] is not None
                and state["response_test_id"] is None
                and not state["reconciled"]):
            raise OperationReadError(
                "response-less Test binding requires first-import reconciliation")
        revisions = [h["to_revision"] for h in history]
        if revisions != list(range(1, state["revision"] + 1)):
            raise OperationReadError("non-contiguous or duplicate transition history")
        first = history[0]
        if (first["from_revision"] is not None or first["from_status"] is not None
                or first["to_revision"] != 1 or first["to_status"] != "pending"):
            raise OperationReadError("invalid initial transition")
        for previous, current in zip(history, history[1:]):
            if (current["from_revision"] != previous["to_revision"]
                    or current["from_status"] != previous["to_status"]):
                raise OperationReadError("transition history is not a contiguous state chain")
        final = history[-1]
        if (final["to_revision"] != state["revision"]
                or final["to_status"] != state["status"]):
            raise OperationReadError("final transition does not match persisted state")
        post_transitions = [
            transition for transition in history
            if transition["transition_reason"] == "POST issued"
        ]
        if len(post_transitions) > 1 or state["post_issued"] != (len(post_transitions) == 1):
            raise OperationReadError("persisted issuance flag does not match transition history")
        baseline_transitions = [
            transition for transition in history
            if transition["transition_reason"] == "first-import baseline recorded"
        ]
        if state["first_import_baseline_ref"] is None:
            if baseline_transitions:
                raise OperationReadError("baseline transition exists without a durable reference")
        elif (req["request_kind"] != REQUEST_IMPORT or len(baseline_transitions) != 1
              or baseline_transitions[0]["to_revision"] != 2
              or baseline_transitions[0]["from_revision"] != 1
              or baseline_transitions[0]["evidence_ref"] != state["first_import_baseline_ref"]):
            raise OperationReadError("first-import baseline reference does not match its transition")
        reconciliation_transitions = [
            transition for transition in history
            if transition["transition_reason"] == "reconciliation inventory recorded"
        ]
        if state["reconciliation_evidence_ref"] is None:
            if reconciliation_transitions:
                raise OperationReadError(
                    "reconciliation transition exists without a durable reference"
                )
        elif (req["request_kind"] != REQUEST_IMPORT
              or state["status"] not in ("quarantined", "settled")
              or not state["post_issued"]
              or state["response_ref"] is not None
              or state["first_import_baseline_ref"] is None
              or len(reconciliation_transitions) != 1
              or reconciliation_transitions[0]["evidence_ref"] !=
              state["reconciliation_evidence_ref"]
              or reconciliation_transitions[0]["from_status"] != "quarantined"
              or reconciliation_transitions[0]["to_status"] != "quarantined"
              or (state["status"] == "quarantined"
                  and reconciliation_transitions[0]["to_revision"] != state["revision"])
              or (state["status"] == "settled"
                  and (not state["reconciled"]
                       or reconciliation_transitions[0]["to_revision"] >= state["revision"]))):
            raise OperationReadError(
                "first-import reconciliation reference does not match its immutable checkpoint"
            )
        if post_transitions:
            expected_from_revision = 2 if state["first_import_baseline_ref"] is not None else 1
            issue = post_transitions[0]
            if (issue["from_revision"] != expected_from_revision
                    or issue["to_revision"] != expected_from_revision + 1):
                raise OperationReadError("POST issuance transition does not follow its baseline state")
        response_transitions = [
            transition for transition in history
            if transition["transition_reason"] == "response recorded"
        ]
        if state["response_ref"] is None:
            if response_transitions:
                raise OperationReadError(
                    "response transition exists without response artifact")
        elif len(response_transitions) != 1:
            raise OperationReadError(
                "response artifact has missing or ambiguous response transition")
        elif response_transitions[0]["evidence_ref"] != state["response_ref"]:
            raise OperationReadError(
                "response artifact does not match original response transition")

    @staticmethod
    def _validate_settled_test_ids(state):
        response_backed = (
            state["response_test_id"] is not None
            and state["bound_test_id"] == state["response_test_id"]
            and not state["reconciled"]
        )
        recovered_first_import = (
            state["response_test_id"] is None
            and state["bound_test_id"] is not None
            and state["reconciled"]
            and state["reconciliation_evidence_ref"] is not None
            and state["first_import_baseline_ref"] is not None
        )
        if not (response_backed or recovered_first_import):
            raise OperationConflictError(
                "settled state has incomplete or conflicting Test ownership")

    @classmethod
    def _validate_settled_ownership(cls, settled):
        """Validate every settled context/Test ownership row fail-closed."""
        settled_by_context = {}
        settled_by_test = {}
        history_by_mapping = {}
        for row in settled:
            cls._validate_settled_test_ids(row)
            bound_test = row["bound_test_id"]
            revision = row["mapping_revision"]
            if (not isinstance(revision, int)
                    or isinstance(revision, bool) or revision < 1):
                raise OperationConflictError(
                    "settled state has an invalid mapping revision")
            settled_by_context.setdefault(row["context_key"], set()).add(bound_test)
            settled_by_test.setdefault(bound_test, set()).add(row["context_key"])
            history_by_mapping.setdefault(
                (row["context_key"], bound_test), []).append(row)
        if (any(len(tests) > 1 for tests in settled_by_context.values())
                or any(len(contexts) > 1
                       for contexts in settled_by_test.values())):
            raise OperationConflictError(
                "conflicting settled context/Test mappings")
        for rows in history_by_mapping.values():
            by_revision = {row["mapping_revision"]: row for row in rows}
            if len(by_revision) != len(rows):
                raise OperationConflictError(
                    "duplicate settled mapping revision")
            revisions = sorted(by_revision)
            if revisions != list(range(revisions[0], revisions[-1] + 1)):
                raise OperationConflictError(
                    "settled mapping revision history has a gap")
            for previous_revision, revision in zip(revisions, revisions[1:]):
                if by_revision[revision]["prior_mapping_revision"] != previous_revision:
                    raise OperationConflictError(
                        "settled mapping revision history is not linked")
        return settled_by_context, settled_by_test

    @staticmethod
    def _require_settled_reimport_mapping(operation, settled):
        """Require the exact durable mapping before reimport registration/POST."""
        mappings = [
            row for row in settled
            if row["context_key"] == operation.context_key
            and row["bound_test_id"] == operation.test_id
            and (row["response_test_id"] == operation.test_id
                 or (row["response_test_id"] is None
                     and row["reconciled"]
                     and row["reconciliation_evidence_ref"] is not None
                     and row["first_import_baseline_ref"] is not None))
        ]
        if not mappings:
            raise OperationConflictError(
                "reimport requires an existing settled context/Test mapping")
        latest_revision = max(row["mapping_revision"] for row in mappings)
        if (not isinstance(operation.prior_mapping_revision, int)
                or isinstance(operation.prior_mapping_revision, bool)
                or operation.prior_mapping_revision < 1
                or latest_revision is None
                or operation.prior_mapping_revision != latest_revision):
            raise OperationConflictError(
                "prior mapping revision does not match settled context/Test mapping")
