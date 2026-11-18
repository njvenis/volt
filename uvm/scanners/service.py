"""Manual Qualys coordinator using the backend-owned current-authority bridge.

No shared policy/crypto implementation or environment-selectable fixture transport.
Only the final provider publication makes independently retained facts readable.
"""
from __future__ import annotations

import hashlib
import math
import json
import secrets
import time
import threading
from contextlib import contextmanager
import uuid
from dataclasses import asdict, fields
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime

import sqlalchemy as sa
from fastapi import HTTPException

from uvm.ingestion.run import (AttemptFact, CollectionRunV1, CollectionScheduleV1,
    PageFact)
from uvm.identity.resolver import RuleV1
from uvm.persistence.ingestion_store import IngestionStore
from uvm.persistence.observation_store import ObservationRepository
from uvm.persistence.identity_repository import IdentityRepository
from uvm.scanners import contracts as dto, store
from uvm.scanners.evidence import PrivateEvidenceStore
from uvm.scanners.qualys_vm import (QualysError, QualysVMClient,
    MAX_PAGES, MAX_PAGE_ATTEMPTS, TOTAL_DEADLINE_SECONDS, PLATFORM_ORIGINS, observations_for_page)

UTC = timezone.utc
_WORKER_LOCK = (0x51564D, 0x574B5231)
_ACTIONS = dto.SCANNER_GRANT_BY_ACTION.keys() - {'connector.read', 'assessment.read'}
def qualys_source_only_rule():
    """Pinned rule for backend's existing trusted provisioner at installation.

    Provider never provisions shared identity configuration or supplies an
    authorizer. Empty matching inputs and unverified component identity preserve
    native QID grouping without workload/occurrence creation.
    """
    return RuleV1('qualys_vm_source_only_v1', 1, ('provisioning_key',))


def instant(value):
    return value.astimezone(UTC).isoformat().replace('+00:00', 'Z')


def canonical_uuid(value):
    try:
        if type(value) is not str or str(uuid.UUID(value)) != value:
            raise ValueError
    except (ValueError, TypeError, AttributeError):
        raise store.OperationError('invalid_request') from None
    return value


def digest(value):
    return hashlib.sha256(value.encode('utf-8')).hexdigest()


def parse_command(connector_id, command):
    canonical_uuid(connector_id)
    keys = {'schema_version', 'command_id', 'action', 'target_id', 'membership_ids',
        'expected_revisions', 'payload'}
    if (type(command) is not dict or set(command) != keys
            or type(command['schema_version']) is not int or command['schema_version'] != 1
            or command['target_id'] != connector_id or type(command['membership_ids']) is not list
            or command['membership_ids'] != [] or type(command['action']) is not str
            or command['action'] not in _ACTIONS):
        raise store.OperationError('invalid_request')
    canonical_uuid(command['command_id'])
    vector = command['expected_revisions']
    if (type(vector) is not dict or set(vector) != {f.name for f in fields(dto.ExpectedRevisions)}
            or vector['secret'] is not None):
        raise store.OperationError('invalid_request')
    try:
        expected = dto.ExpectedRevisions(**vector)
    except (ValueError, TypeError):
        raise store.OperationError('invalid_request') from None
    action = command['action']
    payload = command['payload']
    extra = {'scanner.configuration.save': {'settings'},
        'scanner.connection.test': {'configuration_revision', 'credential_version_id'},
        'scanner.configuration.activate': {'configuration_revision', 'credential_version_id',
            'validation_operation_id'},
        'scanner.collection.start': {'configuration_revision', 'credential_version_id'},
        'scanner.configuration.disable': set()}[action]
    if type(payload) is not dict or set(payload) != {'source_id', 'rationale', 'evidence_ref'} | extra:
        raise store.OperationError('invalid_request')
    canonical_uuid(payload['source_id'])
    for name in ('rationale', 'evidence_ref'):
        if (type(payload[name]) is not str or not payload[name].strip()
                or len(payload[name]) > 2048):
            raise store.OperationError('invalid_request')
    if 'configuration_revision' in payload:
        if type(payload['configuration_revision']) is not int or payload['configuration_revision'] < 1:
            raise store.OperationError('invalid_request')
        canonical_uuid(payload['credential_version_id'])
    if 'validation_operation_id' in payload:
        canonical_uuid(payload['validation_operation_id'])
    return expected


class ScannerService:
    def __init__(self, engine, adapters: dto.ScannerRuntimeAdapters,
                 evidence: PrivateEvidenceStore, *, _client_factory=None,
                 _clock=None, _checkpoint_hook=None, _monotonic=None):
        self.engine, self.adapters, self.evidence = engine, adapters, evidence
        self._worker_guard = threading.RLock()
        self._worker_connection = None
        self._startup_recovery_allowed = False
        # Explicit dependency composition only; never read from installation config.
        self._client_factory = _client_factory or QualysVMClient
        self._clock = _clock or (lambda: datetime.now(UTC))
        self._monotonic = _monotonic or time.monotonic
        self._checkpoint_hook = _checkpoint_hook or (lambda _stage, _operation: None)
        self.ingestion = IngestionStore(engine)
        self.observations = ObservationRepository(engine)
        self.identities = IdentityRepository(engine)

    def _assert_worker(self):
        """Fail closed on loss of our dedicated lifetime-lock DB session."""
        with self._worker_guard:
            connection = self._worker_connection
            if connection is None or connection.closed or connection.invalidated:
                raise store.OperationError('scanner_worker_unavailable')
            try:
                connection.execute(sa.text('SELECT 1'))
                connection.commit()
            except sa.exc.SQLAlchemyError:
                connection.invalidate()
                raise store.OperationError('scanner_worker_unavailable') from None

    @contextmanager
    def _transaction(self, request, action, connector_id, source_id, **fences):
        writing = action in _ACTIONS
        if writing:
            self._assert_worker()
        with self.adapters.transaction(request=request, action=action,
                connector_id=connector_id, source_id=source_id, **fences) as transaction:
            if writing:
                self._assert_worker()
            yield transaction
            if writing:
                self._assert_worker()

    @staticmethod
    def _release_worker_session(connection, acquired):
        try:
            if acquired and not connection.closed and not connection.invalidated:
                connection.rollback()
                connection.execute(sa.text('SELECT pg_advisory_unlock(:a, :b)'),
                    {'a': _WORKER_LOCK[0], 'b': _WORKER_LOCK[1]})
                connection.commit()
        except sa.exc.SQLAlchemyError:
            # Discard the physical session; never return a locked session to pool.
            connection.invalidate()
        finally:
            connection.close()

    @contextmanager
    def worker_lifetime(self):
        """Exclusive PostgreSQL worker session; enter AFTER migrations/state setup.

        This is a worker-ownership lock, not the short authority/policy lock.
        PostgreSQL releases it on process/session loss. Route/app construction
        never calls this method. Another process cannot acquire it and therefore
        cannot recover our live operations. The owner session is health-fenced
        before writes/outbound dispatch and before final publication commit.
        """
        with self._worker_guard:
            if self._worker_connection is not None:
                raise store.OperationError('scanner_worker_already_running')
            if self.engine.dialect.name != 'postgresql':
                raise store.OperationError('scanner_state_unavailable')
            connection = self.engine.connect()
            acquired = False
            try:
                acquired = bool(connection.execute(sa.text(
                    'SELECT pg_try_advisory_lock(:a, :b)'),
                    {'a': _WORKER_LOCK[0], 'b': _WORKER_LOCK[1]}).scalar_one())
                connection.commit()
                if not acquired:
                    raise store.OperationError('scanner_worker_already_running')
                required = set(store._metadata.tables)
                inspector = sa.inspect(connection)
                if not all(inspector.has_table(name) for name in required):
                    raise store.OperationError('scanner_state_unavailable')
                connection.commit()
                # Validate the provider-owned private state without writing files.
                descriptor = self.evidence._directory_fd()
                import os
                os.close(descriptor)
                self._worker_connection = connection
                self._startup_recovery_allowed = True
                try:
                    recovered = self.recover_interrupted()
                finally:
                    self._startup_recovery_allowed = False
            except BaseException:
                self._worker_connection = None
                self._release_worker_session(connection, acquired)
                raise
        try:
            yield recovered
        finally:
            with self._worker_guard:
                self._worker_connection = None
                self._release_worker_session(connection, acquired)

    def recover_interrupted(self):
        """Only the newly acquired exclusive owner may run startup recovery once."""
        with self._worker_guard:
            if not self._startup_recovery_allowed:
                raise store.OperationError('startup_recovery_required')
            self._assert_worker()
            with self.engine.begin() as connection:
                return store.interrupt_running(connection, now=self._clock())

    def _metadata(self, tx):
        metadata = self.adapters.read_registration_metadata(transaction=tx)
        snapshot = tx.snapshot
        if (snapshot.source_family != 'qualys' or metadata.product != 'qualys_vm'
                or metadata.platform_id not in PLATFORM_ORIGINS
                or metadata.scope.kind != 'account_visible'
                or (metadata.connector_id, metadata.source_id,
                    metadata.source_tuple.source_family, metadata.source_tuple.source_account_id,
                    metadata.source_tuple.scope_key) != (snapshot.connector_id, snapshot.source_id,
                        snapshot.source_family, snapshot.source_account_id, snapshot.scope_key)):
            raise store.OperationError('invalid_settings')
        return metadata

    def _deadline(self, deadline):
        if self._monotonic() >= deadline:
            raise QualysError('deadline_exceeded')

    def _configuration(self, tx):
        snapshot = tx.snapshot
        return store.read_configuration(tx.connection, snapshot.connector_id, snapshot.source_id)

    @staticmethod
    def _operation_view(row):
        return asdict(dto.OperationView(1, str(row['operation_id']), row['command_id'],
            row['action'], row['status'], row['configuration_revision'],
            row['credential_version_id'], instant(row['started_at']),
            instant(row['finished_at']) if row['finished_at'] else None,
            str(row['run_id']) if row['run_id'] else None, row['error_code'], row['receipt_id']))

    def operation(self, request, connector_id, source_id, operation_id):
        for value in (connector_id, source_id, operation_id):
            canonical_uuid(value)
        with self._transaction(request, 'connector.read', connector_id, source_id) as tx:
            return self._operation_view(store.scoped_operation(tx.connection,
                connector_id, source_id, operation_id))

    def _replay(self, tx, command, request_digest):
        state = tx.read_command(command_id=command['command_id'], request_digest=request_digest)
        if state is None:
            return None
        if state.receipt is not None:
            return asdict(state.receipt), 200
        operation_id = state.intent.operation_id
        if operation_id is None:
            raise store.OperationError('outcome_unknown')
        row = store.scoped_operation(tx.connection, tx.snapshot.connector_id,
            tx.snapshot.source_id, operation_id)
        return self._operation_view(row), 202 if row['status'] == 'running' else 200

    def command(self, request, connector_id, command):
        expected = parse_command(connector_id, command)
        payload, action = command['payload'], command['action']
        source_id = payload['source_id']
        operation_deadline = self._monotonic() + TOTAL_DEADLINE_SECONDS
        # Current-authorized replay precedes historical revision checks.
        with self._transaction(request, action, connector_id, source_id) as tx:
            request_digest = store.command_digest(tx.snapshot.principal_id, command)
            replay = self._replay(tx, command, request_digest)
            if replay:
                return replay
        try:
            with self._transaction(request, action, connector_id, source_id,
                    expected_revisions=expected) as tx:
                replay = self._replay(tx, command, request_digest)
                if replay:
                    return replay
                metadata = self._metadata(tx)
                config = self._configuration(tx)
                if action in {'scanner.connection.test', 'scanner.collection.start'}:
                    operation, intent = self._admit(tx, command, request_digest, config, metadata)
                else:
                    intent = tx.record_audited_intent(command_id=command['command_id'],
                        request_digest=request_digest, rationale=payload['rationale'],
                        evidence_ref=payload['evidence_ref'], operation_id=None, run_id=None)
                    result, change = self._local_command(tx, command, config, metadata)
                    committed = tx.record_audited_receipt(intent_id=intent.intent_id,
                        result=result, shared_state=change)
                    if action == 'scanner.configuration.activate':
                        store.update_configuration(tx.connection, connector_id, source_id,
                            active_snapshot=asdict(committed.snapshot))
            if action not in {'scanner.connection.test', 'scanner.collection.start'}:
                return self._read_receipt(request, connector_id, source_id, command, request_digest)
        except (store.OperationError, HTTPException) as exc:
            if isinstance(exc, HTTPException):
                if exc.status_code != 409:
                    raise
            elif exc.code not in {'operation_in_progress', 'command_id_reused', 'revision_conflict'}:
                raise
            # Resolve an admission race through the same current-authorized lookup.
            with self._transaction(request, action, connector_id, source_id) as tx:
                replay = self._replay(tx, command, request_digest)
                if replay:
                    return replay
            raise
        self._checkpoint_hook('admitted', operation)
        self._execute(request, operation, intent, metadata.platform_id, operation_deadline)
        return self._read_receipt(request, connector_id, source_id, command, request_digest)

    def _read_receipt(self, request, connector_id, source_id, command, request_digest):
        with self._transaction(request, command['action'], connector_id, source_id) as tx:
            replay = self._replay(tx, command, request_digest)
            if replay is None:
                raise store.OperationError('outcome_unknown')
            return replay

    def _local_command(self, tx, command, config, metadata):
        action, payload, snapshot = command['action'], command['payload'], tx.snapshot
        revision = snapshot.configuration_revision
        if action == 'scanner.configuration.save':
            expected_settings = {'product': 'qualys_vm', 'api_version': '2.0',
                'platform_id': metadata.platform_id, 'scope': {'kind': 'account_visible'},
                'collection_mode': 'manual'}
            if payload['settings'] != expected_settings:
                raise store.OperationError('invalid_settings')
            revision += 1
            store.save_configuration(tx.connection, snapshot.connector_id, snapshot.source_id,
                revision=revision, settings=expected_settings)
            return dto.SaveConfigurationResult('staged', revision), dto.ScannerSharedStateChange(
                'staged', revision, None)
        if config is None:
            raise store.OperationError('configuration_missing')
        if action == 'scanner.configuration.disable':
            store.update_configuration(tx.connection, snapshot.connector_id, snapshot.source_id,
                validation=None, active_snapshot=None)
            return dto.DisableConfigurationResult('disabled', revision), dto.ScannerSharedStateChange(
                'disabled', revision, None)
        self._require_configuration(snapshot, payload, config, metadata)
        proof = config['validation']
        now = self._clock()
        if (not proof or proof['status'] != 'succeeded'
                or proof['operation_id'] != payload['validation_operation_id']
                or proof['configuration_revision'] != revision
                or proof['credential_version_id'] != snapshot.credential_version_id
                or proof['restore_epoch_id'] != snapshot.restore_epoch_id
                or not timedelta(0) <= now - datetime.fromisoformat(proof['checked_at']) <= timedelta(minutes=15)):
            raise store.OperationError('validation_required')
        return dto.ActivateConfigurationResult('active', revision, revision), dto.ScannerSharedStateChange(
            'active', revision, revision)

    @staticmethod
    def _require_configuration(snapshot, payload, config, metadata):
        if (config is None or config['configuration_revision'] != snapshot.configuration_revision
                or payload['configuration_revision'] != snapshot.configuration_revision
                or payload['credential_version_id'] != snapshot.credential_version_id
                or snapshot.credential_version_id is None
                or metadata.credential.state != 'active'):
            raise store.OperationError('revision_conflict')

    def _admit(self, tx, command, request_digest, config, metadata):
        snapshot, payload = tx.snapshot, command['payload']
        self._require_configuration(snapshot, payload, config, metadata)
        kind = 'test' if command['action'] == 'scanner.connection.test' else 'collect'
        if kind == 'collect':
            active = config['active_snapshot']
            if (snapshot.lifecycle != 'active'
                    or snapshot.active_configuration_revision != snapshot.configuration_revision
                    or not active or any(active[name] != getattr(snapshot, name) for name in
                        ('configuration_revision', 'connector_revision', 'credential_version_id', 'restore_epoch_id'))):
                raise store.OperationError('validation_required')
        run_id = str(uuid.uuid4()) if kind == 'collect' else None
        operation, replayed = store.admit(tx.connection, store.OperationAdmission(
            snapshot.connector_id, snapshot.source_id, command['command_id'], snapshot.principal_id,
            kind, request_digest, snapshot.configuration_revision, snapshot.credential_version_id,
            snapshot.restore_epoch_id, run_id), now=self._clock())
        if replayed:
            raise store.OperationError('command_id_reused')
        intent = tx.record_audited_intent(command_id=command['command_id'],
            request_digest=request_digest, rationale=payload['rationale'], evidence_ref=payload['evidence_ref'],
            operation_id=operation['operation_id'], run_id=run_id)
        tx.connection.execute(store.operations.update().where(
            store.operations.c.operation_id == operation['operation_id']).values(intent_id=intent.intent_id))
        operation['intent_id'] = intent.intent_id
        if run_id:
            store.update_configuration(tx.connection, snapshot.connector_id, snapshot.source_id,
                latest_attempt_run_id=run_id)
        return operation, intent

    def _fenced(self, request, intent):
        return self._transaction(request, intent.action, intent.connector_id,
            intent.source_id, snapshot=intent.snapshot)

    def _execute(self, request, operation, intent, platform_id, deadline):
        try:
            self._deadline(deadline)
            self._execute_inner(request, operation, intent, platform_id, deadline)
        except Exception as exc:
            # No authority assertion is synthesized for error metadata. The final
            # publication transaction has rolled back; retained checkpoints stay private.
            with self.engine.begin() as connection:
                row = store.read_operation(connection, operation['operation_id'])
                if row and row['status'] == 'running':
                    store.finish(connection, row['operation_id'],
                        status='failed' if isinstance(exc, QualysError) else 'interrupted',
                        error_code=exc.code if isinstance(exc, QualysError) else 'finalization_interrupted',
                        now=self._clock())
            raise

    def _execute_inner(self, request, operation, intent, platform_id, deadline):
        operation_id = operation['operation_id']
        client = self._client_factory(platform_id)
        transport = client._transport
        position = {'page': 1}
        def tracked_transport(outbound, timeout, deadline):
            identity = digest(outbound.full_url)
            self._deadline(deadline)
            with self._fenced(request, intent) as tx:
                attempt = store.reserve_attempt(tx.connection, operation_id,
                    page_ordinal=position['page'], request_identity_sha256=identity, now=self._clock())
            self._assert_worker()
            try:
                status, body, headers = transport(outbound, timeout, deadline)
            except QualysError as exc:
                with self.engine.begin() as connection:
                    store.finish_attempt(connection, operation_id, attempt,
                        response_class='transport_error', success=False, error_code=exc.code,
                        now=self._clock())
                raise
            with self.engine.begin() as connection:
                store.finish_attempt(connection, operation_id, attempt,
                    response_class='http_success' if 200 <= status < 300 else 'http_failure',
                    success=200 <= status < 300, http_status=status,
                    retry_after_seconds=self._retry_after(headers), now=self._clock())
            return status, body, headers
        client._transport = tracked_transport
        pages = []
        byte_count = 0
        failure = None
        iterator = client.iter_pages(
            credential_scope=lambda: self.adapters.credential_attempt(request=request,
                action=operation['action'], snapshot=intent.snapshot),
            before_request=lambda: self.adapters.assert_current(request=request,
                action=intent.action, snapshot=intent.snapshot),
            deadline=deadline)
        try:
            for page in iterator:
                self._deadline(deadline)
                evidence = self.evidence.write(page.raw_bytes, operation_bytes=byte_count)
                byte_count += len(page.raw_bytes)
                with self._fenced(request, intent) as tx:
                    attempt_rows = tx.connection.execute(sa.select(store.attempts).where(
                        store.attempts.c.operation_id == operation_id,
                        store.attempts.c.page_ordinal == page.ordinal).order_by(
                        store.attempts.c.attempt_no)).mappings().all()
                    store.record_page(tx.connection, operation_id, page_ordinal=page.ordinal,
                        request_identity_sha256=digest(page.request_url),
                        continuation_sha256=digest(page.parsed.continuation) if page.parsed.continuation else None,
                        evidence_ref=evidence.ref, response_sha256=evidence.sha256, byte_count=evidence.size,
                        host_count=page.parsed.host_count, detection_count=len(page.parsed.detections),
                        attempt_count=len(attempt_rows), now=self._clock())
                pages.append((page, evidence, attempt_rows[-1]['attempt_no']))
                self._checkpoint_hook('page', operation)
                if operation['action'] == 'test':
                    break
                position['page'] += 1
        except QualysError as exc:
            failure = exc.code
        finally:
            iterator.close()
        if operation['action'] == 'test':
            now = self._clock()
            status = 'failed' if failure else 'succeeded'
            self._deadline(deadline)
            with self._fenced(request, intent) as tx:
                self._deadline(deadline)
                store.update_configuration(tx.connection, intent.connector_id, intent.source_id,
                    validation={'status': status, 'checked_at': instant(now),
                        'configuration_revision': intent.snapshot.configuration_revision,
                        'credential_version_id': intent.snapshot.credential_version_id,
                        'restore_epoch_id': intent.snapshot.restore_epoch_id,
                        'operation_id': operation_id, 'error_code': failure})
                committed = tx.record_audited_receipt(intent_id=intent.intent_id,
                    result=dto.TestConnectionResult(operation_id, status, failure))
                self._finish(tx.connection, operation_id, status, failure, committed)
            return
        self._finalize_collection(request, operation, intent, pages, failure, deadline)

    def _retry_after(self, headers):
        raw = next((value for key, value in headers.items() if key.lower() == 'retry-after'), None)
        if not raw:
            return None
        try:
            value = float(raw)
        except (ValueError, TypeError):
            try:
                at = parsedate_to_datetime(raw)
                if at.tzinfo is None:
                    at = at.replace(tzinfo=UTC)
                value = (at - self._clock()).total_seconds()
            except (ValueError, TypeError, OverflowError):
                return None
        # Metadata only; the existing protocol client owns retry/deadline policy.
        return max(0.0, value) if math.isfinite(value) and value <= 86400 * 365 else None

    def _finish(self, connection, operation_id, status, failure, committed):
        store.finish(connection, operation_id, status=status, error_code=failure, now=self._clock())
        connection.execute(store.operations.update().where(
            store.operations.c.operation_id == operation_id).values(receipt_id=committed.receipt.command_id))

    def _finalize_collection(self, request, operation, intent, pages, failure, deadline):
        operation_id, run_id = operation['operation_id'], operation['run_id']
        self._deadline(deadline)
        with self._fenced(request, intent) as tx:
            store.advance_finalization(tx.connection, operation_id, 'evidence')
        rows = []
        for page, evidence, _attempt in pages:
            self._deadline(deadline)
            rows.extend(observations_for_page(page, source_account_id=intent.snapshot.source_account_id,
                account_authority_id=intent.snapshot.source_account_id, run_id=run_id,
                collected_at=operation['started_at'], evidence_ref=evidence.ref,
                evidence_sha256=evidence.sha256, first_ordinal=len(rows) + 1))
        # Existing repositories own independent commits: never invoke in shared lock.
        self.adapters.assert_current(request=request, action=intent.action, snapshot=intent.snapshot)
        self.observations.write_run(intent.snapshot.source_account_id, run_id,
            [(row, 'created') for row in rows])
        self._checkpoint_hook('observation_commit', operation)
        retained = self.observations.read_run(intent.snapshot.source_account_id, run_id)
        if len(retained.rows) != len(rows):
            raise store.OperationError('persistence_unavailable')
        with self._fenced(request, intent) as tx:
            for ordinal, observation in enumerate(rows, 1):
                lineage = json.loads(observation.source_record_locator)
                value = dto.DetectionView(observation.observation_id, None, observation.native_id_value,
                    observation.asset_locator, lineage['type'], lineage['severity'], lineage['status'],
                    lineage['port'], lineage['protocol'], lineage['ssl'], lineage['unique_vuln_id'],
                    lineage['vendor_times'], instant(observation.collected_at),
                    instant(observation.observed_at) if observation.observed_at else None,
                    'unresolved_workload', observation.raw_evidence_ref, observation.raw_evidence_sha256)
                store.record_detection(tx.connection, operation_id, ordinal,
                    observation.observation_id, asdict(value))
            store.advance_finalization(tx.connection, operation_id, 'observations')
        for ordinal, observation in enumerate(rows, 1):
            self._deadline(deadline)
            self.adapters.assert_current(request=request, action=intent.action, snapshot=intent.snapshot)
            resolution = self.identities.resolve_retained(
                str(uuid.uuid5(uuid.UUID(run_id), f'resolve:{ordinal}')), observation,
                observation.revision, qualys_source_only_rule(), {}, operation['started_at'])
            with self._fenced(request, intent) as tx:
                store.resolve_detection(tx.connection, operation_id, ordinal,
                    group_id=resolution.group_id, state='native_group_resolved_workload_unresolved'
                    if resolution.group_id else 'unresolved_native_identity')
        with self._fenced(request, intent) as tx:
            store.advance_finalization(tx.connection, operation_id, 'resolution')
        self._checkpoint_hook('resolution', operation)
        ended = self._clock()
        with self.engine.connect() as connection:
            attempts = connection.execute(sa.select(store.attempts).where(
                store.attempts.c.operation_id == operation_id).order_by(store.attempts.c.attempt_no)
                ).mappings().all()
        schedule = CollectionScheduleV1(str(uuid.uuid5(uuid.UUID(run_id), 'manual-accounting')),
            1, 'qualys', intent.snapshot.source_account_id, intent.snapshot.scope_key,
            enabled=False, cadence='manual', max_attempts=MAX_PAGES * MAX_PAGE_ATTEMPTS,
            total_deadline=timedelta(seconds=TOTAL_DEADLINE_SECONDS))
        attempt_facts = [AttemptFact(a['attempt_no'], a['started_at'], a['finished_at'],
            a['response_class'], a['success'],
            retry_after=timedelta(seconds=a['retry_after_seconds']) if a['retry_after_seconds'] is not None else None,
            error_code=a['error_code']) for a in attempts]
        page_facts = []
        for page, evidence, attempt in pages:
            cursor = page_facts[-1].next_cursor if page_facts else None
            continuation = digest(page.parsed.continuation) if page.parsed.continuation else None
            page_facts.append(PageFact(page.ordinal, cursor, evidence.ref, attempt, 'http_success',
                page.parsed.host_count, evidence.sha256, next_cursor=continuation,
                is_terminal=page.parsed.continuation is None, request_identity=digest(page.request_url),
                query_scope='qualys_vm_account_visible_v1'))
        state = 'failed' if not pages else 'partial' if failure else 'completed'
        run = CollectionRunV1.from_facts(schedule=schedule, run_id=run_id, revision=1,
            manual_origin='qualys_vm_manual_v1', started_at=operation['started_at'], ended_at=ended,
            state=state, attempts=attempt_facts, pages=page_facts, observations=rows)
        self.adapters.assert_current(request=request, action=intent.action, snapshot=intent.snapshot)
        self.ingestion.save_schedule(schedule, operation['started_at'])
        evidence_facts = [(str(uuid.uuid5(uuid.UUID(run_id), f'page:{page.ordinal}')),
            evidence.ref, evidence.sha256, evidence.size) for page, evidence, _ in pages]
        self.ingestion.save_run_transition(run, attempts=attempt_facts, pages=page_facts,
            evidence=evidence_facts, created_at=operation['started_at'])
        if self.ingestion.read_run(run_id, 1) is None:
            raise store.OperationError('persistence_unavailable')
        self._checkpoint_hook('run_commit', operation)
        retrieval = asdict(dto.RetrievalView('failed' if not pages else
            'partial' if failure or run.quality[0].status != 'complete' else 'complete',
            tuple(dict.fromkeys(([failure] if failure else []) + list(run.quality[0].reason_codes)))))
        coverage = asdict(dto.CoverageView('unknown', ('account_visibility_not_asset_coverage',)))
        freshness = asdict(dto.SourceFreshnessView('unknown', ('source_freshness_rule_unverified',)))
        status = {'complete': 'succeeded', 'partial': 'partial', 'failed': 'failed'}[retrieval['status']]
        self._deadline(deadline)
        with self._fenced(request, intent) as tx:
            self._deadline(deadline)
            store.publish(tx.connection, operation, published_at=self._clock(), retrieval=retrieval,
                coverage=coverage, freshness=freshness)
            store.advance_finalization(tx.connection, operation_id, 'published')
            committed = tx.record_audited_receipt(intent_id=intent.intent_id,
                result=dto.CollectResult(operation_id, run_id, status, failure))
            self._finish(tx.connection, operation_id, status, failure, committed)
            self._deadline(deadline)
            if status == 'succeeded':
                store.update_configuration(tx.connection, intent.connector_id, intent.source_id,
                    latest_complete_run_id=run_id)
        self._checkpoint_hook('published', operation)

    def _recency(self, connection, config):
        now = self._clock()
        completed = None
        if config and config['latest_complete_run_id']:
            completed = connection.execute(sa.select(store.publications.c.published_at).where(
                store.publications.c.run_id == config['latest_complete_run_id'])).scalar_one_or_none()
        status = 'never' if completed is None else 'stale' if now - completed >= timedelta(hours=24) else 'recent'
        return dto.CollectionRecencyView(status, instant(now), instant(completed) if completed else None)

    def view(self, request, connector_id, source_id):
        canonical_uuid(connector_id)
        canonical_uuid(source_id)
        with self._transaction(request, 'connector.read', connector_id, source_id) as tx:
            metadata = self._metadata(tx)
            config = self._configuration(tx)
            validation = config['validation'] if config else None
            if validation and (validation['configuration_revision'] != tx.snapshot.configuration_revision
                    or validation['credential_version_id'] != tx.snapshot.credential_version_id
                    or validation['restore_epoch_id'] != tx.snapshot.restore_epoch_id):
                validation = None
            active = config['active_snapshot'] if config else None
            effective = bool(active) and all(active[name] == getattr(tx.snapshot, name) for name in
                ('configuration_revision', 'connector_revision', 'credential_version_id', 'restore_epoch_id'))
            lifecycle = metadata.lifecycle
            active_revision = metadata.active_configuration_revision
            if lifecycle == 'active' and not effective:
                lifecycle, active_revision = 'staged', None
            proof = dto.ValidationView(**{f.name: validation[f.name]
                for f in fields(dto.ValidationView)}) if validation else None
            return asdict(dto.ScannerView(1, connector_id, source_id,
                metadata.source_tuple, metadata.display_name, metadata.account_label,
                metadata.environment_label, metadata.product, metadata.platform_id,
                metadata.scope, lifecycle, metadata.configuration_revision,
                active_revision, metadata.credential,
                tx.snapshot.expected_revisions, proof, dto.ScannerLimitsView(),
                'manual', False, config['latest_attempt_run_id'] if config else None,
                config['latest_complete_run_id'] if config else None,
                self._recency(tx.connection, config)))

    def detection_page(self, request, connector_id, source_id, run_id, *, limit=50, cursor=None):
        for value in (connector_id, source_id, run_id):
            canonical_uuid(value)
        if type(limit) is not int or not 1 <= limit <= 100:
            raise store.OperationError('invalid_request')
        if cursor is not None and (type(cursor) is not str or not cursor or len(cursor) > 128):
            raise store.OperationError('invalid_cursor')
        with self._transaction(request, 'assessment.read', connector_id, source_id) as tx:
            publication = tx.connection.execute(sa.select(store.publications).where(
                store.publications.c.run_id == run_id,
                store.publications.c.connector_id == connector_id,
                store.publications.c.source_id == source_id)).mappings().first()
            if publication is None:
                raise store.OperationError('not_found')
            binding = digest(json.dumps({'principal': tx.snapshot.principal_id,
                'connector': connector_id, 'source': source_id, 'run': run_id,
                'snapshot': instant(publication['published_at']),
                'restore_epoch': tx.snapshot.restore_epoch_id,
                'authority': asdict(tx.snapshot.expected_revisions)}, sort_keys=True))
            after = 0
            now = self._clock()
            if cursor:
                retained = tx.connection.execute(sa.select(store.cursors).where(
                    store.cursors.c.token_hash == digest(cursor),
                    store.cursors.c.binding_hash == binding,
                    store.cursors.c.run_id == run_id)).mappings().first()
                if retained is None or now >= retained['expires_at']:
                    raise store.OperationError('invalid_cursor')
                after = retained['after_ordinal']
            rows = tx.connection.execute(sa.select(store.detections).where(
                store.detections.c.operation_id == publication['operation_id'],
                store.detections.c.ordinal > after).order_by(store.detections.c.ordinal)
                .limit(limit + 1)).mappings().all()
            next_cursor = None
            if len(rows) > limit:
                next_cursor = secrets.token_urlsafe(32)
                tx.connection.execute(store.cursors.insert().values(token_hash=digest(next_cursor),
                    binding_hash=binding, run_id=run_id, after_ordinal=rows[limit - 1]['ordinal'],
                    expires_at=now + timedelta(minutes=15)))
            return asdict(dto.DetectionPage(1, run_id, instant(publication['published_at']),
                tuple(dto.DetectionView(**row['payload']) for row in rows[:limit]), next_cursor,
                dto.RetrievalView(**publication['retrieval']), dto.CoverageView(**publication['coverage']),
                dto.SourceFreshnessView(**publication['source_freshness']),
                self._recency(tx.connection, self._configuration(tx))))
