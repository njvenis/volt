"""Explicit test-only authority/audit composition; NEVER imported by production.

These isolated test tables simulate bridge semantics. They do not exercise real
shared grants, session/CSRF verification, policy locks, audit tables or crypto.
"""
from contextlib import contextmanager
from dataclasses import asdict, replace
from datetime import datetime, timezone
import threading
import uuid

import sqlalchemy as sa
from fastapi import HTTPException
from uvm.scanners import contracts as dto
from uvm.scanners.store import OperationError

metadata = sa.MetaData()
bindings = sa.Table('test_qualys_bridge_bindings', metadata,
    sa.Column('connector_id', sa.String(36), primary_key=True),
    sa.Column('document', sa.JSON(), nullable=False))
commands = sa.Table('test_qualys_bridge_commands', metadata,
    sa.Column('connector_id', sa.String(36), primary_key=True),
    sa.Column('command_id', sa.String(36), primary_key=True),
    sa.Column('intent', sa.JSON(), nullable=False),
    sa.Column('receipt', sa.JSON()))
audit = sa.Table('test_qualys_bridge_audit', metadata,
    sa.Column('event_id', sa.String(36), primary_key=True),
    sa.Column('connector_id', sa.String(36), nullable=False),
    sa.Column('phase', sa.String(16), nullable=False))


def snapshot(document):
    value = dict(document['snapshot'])
    value['expected_revisions'] = dto.ExpectedRevisions(**value['expected_revisions'])
    return dto.ScannerBindingSnapshot(**value)


def intent(value):
    value = dict(value)
    value['snapshot'] = snapshot({'snapshot': value['snapshot']})
    return dto.ScannerCommandIntent(**value)


_VARIANTS = {
    'scanner.configuration.save': (dto.SaveConfigurationReceipt, dto.SaveConfigurationResult),
    'scanner.connection.test': (dto.TestConnectionReceipt, dto.TestConnectionResult),
    'scanner.configuration.activate': (dto.ActivateConfigurationReceipt, dto.ActivateConfigurationResult),
    'scanner.collection.start': (dto.CollectReceipt, dto.CollectResult),
    'scanner.configuration.disable': (dto.DisableConfigurationReceipt, dto.DisableConfigurationResult)}


def receipt(value):
    cls, result = _VARIANTS[value['action']]
    return cls(**dict(value, result=result(**value['result'])))


class Bridge:
    def __init__(self, engine, connector_id):
        self.engine, self.connector_id = engine, connector_id
        self.local = threading.local()
        self.fail_receipt = False

    @property
    def inside_lock(self):
        return getattr(self.local, 'inside', False)

    def mutate(self, **updates):
        with self.engine.begin() as connection:
            document = dict(connection.execute(sa.select(bindings.c.document).where(
                bindings.c.connector_id == self.connector_id).with_for_update()).scalar_one())
            if 'snapshot' in updates:
                document['snapshot'] = dict(document['snapshot'], **updates.pop('snapshot'))
            document.update(updates)
            connection.execute(bindings.update().where(bindings.c.connector_id == self.connector_id)
                .values(document=document))

    @contextmanager
    def transaction(self, *, request, action, connector_id, source_id,
                    expected_revisions=None, snapshot=None):
        assert not self.inside_lock, 'independent/nested bridge transaction'
        with self.engine.begin() as connection:
            document = connection.execute(sa.select(bindings.c.document).where(
                bindings.c.connector_id == connector_id).with_for_update()).scalar_one_or_none()
            if document is None or document['snapshot']['source_id'] != source_id:
                raise HTTPException(404)
            actor = request.headers.get('x-test-principal', document['snapshot']['principal_id'])
            if actor != document['snapshot']['principal_id']:
                raise HTTPException(403)
            if dto.required_scanner_grant(action) not in document['grants']:
                raise HTTPException(403)
            current = globals()['snapshot'](document)
            if expected_revisions is not None and expected_revisions != current.expected_revisions:
                raise OperationError('revision_conflict')
            if snapshot is not None and snapshot != current:
                raise OperationError('revision_conflict')
            self.local.inside = True
            try:
                yield Transaction(self, connection, current, document, action, expected_revisions)
            finally:
                self.local.inside = False

    def authorize(self, **kwargs):
        with self.transaction(**kwargs) as tx:
            return tx.snapshot

    def assert_current(self, *, request, action, snapshot):
        with self.transaction(request=request, action=action, connector_id=snapshot.connector_id,
                source_id=snapshot.source_id, snapshot=snapshot):
            pass

    @contextmanager
    def credential_attempt(self, *, request, action, snapshot):
        self.assert_current(request=request, action='scanner.connection.test' if action == 'test'
            else 'scanner.collection.start', snapshot=snapshot)
        if snapshot.credential_version_id is None:
            raise OperationError('revision_conflict')
        assert not self.inside_lock
        with dto.QualysBasicCredential('fixture-user', b'fixture-only-password') as lease:
            yield lease

    def read_registration_metadata(self, *, transaction):
        assert self.inside_lock
        current = transaction.snapshot
        return dto.ScannerRegistrationMetadata(current.connector_id, current.source_id,
            dto.SourceTupleView('qualys', current.source_account_id, current.scope_key),
            'Fixture Qualys', 'Synthetic account', 'local-test', 'qualys_vm', 'us1',
            dto.ScannerScopeView('account_visible'), current.lifecycle,
            current.configuration_revision, current.active_configuration_revision,
            dto.CredentialView(current.credential_slot_id, current.credential_version_id, 'active',
                transaction.document['credential_revision']))


class Transaction:
    def __init__(self, bridge, connection, snapshot, document, action, expected):
        self.bridge, self.connection, self.snapshot = bridge, connection, snapshot
        self.document, self.action, self.expected = document, action, expected

    def read_command(self, *, command_id, request_digest):
        row = self.connection.execute(sa.select(commands).where(
            commands.c.connector_id == self.snapshot.connector_id,
            commands.c.command_id == command_id)).mappings().first()
        if row is None:
            return None
        retained = intent(row['intent'])
        if (retained.principal_id != self.snapshot.principal_id
                or retained.action != self.action or retained.request_digest != request_digest
                or retained.source_id != self.snapshot.source_id):
            raise OperationError('command_id_reused')
        return dto.ScannerCommandState(retained, receipt(row['receipt']) if row['receipt'] else None)

    def record_audited_intent(self, *, command_id, request_digest, rationale, evidence_ref,
                             operation_id, run_id):
        assert self.expected is not None
        value = dto.ScannerCommandIntent(str(uuid.uuid4()), command_id, self.snapshot.connector_id,
            self.snapshot.source_id, self.snapshot.principal_id, self.action, request_digest,
            datetime.now(timezone.utc).isoformat(), operation_id, run_id, self.snapshot)
        self.connection.execute(commands.insert().values(connector_id=self.snapshot.connector_id,
            command_id=command_id, intent=asdict(value), receipt=None))
        self.connection.execute(audit.insert().values(event_id=str(uuid.uuid4()),
            connector_id=self.snapshot.connector_id, phase='admission'))
        return value

    def record_audited_receipt(self, *, intent_id, result, shared_state=None):
        if self.bridge.fail_receipt:
            raise RuntimeError('injected audit failure')
        row = self.connection.execute(sa.select(commands).where(
            commands.c.connector_id == self.snapshot.connector_id)).mappings().all()
        selected = next(r for r in row if r['intent']['intent_id'] == intent_id)
        original = intent(selected['intent'])
        assert original.snapshot == self.snapshot
        if shared_state is not None:
            current = replace(self.snapshot, lifecycle=shared_state.lifecycle,
                configuration_revision=shared_state.configuration_revision,
                active_configuration_revision=shared_state.active_configuration_revision,
                connector_revision=self.snapshot.connector_revision + 1,
                expected_revisions=replace(self.snapshot.expected_revisions,
                    connector=self.snapshot.connector_revision + 1))
            self.document['snapshot'] = asdict(current)
            self.connection.execute(bindings.update().where(
                bindings.c.connector_id == current.connector_id).values(document=self.document))
        else:
            current = self.snapshot
        cls, result_cls = _VARIANTS[self.action]
        assert isinstance(result, result_cls)
        value = cls(schema_version=1, command_id=original.command_id,
            decision_id=str(uuid.uuid4()), audit_event_id=str(uuid.uuid4()), intent_id=intent_id,
            committed_revision=current.connector_revision, projection={}, action=self.action,
            target_id=current.connector_id, policy_revision=current.expected_revisions.policy,
            intents=(), occurred_at=datetime.now(timezone.utc).isoformat(), result=result)
        self.connection.execute(commands.update().where(
            commands.c.connector_id == current.connector_id,
            commands.c.command_id == original.command_id).values(receipt=asdict(value)))
        self.connection.execute(audit.insert().values(event_id=value.audit_event_id,
            connector_id=current.connector_id, phase='receipt'))
        return dto.ScannerCommandCommit(value, current)
