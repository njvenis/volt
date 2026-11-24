"""Real PG/HTTPS provider composition with injected authority, not shared-auth proof."""
from contextlib import contextmanager, ExitStack, asynccontextmanager
from dataclasses import asdict
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import tempfile
import ssl
import subprocess
import sys
import threading
import time
import unittest
import uuid

import sqlalchemy as sa
from fastapi import FastAPI
from fastapi.testclient import TestClient

import uvm.api.app  # existing repository table metadata
from uvm.scanners import contracts as dto, store
from uvm.scanners.service import ScannerService, qualys_source_only_rule
from uvm.persistence.identity_repository import IdentityRepository, AuthorisationDecision
from uvm.scanners.api import install_scanner_routes, scanner_worker_lifespan
from uvm.scanners.evidence import PrivateEvidenceStore
from uvm.scanners.qualys_vm import QualysVMClient, _production_transport, ENDPOINT_PATH
from wire_validation import assert_response
from support_bridge import Bridge, bindings, commands, audit, metadata
from test_qualys_vm_protocol import PAGE, LAST_PAGE, local_https_server
from http.server import BaseHTTPRequestHandler

PG_URL = os.environ.get('UVM_TEST_PG_URL')


@unittest.skipUnless(PG_URL, 'requires disposable migrated PostgreSQL')
class CoordinatorPostgresTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.engine = sa.create_engine(PG_URL)
        metadata.create_all(cls.engine)
        def synthetic_provisioner(action, target_id, context):
            return AuthorisationDecision(str(uuid.uuid4()), True, 'synthetic-rule-provisioner',
                action, target_id, 'local-fixture', '1', 'synthetic-test-only',
                'fixture-only', str(uuid.uuid4()), datetime.now(timezone.utc), {})
        IdentityRepository(cls.engine, synthetic_provisioner).provision_rule(
            qualys_source_only_rule(), datetime.now(timezone.utc))

    @classmethod
    def tearDownClass(cls):
        cls.engine.dispose()

    def setUp(self):
        self.connector_id, self.source_id, self.account_id = [str(uuid.uuid4()) for _ in range(3)]
        self.snapshot = dto.ScannerBindingSnapshot('synthetic-actor', self.connector_id,
            self.source_id, 'qualys', self.account_id, 'account_visible', 0, 1,
            str(uuid.uuid4()), str(uuid.uuid4()), str(uuid.uuid4()),
            dto.ExpectedRevisions(0, 1, 1, 0, 1, 1, 1, 0, None), 'disabled', None)
        with self.engine.begin() as connection:
            connection.execute(sa.text('''INSERT INTO g7_connectors
                (connector_id,source_id,source_family,source_account_id,scope_key,
                source_revision,secret_source_revision,connector_revision,configuration_revision,
                lifecycle,validation,recovery,environment_label,updated_at)
                VALUES (:connector,:source,'qualys',:account,'account_visible',1,0,1,0,
                'disabled','{}'::jsonb,'{}'::jsonb,'coordinator-fixture',now())'''),
                {'connector': self.connector_id, 'source': self.source_id, 'account': self.account_id})
            connection.execute(bindings.insert().values(connector_id=self.connector_id,
                document={'snapshot': asdict(self.snapshot), 'credential_revision': 1, 'grants':
                    ['connector.read', 'connector.configure', 'assessment.read']}))
        self.bridge = Bridge(self.engine, self.connector_id)
        self.directory = tempfile.TemporaryDirectory()
        self.request = type('SyntheticRequest', (), {'headers': {}})()
        self.calls = []
        self.hook = lambda *_: None

    def tearDown(self):
        with self.engine.begin() as connection:
            for table in (commands, audit, bindings):
                connection.execute(table.delete().where(table.c.connector_id == self.connector_id))
            connection.execute(sa.text('DELETE FROM g7_connectors WHERE connector_id=:id'),
                {'id': self.connector_id})
        self.directory.cleanup()

    @contextmanager
    def composition(self, responses=None):
        case = self
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                case.assertFalse(case.bridge.inside_lock)
                case.calls.append(self.path)
                query = self.path.split('?', 1)[-1]
                body = LAST_PAGE if 'id_min=' in query else PAGE
                headers = {}
                if responses:
                    returned = responses(len(case.calls), self.path, body)
                    status, body = returned[:2]
                    if len(returned) == 3:
                        headers = returned[2]
                else:
                    status = 200
                body = body.replace(b'https://qualysapi.qualys.com', case.origin.encode())
                self.send_response(status)
                self.send_header('Content-Length', str(len(body)))
                for name, value in headers.items():
                    self.send_header(name, value)
                self.end_headers()
                self.wfile.write(body)
            def log_message(self, *_): pass
        with local_https_server(Handler) as (server, context):
            self.origin = f'https://127.0.0.1:{server.server_port}'
            self.context = context
            def factory(platform):
                def transport(request, timeout, deadline):
                    case.assertFalse(case.bridge.inside_lock)
                    return _production_transport(request, timeout, deadline, _ssl_context=context)
                client = QualysVMClient(platform, _transport=transport)
                client.origin = self.origin  # test-composition-only; no config/env path
                return client
            self.service = ScannerService(self.engine, self.bridge,
                PrivateEvidenceStore(Path(self.directory.name)), _client_factory=factory,
                _checkpoint_hook=lambda *args: self.hook(*args))
            app = FastAPI()
            install_scanner_routes(app, self.service, public_origin='http://testserver')
            with ExitStack() as worker_stack:
                self.worker_stack = worker_stack
                self.recovered_at_startup = worker_stack.enter_context(self.service.worker_lifetime())
                with TestClient(app) as browser:
                    self.browser = browser
                    self.app = app
                    yield

    def command(self, action, **extra):
        view = self.service.view(self.request, self.connector_id, self.source_id)
        return {'schema_version': 1, 'command_id': str(uuid.uuid4()), 'action': action,
            'target_id': self.connector_id, 'membership_ids': [],
            'expected_revisions': view['expected_revisions'],
            'payload': {'source_id': self.source_id, 'rationale': 'Synthetic integration',
                'evidence_ref': 'local-fixture', **extra}}

    def post(self, command):
        response = self.browser.post(f'/api/v1/scanners/{self.connector_id}/commands',
            json=command, headers={'Origin': 'http://testserver', 'X-CSRF-Token': 'fixture-only'})
        self.assertEqual(response.headers['cache-control'], 'no-store')
        if response.status_code in (200, 202):
            assert_response(self, self.app, '/api/v1/scanners/{connector_id}/commands', response)
        return response

    def save(self):
        response = self.post(self.command('scanner.configuration.save', settings={
            'product': 'qualys_vm', 'api_version': '2.0', 'platform_id': 'us1',
            'scope': {'kind': 'account_visible'}, 'collection_mode': 'manual'}))
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(self.calls, [])

    def version(self):
        view = self.service.view(self.request, self.connector_id, self.source_id)
        return dict(configuration_revision=view['configuration_revision'],
            credential_version_id=view['credential']['version_id'])

    def activate(self):
        self.save()
        probe = self.post(self.command('scanner.connection.test', **self.version()))
        self.assertEqual(probe.status_code, 200, probe.text)
        self.assertEqual(probe.json()['result']['status'], 'succeeded')
        self.assertEqual(len(self.calls), 1)
        response = self.post(self.command('scanner.configuration.activate', **self.version(),
            validation_operation_id=probe.json()['result']['operation_id']))
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(len(self.calls), 1)
        with self.engine.connect() as connection:
            self.assertEqual(connection.execute(sa.select(sa.func.count()).select_from(store.detections)
                .join(store.operations, store.operations.c.operation_id == store.detections.c.operation_id)
                .where(store.operations.c.connector_id == self.connector_id)).scalar_one(), 0)

    def test_public_lifecycle_exact_evidence_native_qid_readback_and_replay(self):
        with self.composition():
            self.activate()
            command = self.command('scanner.collection.start', **self.version())
            collected = self.post(command)
            self.assertEqual(collected.status_code, 200, collected.text)
            result = collected.json()['result']
            self.assertEqual(result['status'], 'succeeded', collected.text)
            self.assertEqual(len(self.calls), 3)
            again = self.post(command)
            self.assertEqual(again.json(), collected.json())
            self.assertEqual(len(self.calls), 3)
            run_id = result['run_id']
            url = f'/api/v1/scanners/{self.connector_id}/runs/{run_id}/detections'
            page = self.browser.get(url, params={'source_id': self.source_id, 'limit': 2})
            self.assertEqual(page.status_code, 200, page.text)
            assert_response(self, self.app, '/api/v1/scanners/{connector_id}/runs/{run_id}/detections', page, 'get')
            first = page.json()
            second = self.browser.get(url, params={'source_id': self.source_id,
                'cursor': first['next_cursor'], 'limit': 2}).json()
            rows = first['items'] + second['items']
            self.assertEqual(len(rows), 3)
            self.assertEqual(len({r['group_id'] for r in rows}), 1)
            self.assertIsNotNone(rows[0]['group_id'])
            self.assertEqual([(r['port'], r['protocol']) for r in rows[:2]], [('443', 'tcp'), ('53', 'udp')])
            self.assertEqual(first['retrieval']['status'], 'complete')
            self.assertEqual(first['coverage']['status'], 'unknown')
            self.assertEqual(first['source_freshness']['status'], 'unknown')
            self.assertEqual(first['collection_recency']['status'], 'recent')
            retained = self.service.evidence.read(rows[0]['evidence_ref'])
            self.assertEqual(retained, PAGE.replace(b'https://qualysapi.qualys.com', self.origin.encode()))
            self.assertNotIn('fixture-only-password', page.text)
            self.assertNotIn('<HOST>', page.text)
            self.assertEqual(self.service.ingestion.read_run(run_id)['run']['state'], 'completed')

    def detections_url(self, run_id):
        return f'/api/v1/scanners/{self.connector_id}/runs/{run_id}/detections'

    def latest_operation(self):
        with self.engine.connect() as connection:
            return dict(connection.execute(sa.select(store.operations).where(
                store.operations.c.connector_id == self.connector_id).order_by(
                store.operations.c.started_at.desc())).mappings().first())

    def test_partial_run_keeps_older_complete_pointer_and_positive_rows(self):
        failing = {'enabled': False}
        def responses(_number, path, body):
            return (500, b'private vendor failure') if failing['enabled'] and 'id_min=' in path else (200, body)
        with self.composition(responses):
            self.activate()
            complete = self.post(self.command('scanner.collection.start', **self.version())).json()['result']
            failing['enabled'] = True
            partial_response = self.post(self.command('scanner.collection.start', **self.version()))
            self.assertEqual(partial_response.status_code, 200, partial_response.text)
            partial = partial_response.json()['result']
            self.assertEqual(partial['status'], 'partial')
            view = self.service.view(self.request, self.connector_id, self.source_id)
            self.assertEqual(view['latest_complete_run_id'], complete['run_id'])
            self.assertEqual(view['latest_attempt_run_id'], partial['run_id'])
            result = self.browser.get(self.detections_url(partial['run_id']),
                params={'source_id': self.source_id})
            self.assertEqual(result.status_code, 200, result.text)
            self.assertEqual(len(result.json()['items']), 2)
            self.assertEqual(result.json()['retrieval']['status'], 'partial')
            self.assertNotIn('private vendor failure', result.text)

    def test_probe_auth_failure_is_typed_durable_and_does_not_ingest(self):
        with self.composition(lambda *_: (401, b'sensitive authentication rejection')):
            self.save()
            command = self.command('scanner.connection.test', **self.version())
            failed = self.post(command)
            self.assertEqual(failed.status_code, 200, failed.text)
            self.assertEqual(failed.json()['result']['status'], 'failed')
            self.assertEqual(failed.json()['result']['error_code'], 'authentication_rejected')
            self.assertEqual(len(self.calls), 1)
            self.assertEqual(self.post(command).json(), failed.json())
            self.assertEqual(len(self.calls), 1)
            self.assertIsNone(self.latest_operation()['run_id'])
            activate = self.post(self.command('scanner.configuration.activate', **self.version(),
                validation_operation_id=failed.json()['result']['operation_id']))
            self.assertEqual(activate.status_code, 409)
            self.assertNotIn('sensitive authentication rejection', failed.text)

    def test_revoke_between_pages_stops_outbound_and_prevents_publication(self):
        with self.composition():
            self.activate()
            def hook(stage, operation):
                if stage == 'page' and operation['action'] == 'collect':
                    self.bridge.mutate(grants=['connector.read', 'assessment.read'])
            self.hook = hook
            response = self.post(self.command('scanner.collection.start', **self.version()))
            self.assertEqual(response.status_code, 403, response.text)
            self.assertEqual(len(self.calls), 2)  # one probe + first collection page
            operation = self.latest_operation()
            self.assertEqual(operation['status'], 'interrupted')
            result = self.browser.get(self.detections_url(str(operation['run_id'])),
                params={'source_id': self.source_id})
            self.assertEqual(result.status_code, 404)
            metadata = self.service.operation(self.request, self.connector_id, self.source_id,
                str(operation['operation_id']))
            self.assertNotIn('detection_count', metadata)
            self.assertNotIn('host_count', metadata)

    def test_restore_change_after_native_commit_prevents_final_publication(self):
        with self.composition():
            self.activate()
            def hook(stage, operation):
                if stage == 'run_commit':
                    self.bridge.mutate(snapshot={'restore_epoch_id': str(uuid.uuid4())})
            self.hook = hook
            response = self.post(self.command('scanner.collection.start', **self.version()))
            self.assertEqual(response.status_code, 409, response.text)
            operation = self.latest_operation()
            self.assertIsNotNone(self.service.ingestion.read_run(str(operation['run_id'])))
            self.assertEqual(self.browser.get(self.detections_url(str(operation['run_id'])),
                params={'source_id': self.source_id}).status_code, 404)
            self.assertIsNone(self.service.view(self.request, self.connector_id,
                self.source_id)['latest_complete_run_id'])

    def test_audit_failure_rolls_back_local_configuration_and_intent(self):
        with self.composition():
            self.bridge.fail_receipt = True
            response = self.post(self.command('scanner.configuration.save', settings={
                'product': 'qualys_vm', 'api_version': '2.0', 'platform_id': 'us1',
                'scope': {'kind': 'account_visible'}, 'collection_mode': 'manual'}))
            self.assertEqual(response.status_code, 503, response.text)
            self.assertEqual(self.calls, [])
            with self.engine.connect() as connection:
                self.assertIsNone(store.read_configuration(connection, self.connector_id, self.source_id))
                self.assertEqual(connection.execute(sa.select(sa.func.count()).select_from(commands).where(
                    commands.c.connector_id == self.connector_id)).scalar_one(), 0)
                self.assertEqual(connection.execute(sa.select(sa.func.count()).select_from(audit).where(
                    audit.c.connector_id == self.connector_id)).scalar_one(), 0)
            self.assertEqual(self.service.view(self.request, self.connector_id,
                self.source_id)['configuration_revision'], 0)

    def test_audit_failure_at_finalization_leaves_independent_facts_private(self):
        with self.composition():
            self.activate()
            self.hook = lambda stage, _operation: setattr(self.bridge, 'fail_receipt', True) if stage == 'run_commit' else None
            command = self.command('scanner.collection.start', **self.version())
            response = self.post(command)
            self.assertEqual(response.status_code, 503, response.text)
            operation = self.latest_operation()
            run_id = str(operation['run_id'])
            self.assertIsNotNone(self.service.ingestion.read_run(run_id))
            self.assertEqual(self.browser.get(self.detections_url(run_id),
                params={'source_id': self.source_id}).status_code, 404)
            previous_calls = len(self.calls)
            replay = self.post(command)
            self.assertEqual(replay.status_code, 200, replay.text)
            self.assertEqual(replay.json()['status'], 'interrupted')
            self.assertEqual(len(self.calls), previous_calls)

    def test_current_read_grants_cross_source_and_cursor_fence(self):
        with self.composition():
            self.activate()
            result = self.post(self.command('scanner.collection.start', **self.version())).json()['result']
            url = self.detections_url(result['run_id'])
            page = self.browser.get(url, params={'source_id': self.source_id, 'limit': 1}).json()
            self.assertIsNotNone(page['next_cursor'])
            self.assertEqual(self.browser.get(url, params={'source_id': str(uuid.uuid4())}).status_code, 404)
            self.bridge.mutate(grants=['connector.read', 'connector.configure'])
            self.assertEqual(self.browser.get(url, params={'source_id': self.source_id}).status_code, 403)
            self.assertEqual(self.browser.get(f'/api/v1/scanners/{self.connector_id}/operations/{result["operation_id"]}',
                params={'source_id': self.source_id}).status_code, 200)
            current = self.service.view(self.request, self.connector_id, self.source_id)['expected_revisions']
            self.bridge.mutate(grants=['connector.read', 'connector.configure', 'assessment.read'],
                snapshot={'expected_revisions': dict(current, policy=current['policy'] + 1)})
            response = self.browser.get(url, params={'source_id': self.source_id,
                'cursor': page['next_cursor']})
            self.assertEqual(response.status_code, 422)

    def test_route_checks_no_store_origin_json_and_denies_unsafe_settings_without_http(self):
        with self.composition():
            command = self.command('scanner.configuration.save', settings={'endpoint': 'https://evil.invalid'})
            denied = self.browser.post(f'/api/v1/scanners/{self.connector_id}/commands', json=command,
                headers={'Origin': 'https://evil.invalid', 'X-CSRF-Token': 'fixture-only'})
            self.assertEqual(denied.status_code, 403)
            self.assertEqual(denied.headers['cache-control'], 'no-store')
            invalid = self.post(command)
            self.assertEqual(invalid.status_code, 422, invalid.text)
            raw = self.browser.post(f'/api/v1/scanners/{self.connector_id}/commands', content='{"a":1,"a":2}',
                headers={'Origin': 'http://testserver', 'X-CSRF-Token': 'fixture-only',
                    'Content-Type': 'application/json'})
            self.assertEqual(raw.status_code, 422)
            self.assertEqual(self.calls, [])

    def test_fixed_source_status_does_not_create_workload_or_occurrence(self):
        from uvm.persistence.schema import workloads, exposures, occurrences
        with self.engine.connect() as connection:
            before = [connection.execute(sa.select(sa.func.count()).select_from(table)).scalar_one()
                for table in (workloads, exposures, occurrences)]
        with self.composition(lambda _n, _p, body: (200,
                body.replace(b'<STATUS>Active</STATUS>', b'<STATUS>Fixed</STATUS>'))):
            self.activate()
            response = self.post(self.command('scanner.collection.start', **self.version()))
            self.assertEqual(response.status_code, 200, response.text)
            rows = self.browser.get(self.detections_url(response.json()['result']['run_id']),
                params={'source_id': self.source_id}).json()['items']
            self.assertEqual(rows[0]['vendor_status'], 'Fixed')
            self.assertTrue(all(r['identity_resolution'] == 'native_group_resolved_workload_unresolved' for r in rows))
        with self.engine.connect() as connection:
            after = [connection.execute(sa.select(sa.func.count()).select_from(table)).scalar_one()
                for table in (workloads, exposures, occurrences)]
        self.assertEqual(before, after)

    def test_concurrent_public_admission_and_running_replay_issue_one_walk(self):
        entered, release = threading.Event(), threading.Event()
        enabled = {'value': False}
        def responses(_number, path, body):
            if enabled['value'] and 'id_min=' not in path:
                entered.set()
                if not release.wait(5):
                    raise RuntimeError('fixture release missing')
            return 200, body
        with self.composition(responses):
            self.activate()
            enabled['value'] = True
            command = self.command('scanner.collection.start', **self.version())
            output = []
            worker = threading.Thread(target=lambda: output.append(self.post(command)))
            worker.start()
            try:
                self.assertTrue(entered.wait(5))
                replay = self.post(command)
                self.assertEqual(replay.status_code, 202, replay.text)
                self.assertEqual(replay.json()['status'], 'running')
                competing = self.post(self.command('scanner.collection.start', **self.version()))
                self.assertEqual(competing.status_code, 409, competing.text)
                self.assertEqual(len(self.calls), 2)
            finally:
                release.set()
                worker.join(8)
            self.assertFalse(worker.is_alive())
            self.assertEqual(output[0].status_code, 200, output[0].text)
            self.assertEqual(len(self.calls), 3)

    def test_actual_process_loss_after_observation_commit_restart_never_reissues_http(self):
        with self.composition():
            self.activate()
            command = self.command('scanner.collection.start', **self.version())
            directory = Path(self.directory.name)
            command_file = directory / 'child-command.json'
            command_file.write_text(json.dumps(command))
            cert_file = directory / 'fixture-ca.pem'
            cert_file.write_text(ssl.DER_cert_to_PEM_cert(self.context.get_ca_certs(binary_form=True)[0]))
            script = directory / 'process_loss.py'
            script.write_text('''import json, os, ssl, sys
from pathlib import Path
import sqlalchemy as sa
from support_bridge import Bridge
from uvm.scanners.service import ScannerService
from uvm.scanners.evidence import PrivateEvidenceStore
from uvm.scanners.qualys_vm import QualysVMClient, _production_transport
command = json.loads(Path(sys.argv[1]).read_text())
engine = sa.create_engine(os.environ['UVM_TEST_PG_URL'])
context = ssl.create_default_context(cafile=sys.argv[2])
def factory(platform):
    def transport(request, timeout, deadline):
        return _production_transport(request, timeout, deadline, _ssl_context=context)
    client = QualysVMClient(platform, _transport=transport)
    client.origin = sys.argv[3]
    return client
def interrupt(stage, operation):
    if stage == 'observation_commit':
        os._exit(73)
service = ScannerService(engine, Bridge(engine, command['target_id']),
    PrivateEvidenceStore(Path(sys.argv[1]).parent), _client_factory=factory,
    _checkpoint_hook=interrupt)
request = type('SyntheticRequest', (), {'headers': {}})()
with service.worker_lifetime():
    service.command(request, command['target_id'], command)
raise SystemExit('checkpoint not reached')
''')
            environment = dict(os.environ, PYTHONPATH=os.pathsep.join((str(Path.cwd()),
                str(Path.cwd() / 'tests/scanners'))))
            self.worker_stack.close()  # parent worker has shut down, fixture HTTPS stays alive
            child = subprocess.run([sys.executable, str(script), str(command_file),
                str(cert_file), self.origin], env=environment, capture_output=True,
                text=True, timeout=15)
            self.assertEqual(child.returncode, 73, child.stdout + child.stderr)
            operation = self.latest_operation()
            run_id = str(operation['run_id'])
            self.assertEqual(operation['status'], 'running')
            self.assertEqual(operation['finalization_stage'], 'evidence')
            self.assertEqual(len(self.service.observations.read_run(self.account_id, run_id).rows), 3)
            reconnect_engine = sa.create_engine(PG_URL)
            restarted = ScannerService(reconnect_engine, Bridge(reconnect_engine, self.connector_id),
                PrivateEvidenceStore(directory),
                _client_factory=lambda _: self.fail('interrupted replay must not construct HTTP client'))
            try:
                with restarted.worker_lifetime() as recovered:
                    self.assertEqual(recovered, 1)
                    replay, status = restarted.command(self.request, self.connector_id, command)
                    self.assertEqual(status, 200)
                    self.assertEqual(replay['status'], 'interrupted')
                    self.assertEqual(len(self.calls), 3)
                    with self.assertRaisesRegex(store.OperationError, 'not_found'):
                        restarted.detection_page(self.request, self.connector_id, self.source_id, run_id)
            finally:
                reconnect_engine.dispose()

    def test_expired_probe_requires_retest_and_collection_age_is_separate(self):
        with self.composition():
            self.save()
            probe = self.post(self.command('scanner.connection.test', **self.version())).json()
            original_clock = self.service._clock
            self.service._clock = lambda: original_clock() + timedelta(minutes=16)
            expired = self.post(self.command('scanner.configuration.activate', **self.version(),
                validation_operation_id=probe['result']['operation_id']))
            self.assertEqual(expired.status_code, 409)
            self.assertEqual(len(self.calls), 1)
            self.service._clock = original_clock
            activated = self.post(self.command('scanner.configuration.activate', **self.version(),
                validation_operation_id=probe['result']['operation_id']))
            self.assertEqual(activated.status_code, 200, activated.text)
            collected = self.post(self.command('scanner.collection.start', **self.version()))
            self.assertEqual(collected.status_code, 200, collected.text)
            self.service._clock = lambda: original_clock() + timedelta(hours=25)
            view = self.service.view(self.request, self.connector_id, self.source_id)
            self.assertEqual(view['collection_recency']['status'], 'stale')
            result = self.service.detection_page(self.request, self.connector_id, self.source_id,
                collected.json()['result']['run_id'])
            self.assertEqual(result['source_freshness']['status'], 'unknown')

    def test_credential_change_invalidates_activation_and_prevents_next_attempt(self):
        with self.composition():
            self.activate()
            def hook(stage, operation):
                if stage == 'page' and operation['action'] == 'collect':
                    self.bridge.mutate(snapshot={'credential_version_id': str(uuid.uuid4())})
            self.hook = hook
            response = self.post(self.command('scanner.collection.start', **self.version()))
            self.assertEqual(response.status_code, 409)
            self.assertEqual(len(self.calls), 2)
            self.hook = lambda *_: None
            self.assertEqual(self.post(self.command('scanner.collection.start', **self.version())).status_code, 409)
            self.assertEqual(len(self.calls), 2)

    def test_collect_zero_page_failure_is_failed_and_not_proved_empty(self):
        failing = {'enabled': False}
        def responses(_n, _path, body):
            return (403, b'private vendor body') if failing['enabled'] else (200, body)
        with self.composition(responses):
            self.activate()
            failing['enabled'] = True
            response = self.post(self.command('scanner.collection.start', **self.version()))
            self.assertEqual(response.status_code, 200, response.text)
            result = response.json()['result']
            self.assertEqual(result['status'], 'failed')
            page = self.service.detection_page(self.request, self.connector_id, self.source_id, result['run_id'])
            self.assertEqual(page['items'], ())
            self.assertEqual(page['retrieval']['status'], 'failed')
            self.assertEqual(page['coverage']['status'], 'unknown')

    def test_deadline_between_run_commit_and_publication_cannot_succeed(self):
        with self.composition():
            self.activate()
            real_monotonic = self.service._monotonic
            def hook(stage, operation):
                if stage == 'run_commit':
                    self.service._monotonic = lambda: real_monotonic() + 121
            self.hook = hook  # injected coordinator clock, not transport timeout proof
            response = self.post(self.command('scanner.collection.start', **self.version()))
            self.assertEqual(response.status_code, 409, response.text)
            operation = self.latest_operation()
            self.assertEqual(operation['status'], 'failed')
            self.assertEqual(operation['error_code'], 'deadline_exceeded')
            self.assertIsNotNone(self.service.ingestion.read_run(str(operation['run_id'])))
            self.assertEqual(self.browser.get(self.detections_url(str(operation['run_id'])),
                params={'source_id': self.source_id}).status_code, 404)

    def test_provider_throttle_attempts_are_durable_and_retry_after_is_recorded(self):
        enabled = {'value': False, 'rejected': False}
        def responses(_number, _path, body):
            if enabled['value'] and not enabled['rejected']:
                enabled['rejected'] = True
                return 429, b'private throttle', {'Retry-After': '0'}
            return 200, body
        with self.composition(responses):
            self.activate()
            enabled['value'] = True
            result = self.post(self.command('scanner.collection.start', **self.version()))
            self.assertEqual(result.status_code, 200, result.text)
            self.assertEqual(result.json()['result']['status'], 'succeeded')
            operation = self.latest_operation()
            with self.engine.connect() as connection:
                attempts = connection.execute(sa.select(store.attempts).where(
                    store.attempts.c.operation_id == operation['operation_id']).order_by(
                    store.attempts.c.attempt_no)).mappings().all()
            self.assertEqual([a['http_status'] for a in attempts], [429, 200, 200])
            self.assertEqual(attempts[0]['retry_after_seconds'], 0)
            self.assertEqual([a['page_ordinal'] for a in attempts], [1, 1, 2])

    def test_changed_command_content_conflicts_and_disable_is_local(self):
        with self.composition():
            self.activate()
            command = self.command('scanner.collection.start', **self.version())
            response = self.post(command)
            self.assertEqual(response.status_code, 200, response.text)
            command['payload']['rationale'] = 'changed immutable command'
            self.assertEqual(self.post(command).status_code, 409)
            before = len(self.calls)
            disabled = self.post(self.command('scanner.configuration.disable'))
            self.assertEqual(disabled.status_code, 200, disabled.text)
            self.assertEqual(disabled.json()['result']['lifecycle'], 'disabled')
            self.assertEqual(len(self.calls), before)
            self.assertEqual(self.post(self.command('scanner.collection.start', **self.version())).status_code, 409)
            self.assertEqual(len(self.calls), before)
            missing_source = self.browser.get(f'/api/v1/scanners/{self.connector_id}')
            self.assertEqual(missing_source.status_code, 422)
            self.assertEqual(missing_source.json()['schema_version'], 1)

    def test_admission_time_consumes_the_overall_deadline_before_first_http(self):
        with self.composition():
            self.activate()
            real_monotonic = self.service._monotonic
            def hook(stage, operation):
                if stage == 'admitted':
                    self.service._monotonic = lambda: real_monotonic() + 121
            self.hook = hook  # coordinator admission-clock injection only
            response = self.post(self.command('scanner.collection.start', **self.version()))
            self.assertEqual(response.status_code, 409, response.text)
            self.assertEqual(len(self.calls), 1)  # prior probe only
            operation = self.latest_operation()
            self.assertEqual(operation['status'], 'failed')
            self.assertEqual(operation['error_code'], 'deadline_exceeded')
            with self.engine.connect() as connection:
                self.assertEqual(connection.execute(sa.select(sa.func.count()).select_from(store.attempts)
                    .where(store.attempts.c.operation_id == operation['operation_id'])).scalar_one(), 0)

    def test_repeated_app_and_second_process_cannot_recover_live_worker(self):
        entered, release = threading.Event(), threading.Event()
        enabled = {'value': False}
        def responses(_number, path, body):
            if enabled['value'] and 'id_min=' not in path:
                entered.set()
                if not release.wait(8):
                    raise RuntimeError('fixture release missing')
            return 200, body
        with self.composition(responses):
            self.activate()
            enabled['value'] = True
            output = []
            command = self.command('scanner.collection.start', **self.version())
            worker = threading.Thread(target=lambda: output.append(self.post(command)))
            worker.start()
            try:
                self.assertTrue(entered.wait(5))
                running = self.latest_operation()
                other = ScannerService(self.engine, self.bridge,
                    PrivateEvidenceStore(Path(self.directory.name)))
                for _ in range(2):
                    app = FastAPI()
                    original_lifespan = app.router.lifespan_context
                    install_scanner_routes(app, other, public_origin='http://testserver')
                    self.assertIn('/api/v1/scanners/{connector_id}', app.openapi()['paths'])
                self.assertEqual(self.latest_operation()['status'], 'running')
                with self.assertRaisesRegex(store.OperationError, 'scanner_worker_already_running'):
                    with other.worker_lifetime():
                        self.fail('second worker must not start')
                with self.assertRaisesRegex(store.OperationError, 'startup_recovery_required'):
                    self.service.recover_interrupted()
                script = Path(self.directory.name) / 'second_worker.py'
                script.write_text('''import os, sys
from pathlib import Path
import sqlalchemy as sa
from support_bridge import Bridge
from uvm.scanners.service import ScannerService
from uvm.scanners.evidence import PrivateEvidenceStore
from uvm.scanners.store import OperationError
engine=sa.create_engine(os.environ['UVM_TEST_PG_URL'])
service=ScannerService(engine, Bridge(engine, sys.argv[1]), PrivateEvidenceStore(Path(sys.argv[2])))
try:
    with service.worker_lifetime():
        raise SystemExit('unexpected worker ownership')
except OperationError as error:
    assert error.code == 'scanner_worker_already_running', error.code
print('second process denied; no recovery')
''')
                environment = dict(os.environ, PYTHONPATH=os.pathsep.join((str(Path.cwd()),
                    str(Path.cwd() / 'tests/scanners'))))
                second = subprocess.run([sys.executable, str(script), self.connector_id,
                    self.directory.name], env=environment, text=True, capture_output=True, timeout=5)
                self.assertEqual(second.returncode, 0, second.stdout + second.stderr)
                self.assertIn('second process denied', second.stdout)
                self.assertEqual(self.latest_operation()['operation_id'], running['operation_id'])
                self.assertEqual(self.latest_operation()['status'], 'running')
                self.assertEqual(len(self.calls), 2)
            finally:
                release.set()
                worker.join(8)
            self.assertFalse(worker.is_alive())
            self.assertEqual(output[0].status_code, 200, output[0].text)
            self.assertEqual(output[0].json()['result']['status'], 'succeeded')


    def test_async_worker_hook_composes_existing_lifespan_and_releases_ownership(self):
        events = []
        service = ScannerService(self.engine, self.bridge,
            PrivateEvidenceStore(Path(self.directory.name)))
        @asynccontextmanager
        async def existing_lifespan(app):
            events.append('existing:start')
            async with scanner_worker_lifespan(service) as recovered:
                events.append(f'worker:{recovered}')
                yield
            events.append('worker:end')
            events.append('existing:end')
        app = FastAPI(lifespan=existing_lifespan)
        original = app.router.lifespan_context
        install_scanner_routes(app, service, public_origin='http://testserver')
        self.assertEqual(events, [])
        with TestClient(app) as browser:
            self.assertEqual(events, ['existing:start', 'worker:0'])
            result = browser.get(f'/api/v1/scanners/{self.connector_id}',
                params={'source_id': self.source_id})
            self.assertEqual(result.status_code, 200, result.text)
        self.assertEqual(events, ['existing:start', 'worker:0', 'worker:end', 'existing:end'])
        another = ScannerService(self.engine, self.bridge,
            PrivateEvidenceStore(Path(self.directory.name)))
        with another.worker_lifetime() as recovered:
            self.assertEqual(recovered, 0)


    def test_succeeded_without_shared_receipt_is_inconsistent_and_never_replayed(self):
        with self.composition():
            self.activate()
            command = self.command('scanner.collection.start', **self.version())
            response = self.post(command)
            self.assertEqual(response.status_code, 200, response.text)
            operation_id = response.json()['result']['operation_id']
            with self.engine.begin() as connection:
                connection.execute(commands.update().where(commands.c.connector_id == self.connector_id,
                    commands.c.command_id == command['command_id']).values(receipt=None))
                connection.execute(store.operations.update().where(
                    store.operations.c.operation_id == operation_id).values(receipt_id=None))
            before = len(self.calls)
            replay = self.post(command)
            self.assertEqual(replay.status_code, 503, replay.text)
            self.assertEqual(replay.json()['error']['code'], 'inconsistent_operation')
            metadata = self.browser.get(f'/api/v1/scanners/{self.connector_id}/operations/{operation_id}',
                params={'source_id': self.source_id})
            self.assertEqual(metadata.status_code, 503)
            self.assertEqual(len(self.calls), before)


class RouteConstructionTests(unittest.TestCase):
    def test_construct_and_export_without_scanner_tables_preserves_lifespan(self):
        engine = sa.create_engine('sqlite:///:memory:')
        sql = []
        @sa.event.listens_for(engine, 'before_cursor_execute')
        def no_database(*args):
            sql.append(args[2])
            raise AssertionError('route construction must not query provider state')
        events = []
        @asynccontextmanager
        async def existing_lifespan(app):
            events.append('start')
            yield
            events.append('end')
        app = FastAPI(lifespan=existing_lifespan)
        original_lifespan = app.router.lifespan_context
        # Adapter and private directory need not be operational during export.
        service = ScannerService(engine, object(), PrivateEvidenceStore(
            Path('/tmp') / ('absent-qualys-' + uuid.uuid4().hex)))
        install_scanner_routes(app, service, public_origin='http://testserver')
        self.assertIn('/api/v1/scanners/{connector_id}', app.openapi()['paths'])
        self.assertEqual(sql, [])
        self.assertEqual(events, [])
        with TestClient(app):
            self.assertEqual(events, ['start'])
        self.assertEqual(events, ['start', 'end'])
        self.assertEqual(sql, [])
        engine.dispose()
