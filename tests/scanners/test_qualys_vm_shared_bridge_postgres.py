"""Unmerged combined-source development proof with the REAL shared backend.

Requires explicit owned Qualys test database and backend scanner_runtime module.
No fake authority/crypto/session adapter. Only the vendor HTTPS endpoint is a local
fixture, injected at constructor composition. Restore recovery is deliberately not
exercised until the backend's recovery contract is reviewed.
"""
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
import json
import base64
import os
from pathlib import Path
import secrets
import subprocess
import sys
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor
import unittest
import uuid
from unittest.mock import patch
from http.server import BaseHTTPRequestHandler

import sqlalchemy as sa
from fastapi.testclient import TestClient

from uvm.scanners.api import install_scanner_routes, scanner_worker_lifespan
from uvm.scanners.service import ScannerService
from uvm.scanners.evidence import PrivateEvidenceStore
from uvm.scanners.qualys_vm import QualysVMClient, _production_transport
from wire_validation import assert_response
from test_qualys_vm_protocol import PAGE, LAST_PAGE, local_https_server

DSN = os.environ.get('UVM_QUALYS_SHARED_TEST_DSN')
DISPOSITION_TESTS = os.environ.get('UVM_QUALYS_DISPOSITION_TESTS') == '1'


@unittest.skipUnless(DSN, 'explicit owned Qualys shared-backend development database required')
class ActualSharedBridgePostgresTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from uvm.connectors.scanner_runtime import SharedScannerRuntime
        cls.runtime_type = SharedScannerRuntime
        url = sa.make_url(DSN)
        if url.host != '127.0.0.1' or url.port != 47432 or url.database != 'volt_qualys_shared_test':
            raise RuntimeError('shared composition must use the owned Qualys disposable database')
        cls.engine = sa.create_engine(DSN, pool_pre_ping=True)
        with cls.engine.connect() as connection:
            if (connection.dialect.name != 'postgresql' or
                    connection.exec_driver_sql('select current_database()').scalar_one() != 'volt_qualys_shared_test'):
                raise RuntimeError('wrong development database')

    @classmethod
    def tearDownClass(cls):
        if hasattr(cls, 'engine'):
            cls.engine.dispose()

    def setUp(self):
        # This named database is an explicit throwaway in our owned container;
        # never reset backend/delivery databases or an arbitrary caller DSN.
        with self.engine.begin() as connection:
            connection.exec_driver_sql('DROP SCHEMA public CASCADE')
            connection.exec_driver_sql('CREATE SCHEMA public')
        subprocess.run([sys.executable, '-m', 'alembic', 'upgrade', 'head'],
            cwd=Path(__file__).resolve().parents[2], env=dict(os.environ, UVM_DB_URL=DSN),
            check=True, timeout=45)
        self.temp = tempfile.TemporaryDirectory(prefix='volt-easy-qualys-shared-')
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.key = root / 'connector.key'
        self.key.write_bytes(secrets.token_bytes(32))
        self.key.chmod(0o600)
        self.config = root / 'local-auth.json'
        self.delivery = root / 'bootstrap.json'
        self.pages = root / 'pages'
        self.pages.mkdir(mode=0o700)
        self.config.write_text(json.dumps({'schema_version': 1,
            'installation_id': str(uuid.uuid4()), 'public_origin': 'http://127.0.0.1',
            'secret_source': {'kind': 'encrypted_local_v1', 'secret_source_id': str(uuid.uuid4()),
                'key_path': str(self.key)},
            'bootstrap_delivery': {'kind': 'private_file', 'path': str(self.delivery)},
            'session_policy': {'ttl_seconds': 3600},
            'trusted_ingress': {'mode': 'loopback', 'allowed_hosts': ['127.0.0.1'],
                'allowed_peer_cidrs': ['127.0.0.0/8']}}))
        self.config.chmod(0o600)
        environment = patch.dict(os.environ, {'UVM_AUTH_MODE': 'local',
            'UVM_LOCAL_AUTH_CONFIG_FILE': str(self.config), 'UVM_DB_URL': DSN,
            'UVM_API_CURSOR_SECRET': secrets.token_urlsafe(32),
            'UVM_INGRESS_ALLOWED_PEER_CIDRS': '127.0.0.0/8',
            'UVM_INGRESS_ALLOWED_HOSTS': '127.0.0.1',
            'UVM_SCANNER_EVIDENCE_DIR': str(self.pages)})
        environment.start()
        self.addCleanup(environment.stop)
        from uvm.auth.maintenance import run as maintain
        maintain('prepare-setup', config_path=str(self.config))
        from uvm.api.app import create_app
        self.app = create_app(self.engine, principals={}, cursor_secret=secrets.token_bytes(32))
        self.assertIsInstance(self.app.state.scanner_runtime, self.runtime_type)
        self.calls = []
        self.rejected = False
        case = self
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                case.calls.append(self.path)
                body = LAST_PAGE if 'id_min=' in self.path else PAGE
                body = body.replace(b'https://qualysapi.qualys.com', case.https_origin.encode())
                expected_auth = 'Basic ' + base64.b64encode(
                    b'synthetic-reader:Synthetic local fixture only 7!').decode('ascii')
                rejected = case.rejected or self.headers.get('Authorization') != expected_auth
                self.send_response(401 if rejected else 200)
                if rejected:
                    body = b'private synthetic vendor authentication response'
                self.send_header('Content-Length', str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            def log_message(self, *_): pass
        server, context = self.enterContext(local_https_server(Handler))
        self.https_origin = f'https://127.0.0.1:{server.server_port}'
        def factory(platform):
            def transport(request, timeout, deadline):
                return _production_transport(request, timeout, deadline, _ssl_context=context)
            client = QualysVMClient(platform, _transport=transport)
            client.origin = self.https_origin  # test composition only, no production selector
            return client
        # Exercise the backend's real route/lifespan composition. Only replace
        # the explicit client-factory test dependency BEFORE startup/HTTP, never
        # shared authority, credential crypto, or the production transport code.
        self.service = self.app.state.scanner_service
        self.assertIs(self.service.adapters, self.app.state.scanner_runtime)
        self.assertEqual(self.service.evidence.directory, self.pages)
        self.service._client_factory = factory
        self.client = self.enterContext(TestClient(self.app, base_url='http://127.0.0.1',
            client=('127.0.0.1', 52123)))
        capability = json.loads(self.delivery.read_text())['capability']
        claim = self.client.post('/api/v1/auth/setup/claim', json={'capability': capability,
            'username': 'qualys-local-admin', 'display_name': 'Synthetic Qualys Administrator',
            'password': secrets.token_urlsafe(20) + 'A7!'}, headers={'Origin': 'http://127.0.0.1'})
        self.assertEqual(claim.status_code, 201, claim.text)
        self.headers = {'Origin': 'http://127.0.0.1', 'X-CSRF-Token': claim.json()['csrf_token']}

    def register(self, *, initial_read=True):
        calls_before = list(self.calls)
        deployment = self.client.get('/api/v1/deployment').json()
        command = {'schema_version': 1, 'command_id': str(uuid.uuid4()),
            'action': 'connector.binding.register', 'target_id': '00000000-0000-0000-0000-000000000000',
            'membership_ids': [], 'expected_policy_revision': deployment['policy_revision'],
            'expected_authority_revision': deployment['authority_revision'],
            'expected_connector_registry_revision': deployment['connector_registry_revision'],
            'payload': {'display_name': 'Synthetic Qualys', 'source_family': 'qualys',
                'account_label': 'Synthetic subscription', 'environment_label': 'Local development',
                'product': 'qualys_vm', 'platform_id': 'us1', 'scope': {'kind': 'account_visible'},
                'rationale': 'Local shared-source proof', 'evidence_ref': 'fixture:qualys',
                'grant_initial_read': initial_read}}
        response = self.client.post('/api/v1/assessment/commands', json=command, headers=self.headers)
        self.assertEqual(response.status_code, 200, response.text)
        self.registration_command = command
        self.registration = response.json()['result']
        self.connector = self.registration['allocated_ids']['connector_id']
        self.source = self.registration['allocated_ids']['source_id']
        self.assertEqual(self.calls, calls_before)

    def view(self):
        response = self.client.get(f'/api/v1/scanners/{self.connector}', params={'source_id': self.source})
        self.assertEqual(response.status_code, 200, response.text)
        assert_response(self, self.app, '/api/v1/scanners/{connector_id}', response, 'get')
        return response.json()

    def command(self, action, **extra):
        return {'schema_version': 1, 'command_id': str(uuid.uuid4()), 'action': action,
            'target_id': self.connector, 'membership_ids': [],
            'expected_revisions': self.view()['expected_revisions'],
            'payload': {'source_id': self.source, 'rationale': 'Actual shared bridge proof',
                'evidence_ref': 'fixture:actual-shared', **extra}}

    def post(self, command, **kwargs):
        response = self.client.post(f'/api/v1/scanners/{self.connector}/commands',
            json=command, headers=kwargs.get('headers', self.headers))
        if response.status_code in (200, 202):
            assert_response(self, self.app, '/api/v1/scanners/{connector_id}/commands', response)
        return response

    def prepare(self):
        self.register()
        save = self.post(self.command('scanner.configuration.save', settings={
            'product': 'qualys_vm', 'api_version': '2.0', 'platform_id': 'us1',
            'scope': {'kind': 'account_visible'}, 'collection_mode': 'manual'}))
        self.assertEqual(save.status_code, 200, save.text)
        slot = self.registration['credential_slots']['qualys_vm_basic']['secret_id']
        metadata = self.client.get(f'/api/v1/connectors/{self.connector}/secrets/{slot}',
            params={'source_id': self.source})
        self.assertEqual(metadata.status_code, 200, metadata.text)
        scanner = self.view()
        self.assertIsNone(scanner['expected_revisions']['secret'])
        expected = dict(scanner['expected_revisions'], secret=scanner['credential']['revision'])
        self.assertEqual(expected, metadata.json()['revisions'])
        body = {'schema_version': 1, 'submission_id': str(uuid.uuid4()), 'version_id': str(uuid.uuid4()),
            'source_id': self.source, 'purpose': 'qualys_vm_basic',
            'expected_revisions': expected,
            'rationale': 'Synthetic credential only', 'evidence_ref': 'fixture:local-credential',
            'input': {'kind': 'value', 'value': json.dumps({'username': 'synthetic-reader',
                'password': 'Synthetic local fixture only 7!'})}}
        submitted = self.client.post(f'/api/v1/connectors/{self.connector}/secrets/{slot}/versions',
            json=body, headers=self.headers)
        self.assertEqual(submitted.status_code, 201, submitted.text)
        self.secret_submission = body
        self.assertEqual(self.calls, [])
        return body['version_id']

    def version(self):
        view = self.view()
        return {'configuration_revision': view['configuration_revision'],
            'credential_version_id': view['credential']['version_id']}

    def activate(self):
        self.prepare()
        probe = self.post(self.command('scanner.connection.test', **self.version()))
        self.assertEqual(probe.status_code, 200, probe.text)
        self.assertEqual(probe.json()['result']['status'], 'succeeded')
        self.assertEqual(len(self.calls), 1)
        activate = self.post(self.command('scanner.configuration.activate', **self.version(),
            validation_operation_id=probe.json()['result']['operation_id']))
        self.assertEqual(activate.status_code, 200, activate.text)
        self.assertEqual(len(self.calls), 1)
        return probe

    def test_real_registration_crypto_probe_activation_receipts_and_replay(self):
        self.activate()
        self.assertEqual(self.view()['lifecycle'], 'active')
        with self.engine.connect() as connection:
            stored = connection.execute(sa.text('select ciphertext,purpose,state from g7_connector_secrets')).first()
            self.assertEqual((stored.purpose, stored.state), ('qualys_vm_basic', 'active'))
            self.assertNotIn(b'Synthetic local fixture only', stored.ciphertext)
            self.assertGreaterEqual(connection.execute(sa.text("select count(*) from assessment_audit_events where origin='scanner_api'")).scalar_one(), 6)

    def test_real_csrf_denial_and_cross_source_metadata_are_local(self):
        self.prepare()
        command = self.command('scanner.connection.test', **self.version())
        rejected = self.post(command, headers={**self.headers, 'X-CSRF-Token': 'wrong'})
        self.assertEqual(rejected.status_code, 403)
        self.assertEqual(self.calls, [])
        other = self.client.get(f'/api/v1/scanners/{self.connector}',
            params={'source_id': str(uuid.uuid4())})
        self.assertEqual(other.status_code, 403)
        self.assertEqual(other.headers['cache-control'], 'no-store')

    def test_real_collection_failed_provider_response_publishes_only_failed_retrieval(self):
        self.activate()
        self.rejected = True
        command = self.command('scanner.collection.start', **self.version())
        response = self.post(command)
        self.assertEqual(response.status_code, 200, response.text)
        result = response.json()['result']
        self.assertEqual(result['status'], 'failed')
        self.assertEqual(result['error_code'], 'authentication_rejected')
        before = len(self.calls)
        replay = self.post(command)
        self.assertEqual(replay.json(), response.json())
        self.assertEqual(len(self.calls), before)
        page = self.client.get(f'/api/v1/scanners/{self.connector}/runs/{result["run_id"]}/detections',
            params={'source_id': self.source})
        self.assertEqual(page.status_code, 200, page.text)
        self.assertEqual(page.json()['retrieval']['status'], 'failed')
        self.assertEqual(page.json()['items'], [])
        self.assertEqual(page.json()['coverage']['status'], 'unknown')
        self.assertNotIn('private synthetic vendor authentication', page.text)


    def test_real_revocation_between_pages_uses_current_shared_authority(self):
        self.activate()
        principal = self.client.get('/api/v1/auth/session').json()['principal_id']
        revoked = []
        def checkpoint(stage, operation):
            if stage != 'page' or operation['action'] != 'collect' or revoked:
                return
            deployment = self.client.get('/api/v1/deployment').json()
            revision = deployment['policy_revision']
            response = self.client.post('/api/v1/assessment/commands', json={
                'command_id': str(uuid.uuid4()), 'action': 'access_group.membership.set',
                'target_id': '00000000-0000-4000-8000-000000000000', 'membership_ids': [],
                'expected_revisions': {'target': revision, 'policy': revision,
                    'identity_membership': 0, 'owners': 0,
                    'authority': deployment['authority_revision'], 'access_group': 1},
                'payload': {'access_group_id': self.registration['allocated_ids']['access_group_id'],
                    'principal_id': principal, 'enabled': False,
                    'effective_from': datetime.now(timezone.utc).isoformat(), 'effective_until': None,
                    'rationale': 'Revoke source grant during actual collection',
                    'evidence_ref': 'fixture:source-revocation'}}, headers=self.headers)
            self.assertEqual(response.status_code, 200, response.text)
            revoked.append(True)
        self.service._checkpoint_hook = checkpoint
        response = self.post(self.command('scanner.collection.start', **self.version()))
        self.assertEqual(response.status_code, 403, response.text)
        self.assertEqual(revoked, [True])
        self.assertEqual(len(self.calls), 2)  # probe plus first collection page only
        self.assertEqual(self.client.get(f'/api/v1/scanners/{self.connector}',
            params={'source_id': self.source}).status_code, 403)
        with self.engine.connect() as connection:
            operation = connection.execute(sa.text("select operation_id,status,run_id from qualys_vm_operations where action='collect'")).one()
            self.assertEqual(operation.status, 'interrupted')
            self.assertEqual(connection.execute(sa.text('select count(*) from qualys_vm_publications where run_id=:id'),
                {'id': operation.run_id}).scalar_one(), 0)


    def initialize_rule(self):
        result = subprocess.run([sys.executable, '-m', 'uvm.auth.maintenance',
            'initialize-scanner-rule', '--config', str(self.config)],
            cwd=Path(__file__).resolve().parents[2], capture_output=True, text=True, timeout=20)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_real_positive_collection_serialized_readback_with_trusted_rule(self):
        self.initialize_rule()  # actual backend host maintenance; no fixture authorizer
        self.activate()
        result = self.post(self.command('scanner.collection.start', **self.version()))
        self.assertEqual(result.status_code, 200, result.text)
        self.assertEqual(result.json()['result']['status'], 'succeeded')
        run_id = result.json()['result']['run_id']
        page = self.client.get(f'/api/v1/scanners/{self.connector}/runs/{run_id}/detections',
            params={'source_id': self.source})
        self.assertEqual(page.status_code, 200, page.text)
        assert_response(self, self.app,
            '/api/v1/scanners/{connector_id}/runs/{run_id}/detections', page, 'get')
        rows = page.json()['items']
        self.assertEqual(len(rows), 3)
        self.assertEqual(len({row['group_id'] for row in rows}), 1)
        self.assertIsNotNone(rows[0]['group_id'])
        self.assertEqual(page.json()['coverage']['status'], 'unknown')
        self.assertEqual(page.json()['source_freshness']['status'], 'unknown')
        self.assertEqual(self.view()['credential']['revision'], 1)
        self.assertEqual(self.view()['latest_complete_run_id'], run_id)

    def test_real_final_audit_failure_recovers_typed_receiptless_terminal_200(self):
        self.initialize_rule()
        self.activate()
        with self.engine.begin() as connection:
            connection.exec_driver_sql("""CREATE FUNCTION qualys_test_reject_final_audit() RETURNS trigger
                LANGUAGE plpgsql AS $$ BEGIN
                IF NEW.origin='scanner_api' AND NEW.action='scanner.collection.start'
                    AND NEW.after_value->>'stage'='committed' THEN
                    RAISE EXCEPTION 'synthetic private final audit failure';
                END IF; RETURN NEW; END $$""")
            connection.exec_driver_sql('CREATE TRIGGER qualys_test_reject_final_audit BEFORE INSERT ON assessment_audit_events FOR EACH ROW EXECUTE FUNCTION qualys_test_reject_final_audit()')
        command = self.command('scanner.collection.start', **self.version())
        failed = self.post(command)
        self.assertEqual(failed.status_code, 503, failed.text)
        self.assertNotIn('synthetic private final audit failure', failed.text)
        before = len(self.calls)
        recovered = self.post(command)
        self.assertEqual(recovered.status_code, 200, recovered.text)
        self.assertEqual(recovered.json()['status'], 'interrupted')
        self.assertIsNone(recovered.json()['receipt_id'])
        self.assertEqual(len(self.calls), before)
        run_id = recovered.json()['run_id']
        self.assertEqual(self.client.get(f'/api/v1/scanners/{self.connector}/runs/{run_id}/detections',
            params={'source_id': self.source}).status_code, 404)
        self.assertEqual(self.client.get(f'/api/v1/ingestion/runs/{run_id}').status_code, 404)
        if DISPOSITION_TESTS:
            disposition = self.disposition(command)
            self.assertEqual(disposition.status_code, 200, disposition.text)
            self.assertEqual(disposition.json()['disposition'], 'admitted')
            self.assertEqual(disposition.json()['operation'], recovered.json())
            self.assertEqual(len(self.calls), before)


    def disposition(self, command, *, rationale='Resolve frozen source request', evidence_ref='fixture:disposition'):
        body = {'schema_version': 1, 'command': command,
            'rationale': rationale, 'evidence_ref': evidence_ref}
        response = self.client.post(
            f'/api/v1/scanners/{command["target_id"]}/commands/{command["command_id"]}/abandon',
            json=body, headers=self.headers)
        if response.status_code == 200:
            assert_response(self, self.app,
                '/api/v1/scanners/{connector_id}/commands/{command_id}/abandon', response)
        return response

    @unittest.skipUnless(DISPOSITION_TESTS, 'requires real amended shared occupancy/tombstone bridge')
    def test_disposition_stale_request_terminal_replay_and_first_audit_metadata(self):
        self.activate()
        command = self.command('scanner.collection.start', **self.version())
        command['expected_revisions']['connector'] -= 1
        original = json.loads(json.dumps(command))
        self.assertEqual(self.post(command).status_code, 409)
        before = len(self.calls)
        proof = self.disposition(command)
        self.assertEqual(proof.status_code, 200, proof.text)
        self.assertEqual(proof.json()['disposition'], 'not_committed')
        again = self.disposition(command, rationale='Changed retry metadata', evidence_ref='fixture:changed')
        self.assertEqual(again.json(), proof.json())
        self.assertEqual(command, original)
        delayed = self.post(command)
        self.assertEqual(delayed.status_code, 409)
        self.assertEqual(delayed.json()['error']['code'], 'command_terminal')
        self.assertEqual(len(self.calls), before)
        with self.engine.connect() as connection:
            row = connection.execute(sa.text('select rationale,evidence_ref from assessment_audit_events where event_id=:id'),
                {'id': proof.json()['audit_event_id']}).one()
            self.assertEqual((row.rationale, row.evidence_ref), ('Resolve frozen source request', 'fixture:disposition'))
        changed = json.loads(json.dumps(command))
        changed['payload']['rationale'] = 'Different original command content'
        self.assertEqual(self.disposition(changed).status_code, 409)
        self.rejected = True
        replacement = self.command('scanner.collection.start', **self.version())
        self.assertNotEqual(replacement['command_id'], command['command_id'])
        self.assertEqual(self.post(replacement).status_code, 200)

    @unittest.skipUnless(DISPOSITION_TESTS, 'requires real amended shared occupancy/tombstone bridge')
    def test_disposition_admitted_and_committed_recovery_never_issues_http(self):
        self.initialize_rule()
        self.activate()
        command = self.command('scanner.collection.start', **self.version())
        entered, release = threading.Event(), threading.Event()
        def checkpoint(stage, operation):
            if stage == 'admitted' and operation['action'] == 'collect':
                entered.set()
                if not release.wait(8):
                    raise RuntimeError('fixture admission gate timed out')
        self.service._checkpoint_hook = checkpoint
        responses = []
        worker = threading.Thread(target=lambda: responses.append(self.post(command)))
        worker.start()
        try:
            self.assertTrue(entered.wait(5))
            before = len(self.calls)
            admitted = self.disposition(command)
            self.assertEqual(admitted.status_code, 200, admitted.text)
            self.assertEqual(admitted.json()['disposition'], 'admitted')
            self.assertEqual(admitted.json()['operation']['status'], 'running')
            self.assertEqual(len(self.calls), before)
        finally:
            release.set()
            worker.join(12)
        self.assertFalse(worker.is_alive())
        self.assertEqual(responses[0].status_code, 200, responses[0].text)
        before = len(self.calls)
        committed = self.disposition(command)
        self.assertEqual(committed.status_code, 200, committed.text)
        self.assertEqual(committed.json()['disposition'], 'committed')
        self.assertEqual(committed.json()['receipt'], responses[0].json())
        self.assertEqual(len(self.calls), before)

    @unittest.skipUnless(DISPOSITION_TESTS, 'requires real amended shared occupancy/tombstone bridge')
    def test_disposition_audit_failure_is_not_noncommit_proof_and_rolls_back(self):
        self.activate()
        command = self.command('scanner.collection.start', **self.version())
        with self.engine.begin() as connection:
            before = connection.exec_driver_sql('select count(*) from assessment_audit_events').scalar_one()
            connection.exec_driver_sql('create sequence qualys_disposition_fault_seen')
            connection.exec_driver_sql("""CREATE FUNCTION qualys_disposition_reject_audit() RETURNS trigger
                LANGUAGE plpgsql AS $$ BEGIN PERFORM nextval('qualys_disposition_fault_seen');
                RAISE EXCEPTION 'synthetic private disposition audit fault'; END $$""")
            connection.exec_driver_sql('create trigger qualys_disposition_reject_audit before insert on assessment_audit_events for each row execute function qualys_disposition_reject_audit()')
        failed = self.disposition(command)
        self.assertEqual(failed.status_code, 503, failed.text)
        self.assertNotIn('synthetic private disposition audit fault', failed.text)
        with self.engine.begin() as connection:
            self.assertTrue(connection.exec_driver_sql('select is_called from qualys_disposition_fault_seen').scalar_one())
            self.assertEqual(connection.exec_driver_sql('select count(*) from assessment_audit_events').scalar_one(), before)
            self.assertEqual(connection.execute(sa.text('select count(*) from assessment_command_abandonments where command_id=:id'),
                {'id': command['command_id']}).scalar_one(), 0)
            connection.exec_driver_sql('drop trigger qualys_disposition_reject_audit on assessment_audit_events')
            connection.exec_driver_sql('drop function qualys_disposition_reject_audit()')
        proof = self.disposition(command)
        self.assertEqual(proof.status_code, 200, proof.text)
        self.assertEqual(proof.json()['disposition'], 'not_committed')

    @unittest.skipUnless(DISPOSITION_TESTS, 'requires real amended shared occupancy/tombstone bridge')
    def test_disposition_concurrent_admission_has_one_truthful_winner(self):
        self.initialize_rule()
        self.activate()
        command = self.command('scanner.collection.start', **self.version())
        gate = threading.Barrier(2)
        def admission():
            gate.wait(timeout=5)
            return self.post(command)
        def abandonment():
            gate.wait(timeout=5)
            return self.disposition(command)
        with ThreadPoolExecutor(max_workers=2) as pool:
            a, b = pool.submit(admission), pool.submit(abandonment)
            admitted, disposed = a.result(timeout=15), b.result(timeout=15)
        self.assertEqual(disposed.status_code, 200, disposed.text)
        if disposed.json()['disposition'] == 'not_committed':
            self.assertEqual(admitted.status_code, 409, admitted.text)
            self.assertEqual(len(self.calls), 1)
        else:
            self.assertIn(disposed.json()['disposition'], ('admitted', 'committed'))
            self.assertEqual(admitted.status_code, 200, admitted.text)
            self.assertEqual(len(self.calls), 3)
        with self.engine.connect() as connection:
            tombstones = connection.execute(sa.text('select count(*) from assessment_command_abandonments where command_id=:id'),
                {'id': command['command_id']}).scalar_one()
            intents = connection.execute(sa.text("select count(*) from g7_connector_intents where kind='scanner.command' and payload->>'command_id'=:id"),
                {'id': command['command_id']}).scalar_one()
            self.assertEqual(tombstones + intents, 1)

    @unittest.skipUnless(DISPOSITION_TESTS, 'requires real amended shared occupancy/tombstone bridge')
    def test_disposition_foreign_assessment_and_secret_ids_never_prove_noncommit(self):
        self.activate()
        before = len(self.calls)
        with self.engine.connect() as connection:
            audit_before = connection.exec_driver_sql('select count(*) from assessment_audit_events').scalar_one()
        for occupied in (self.registration_command['command_id'], self.secret_submission['submission_id']):
            with self.subTest(occupied=occupied):
                command = self.command('scanner.collection.start', **self.version())
                command['command_id'] = occupied
                conflict = self.disposition(command)
                self.assertEqual(conflict.status_code, 409, conflict.text)
                self.assertEqual(conflict.json()['error']['code'], 'command_conflict')
                self.assertNotIn('disposition', conflict.json())
                self.assertEqual(self.post(command).status_code, 409)
        with self.engine.connect() as connection:
            self.assertEqual(connection.exec_driver_sql('select count(*) from assessment_audit_events').scalar_one(), audit_before)
        self.assertEqual(len(self.calls), before)

    @unittest.skipUnless(DISPOSITION_TESTS, 'requires real amended shared occupancy/tombstone bridge')
    def test_disposition_tombstone_fences_later_secret_submission(self):
        self.activate()
        command = self.command('scanner.collection.start', **self.version())
        proof = self.disposition(command)
        self.assertEqual(proof.status_code, 200, proof.text)
        self.assertEqual(proof.json()['disposition'], 'not_committed')
        slot = self.registration['credential_slots']['qualys_vm_basic']['secret_id']
        metadata = self.client.get(f'/api/v1/connectors/{self.connector}/secrets/{slot}',
            params={'source_id': self.source})
        self.assertEqual(metadata.status_code, 200, metadata.text)
        submission = dict(self.secret_submission, submission_id=command['command_id'],
            version_id=str(uuid.uuid4()), expected_revisions=metadata.json()['revisions'])
        before = len(self.calls)
        conflict = self.client.post(f'/api/v1/connectors/{self.connector}/secrets/{slot}/versions',
            json=submission, headers=self.headers)
        self.assertEqual(conflict.status_code, 409, conflict.text)
        self.assertEqual(self.disposition(command).json(), proof.json())
        self.assertEqual(len(self.calls), before)

    @unittest.skipUnless(DISPOSITION_TESTS, 'requires real amended shared occupancy/tombstone bridge')
    def test_disposition_ordinary_connector_command_collision_both_orders(self):
        self.activate()
        command = self.command('scanner.collection.start', **self.version())
        slot = self.registration['credential_slots']['qualys_vm_basic']['secret_id']
        def connector_command(action, **extra):
            metadata = self.client.get(f'/api/v1/connectors/{self.connector}/secrets/{slot}',
                params={'source_id': self.source})
            self.assertEqual(metadata.status_code, 200, metadata.text)
            return {'schema_version': 1, 'command_id': str(uuid.uuid4()), 'action': action,
                'target_id': '00000000-0000-4000-8000-000000000000', 'membership_ids': [],
                'expected_revisions': metadata.json()['revisions'], 'payload': {
                    'connector_id': self.connector, 'source_id': self.source, 'secret_id': slot,
                    'rationale': 'Explicit local lifecycle collision', 'evidence_ref': 'fixture:connector-collision', **extra}}
        revoke = connector_command('connector.secret.version.revoke', version_id=self.secret_submission['version_id'])
        revoked = self.client.post('/api/v1/assessment/commands', json=revoke, headers=self.headers)
        self.assertEqual(revoked.status_code, 200, revoked.text)
        command['command_id'] = revoke['command_id']
        before = len(self.calls)
        occupied = self.disposition(command)
        self.assertEqual(occupied.status_code, 409, occupied.text)
        self.assertEqual(occupied.json()['error']['code'], 'command_conflict')
        command['command_id'] = str(uuid.uuid4())
        proof = self.disposition(command)
        self.assertEqual(proof.status_code, 200, proof.text)
        reconcile = connector_command('connector.secret.submission.reconcile',
            submission_id=str(uuid.uuid4()), version_id=str(uuid.uuid4()))
        reconcile['command_id'] = command['command_id']
        fenced = self.client.post('/api/v1/assessment/commands', json=reconcile, headers=self.headers)
        self.assertEqual(fenced.status_code, 409, fenced.text)
        self.assertEqual(self.disposition(command).json(), proof.json())
        self.assertEqual(len(self.calls), before)

    @unittest.skipUnless(DISPOSITION_TESTS, 'requires real amended shared occupancy/tombstone bridge')
    def test_disposition_changed_source_is_conflict_without_replacement_proof(self):
        self.activate()
        command = self.command('scanner.collection.start', **self.version())
        proof = self.disposition(command)
        self.assertEqual(proof.status_code, 200, proof.text)
        self.register()
        changed = json.loads(json.dumps(command))
        changed['target_id'] = self.connector
        changed['payload']['source_id'] = self.source
        before = len(self.calls)
        conflict = self.disposition(changed)
        self.assertEqual(conflict.status_code, 409, conflict.text)
        self.assertEqual(conflict.json()['error']['code'], 'command_conflict')
        self.assertEqual(self.disposition(command).json(), proof.json())
        self.assertEqual(len(self.calls), before)

    @unittest.skipUnless(DISPOSITION_TESTS, 'requires real amended shared occupancy/tombstone bridge')
    def test_disposition_changed_actor_conflicts_and_current_revocation_denies_proof(self):
        self.activate()
        command = self.command('scanner.collection.start', **self.version())
        proof = self.disposition(command)
        self.assertEqual(proof.status_code, 200, proof.text)
        original_principal = self.client.get('/api/v1/auth/session').json()['principal_id']
        from uvm.auth.maintenance import run as maintain
        maintain('create-account', 'disposition-operator', 'Disposition Operator', str(self.config))
        capability = json.loads(self.delivery.read_text())['capability']
        operator = TestClient(self.app, base_url='http://127.0.0.1', client=('127.0.0.1', 52141))
        self.addCleanup(operator.close)
        origin = {'Origin': 'http://127.0.0.1'}
        enrolled = operator.post('/api/v1/auth/local/enrol', json={'capability': capability,
            'new_password': 'Synthetic disposition operator 7!'}, headers=origin)
        self.assertEqual(enrolled.status_code, 204, enrolled.text)
        login = operator.post('/api/v1/auth/local/login', json={'username': 'disposition-operator',
            'password': 'Synthetic disposition operator 7!'}, headers=origin)
        self.assertEqual(login.status_code, 200, login.text)
        def membership(principal, enabled, group_revision):
            deployment = self.client.get('/api/v1/deployment').json()
            revision = deployment['policy_revision']
            response = self.client.post('/api/v1/assessment/commands', json={
                'command_id': str(uuid.uuid4()), 'action': 'access_group.membership.set',
                'target_id': '00000000-0000-4000-8000-000000000000', 'membership_ids': [],
                'expected_revisions': {'target': revision, 'policy': revision,
                    'identity_membership': 0, 'owners': 0,
                    'authority': deployment['authority_revision'], 'access_group': group_revision},
                'payload': {'access_group_id': self.registration['allocated_ids']['access_group_id'],
                    'principal_id': principal, 'enabled': enabled,
                    'effective_from': (datetime.now(timezone.utc) + timedelta(seconds=1 if enabled else 0)).isoformat(), 'effective_until': None,
                    'rationale': 'Disposition current-authority test', 'evidence_ref': 'fixture:disposition-grant'}},
                headers=self.headers)
            self.assertEqual(response.status_code, 200, response.text)
            if enabled:
                time.sleep(1.1)  # Real clock: wait until the newly granted membership is effective.
        membership(login.json()['principal_id'], True, 1)
        before = len(self.calls)
        conflict = operator.post(f'/api/v1/scanners/{self.connector}/commands/{command["command_id"]}/abandon',
            json={'schema_version': 1, 'command': command, 'rationale': 'Recover original request',
                'evidence_ref': 'fixture:other-actor'},
            headers={**origin, 'X-CSRF-Token': login.json()['csrf_token']})
        self.assertEqual(conflict.status_code, 409, conflict.text)
        self.assertEqual(conflict.json()['error']['code'], 'command_conflict')
        membership(original_principal, False, 2)
        denied = self.disposition(command)
        self.assertEqual(denied.status_code, 403, denied.text)
        self.assertNotIn('disposition', denied.json())
        self.assertEqual(len(self.calls), before)
