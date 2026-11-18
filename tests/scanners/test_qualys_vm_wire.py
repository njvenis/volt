"""Validate actual serialized route payloads with independent JSON Schema tools."""
from copy import deepcopy
from dataclasses import asdict
from datetime import datetime, timezone
import json
import unittest
import uuid

from fastapi import FastAPI
from fastapi.testclient import TestClient

from uvm.scanners import contracts as dto
from uvm.scanners.api import install_scanner_routes
from uvm.scanners.service import parse_command
from wire_validation import schema_accepts, assert_response

PATH = '/api/v1/scanners/{connector_id}/commands'
NOW = datetime.now(timezone.utc).isoformat()


class WireService:
    def __init__(self):
        self.mode = 'receipt'
        self.terminal = 'interrupted'
        self.connector, self.source, self.operation_id, self.version = [str(uuid.uuid4()) for _ in range(4)]
        self.revisions = dto.ExpectedRevisions(0, 1, 0, 0, 1, 1, 1, 0, None)

    def view(self, *_):
        return asdict(dto.ScannerView(1, self.connector, self.source,
            dto.SourceTupleView('qualys', str(uuid.uuid4()), str(uuid.uuid4())),
            'Synthetic', 'Account label', 'Local', 'qualys_vm', 'us1',
            dto.ScannerScopeView('account_visible'), 'disabled', 0, None,
            dto.CredentialView(str(uuid.uuid4()), None, 'unconfigured', 0),
            self.revisions, None, dto.ScannerLimitsView(), 'manual', False,
            None, None, dto.CollectionRecencyView('never', NOW, None)))

    def command(self, request, connector_id, command):
        parse_command(connector_id, command)
        if self.mode != 'receipt':
            status = 'running' if self.mode == 'running' else 'succeeded' if self.mode == 'inconsistent' else self.terminal
            return asdict(dto.OperationView(1, self.operation_id, command['command_id'],
                'collect', status, 1, self.version, NOW, None if status == 'running' else NOW,
                str(uuid.uuid4()), None, None)), 202 if status == 'running' else 200
        action = command['action']
        receipt, result = {
            'scanner.configuration.save': (dto.SaveConfigurationReceipt, dto.SaveConfigurationResult('staged', 1)),
            'scanner.connection.test': (dto.TestConnectionReceipt, dto.TestConnectionResult(self.operation_id, 'succeeded', None)),
            'scanner.configuration.activate': (dto.ActivateConfigurationReceipt, dto.ActivateConfigurationResult('active', 1, 1)),
            'scanner.collection.start': (dto.CollectReceipt, dto.CollectResult(self.operation_id, str(uuid.uuid4()), 'partial', 'provider_unavailable')),
            'scanner.configuration.disable': (dto.DisableConfigurationReceipt, dto.DisableConfigurationResult('disabled', 1)),
        }[action]
        return asdict(receipt(schema_version=1, command_id=command['command_id'],
            decision_id=str(uuid.uuid4()), audit_event_id=str(uuid.uuid4()),
            intent_id=str(uuid.uuid4()), committed_revision=1, projection={}, action=action,
            target_id=connector_id, policy_revision=1, intents=(), occurred_at=NOW, result=result)), 200


class ScannerWireTests(unittest.TestCase):
    def setUp(self):
        self.service = WireService()
        self.app = FastAPI()
        install_scanner_routes(self.app, self.service, public_origin='http://testserver')
        self.client = self.enterContext(TestClient(self.app))
        self.schema = self.app.openapi()['paths'][PATH]['post']
        self.request_schema = self.schema['requestBody']['content']['application/json']['schema']
        self.headers = {'Origin': 'http://testserver', 'X-CSRF-Token': 'wire-fixture-only'}

    def command(self, action='scanner.configuration.save'):
        payload = {'source_id': self.service.source, 'rationale': 'Local wire proof', 'evidence_ref': 'fixture:wire'}
        if action == 'scanner.configuration.save':
            payload['settings'] = {'product': 'qualys_vm', 'api_version': '2.0', 'platform_id': 'us1',
                'scope': {'kind': 'account_visible'}, 'collection_mode': 'manual'}
        elif action != 'scanner.configuration.disable':
            payload.update(configuration_revision=1, credential_version_id=self.service.version)
            if action == 'scanner.configuration.activate':
                payload['validation_operation_id'] = self.service.operation_id
        return {'schema_version': 1, 'command_id': str(uuid.uuid4()), 'action': action,
            'target_id': self.service.connector, 'membership_ids': [],
            'expected_revisions': asdict(self.service.revisions), 'payload': payload}

    def post(self, command):
        return self.client.post(f'/api/v1/scanners/{self.service.connector}/commands',
            json=command, headers=self.headers)

    def test_serialized_receipts_for_every_action_match_disjoint_200_schema(self):
        for action in ('scanner.configuration.save', 'scanner.connection.test', 'scanner.configuration.activate',
                       'scanner.collection.start', 'scanner.configuration.disable'):
            with self.subTest(action=action):
                command = self.command(action)
                self.assertTrue(schema_accepts(self.request_schema, command))
                response = self.post(command)
                self.assertEqual(response.status_code, 200, response.text)
                assert_response(self, self.app, PATH, response)
                serialized = response.json()
                wrong = deepcopy(serialized)
                wrong['result']['unexpected'] = 'not a declared result'
                self.assertFalse(schema_accepts(self.schema['responses']['200']['content']['application/json']['schema'], wrong))
                self.assertNotIn('operation_id', serialized)

    def test_terminal_receiptless_200_running_202_and_inconsistent_success_fail_closed(self):
        self.service.mode = 'terminal'
        for status in ('failed', 'partial', 'interrupted'):
            self.service.terminal = status
            response = self.post(self.command('scanner.collection.start'))
            self.assertEqual(response.status_code, 200)
            assert_response(self, self.app, PATH, response)
            self.assertIsNone(response.json()['receipt_id'])
            wrong = dict(response.json(), status='succeeded')
            self.assertFalse(schema_accepts(self.schema['responses']['200']['content']['application/json']['schema'], wrong))
        self.service.mode = 'running'
        running = self.post(self.command('scanner.collection.start'))
        self.assertEqual(running.status_code, 202)
        assert_response(self, self.app, PATH, running)
        self.assertFalse(schema_accepts(self.schema['responses']['200']['content']['application/json']['schema'], running.json()))
        self.service.mode = 'inconsistent'
        inconsistent = self.post(self.command('scanner.collection.start'))
        self.assertEqual(inconsistent.status_code, 503)
        self.assertEqual(inconsistent.json()['error']['code'], 'inconsistent_operation')
        self.assertEqual(inconsistent.headers['cache-control'], 'no-store')

    def test_malformed_command_examples_fail_schema_and_redacted_actual_route(self):
        mutations = [
            lambda c: c.update(schema_version=True),
            lambda c: c.update(command_id='not-a-uuid'),
            lambda c: c.update(membership_ids=[str(uuid.uuid4())]),
            lambda c: c.update(extra='REDACT-ME-FIXTURE'),
            lambda c: c['expected_revisions'].update(secret=0),
            lambda c: c['expected_revisions'].update(connector=-1),
            lambda c: c['expected_revisions'].update(connector=True),
            lambda c: c['payload'].update(rationale='   '),
            lambda c: c['payload'].update(password='REDACT-ME-FIXTURE'),
            lambda c: c['payload']['settings'].update(api_version='3.0'),
            lambda c: c['payload']['settings'].update(platform_id='https://evil.invalid'),
            lambda c: c['payload']['settings']['scope'].update(kind='custom'),
        ]
        for mutate in mutations:
            command = self.command()
            mutate(command)
            with self.subTest(command=command['command_id']):
                self.assertFalse(schema_accepts(self.request_schema, command))
                response = self.post(command)
                self.assertEqual(response.status_code, 422, response.text)
                self.assertNotIn('REDACT-ME-FIXTURE', response.text)
                self.assertEqual(response.json()['error']['code'], 'invalid_request')
        duplicate = json.dumps(self.command())[:-1] + ',"schema_version":1}'
        response = self.client.post(f'/api/v1/scanners/{self.service.connector}/commands',
            content=duplicate, headers={**self.headers, 'Content-Type': 'application/json'})
        self.assertEqual(response.status_code, 422)

    def test_serialized_credential_revision_zero_is_required_and_never_guessed(self):
        response = self.client.get(f'/api/v1/scanners/{self.service.connector}', params={'source_id': self.service.source})
        self.assertEqual(response.status_code, 200)
        assert_response(self, self.app, '/api/v1/scanners/{connector_id}', response, 'get')
        view = response.json()
        self.assertEqual(view['credential']['revision'], 0)
        schema = self.app.openapi()['paths']['/api/v1/scanners/{connector_id}']['get']['responses']['200']['content']['application/json']['schema']
        for value in (-1, True, '0'):
            wrong = deepcopy(view)
            wrong['credential']['revision'] = value
            self.assertFalse(schema_accepts(schema, wrong))
        missing = deepcopy(view)
        del missing['credential']['revision']
        self.assertFalse(schema_accepts(schema, missing))
        with self.assertRaises(TypeError):
            dto.CredentialView(str(uuid.uuid4()), None, 'unconfigured')
        with self.assertRaises(ValueError):
            dto.CredentialView(str(uuid.uuid4()), None, 'unconfigured', -1)
