"""Focused local regressions for the reviewed G7 recovery false passes."""
import base64
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
import uuid
from unittest.mock import patch

import sqlalchemy as sa
from fastapi import FastAPI, HTTPException
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

from uvm.operations.api import install_observer_settings_routes
from uvm.operations.backup_host import canonical_json, digest
from uvm.persistence.backup_settings_schema import (g7_backup_state,
    g7_backup_host_records, g7_backup_settings_revisions, g7_backup_connector_quarantine)
from uvm.persistence.assessment_schema import (assessment_policy,
    assessment_audit_events, assessment_command_receipts)
from tools.g7_backup_recovery import _container_mounts, RecoveryError, VOLUMES


class RecoverySafetyTests(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.TemporaryDirectory()
        self.addCleanup(self.root.cleanup)
        self.now = datetime.now(timezone.utc).replace(microsecond=0)
        self.key = Ed25519PrivateKey.generate()
        self.public = Path(self.root.name) / 'public.pem'
        self.public.write_bytes(self.key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
        self.instance = str(uuid.uuid4())
        self.env = patch.dict('os.environ', {'UVM_G7_CONTROLLER_INSTANCE_ID': self.instance,
            'UVM_G7_HOST_KEY_ID': 'test-key', 'UVM_G7_INITIAL_MAXIMUM_FUTURE_SKEW_SECONDS': '5'})
        self.env.start(); self.addCleanup(self.env.stop)
        self.engine = sa.create_engine('sqlite://')
        self.addCleanup(self.engine.dispose)
        for table in (assessment_policy, assessment_audit_events, assessment_command_receipts,
                g7_backup_state, g7_backup_host_records, g7_backup_settings_revisions,
                g7_backup_connector_quarantine):
            table.create(self.engine)
        self.app = FastAPI()
        self.app.state.engine = self.engine
        self.app.state.principals = {}
        self.app.state.utc_now = lambda: self.now
        install_observer_settings_routes(self.app)
        self.identity = ('host', {'deployment_id': 'local', 'verification_key_file': str(self.public)})
        self.policy = {'revision': 1, 'bounds': {
            key: {'min': 60 if key in ('interval_seconds', 'maximum_backup_age_seconds') else 1,
                'max': 86400} for key in ('interval_seconds', 'timeout_seconds',
                    'maximum_backup_age_seconds', 'restore_verification_timeout_seconds')},
            'archive_target_refs': ['archive-a'], 'recovery_profile_refs': ['profile-a'],
            'maximum_report_age_seconds': 300, 'maximum_future_skew_seconds': 5}
        self.policy['digest'] = 'sha256:' + digest(self.policy)
        with self.engine.begin() as connection:
            connection.execute(assessment_policy.insert().values(policy_id=1, revision=1,
                document={}, updated_at=self.now, updated_by='fixture'))
            connection.execute(g7_backup_state.insert().values(deployment_id='local',
                host_policy_revision=1, host_policy_document=self.policy,
                host_policy_digest=self.policy['digest'][7:], host_policy_key_id='test-key',
                host_policy_observed_at=self.now - timedelta(hours=1),
                host_policy_future_skew_seconds=5, latest_sequence=1))

    def endpoint(self, suffix):
        return next(route.endpoint for route in self.app.routes if route.path.endswith(suffix))

    def signed(self, body):
        return {**body, 'signature': {'algorithm': 'Ed25519', 'key_id': 'test-key',
            'value': base64.urlsafe_b64encode(self.key.sign(canonical_json(body))).decode().rstrip('=')}}

    def test_expired_policy_allows_fresh_authenticated_renewal(self):
        policy = {**self.policy, 'revision': 5}
        policy['digest'] = 'sha256:' + digest({k: v for k, v in policy.items() if k != 'digest'})
        report = self.signed({'schema_version': 1, 'deployment_id': 'local',
            'report_id': str(uuid.uuid4()), 'sequence': 2, 'controller_instance_id': self.instance,
            'report_kind': 'policy', 'host_policy': policy,
            **{k: None for k in ('desired', 'settings_application', 'completed_archive',
                'freshness', 'restore_verification', 'recovery_epoch')},
            'observed_at': self.now.isoformat(), 'fresh_until': (self.now + timedelta(seconds=300)).isoformat()})
        result = self.endpoint('/reports')('local', report, None, self.identity)
        self.assertTrue(result['accepted'])
        self.assertEqual(self.endpoint('/reports')('local', report, None, self.identity), result)

    def test_resync_retains_full_external_floor_despite_expired_policy(self):
        body = {'schema_version': 1, 'deployment_id': 'local', 'resync_id': str(uuid.uuid4()),
            'controller_instance_id': self.instance, 'database_epoch_seen': 0,
            'database_sequence_seen': 1, 'checkpoint_epoch_floor': 3,
            'checkpoint_last_sequence': 9, 'issued_at': self.now.isoformat()}
        result = self.endpoint('/sequence-resync')('local', body, None, self.identity)
        self.assertEqual(result['recovery_epoch_floor'], 3)
        with self.engine.connect() as connection:
            record = connection.execute(sa.select(g7_backup_host_records)).mappings().one()
            self.assertEqual(record['document'], body)
            self.assertEqual(record['recovery_epoch'], 3)
        # A new authenticated startup checkpoint does not consume a report
        # sequence and must not collide with the same external sequence base.
        renewed = {**body, 'resync_id': str(uuid.uuid4())}
        again = self.endpoint('/sequence-resync')('local', renewed, None, self.identity)
        self.assertEqual(again['next_sequence'], 10)


    def test_lost_commit_ack_returns_unknown_and_keeps_receipt(self):
        with self.engine.begin() as connection:
            connection.execute(g7_backup_state.update().values(host_policy_observed_at=self.now))
        values = {'interval_seconds': 300, 'timeout_seconds': 120,
            'maximum_backup_age_seconds': 7200, 'restore_verification_timeout_seconds': 600,
            'archive_target_ref': 'archive-a', 'recovery_profile_ref': 'profile-a'}
        body = {'schema_version': 1, 'command_id': str(uuid.uuid4()),
            'action': 'backup.settings.publish', 'expected_revisions': {
                'configuration': 0, 'policy': 1, 'authority': 0, 'host_policy': 1},
            'values': values, 'rationale': 'local regression', 'evidence_ref': None}
        original_begin = self.engine.begin
        @contextmanager
        def lost_ack():
            with original_begin() as connection:
                yield connection
            raise sa.exc.OperationalError('COMMIT', {}, OSError('lost acknowledgement'),
                connection_invalidated=True)
        request = SimpleNamespace(state=SimpleNamespace(), headers={})
        with patch('uvm.operations.api._registry', return_value={'local': {}}), \
                patch('uvm.operations.api.deployment_grants', return_value=True), \
                patch.object(self.engine, 'begin', lost_ack):
            response = self.endpoint('/commands')('local', body, request, 'admin')
        result = json.loads(response.body)
        self.assertEqual(result['error']['details']['outcome'], 'unknown')
        self.assertTrue(result['error']['details']['lookup_url'].endswith(body['command_id']))
        with self.engine.connect() as connection:
            receipt = connection.execute(sa.select(assessment_command_receipts.c.result)).scalar_one()
            self.assertEqual(receipt['command_id'], body['command_id'])

    def test_duplicate_bind_and_shadow_mounts_fail_closed(self):
        mounts = [{'Type': 'volume', 'Name': name, 'Destination': target}
            for name, target in VOLUMES.items()]
        for extra in (mounts[0], {'Type': 'bind', 'Destination': '/app/media'},
                {'Type': 'bind', 'Destination': '/app/media/shadow'},
                {'Type': 'bind', 'Destination': '/app'}):
            inspected = {'Image': 'fixture-image', 'Mounts': mounts + [extra],
                'State': {'Running': False, 'ExitCode': 0}}
            image = {'Config': {'Volumes': {target: {} for target in VOLUMES.values()}}}
            with self.subTest(extra=extra), patch('tools.g7_backup_recovery._run',
                    side_effect=[json.dumps([inspected]), json.dumps([image])]):
                with self.assertRaises(RecoveryError):
                    _container_mounts('fixture')

    def test_recovery_event_cannot_change_same_epoch_archive_or_uuid(self):
        with self.engine.begin() as connection:
            connection.execute(g7_backup_state.update().values(host_policy_observed_at=self.now))
        common = {'schema_version': 1, 'deployment_id': 'local',
            'controller_instance_id': self.instance, 'recovery_epoch': 1,
            'connector_recovery_id': str(uuid.uuid4()), 'previous_epoch': 0,
            'event_type': 'restore_started', 'archive_id': str(uuid.uuid4()),
            'manifest_digest': 'sha256:' + 'a' * 64, 'source_image_digest': 'sha256:' + 'b' * 64,
            'target_image_digest': None, 'new_volume_ids': None,
            'verification': {**{k: 'not_run' for k in ('uvm_public_api', 'ce_public_api',
                'media_readback', 'queue_reconciliation', 'migration')}, 'details_digest': None},
            'queue_inventory_digest': 'sha256:' + 'c' * 64, 'public_readback_digest': None,
            'failure_code': None, 'observed_at': self.now.isoformat()}
        started = self.signed({**common, 'event_id': str(uuid.uuid4()), 'sequence': 2})
        self.assertTrue(self.endpoint('/recovery-events')('local', started, self.identity)['accepted'])
        for field, value in (('archive_id', str(uuid.uuid4())),
                ('connector_recovery_id', str(uuid.uuid4())), ('manifest_digest', 'sha256:' + 'd' * 64)):
            changed = self.signed({**common, 'event_id': str(uuid.uuid4()), 'sequence': 3,
                'previous_epoch': 1, 'event_type': 'volumes_restored', field: value,
                'target_image_digest': common['source_image_digest'],
                'new_volume_ids': {'postgres_cluster': 'pg', 'ce_media': 'media', 'uvm_state': 'state'}})
            with self.subTest(field=field), self.assertRaises(HTTPException) as caught:
                self.endpoint('/recovery-events')('local', changed, self.identity)
            self.assertEqual(caught.exception.status_code, 409)
        with self.engine.connect() as connection:
            self.assertEqual(connection.execute(sa.select(g7_backup_state.c.latest_sequence)).scalar_one(), 2)

    def test_signed_status_projects_archive_atomically_and_replays(self):
        with self.engine.begin() as connection:
            connection.execute(g7_backup_state.update().values(host_policy_observed_at=self.now))
        body = {'schema_version': 1, 'deployment_id': 'local', 'report_id': str(uuid.uuid4()),
            'sequence': 2, 'controller_instance_id': self.instance, 'report_kind': 'status',
            'host_policy': self.policy, 'desired': None, 'settings_application': None,
            'completed_archive': {'archive_id': str(uuid.uuid4()), 'completed_at': self.now.isoformat(),
                'manifest_digest': 'sha256:' + 'a' * 64, 'outcome': 'complete'},
            'freshness': {'state': 'unknown', 'evaluated_at': None, 'age_seconds': None,
                'basis_completed_at': None, 'maximum_backup_age_seconds': None},
            'restore_verification': {'state': 'unknown', 'archive_id': None,
                'recovery_epoch': 0, 'verified_at': None, 'failure_code': None},
            'recovery_epoch': 0, 'observed_at': self.now.isoformat(),
            'fresh_until': (self.now + timedelta(seconds=300)).isoformat()}
        signed = self.signed(body)
        result = self.endpoint('/reports')('local', signed, None, self.identity)
        self.assertEqual(self.endpoint('/reports')('local', signed, None, self.identity), result)
        changed = self.signed({**body, 'completed_archive': {**body['completed_archive'],
            'archive_id': str(uuid.uuid4())}})
        with self.assertRaises(HTTPException):
            self.endpoint('/reports')('local', changed, None, self.identity)
        with self.engine.connect() as connection:
            state = connection.execute(sa.select(g7_backup_state)).mappings().one()
            self.assertEqual(state['archive_id'], body['completed_archive']['archive_id'])
            self.assertEqual(connection.execute(sa.select(sa.func.count()).select_from(g7_backup_host_records)).scalar_one(), 1)

    def test_scheduler_consumes_exact_values_and_retains_last_good_on_bad_candidate(self):
        from tools.g7_backup_scheduler import consume
        root = Path(self.root.name)
        config = {'deployment_id': 'local', 'host_policy': self.policy,
            'active_settings_file': str(root/'active.json'), 'scheduler_readback_file': str(root/'consumer.json'),
            'capture_request_file': str(root/'capture.json')}
        values = {'interval_seconds': 300, 'timeout_seconds': 120, 'maximum_backup_age_seconds': 7200,
            'restore_verification_timeout_seconds': 600, 'archive_target_ref': 'archive-a', 'recovery_profile_ref': 'profile-a'}
        candidate = {'deployment_id': 'local', 'revision': 1, 'digest': 'sha256:'+digest(values),
            'intent_id': str(uuid.uuid4()), 'values': values}
        Path(config['active_settings_file']).write_text(json.dumps(candidate))
        consumed = consume(config, self.now)
        request = json.loads(Path(config['capture_request_file']).read_text())
        self.assertEqual(consumed['values'], values)
        self.assertEqual(request['capture_timeout_seconds'], 120)
        self.assertEqual(request['verification_timeout_seconds'], 600)
        self.assertEqual(consumed['next_capture_at'], int(self.now.timestamp())+300)
        Path(config['active_settings_file']).write_text(json.dumps({**candidate, 'revision': 2,
            'values': {**values, 'interval_seconds': False}}))
        last_good = consume(config, self.now+timedelta(seconds=301))
        self.assertEqual(last_good['revision'], 1)
        self.assertEqual(last_good['values'], values)
        self.assertEqual(json.loads(Path(config['capture_request_file']).read_text())['revision'], 1)

    def test_restricted_app_disables_all_normal_startup_hooks(self):
        from uvm.api.app import create_app
        with patch.dict('os.environ', {'UVM_G7_VERIFICATION_ONLY': '1', 'UVM_AUTH_MODE': 'bearer'}):
            app = create_app(self.engine, principals={}, cursor_secret='synthetic-cursor-secret')
        self.assertEqual(app.router.on_startup, [])
        self.assertEqual(app.router.on_shutdown, [])

    def test_rollback_admits_external_epoch_even_when_database_is_several_epochs_behind(self):
        checkpoint = {'schema_version': 1, 'deployment_id': 'local', 'resync_id': str(uuid.uuid4()),
            'controller_instance_id': self.instance, 'database_epoch_seen': 0, 'database_sequence_seen': 1,
            'checkpoint_epoch_floor': 3, 'checkpoint_last_sequence': 9, 'issued_at': self.now.isoformat()}
        self.endpoint('/sequence-resync')('local', checkpoint, None, self.identity)
        with self.engine.begin() as c:
            c.execute(g7_backup_state.update().values(host_policy_observed_at=self.now))
        started = self.signed({'schema_version': 1, 'deployment_id': 'local', 'event_id': str(uuid.uuid4()),
            'controller_instance_id': self.instance, 'sequence': 10, 'recovery_epoch': 3, 'previous_epoch': 2,
            'connector_recovery_id': str(uuid.uuid4()), 'event_type': 'restore_started',
            'archive_id': str(uuid.uuid4()), 'manifest_digest': 'sha256:'+'a'*64,
            'source_image_digest': 'sha256:'+'b'*64, 'target_image_digest': None, 'new_volume_ids': None,
            'verification': {**{k: 'not_run' for k in ('uvm_public_api','ce_public_api','media_readback','queue_reconciliation','migration')}, 'details_digest': None},
            'queue_inventory_digest': 'sha256:'+'c'*64, 'public_readback_digest': None,
            'failure_code': None, 'observed_at': self.now.isoformat()})
        result = self.endpoint('/recovery-events')('local', started, self.identity)
        self.assertEqual(result['recovery_epoch'], 3)
        self.assertEqual(result['current_state'], 'started')

    def test_quarantined_projection_never_opens_a_provider_write(self):
        from unittest.mock import Mock
        from uvm.github.lifecycle import _send_projection_step
        from uvm.github.client import GitHubOutcomeUnknown
        intent_id = str(uuid.uuid4())
        with self.engine.begin() as c:
            c.execute(g7_backup_connector_quarantine.insert().values(deployment_id='local',
                intent_id=intent_id, connector_id='github_projection_intents', recovery_epoch=1,
                connector_recovery_id=str(uuid.uuid4()), event_id=str(uuid.uuid4()),
                reason_code='restore_uncertain_effect', created_at=self.now))
        provider = Mock()
        with self.assertRaises(GitHubOutcomeUnknown):
            _send_projection_step(self.engine, {'projection_id': intent_id}, str(uuid.uuid4()),
                'comment_create', {'method': 'POST', 'path': '/synthetic', 'body': {}}, provider)
        provider.write.assert_not_called()

    def test_missing_consumer_receipt_is_uncertain_and_retains_effective_revision(self):
        from tools.g7_backup_controller import Controller
        root = Path(self.root.name)
        key_file = root/'private.pem'
        key_file.write_bytes(self.key.private_bytes(serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        controller = Controller.__new__(Controller)
        controller.config = {'controller_instance_id': self.instance, 'host_policy': self.policy,
            'signing_key_file': str(key_file), 'signing_key_id': 'test-key',
            'scheduler_readback_file': str(root/'missing-consumer.json')}
        controller.deployment = 'local'
        controller.journal = root/'controller.json'
        controller.active_file = root/'active.json'
        last_good = {'revision': 1, 'digest': 'sha256:'+'b'*64}
        controller.state = {'last_sequence': 2, 'recovery_epoch_floor': 0, 'last_intent': None,
            'last_ack': None, 'last_effective': last_good.copy()}
        values = {'interval_seconds': 300, 'timeout_seconds': 120, 'maximum_backup_age_seconds': 7200,
            'restore_verification_timeout_seconds': 600, 'archive_target_ref': 'archive-a', 'recovery_profile_ref': 'profile-a'}
        desired = {'revision': 2, 'digest': 'sha256:'+digest(values), 'values': values,
            'command_id': str(uuid.uuid4()), 'intent_id': str(uuid.uuid4()), 'issued_at': self.now.isoformat()}
        requests = []
        def request(path, body=None):
            if path == 'desired': return {'schema_version': 1, 'deployment_id': 'local', 'revisions': {'host_policy': 1}, 'desired': desired}
            requests.append(body)
            return {'accepted': True, 'ack_id': body['ack_id']}
        controller._request = request
        with patch('tools.g7_backup_controller.time.monotonic', side_effect=[0, 6]):
            result = controller.reconcile_desired()
        self.assertEqual(result['state'], 'uncertain')
        self.assertEqual(requests[0]['active_revision'], 1)
        self.assertEqual(requests[0]['outcome'], 'uncertain')
        self.assertEqual(controller.state['last_effective'], last_good)

    def test_normal_connector_startup_keeps_validated_host_uuid_over_an_old_file(self):
        from uvm.api.app import create_app
        from uvm.connectors.api import _recovery_epoch
        from uvm.persistence.connector_schema import connectors, connector_secrets, connector_intents
        for table in (connectors, connector_secrets, connector_intents):
            table.create(self.engine)
        connector_id, fresh_uuid = str(uuid.uuid4()), str(uuid.uuid4())
        old_file = Path(self.root.name)/'old-recovery-uuid'
        old_file.write_text(str(uuid.uuid4())); old_file.chmod(0o600)
        with self.engine.begin() as c:
            c.execute(connectors.insert().values(connector_id=connector_id,source_id=str(uuid.uuid4()),
                source_family='local',source_account_id='g7-local',scope_key='all',configuration_revision=1,
                lifecycle='active',active_configuration_revision=1,validation={'status':'passed'},
                recovery={'state':'clear','recovery_epoch_id':None},environment_label='synthetic-local',updated_at=self.now))
        with patch.dict('os.environ', {'UVM_AUTH_MODE':'bearer','UVM_G7_VERIFICATION_ONLY':'0',
                'UVM_G7_CONNECTOR_RECOVERY_ID':fresh_uuid,'UVM_CONNECTOR_RECOVERY_EPOCH_FILE':str(old_file)}):
            app=create_app(self.engine,principals={},cursor_secret='synthetic-local-secret')
            self.assertEqual(app.router.on_startup[0].__name__,'quarantine_restored_instance')
            app.router.on_startup[0]()
            self.assertEqual(_recovery_epoch(),fresh_uuid)
        with self.engine.connect() as c:
            restored=c.execute(sa.select(connectors)).mappings().one()
            self.assertEqual(restored['recovery']['recovery_epoch_id'],fresh_uuid)
            self.assertEqual(restored['recovery']['state'],'quarantined')
            self.assertEqual(restored['lifecycle'],'disabled')

    def test_pending_host_ack_replays_before_a_newer_desired_revision_is_fetched(self):
        from tools.g7_backup_controller import Controller
        controller=Controller.__new__(Controller)
        controller.journal=Path(self.root.name)/'controller.json'
        ack={'ack_id':str(uuid.uuid4()),'sequence':3,'requested_revision':2,
            'outcome':'failed','active_revision':1,'active_digest':'sha256:'+'b'*64}
        controller.state={'last_sequence':2,'last_intent':{'revision':2,'status':'received'},
            'last_effective':{'revision':1,'digest':'sha256:'+'b'*64},'pending_ack':ack}
        requests=[]
        def request(path,body=None):
            requests.append((path,body))
            if path!='acks': self.fail('new desired state was fetched before the retained ack replay')
            return {'ack_id':body['ack_id'],'accepted':True}
        controller._request=request
        result=controller.reconcile_desired()
        self.assertEqual(requests,[('acks',ack)])
        self.assertEqual(result['state'],'failed')
        self.assertEqual(controller.state['last_effective']['revision'],1)
        self.assertNotIn('pending_ack',controller.state)
