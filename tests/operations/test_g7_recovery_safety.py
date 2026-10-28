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
    g7_backup_host_records, g7_backup_settings_revisions, g7_backup_connector_quarantine, g7_backup_projection_evidence)
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
                g7_backup_connector_quarantine, g7_backup_projection_evidence):
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

    def make_controller(self):
        from tools.g7_backup_controller import Controller
        root = Path(self.root.name)
        private = root/'private.pem'
        private.write_bytes(self.key.private_bytes(serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        c = Controller.__new__(Controller)
        c.config = {'deployment_id': 'local', 'controller_instance_id': self.instance,
            'host_policy': self.policy.copy(), 'signing_key_file': str(private), 'signing_key_id': 'test-key',
            'journal_file': str(root/'controller.json'), 'active_settings_file': str(root/'active.json'),
            'scheduler_readback_file': str(root/'consumer.json'), 'capture_request_file': str(root/'capture.json')}
        c.deployment, c.journal, c.active_file = 'local', root/'controller.json', root/'active.json'
        c.state = {'schema_version': 1, 'deployment_id': 'local', 'controller_instance_id': self.instance,
            'last_sequence': 1, 'recovery_epoch_floor': 0, 'last_intent': None, 'last_ack': None}
        return c

    def publish_backup(self, revision=0, host_policy=1):
        with self.engine.begin() as connection:
            connection.execute(g7_backup_state.update().values(host_policy_observed_at=self.now))
        values = {'interval_seconds': 300, 'timeout_seconds': 7,
            'maximum_backup_age_seconds': 7200, 'restore_verification_timeout_seconds': 83,
            'archive_target_ref': 'archive-a', 'recovery_profile_ref': 'profile-a'}
        body = {'schema_version': 1, 'command_id': str(uuid.uuid4()), 'action': 'backup.settings.publish',
            'expected_revisions': {'configuration': revision, 'policy': 1, 'authority': 0, 'host_policy': host_policy},
            'values': values, 'rationale': 'local regression', 'evidence_ref': None}
        with patch('uvm.operations.api._registry', return_value={'local': {}}), \
                patch('uvm.operations.api.deployment_grants', return_value=True):
            return self.endpoint('/commands')('local', body, SimpleNamespace(state=SimpleNamespace(), headers={}), 'admin')

    def test_capture_nondefault_timeout_bounds_actual_subprocess_and_removes_partial_archive(self):
        import subprocess, sys, time
        from tools.g7_backup_recovery import create_archive, _run
        destination = Path(self.root.name)/'archive'
        def staging(**kwargs):
            kwargs['archive_dir'].mkdir()
            _run([sys.executable, '-c', 'import time; time.sleep(5)'])
        started = time.monotonic()
        with patch('tools.g7_backup_recovery._create_archive_staging', side_effect=staging):
            with self.assertRaises(subprocess.TimeoutExpired):
                create_archive(archive_dir=destination, stop_timeout=1)
        self.assertLess(time.monotonic()-started, 3)
        self.assertFalse(destination.exists())
        self.assertEqual(list(destination.parent.glob('archive.incomplete-*')), [])

    def test_new_policy_rejects_desired_with_signed_failure_and_keeps_last_good_running(self):
        from tools.g7_backup_scheduler import consume
        from tools.g7_backup_controller import atomic_json
        c = self.make_controller()
        values = {'interval_seconds': 300, 'timeout_seconds': 7, 'maximum_backup_age_seconds': 7200,
            'restore_verification_timeout_seconds': 83, 'archive_target_ref': 'archive-a', 'recovery_profile_ref': 'profile-a'}
        prior = {'deployment_id': 'local', 'revision': 1, 'intent_id': str(uuid.uuid4()),
            'digest': 'sha256:'+digest(values), 'values': values}
        atomic_json(c.journal, c.state)
        atomic_json(c.active_file, prior)
        consume(c.config, self.now)
        c.state['last_effective'] = {'revision': 1, 'digest': prior['digest']}
        policy = json.loads(json.dumps(self.policy)); policy['revision'] = 2
        policy['bounds']['timeout_seconds']['min'] = 10
        policy['digest'] = 'sha256:'+digest({k:v for k,v in policy.items() if k!='digest'})
        c.config['host_policy'] = policy
        desired = {**prior, 'revision': 2, 'command_id': str(uuid.uuid4()), 'issued_at': self.now.isoformat()}
        desired.pop('deployment_id')
        sent = []
        def request(path, body=None):
            if path == 'desired': return {'schema_version':1,'deployment_id':'local','revisions':{'host_policy':2},'desired':desired}
            self.assertEqual(json.loads(c.journal.read_text())['pending_ack'], body)
            sent.append(body); return {'accepted':True,'ack_id':body['ack_id']}
        c._request = request
        self.assertEqual(c.reconcile_desired()['state'], 'failed')
        self.assertEqual(sent[0]['failure_code'], 'host_policy_rejected')
        self.assertEqual(sent[0]['active_revision'], 1)
        self.assertEqual(json.loads(c.active_file.read_text()), prior)
        self.assertEqual(consume(c.config, self.now+timedelta(seconds=301))['revision'], 1)
        self.assertEqual(json.loads(Path(c.config['capture_request_file']).read_text())['capture_timeout_seconds'], 7)

    def test_actual_restore_command_renews_expired_policy_and_reconciles_revision_namespace(self):
        from tools.g7_backup_recovery import submit_restore_events
        from tools.g7_backup_controller import atomic_json
        from tools.g7_backup_scheduler import consume
        from uvm.persistence.connector_schema import connectors
        connectors.create(self.engine)
        self.publish_backup()
        with self.engine.begin() as connection:
            connection.execute(g7_backup_state.update().values(host_policy_observed_at=self.now-timedelta(hours=1)))
        c = self.make_controller(); c.state['recovery_epoch_floor'] = 1
        c.state['last_intent'] = {'revision':9,'digest':'sha256:'+'d'*64,'status':'applied'}
        c.state['last_effective'] = {'revision':9,'digest':'sha256:'+'d'*64}
        atomic_json(c.journal,c.state)
        requests=[]
        def request(path, body=None):
            requests.append(path)
            if path == 'desired': return self.endpoint('/desired')('local',None,self.identity)
            if path in ('reports','acks','sequence-resync'):
                return self.endpoint('/'+path)('local',body,None,self.identity)
            return self.endpoint('/'+path)('local',body,self.identity)
        c._request=request
        root=Path(self.root.name); config=root/'config.json'; atomic_json(config,c.config)
        manifest={'recovery_epoch':0,'controller_sequence':1,'archive_id':str(uuid.uuid4()),
            'image_digest':'sha256:'+'b'*64,'queue_inventory_digest':'sha256:'+'c'*64}
        atomic_json(root/'manifest.json',manifest)
        volumes={'postgres_cluster':'pg-new','ce_media':'media-new','uvm_state':'state-new'}
        atomic_json(root/'volumes.json',volumes)
        proof=self.signed({'queue_inventory_digest':manifest['queue_inventory_digest'],
            'queue_inventory':{'intent_inventory':{'held_intents':[]}}})
        atomic_json(root/'proof.json',proof)
        with patch('tools.g7_backup_controller.Controller',return_value=c), \
                patch('tools.g7_backup_controller.load_config',return_value=c.config):
            result=submit_restore_events(config_path=config,manifest_path=root/'manifest.json',
                volume_ids_path=root/'volumes.json',recovery_epoch=1,connector_recovery_id=str(uuid.uuid4()),
                drain_proof_path=root/'proof.json',public_key=self.public)
            again=submit_restore_events(config_path=config,manifest_path=root/'manifest.json',
                volume_ids_path=root/'volumes.json',recovery_epoch=1,
                connector_recovery_id=c.state['last_recovery_event']['event']['connector_recovery_id'],
                drain_proof_path=root/'proof.json',public_key=self.public)
        self.assertEqual(result,again)
        self.assertNotEqual(result['events'][0]['event_id'],result['events'][1]['event_id'])
        self.assertEqual(requests[:4],['sequence-resync','reports','recovery-events','recovery-events'])
        self.assertEqual(result['events'][-1]['current_state'],'restored')
        self.assertEqual(c.state['namespace_history'][0]['last_intent']['revision'],9)
        self.assertEqual(c.state['last_effective']['revision'],9)
        original_atomic=atomic_json
        def consumer(path,value):
            original_atomic(path,value)
            if path == c.active_file: consume(c.config)
        with patch('tools.g7_backup_controller.atomic_json',side_effect=consumer):
            self.assertEqual(c.reconcile_desired()['state'],'applied')
        self.assertEqual(c.state['last_intent']['revision'],1)
        self.assertEqual(c.state['last_intent']['recovery_epoch'],1)
        self.publish_backup(revision=1,host_policy=2)
        with patch('tools.g7_backup_controller.atomic_json',side_effect=consumer):
            self.assertEqual(c.reconcile_desired()['revision'],2)

    def test_cached_recovery_ack_requires_full_context_and_stage_identity(self):
        c=self.make_controller()
        event={'deployment_id':'local','recovery_epoch':1,'connector_recovery_id':str(uuid.uuid4()),
            'archive_id':str(uuid.uuid4()),'manifest_digest':'sha256:'+'a'*64,'source_image_digest':'sha256:'+'b'*64,
            'queue_inventory_digest':'sha256:'+'c'*64,'target_image_digest':'sha256:'+'b'*64,
            'new_volume_ids':{'postgres_cluster':'pg','ce_media':'media','uvm_state':'state'},
            'event_type':'volumes_restored','previous_epoch':1,'verification':{},'public_readback_digest':None,'failure_code':None}
        c.state['last_recovery_event']={'event':event,'response':{'accepted':True}}
        self.assertEqual(c.retained_recovery_ack(event),{'accepted':True})
        for key,value in [('archive_id',str(uuid.uuid4())),('connector_recovery_id',str(uuid.uuid4())),
                ('manifest_digest','sha256:'+'d'*64),('new_volume_ids',{'postgres_cluster':'other'}),
                ('verification',{'uvm_public_api':'passed'})]:
            with self.subTest(key=key),self.assertRaises(RecoveryError):
                c.retained_recovery_ack({**event,key:value})

    def test_control_startup_resumes_verified_and_released_exact_context(self):
        from uvm.operations.startup_fence import startup_admitted
        token={'deployment_id':'local','recovery_epoch':1,'issued_at':self.now.isoformat(),
            'connector_recovery_id':str(uuid.uuid4()),'archive_digest':'sha256:'+'a'*64,
            'target_image_digest':'sha256:'+'b'*64,'volume_ids':{'postgres_cluster':'pg','ce_media':'media','uvm_state':'state'}}
        with self.engine.begin() as connection:
            connection.execute(g7_backup_state.update().values(recovery_epoch=1,restore_state='verified'))
            for kind,doc in [('resync',{'checkpoint_epoch_floor':1,'issued_at':self.now.isoformat()}),
                ('recovery',{'event_type':'volumes_restored','connector_recovery_id':token['connector_recovery_id'],
                    'manifest_digest':token['archive_digest'],'target_image_digest':token['target_image_digest'],'new_volume_ids':token['volume_ids']})]:
                connection.execute(g7_backup_host_records.insert().values(record_id=str(uuid.uuid4()),deployment_id='local',
                    record_kind=kind,recovery_epoch=1,record_digest='a'*64,document=doc,received_at=self.now))
        self.assertTrue(startup_admitted(self.engine,token))
        self.assertFalse(startup_admitted(self.engine,token,released=True))
        with self.engine.begin() as connection: connection.execute(g7_backup_state.update().values(restore_state='released'))
        self.assertTrue(startup_admitted(self.engine,token))
        self.assertTrue(startup_admitted(self.engine,token,released=True))
        self.assertFalse(startup_admitted(self.engine,{**token,'connector_recovery_id':str(uuid.uuid4())}))

    def test_stale_first_delivery_ack_rejected_and_public_application_time_does_not_move(self):
        self.publish_backup()
        with self.engine.connect() as connection: state=connection.execute(sa.select(g7_backup_state)).mappings().one()
        body={'schema_version':1,'deployment_id':'local','ack_id':str(uuid.uuid4()),'sequence':2,
            'controller_instance_id':self.instance,'intent_id':state['application_intent_id'],
            'requested_revision':1,'requested_digest':'sha256:'+state['requested_digest'],
            'active_revision':1,'active_digest':'sha256:'+state['requested_digest'],'host_policy_revision':1,
            'outcome':'applied','failure_code':None,'observed_at':(self.now-timedelta(hours=1)).isoformat()}
        with self.assertRaises(HTTPException): self.endpoint('/acks')('local',self.signed(body),None,self.identity)
        body['observed_at']=self.now.isoformat()
        self.endpoint('/acks')('local',self.signed(body),None,self.identity)
        self.app.state.utc_now=lambda:self.now+timedelta(seconds=100)
        with self.engine.begin() as connection:
            connection.execute(g7_backup_state.update().values(latest_report_at=self.now+timedelta(seconds=80),
                archive_id=str(uuid.uuid4()),archive_completed_at=self.now-timedelta(seconds=10),archive_outcome='complete'))
        request=SimpleNamespace(state=SimpleNamespace())
        with patch('uvm.operations.api._registry',return_value={'local':{}}),patch('uvm.operations.api.deployment_grants',return_value=True):
            dto=self.endpoint('/backup-settings/{deployment_id}')('local',request,'admin')
        self.assertEqual(dto['effective']['verified_at'],self.now.isoformat().replace('+00:00','Z'))
        self.assertEqual(dto['status']['settings_application']['reported_at'],dto['effective']['verified_at'])
        self.assertEqual(dto['status']['freshness']['age_seconds'],110)
        self.assertEqual(dto['status']['freshness']['evaluated_at'],(self.now+timedelta(seconds=100)).isoformat().replace('+00:00','Z'))

    def test_connector_hold_is_non_disclosing_until_authorized_and_bound_to_connector(self):
        from uvm.connectors.api import install_connector_routes
        from uvm.persistence.connector_schema import connectors, connector_intents
        from uvm.operations.backup_settings import intent_quarantined
        from contextlib import ExitStack
        for table in (connectors, connector_intents): table.create(self.engine)
        connector_id, other_id, intent_id, source_id = [str(uuid.uuid4()) for _ in range(4)]
        with self.engine.begin() as connection:
            connection.execute(connectors.insert().values(connector_id=connector_id,source_id=source_id,
                source_family='local',source_account_id='local',scope_key='all',configuration_revision=1,
                lifecycle='disabled',validation={},recovery={},environment_label='synthetic-local',updated_at=self.now))
            connection.execute(connector_intents.insert().values(connector_id=other_id,intent_id=intent_id,
                kind='connector.validate',status='pending',actor_id='operator',payload={},created_at=self.now,updated_at=self.now))
            connection.execute(g7_backup_connector_quarantine.insert().values(deployment_id='local',intent_id=intent_id,
                connector_id=other_id,recovery_epoch=1,connector_recovery_id=str(uuid.uuid4()),event_id=str(uuid.uuid4()),
                reason_code='restore_uncertain_effect',created_at=self.now))
        app=FastAPI();app.state.engine=self.engine;install_connector_routes(app)
        endpoint=next(r.endpoint for r in app.routes if r.path.endswith('/intents/{intent_id}'))
        binding={'source_id':source_id}
        with ExitStack() as stack:
            stack.enter_context(patch('uvm.connectors.api._authenticate',return_value='reader'))
            stack.enter_context(patch('uvm.connectors.api._ensure',return_value=binding))
            stack.enter_context(patch('uvm.connectors.api._auth_context',return_value=None))
            stack.enter_context(patch('uvm.connectors.api._policy',return_value={'document':{},'revision':1}))
            grants=stack.enter_context(patch('uvm.connectors.api._grants',return_value=False))
            hold=stack.enter_context(patch('uvm.operations.backup_settings.intent_quarantined',wraps=intent_quarantined))
            with self.assertRaises(HTTPException) as caught: endpoint(connector_id,intent_id,None,source_id)
            self.assertEqual(caught.exception.status_code,403);hold.assert_not_called()
            grants.return_value=True
            with self.assertRaises(HTTPException) as caught: endpoint(connector_id,intent_id,None,source_id)
            self.assertEqual(caught.exception.status_code,404);hold.assert_not_called()
        with self.engine.connect() as connection:
            self.assertTrue(intent_quarantined(connection,intent_id,other_id))
            self.assertFalse(intent_quarantined(connection,intent_id,connector_id))
        with self.engine.begin() as connection:
            connection.execute(g7_backup_connector_quarantine.update().values(connector_id='g7_connector_intents'))
        with self.engine.connect() as connection:
            self.assertTrue(intent_quarantined(connection,intent_id,other_id))
            self.assertFalse(intent_quarantined(connection,intent_id,connector_id))

    def test_verification_budget_is_durable_and_expires_before_a_late_probe_can_reset_it(self):
        import subprocess,sys,time
        root=Path(self.root.name);request=root/'request.json';journal=root/'deadline.json'
        request.write_text(json.dumps({'revision':3,'digest':'sha256:'+'a'*64,'verification_timeout_seconds':1}))
        # A disposable sleeping child stands in for the outer operation process.
        child=subprocess.Popen([sys.executable,'-c','import time; time.sleep(10)'])
        self.addCleanup(lambda: child.poll() is None and child.kill())
        result=subprocess.run([sys.executable,'tools/g7_backup_deadline.py','--request',str(request),
            '--kind','verification','--journal',str(journal),'--parent-pid',str(child.pid)],timeout=3)
        self.assertEqual(result.returncode,0);self.assertEqual(child.wait(timeout=2),-15)
        value=json.loads(journal.read_text());self.assertEqual(value['outcome'],'timed_out')
        from tools.g7_backup_deadline import remaining
        self.assertLessEqual(remaining(journal),0)
        complete=subprocess.run([sys.executable,'tools/g7_backup_deadline.py','--journal',str(journal),'--complete'])
        self.assertEqual(complete.returncode,124)

    def test_host_release_requires_explicit_exact_context_marker(self):
        from uvm.operations.startup_fence import host_release_authorized
        marker=Path(self.root.name)/'release.json';token={'deployment_id':'local','recovery_epoch':1,'archive_digest':'a'}
        marker.write_text(json.dumps(token));marker.chmod(0o600)
        with patch.object(Path,'stat',return_value=SimpleNamespace(st_uid=0,st_mode=0o100600)):
            self.assertTrue(host_release_authorized(token,str(marker)))
            self.assertFalse(host_release_authorized({**token,'recovery_epoch':2},str(marker)))
        marker.unlink();self.assertFalse(host_release_authorized(token,str(marker)))

    def test_blocking_operation_command_is_killed_at_remaining_durable_deadline(self):
        import subprocess,sys,time
        root=Path(self.root.name);journal=root/'deadline.json';sentinel=root/'late-effect'
        journal.write_text(json.dumps({'deadline_at':(datetime.now(timezone.utc)+timedelta(seconds=1)).isoformat(),'outcome':'running'}))
        started=time.monotonic()
        result=subprocess.run([sys.executable,'tools/g7_backup_deadline.py','--journal',str(journal),'--run',
            sys.executable,'-c','import time,pathlib,sys; time.sleep(5); pathlib.Path(sys.argv[1]).write_text("late")',str(sentinel)],timeout=4)
        self.assertEqual(result.returncode,124)
        self.assertLess(time.monotonic()-started,3)
        self.assertFalse(sentinel.exists())
        self.assertEqual(json.loads(journal.read_text())['outcome'],'timed_out')

    def test_public_verification_event_cannot_succeed_after_operation_budget(self):
        self.publish_backup()
        with self.engine.begin() as c:
            c.execute(g7_backup_state.update().values(recovery_epoch=1,restore_state='restored',effective_revision=1))
        common={'schema_version':1,'deployment_id':'local','controller_instance_id':self.instance,
            'recovery_epoch':1,'connector_recovery_id':str(uuid.uuid4()),'previous_epoch':1,
            'archive_id':str(uuid.uuid4()),'manifest_digest':'sha256:'+'a'*64,'source_image_digest':'sha256:'+'b'*64,
            'target_image_digest':'sha256:'+'b'*64,'new_volume_ids':{'postgres_cluster':'pg','ce_media':'media','uvm_state':'state'},
            'queue_inventory_digest':'sha256:'+'c'*64,'public_readback_digest':'sha256:'+'d'*64,'failure_code':None,
            'verification':{**{k:'passed' for k in ('uvm_public_api','ce_public_api','media_readback','queue_reconciliation','migration')},
                'details_digest':'sha256:'+'d'*64},'observed_at':self.now.isoformat()}
        with self.engine.begin() as c:
            for stage in ('restore_started','volumes_restored'):
                c.execute(g7_backup_host_records.insert().values(record_id=str(uuid.uuid4()),deployment_id='local',
                    record_kind='recovery',recovery_epoch=1,record_digest='f'*64,
                    document={**common,'event_type':stage,'observed_at':(self.now-timedelta(seconds=100)).isoformat()},received_at=self.now-timedelta(seconds=100)))
        body=self.signed({**common,'event_id':str(uuid.uuid4()),'event_type':'verification_passed','sequence':2})
        with self.assertRaises(HTTPException) as caught:
            self.endpoint('/recovery-events')('local',body,self.identity)
        self.assertEqual(caught.exception.status_code,409)
        self.assertIn('deadline expired',caught.exception.detail['message'])

    def test_restore_namespace_cannot_regress_below_authenticated_restored_configuration(self):
        c=self.make_controller();c.state['desired_namespace']={'epoch':1,'configuration':5}
        c.state['last_intent']={'revision':9,'status':'applied'}
        values={'interval_seconds':300,'timeout_seconds':7,'maximum_backup_age_seconds':7200,
            'restore_verification_timeout_seconds':83,'archive_target_ref':'archive-a','recovery_profile_ref':'profile-a'}
        desired={'revision':3,'digest':'sha256:'+digest(values),'values':values,
            'command_id':str(uuid.uuid4()),'intent_id':str(uuid.uuid4()),'issued_at':self.now.isoformat()}
        def request(path,body=None):
            self.assertEqual(path,'desired','regressed namespace must not send an acknowledgement')
            return {'schema_version':1,'deployment_id':'local','revisions':{'host_policy':1},'desired':desired}
        c._request=request
        with self.assertRaises(RecoveryError): c.reconcile_desired()
        self.assertFalse(c.active_file.exists())
        self.assertEqual(c.state['last_intent']['revision'],9)

    def test_history_only_signed_status_cannot_retime_projection_evidence(self):
        self.publish_backup()
        with self.engine.connect() as c: state=c.execute(sa.select(g7_backup_state)).mappings().one()
        ack={'schema_version':1,'deployment_id':'local','ack_id':str(uuid.uuid4()),'sequence':2,
            'controller_instance_id':self.instance,'intent_id':state['application_intent_id'],
            'requested_revision':1,'requested_digest':'sha256:'+state['requested_digest'],
            'active_revision':1,'active_digest':'sha256:'+state['requested_digest'],'host_policy_revision':1,
            'outcome':'applied','failure_code':None,'observed_at':self.now.isoformat()}
        self.endpoint('/acks')('local',self.signed(ack),None,self.identity)
        def read():
            with patch('uvm.operations.api._registry',return_value={'local':{}}),patch('uvm.operations.api.deployment_grants',return_value=True):
                return self.endpoint('/backup-settings/{deployment_id}')('local',SimpleNamespace(state=SimpleNamespace()),'admin')
        before=read()
        application={**before['status']['settings_application'],
            'reported_at':(self.now+timedelta(days=1)).isoformat(),'host_policy_revision':999}
        old=self.now-timedelta(hours=1)
        body={'schema_version':1,'deployment_id':'local','report_id':str(uuid.uuid4()),'sequence':3,
            'controller_instance_id':self.instance,'report_kind':'status','host_policy':self.policy,
            'desired':{'revision':1,'digest':ack['requested_digest']},'settings_application':application,
            'completed_archive':{'archive_id':None,'completed_at':None,'manifest_digest':None,'outcome':None},
            'freshness':{'state':'unknown','evaluated_at':None,'age_seconds':None,'basis_completed_at':None,'maximum_backup_age_seconds':None},
            'restore_verification':{'state':'unknown','archive_id':None,'recovery_epoch':0,'verified_at':None,'failure_code':None},
            'recovery_epoch':0,'observed_at':old.isoformat(),'fresh_until':(old+timedelta(seconds=300)).isoformat()}
        signed=self.signed(body)
        accepted=self.endpoint('/reports')('local',signed,None,self.identity)
        self.assertTrue(accepted['accepted'])
        self.assertEqual(self.endpoint('/reports')('local',signed,None,self.identity),accepted)
        after=read()
        self.assertEqual(after['effective'],before['effective'])
        self.assertEqual(after['status']['settings_application'],before['status']['settings_application'])
        with self.engine.connect() as c:
            state=c.execute(sa.select(g7_backup_state)).mappings().one()
            self.assertEqual(c.execute(sa.select(g7_backup_projection_evidence.c.application_evidence_record_id)).scalar_one(),ack['ack_id'])
            self.assertEqual(c.execute(sa.select(g7_backup_projection_evidence.c.effective_evidence_record_id)).scalar_one(),ack['ack_id'])
            retained=c.execute(sa.select(g7_backup_host_records.c.document).where(g7_backup_host_records.c.record_id==body['report_id'])).scalar_one()
            self.assertEqual(retained,signed)
        # A valid projection-admitted status advances provenance atomically.
        fresh={**body,'report_id':str(uuid.uuid4()),'sequence':4,'observed_at':self.now.isoformat(),
            'fresh_until':(self.now+timedelta(seconds=300)).isoformat(),
            'settings_application':before['status']['settings_application']}
        self.endpoint('/reports')('local',self.signed(fresh),None,self.identity)
        with self.engine.connect() as c:
            state=c.execute(sa.select(g7_backup_state)).mappings().one()
            self.assertEqual(c.execute(sa.select(g7_backup_projection_evidence.c.application_evidence_record_id)).scalar_one(),fresh['report_id'])
            self.assertEqual(c.execute(sa.select(g7_backup_projection_evidence.c.effective_evidence_record_id)).scalar_one(),fresh['report_id'])
        self.assertEqual(read()['effective'],before['effective'])
        failed={**fresh,'report_id':str(uuid.uuid4()),'sequence':5}
        def fail_projection(_connection,_cursor,statement,_parameters,_context,_many):
            if statement.startswith('UPDATE g7_backup_state'):
                raise sa.exc.OperationalError(statement,{},RuntimeError('projection write failure'))
        sa.event.listen(self.engine,'before_cursor_execute',fail_projection)
        try:
            with self.assertRaises(sa.exc.OperationalError):
                self.endpoint('/reports')('local',self.signed(failed),None,self.identity)
        finally: sa.event.remove(self.engine,'before_cursor_execute',fail_projection)
        with self.engine.connect() as c:
            state=c.execute(sa.select(g7_backup_state)).mappings().one()
            self.assertEqual(c.execute(sa.select(g7_backup_projection_evidence.c.effective_evidence_record_id)).scalar_one(),fresh['report_id'])
            self.assertEqual(c.execute(sa.select(g7_backup_projection_evidence.c.application_evidence_record_id)).scalar_one(),fresh['report_id'])
            self.assertEqual(state['latest_sequence'],4)
            self.assertIsNone(c.execute(sa.select(g7_backup_host_records.c.record_id).where(g7_backup_host_records.c.record_id==failed['report_id'])).scalar_one_or_none())

    def assert_revoked_ref_holds_capture(self, ref_key, registry_key):
        from tools.g7_backup_scheduler import consume
        from tools.g7_backup_controller import atomic_json
        c=self.make_controller();atomic_json(c.journal,c.state)
        values={'interval_seconds':300,'timeout_seconds':7,'maximum_backup_age_seconds':7200,
            'restore_verification_timeout_seconds':83,'archive_target_ref':'archive-a','recovery_profile_ref':'profile-a'}
        candidate={'deployment_id':'local','revision':1,'digest':'sha256:'+digest(values),
            'intent_id':str(uuid.uuid4()),'values':values}
        atomic_json(c.active_file,candidate)
        good=consume(c.config,self.now)
        readback=Path(c.config['scheduler_readback_file']);retained=readback.read_bytes()
        capture=Path(c.config['capture_request_file']);self.assertTrue(capture.exists())
        policy=json.loads(json.dumps(self.policy));policy['revision']=2
        policy[registry_key]=['replacement-only']
        policy['digest']='sha256:'+digest({k:v for k,v in policy.items() if k!='digest'})
        c.config['host_policy']=policy
        self.assertEqual(consume(c.config,self.now+timedelta(seconds=301)),good)
        self.assertEqual(readback.read_bytes(),retained)
        self.assertEqual(json.loads(c.active_file.read_text()),candidate)
        self.assertFalse(capture.exists(),'revoked-ref work must not remain queued')
        failure=json.loads(readback.with_suffix('.failure.json').read_text())
        self.assertEqual(failure['failure_code'],'capture_ref_unavailable')
        self.assertEqual(failure['revision'],1)
        # Further due intervals do not produce more revoked-ref work.
        consume(c.config,self.now+timedelta(seconds=602))
        self.assertFalse(capture.exists())
        self.assertEqual(readback.read_bytes(),retained)
        c.config['host_policy']=self.policy
        consume(c.config,self.now+timedelta(seconds=603))
        resumed=json.loads(capture.read_text())
        self.assertEqual(resumed[ref_key],values[ref_key])
        self.assertFalse(readback.with_suffix('.failure.json').exists())

    def test_revoked_archive_target_holds_last_good_capture(self):
        self.assert_revoked_ref_holds_capture('archive_target_ref','archive_target_refs')

    def test_revoked_recovery_profile_holds_last_good_capture(self):
        self.assert_revoked_ref_holds_capture('recovery_profile_ref','recovery_profile_refs')

    def test_projection_provenance_migration_preserves_legacy_state_without_guessing_from_history(self):
        import importlib.util
        from alembic.migration import MigrationContext
        from alembic.operations import Operations
        legacy=sa.create_engine('sqlite://')
        self.addCleanup(legacy.dispose)
        names={'application_evidence_record_id','effective_evidence_record_id'}
        metadata=sa.MetaData()
        state_table=sa.Table('g7_backup_state',metadata,*[
            column._copy() for column in g7_backup_state.columns if column.name not in names])
        metadata.create_all(legacy)
        with legacy.begin() as c:
            c.execute(state_table.insert().values(deployment_id='local',effective_revision=4,
                effective_digest='a'*64,requested_revision=4,requested_digest='a'*64,
                application_status='applied',latest_sequence=17))
        spec=importlib.util.spec_from_file_location('provenance_migration','migrations/versions/0059_g7_backup_projection_evidence.py')
        migration=importlib.util.module_from_spec(spec);spec.loader.exec_module(migration)
        with legacy.begin() as c,Operations.context(MigrationContext.configure(c)):
            migration.upgrade()
            row=c.execute(sa.text('SELECT * FROM g7_backup_state')).mappings().one()
            self.assertEqual(row['effective_revision'],4)
            self.assertEqual(row['application_status'],'applied')
            self.assertEqual(row['latest_sequence'],17)
            from uvm.operations.backup_settings import projection_evidence
            self.assertEqual(projection_evidence(c,'local'),{})
            migration.downgrade()
        self.assertFalse(sa.inspect(legacy).has_table('g7_backup_projection_evidence'))
        self.assertTrue(names.isdisjoint(column['name'] for column in sa.inspect(legacy).get_columns('g7_backup_state')))

    def test_legacy_archive_control_resync_and_public_read_work_before_evidence_migration(self):
        self.publish_backup()
        with self.engine.begin() as c:
            state=c.execute(sa.select(g7_backup_state)).mappings().one()
            c.execute(g7_backup_state.update().values(effective_revision=1,effective_digest=state['requested_digest'],application_status='applied'))
        g7_backup_projection_evidence.drop(self.engine)
        checkpoint={'schema_version':1,'deployment_id':'local','resync_id':str(uuid.uuid4()),
            'controller_instance_id':self.instance,'database_epoch_seen':0,'database_sequence_seen':1,
            'checkpoint_epoch_floor':1,'checkpoint_last_sequence':9,'issued_at':self.now.isoformat()}
        response=self.endpoint('/sequence-resync')('local',checkpoint,None,self.identity)
        self.assertTrue(response['accepted'])
        with patch('uvm.operations.api._registry',return_value={'local':{}}),patch('uvm.operations.api.deployment_grants',return_value=True):
            dto=self.endpoint('/backup-settings/{deployment_id}')('local',SimpleNamespace(state=SimpleNamespace()),'admin')
        self.assertEqual(dto['effective']['revision'],1)
        self.assertIsNone(dto['effective']['verified_at'])
        self.assertEqual(dto['status']['settings_application']['state'],'applied')
        self.assertIsNone(dto['status']['settings_application']['reported_at'])
        # After the explicit upgrade, a report may carry the unchanged legacy
        # applied state with unknown time; it must not invent historical time.
        g7_backup_projection_evidence.create(self.engine)
        with self.engine.begin() as c:c.execute(g7_backup_state.update().values(recovery_epoch=1))
        status={'schema_version':1,'deployment_id':'local','report_id':str(uuid.uuid4()),'sequence':10,
            'controller_instance_id':self.instance,'report_kind':'status','host_policy':self.policy,
            'desired':{'revision':1,'digest':dto['desired']['digest']},
            'settings_application':dto['status']['settings_application'],
            'completed_archive':dto['status']['completed_archive'],'freshness':dto['status']['freshness'],
            'restore_verification':{**dto['status']['restore_verification'],'recovery_epoch':1},
            'recovery_epoch':1,'observed_at':self.now.isoformat(),
            'fresh_until':(self.now+timedelta(seconds=300)).isoformat()}
        self.assertTrue(self.endpoint('/reports')('local',self.signed(status),None,self.identity)['accepted'])
        from uvm.operations.backup_settings import admitted_application_evidence,projection_evidence
        with self.engine.connect() as c:
            links=projection_evidence(c,'local')
            self.assertEqual(links['effective_evidence_record_id'],status['report_id'])
            self.assertIsNone(admitted_application_evidence(c,'local',links['effective_evidence_record_id'])['reported_at'])
