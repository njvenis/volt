from __future__ import annotations

from contextlib import ExitStack
import fcntl
import copy
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import uuid

from uvm.installer import offline_lifecycle as lifecycle
from uvm.installer.offline_artifacts import canonical, digest


class OfflineLifecycleTests(unittest.TestCase):
    def test_unordered_resource_permutations_preserve_every_identity_value(self):
        before = {'image': {'Id': 'image', 'Labels': {'source': 'bound'}},
            'containers': [{'Id': 'container', 'Mounts': [
                {'Destination': '/state', 'Source': 'owned-state', 'RW': True, 'extra_identity': 'preserved'},
                {'Destination': '/config', 'Source': 'owned-config', 'RW': False}]}],
            'volumes': [{'Name': 'state', 'Mountpoint': '/owned/state'}, {'Name': 'media', 'Mountpoint': '/owned/media'}],
            'networks': [{'Name': 'application', 'Id': 'owned-network', 'Internal': False}]}
        permuted = copy.deepcopy(before)
        permuted['containers'][0]['Mounts'].reverse(); permuted['volumes'].reverse()
        self.assertEqual(lifecycle.canonical_resources(before), lifecycle.canonical_resources(permuted))
        changed = copy.deepcopy(permuted); changed['containers'][0]['Mounts'][1]['Source'] = 'different-private-source'
        self.assertNotEqual(lifecycle.canonical_resources(before), lifecycle.canonical_resources(changed))
        changed = copy.deepcopy(before); changed['containers'][0]['Mounts'][0]['extra_identity'] = 'changed'
        self.assertNotEqual(lifecycle.canonical_resources(before), lifecycle.canonical_resources(changed))
        for category in ('mount', 'volume'):
            duplicated = copy.deepcopy(before)
            if category == 'mount':
                duplicated['containers'][0]['Mounts'].append(copy.deepcopy(duplicated['containers'][0]['Mounts'][0]))
            else:
                duplicated['volumes'].append(copy.deepcopy(duplicated['volumes'][0]))
            with self.assertRaisesRegex(ValueError, 'duplicate identity'):
                lifecycle.canonical_resources(duplicated)

    def fixture(self, root, stack):
        instance, incoming, outgoing, package = (root / name for name in ('state', 'input', 'output', 'package'))
        for path in (instance, incoming, outgoing, package):
            path.mkdir(mode=0o700)
        code = b'''import json\nfrom pathlib import Path\ndef load_instance(path, **kwargs):\n root=Path(path);return root,json.loads((root/'instance.json').read_text())\n'''
        setup = package / 'setup.py'; setup.write_bytes(code)
        info = {'mode': 'local', 'installation_id': str(uuid.uuid4()), 'local_recovery_journal_id': str(uuid.uuid4()),
            'image': '127.0.0.1:46150/volt@sha256:' + 'a' * 64, 'platform': 'linux/amd64',
            'local_recovery_custody': {'restore_generation': 0, 'recovery_epoch_id': None},
            'image_admission': {'id': 'sha256:' + 'b' * 64, 'id_kind': 'config',
                'source_revision': 'c' * 40, 'source_snapshot': 'sha256:' + 'd' * 64}}
        metadata = instance / 'instance.json'; metadata.write_bytes(canonical(info)); metadata.chmod(0o600)
        request = incoming / 'request.json'; request.write_bytes(canonical({'schema_version': 1,
            'profile': 'volt_offline_request_v1', 'setup_sha256': digest(code), 'backup_name': 'new-backup'})); request.chmod(0o600)
        fd = os.open(instance / '.install.lock', os.O_CREAT | os.O_RDWR, 0o600)
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        for name, value in (('ROOT', instance), ('INPUT', incoming), ('OUTPUT', outgoing), ('SETUP', setup)):
            stack.enter_context(patch.object(lifecycle, name, value))
        # These tests exercise the FD/exchange boundary only. Real private
        # custody and Docker resources remain required by component qualification.
        stack.enter_context(patch('uvm.installer.recovery_authority._request_for_instance', return_value={}))
        stack.enter_context(patch('uvm.installer.recovery_authority._resume', return_value={}))
        # This fixture isolates FD/phase-chain behaviour. Actual strict installed
        # pin, stage and initial-key checks execute in their dedicated tests.
        stack.enter_context(patch('uvm.installer.installed_artifacts.committed_pin', return_value={}))
        stack.callback(os.close, fd)
        return fd, instance, incoming, outgoing

    def test_current_owner_accepts_only_exact_fresh_phase_chain(self):
        with tempfile.TemporaryDirectory() as tmp, ExitStack() as stack:
            fd, _instance, incoming, outgoing = self.fixture(Path(tmp), stack)
            exchange = lifecycle.Exchange(fd, 'backup-record'); exchange.emit('plan', {})
            value = exchange.record('observed', {'public': 'data'})
            path = incoming / 'observed.json'; path.write_bytes(canonical(value)); path.chmod(0o600)
            self.assertEqual(exchange.receive('observed'), {'public': 'data'})
            (incoming / 'request.json').write_bytes(b'changed')
            with self.assertRaisesRegex(ValueError, 'changed after consumption'):
                exchange.emit('complete', {})
            self.assertFalse((outgoing / 'complete.json').exists())

    def test_stale_cross_operation_wrong_identity_and_boolean_aliases_fail_before_write(self):
        for case in ('uuid', 'operation', 'predecessor', 'identity', 'schema-bool', 'generation-bool'):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as tmp, ExitStack() as stack:
                fd, instance, incoming, outgoing = self.fixture(Path(tmp), stack)
                before = (instance / 'instance.json').read_bytes()
                exchange = lifecycle.Exchange(fd, 'backup-record'); exchange.emit('plan', {})
                value = exchange.record('observed', {})
                if case == 'uuid': value['operation_id'] = str(uuid.uuid4())
                elif case == 'operation': value['operation'] = 'restore-admit'
                elif case == 'predecessor': value['predecessor_sha256'] = 'sha256:' + '0' * 64
                elif case == 'identity': value['identity']['installation_id'] = str(uuid.uuid4())
                elif case == 'schema-bool': value['schema_version'] = True
                else: value['identity']['restore_generation'] = False
                path = incoming / 'observed.json'; path.write_bytes(canonical(value)); path.chmod(0o600)
                with self.assertRaisesRegex(ValueError, 'UUID/identity/predecessor'):
                    exchange.receive('observed')
                self.assertEqual((instance / 'instance.json').read_bytes(), before)
                self.assertFalse((outgoing / 'complete.json').exists())

    def test_unrelated_held_lock_does_not_authorize_initializer_or_phase_output(self):
        with tempfile.TemporaryDirectory() as tmp, ExitStack() as stack:
            _owner, instance, _incoming, outgoing = self.fixture(Path(tmp), stack)
            before = (instance / 'instance.json').read_bytes()
            contender = os.open(instance / '.install.lock', os.O_RDWR)
            try:
                with self.assertRaises(BlockingIOError):
                    lifecycle.Exchange(contender, 'backup-record')
            finally:
                os.close(contender)
            self.assertEqual((instance / 'instance.json').read_bytes(), before)
            self.assertEqual(list(outgoing.iterdir()), [])

    def test_lost_or_replaced_current_fd_blocks_completion(self):
        with tempfile.TemporaryDirectory() as tmp, ExitStack() as stack:
            fd, instance, _incoming, outgoing = self.fixture(Path(tmp), stack)
            exchange = lifecycle.Exchange(fd, 'backup-record'); exchange.emit('plan', {})
            (instance / '.install.lock').unlink()
            descriptor = os.open(instance / '.install.lock', os.O_CREAT | os.O_RDWR, 0o600); os.close(descriptor)
            with self.assertRaisesRegex(ValueError, 'current private lifecycle inode'):
                exchange.emit('complete', {})
            self.assertFalse((outgoing / 'complete.json').exists())

    def test_atomic_completed_backup_never_replaces_existing_destination(self):
        with tempfile.TemporaryDirectory() as tmp:
            parent = Path(tmp); partial = parent / '.partial'; partial.mkdir(); (partial / 'archive').write_text('new')
            completed = parent / 'completed'; completed.mkdir(); (completed / 'original').write_text('preserved')
            with self.assertRaises(OSError):
                lifecycle._rename_new(parent, partial.name, completed.name)
            self.assertEqual((completed / 'original').read_text(), 'preserved')
            self.assertTrue(partial.exists())
            completed.joinpath('original').unlink(); completed.rmdir()
            lifecycle._rename_new(parent, partial.name, completed.name)
            self.assertEqual((completed / 'archive').read_text(), 'new')
