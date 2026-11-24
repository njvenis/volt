from __future__ import annotations

from contextlib import ExitStack
import fcntl
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import types
import unittest
from unittest.mock import Mock, patch
import uuid

from uvm.installer import offline_lifecycle as lifecycle
from uvm.installer.offline_artifacts import canonical, digest

ROOT = Path(__file__).resolve().parents[2]
STARTED = '2026-11-18T12:00:00.123456789Z'


class PublicationCommitTests(unittest.TestCase):
    def fixture(self, root):
        state, parent = root / 'state', root / 'backups'
        state.mkdir(mode=0o700); parent.mkdir(mode=0o700)
        partial = parent / '.completed.partial.test'; partial.mkdir(mode=0o700)
        info = {'installation_id': str(uuid.uuid4()), 'local_recovery_journal_id': str(uuid.uuid4()),
            'image': 'sha256:' + 'a' * 64, 'platform': 'linux/amd64',
            'image_admission': {'id': 'sha256:' + 'b' * 64, 'id_kind': 'config',
                'source_revision': 'c' * 40, 'source_snapshot': 'sha256:' + 'd' * 64},
            'local_recovery_custody': {'restore_generation': 0, 'recovery_epoch_id': None}}
        metadata = state / 'instance.json'; metadata.write_bytes(canonical(info)); metadata.chmod(0o600)
        # Unit scope is commit-point/readback integrity, after producer archive
        # validation (real numeric tar/profile checks are separate coverage).
        archives = {}
        for store in (*lifecycle.STORES, 'instance'):
            path = partial / (store + '.tar'); path.write_bytes(('validated-fixture-' + store).encode()); path.chmod(0o600)
            archives[path.name] = {'bytes': path.stat().st_size, 'sha256': digest(path.read_bytes())}
        operation_id = str(uuid.uuid4()); identity = lifecycle._identity(info)
        receipt = {'schema_version': 1, 'profile': lifecycle.PROFILE, 'operation': 'backup-record',
            'operation_id': operation_id, 'identity': identity, 'phase': 'complete',
            'predecessor_sha256': 'sha256:' + 'e' * 64,
            'data': {'backup_name': 'completed', 'archives': archives}}
        return state, parent, partial, operation_id, digest(canonical(identity)), receipt

    def exchange(self, fd, receipt):
        return types.SimpleNamespace(fd=fd, operation_id=receipt['operation_id'],
            unchanged=lambda: lifecycle.owned_fd(fd), record=lambda phase, data: receipt, emit=Mock())

    def test_owner_loss_before_publication_leaves_only_private_partial(self):
        with tempfile.TemporaryDirectory() as tmp:
            state, parent, partial, operation_id, identity, receipt = self.fixture(Path(tmp))
            fd = os.open(state / '.install.lock', os.O_CREAT | os.O_RDWR, 0o600)
            fcntl.flock(fd, fcntl.LOCK_EX); os.close(fd)  # owner lost before rename
            exchange = self.exchange(fd, receipt)
            with patch.object(lifecycle, 'ROOT', state), patch.object(lifecycle, 'BACKUP_PARENT', parent), \
                    patch.object(lifecycle, 'BACKUP_VIEW', parent / 'completed'):
                with self.assertRaises(OSError):
                    lifecycle._complete_capture(exchange, partial, 'completed', receipt['data']['archives'])
                with self.assertRaises(FileNotFoundError):
                    lifecycle.backup_status(operation_id, identity, 'completed')
            exchange.emit.assert_not_called()
            self.assertTrue(partial.is_dir()); self.assertFalse((parent / 'completed').exists())

    def test_loss_after_publication_reconciles_without_host_response_or_any_write(self):
        with tempfile.TemporaryDirectory() as tmp:
            state, parent, partial, operation_id, identity, receipt = self.fixture(Path(tmp))
            fd = os.open(state / '.install.lock', os.O_CREAT | os.O_RDWR, 0o600); fcntl.flock(fd, fcntl.LOCK_EX)
            exchange = self.exchange(fd, receipt)
            rename = lifecycle._rename_new
            def owner_lost_after_rename(*args):
                rename(*args); os.close(fd)
            with patch.object(lifecycle, 'ROOT', state), patch.object(lifecycle, 'BACKUP_PARENT', parent), \
                    patch.object(lifecycle, '_rename_new', side_effect=owner_lost_after_rename):
                with self.assertRaises(OSError):
                    lifecycle._complete_capture(exchange, partial, 'completed', receipt['data']['archives'])
            exchange.emit.assert_not_called()  # no host completion response
            published = parent / 'completed'
            before = {path.name: path.read_bytes() for path in published.iterdir()}
            with patch.object(lifecycle, 'ROOT', state), patch.object(lifecycle, 'BACKUP_VIEW', published):
                result = lifecycle.backup_status(operation_id, identity, 'completed')
                self.assertEqual(result['status'], 'completed_capture')
                self.assertEqual(result['host_response_acknowledgement'], 'not_inferred')
                self.assertIs(result['restore_authority'], False)
                with self.assertRaises(ValueError):
                    lifecycle.backup_status(str(uuid.uuid4()), identity, 'completed')
                with self.assertRaises(ValueError):
                    lifecycle.backup_status(operation_id, 'sha256:' + '0' * 64, 'completed')
            self.assertEqual({path.name: path.read_bytes() for path in published.iterdir()}, before)
            self.assertFalse(partial.exists())
