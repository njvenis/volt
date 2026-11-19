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


class ShutdownEvidenceTests(unittest.TestCase):
    def test_long_lifetime_single_line_is_streamed_with_bounded_reads(self):
        class Measured(io.BytesIO):
            def read(self, size=-1):
                if not 0 < size <= 65536:
                    raise AssertionError('unbounded lifetime log read')
                return super().read(size)
        history = b'long-lifetime-log-without-newline-' * 600000
        evidence = lifecycle.shutdown_evidence(Measured(history + '\n'.join(lifecycle.SHUTDOWN_MARKERS).encode()), STARTED)
        self.assertGreater(evidence['bytes_seen'], 8 * 1024 * 1024)
        self.assertEqual(evidence['markers'], list(lifecycle.SHUTDOWN_MARKERS))
        self.assertLess(len(canonical(evidence)), 1024)

    def test_missing_failed_or_different_current_run_evidence_is_denied(self):
        for case in ('missing', 'error', 'different-run'):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as tmp:
                markers = lifecycle.SHUTDOWN_MARKERS[:-1] if case == 'missing' else lifecycle.SHUTDOWN_MARKERS
                raw = '\n'.join(markers).encode() + (b'G7_STOP_ERROR' if case == 'error' else b'')
                value = lifecycle.shutdown_evidence(io.BytesIO(raw), STARTED)
                if case == 'different-run':
                    value['queried_started_at'] = '2026-11-17T12:00:00Z'
                path = Path(tmp) / 'evidence.json'; path.write_bytes(canonical(value)); path.chmod(0o600)
                with self.assertRaisesRegex(ValueError, 'current-run shutdown evidence'):
                    lifecycle.read_shutdown_evidence(path, STARTED)

    def test_posix_stream_preserves_failed_docker_producer_even_with_valid_markers(self):
        for producer_exit in (0, 17):
            with self.subTest(exit=producer_exit), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp); observation = root / 'observation'; observation.mkdir(mode=0o700)
                docker = root / 'docker'
                docker.write_text(f'#!{sys.executable}\n' + '''import os,sys,json
from pathlib import Path
args=sys.argv[1:];Path(os.environ['QUERY_ARGV']).write_text(json.dumps(args))
assert args==['logs','--tail','256','--since',os.environ['STARTED'],'owned-volt-1']
for _ in range(300):sys.stdout.buffer.write(b'x'*65536)
sys.stdout.buffer.write(('\\n'.join(json.loads(os.environ['MARKERS']))+'\\n').encode());sys.stdout.flush()
raise SystemExit(int(os.environ['PRODUCER_EXIT']))
'''); docker.chmod(0o700)
                script = '''set -eu
fail() { printf '%s\\n' "$*" >&2; exit 1; }
. "$DRIVER"
offline_data() {
 if [ "$1" = queried-started-at ]; then printf '%s\\n' "$STARTED"; return; fi
 shift
 "$UNIT_PYTHON" -m uvm.installer.offline_lifecycle filter-shutdown "$@"
}
offline_capture_shutdown
'''
                env = {**os.environ, 'PATH': str(root) + os.pathsep + os.environ['PATH'],
                    'WORK': str(root), 'OFFLINE_OBSERVATION': str(observation), 'PROJECT': 'owned',
                    'DRIVER': str(ROOT / 'deploy/compose/offline-host.sh'), 'UNIT_PYTHON': sys.executable,
                    'STARTED': STARTED, 'MARKERS': json.dumps(lifecycle.SHUTDOWN_MARKERS),
                    'PRODUCER_EXIT': str(producer_exit), 'QUERY_ARGV': str(root / 'query.json')}
                result = subprocess.run(['sh', '-c', script], env=env, capture_output=True, text=True, timeout=30)
                self.assertEqual(result.returncode == 0, producer_exit == 0, result.stderr)
                self.assertIn(f'offline_shutdown_producer_exit={producer_exit}', result.stdout)
                self.assertIn('offline_shutdown_filter_exit=0', result.stdout)
                self.assertEqual(json.loads((root / 'query.json').read_text())[4], STARTED)
                self.assertLess((observation / 'shutdown-evidence.json').stat().st_size, 1024)
                self.assertFalse((observation / 'cold.log').exists())


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
