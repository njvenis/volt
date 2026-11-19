from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import select
import subprocess
import shutil
import sys
import tempfile
import time
import unittest

from tests.release.initial_pin_fixture import prepared_graph
from uvm.installer.offline_artifacts import digest

ROOT = Path(__file__).resolve().parents[2]
SETUP = ROOT / 'deploy/compose/setup.py'


class RuntimeInitializationLockTests(unittest.TestCase):
    def fixture(self, root):
        root.chmod(0o700); assets = root / 'compose'; assets.mkdir(mode=0o700)
        for name in ('compose.yaml', 'local.yaml', 'local-restore.yaml'):
            (assets / name).write_text('closed-asset-fixture\n')
        spec = importlib.util.spec_from_file_location('fixed_setup_test', SETUP)
        setup = importlib.util.module_from_spec(spec); spec.loader.exec_module(setup)
        graph_parent = root.parent / (root.name + '.initial-graph')
        graph, cache, receipt = prepared_graph(graph_parent)
        self.addCleanup(shutil.rmtree, graph_parent, True)
        anchor = root.parent / (root.name + '.installer-artifacts'); anchor.mkdir(mode=0o700)
        self.addCleanup(shutil.rmtree, anchor, True)
        stage_name = '.originals.partial.A1b2C3d4'; cache.rename(anchor / stage_name)
        runtime = receipt['runtime']
        argv = ['init', str(root), '--mode', 'local', '--runtime-prepare', '--project', 'volt-init-owner',
            '--image', graph.reference, '--platform', 'linux/amd64',
            '--http-port', '46180', '--recovery-port', '46181', '--oidc-port', '46190',
            '--admitted-image-id', runtime['image_id'], '--admitted-image-id-kind', runtime['image_id_kind'],
            '--admitted-engine-image-id', runtime['image_id'],
            '--admitted-image-config-id', runtime['image_config_id'],
            '--admitted-selected-descriptor', json.dumps(runtime['selected_descriptor']),
            '--admitted-source-revision', graph.source_revision, '--admitted-source-snapshot', graph.source_snapshot,
            '--admitted-installer-json', json.dumps(receipt['offline_artifacts']), '--admitted-cache-stage', stage_name,
            '--admitted-version', '0.1.0-rc.4', '--owner-token', 'f' * 64,
            '--network-subnet', '10.240.250.0/28', '--network-gateway', '10.240.250.1',
            '--runtime-compose-directory', str(assets), '--host-instance-directory', str(root)]
        args = setup.parser().parse_args(argv)
        document = setup.runtime_init_request(args)
        receipt['initial_request_sha256'] = digest(json.dumps(document).encode())
        receipt_file = graph_parent / 'initial-receipt.json'
        receipt_file.write_text(json.dumps(receipt)); receipt_file.chmod(0o600)
        return setup, args, document

    def child(self, root, request, *, initialize, cache_view=None):
        program = ('import sys;from pathlib import Path;import uvm.installer.lock as h;'
            'import uvm.installer.offline_artifacts as a;import uvm.installer.installed_artifacts as i;'
            'h.INSTANCE_ROOT=Path(sys.argv[1]);h.INITIAL_REQUEST=Path(sys.argv[2]);'
            'h.INITIAL_SETUP=Path(sys.argv[3]);'
            'i.CACHE_PARENT=h.INSTANCE_ROOT.parent/(h.INSTANCE_ROOT.name+".installer-artifacts");'
            'a.ROOT=Path(sys.argv[4]);'
            'i.INITIAL_RECEIPT=h.INSTANCE_ROOT.parent/(h.INSTANCE_ROOT.name+".initial-graph")/"initial-receipt.json";'
            'sys.argv=["lock",str(h.INSTANCE_ROOT/".install.lock")]+sys.argv[5:];raise SystemExit(h.main())')
        if cache_view is None:
            cache_view = root.parent / (root.name + '.installer-artifacts') / '.originals.partial.A1b2C3d4'
        return subprocess.Popen([sys.executable, '-c', program, str(root), str(request), str(SETUP),
            str(cache_view),
            *(['--initialize-local'] if initialize else [])], cwd=ROOT,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=0)

    def ready(self, child):
        deadline = time.monotonic() + 20; output = b''
        while time.monotonic() < deadline:
            if select.select([child.stdout], [], [], 0.1)[0]:
                chunk = os.read(child.stdout.fileno(), 4096)
                output += chunk
                if b'locked=1\n' in output:
                    return output
                if not chunk:
                    break
            if child.poll() is not None:
                break
        self.fail('fixed lock owner did not announce readiness: ' + child.stderr.read().decode())

    def stop(self, child):
        if child.poll() is None:
            child.terminate()
        child.communicate(timeout=5)

    def test_request_emission_is_data_only_and_direct_prepare_has_no_ownership(self):
        with tempfile.TemporaryDirectory(prefix='volt init lock ') as temporary:
            root = Path(temporary); setup, args, request = self.fixture(root)
            before = {str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest()
                      for p in root.rglob('*') if p.is_file()}
            self.assertEqual(set(request), {'schema_version', 'profile', 'arguments', 'setup_sha256'})
            with self.assertRaises(SystemExit):
                setup.init(args)
            self.assertEqual(before, {str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest()
                                     for p in root.rglob('*') if p.is_file()})
            self.assertFalse((root / 'instance.json').exists())

    def test_actual_child_owner_initializes_then_keeps_exclusivity_and_inode(self):
        with tempfile.TemporaryDirectory(prefix='volt init lock ') as temporary:
            parent = Path(temporary); root = parent / 'state'; root.mkdir()
            _, _, document = self.fixture(root); request = parent / 'request.json'
            request.write_text(json.dumps(document)); request.chmod(0o600)
            owner = self.child(root, request, initialize=True)
            try:
                output = self.ready(owner)
                self.assertTrue((root / 'instance.json').is_file())
                self.assertIn(b'instance=', output)
                inode = (root / '.install.lock').stat().st_ino
                metadata = (root / 'instance.json').read_bytes()
                concurrent = self.child(root, request, initialize=True)
                stdout, _ = concurrent.communicate(timeout=5)
                self.assertEqual(concurrent.returncode, 75)
                self.assertNotIn(b'locked=1', stdout)
                self.assertEqual((root / '.install.lock').stat().st_ino, inode)
                self.assertEqual((root / 'instance.json').read_bytes(), metadata)
            finally:
                self.stop(owner)

    def test_unrelated_holder_cannot_authorize_initializer_or_direct_prepare(self):
        with tempfile.TemporaryDirectory(prefix='volt init lock ') as temporary:
            parent = Path(temporary); root = parent / 'state'; root.mkdir()
            setup, args, document = self.fixture(root); request = parent / 'request.json'
            request.write_text(json.dumps(document)); request.chmod(0o600)
            (root / '.install.lock').touch(mode=0o600)
            owner = self.child(root, request, initialize=False)
            try:
                self.ready(owner)
                with self.assertRaises(SystemExit):
                    setup.init(args)
                concurrent = self.child(root, request, initialize=True)
                stdout, _ = concurrent.communicate(timeout=5)
                self.assertEqual(concurrent.returncode, 75)
                self.assertNotIn(b'locked=1', stdout)
                self.assertEqual({p.name for p in root.iterdir()}, {'compose', '.install.lock'})
            finally:
                self.stop(owner)

    def test_existing_lifecycle_does_not_create_a_missing_lock_inode(self):
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary); root = parent / 'state'; root.mkdir()
            _, _, document = self.fixture(root); request = parent / 'request.json'
            request.write_text(json.dumps(document)); request.chmod(0o600)
            child = self.child(root, request, initialize=False)
            child.communicate(timeout=5)
            self.assertEqual(child.returncode, 70)
            self.assertFalse((root / '.install.lock').exists())

    def test_malformed_symlink_fifo_requests_fail_before_identity_or_readiness(self):
        for kind in ('unknown-field', 'symlink', 'fifo'):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory(prefix='volt init lock ') as temporary:
                parent = Path(temporary); root = parent / 'state'; root.mkdir()
                _, _, document = self.fixture(root); request = parent / 'request.json'
                if kind == 'unknown-field':
                    request.write_text(json.dumps({**document, 'command': 'arbitrary'})); request.chmod(0o600)
                elif kind == 'symlink':
                    request.symlink_to('/dev/null')
                else:
                    os.mkfifo(request, 0o600)
                child = self.child(root, request, initialize=True)
                stdout, _ = child.communicate(timeout=5)
                self.assertNotEqual(child.returncode, 0)
                self.assertNotIn(b'locked=1', stdout)
                self.assertEqual({p.name for p in root.iterdir()}, {'compose', '.install.lock'})

    def test_lock_custody_and_fixed_source_binding_fail_closed(self):
        for kind in ('lock-symlink', 'lock-fifo', 'lock-mode', 'lock-hardlink', 'lock-content', 'setup-hash'):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory(prefix='volt init lock ') as temporary:
                parent = Path(temporary); root = parent / 'state'; root.mkdir()
                _, _, document = self.fixture(root); request = parent / 'request.json'
                if kind == 'setup-hash':
                    document['setup_sha256'] = 'sha256:' + '0' * 64
                request.write_text(json.dumps(document)); request.chmod(0o600)
                lock = root / '.install.lock'
                if kind == 'lock-symlink':
                    lock.symlink_to('/dev/null')
                elif kind == 'lock-fifo':
                    os.mkfifo(lock, 0o600)
                elif kind.startswith('lock-'):
                    lock.write_bytes(b'not empty' if kind == 'lock-content' else b'')
                    lock.chmod(0o644 if kind == 'lock-mode' else 0o600)
                    if kind == 'lock-hardlink':
                        os.link(lock, parent / 'alias')
                child = self.child(root, request, initialize=True)
                stdout, _ = child.communicate(timeout=5)
                self.assertNotEqual(child.returncode, 0)
                self.assertNotIn(b'locked=1', stdout)
                self.assertFalse((root / 'instance.json').exists())
                self.assertFalse((root / 'secrets').exists())

    def test_original_named_stage_and_receipt_are_required_before_any_keys(self):
        for kind in ('stale-receipt', 'cache-tamper', 'stage-missing', 'stage-replaced',
                'stage-symlink', 'anchor-foreign-child', 'originals-without-pin'):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as temporary:
                parent = Path(temporary); root = parent / 'state'; root.mkdir()
                _, _, document = self.fixture(root); request = parent / 'request.json'
                request.write_text(json.dumps(document)); request.chmod(0o600)
                anchor = parent / 'state.installer-artifacts'; stage = anchor / '.originals.partial.A1b2C3d4'
                view = stage
                if kind == 'stale-receipt':
                    path = parent / 'state.initial-graph/initial-receipt.json'
                    value = json.loads(path.read_text()); value['initial_request_sha256'] = 'sha256:' + '0' * 64
                    path.write_text(json.dumps(value))
                elif kind == 'cache-tamper': (stage / 'package/launcher.sh').write_bytes(b'changed after receipt')
                elif kind in ('stage-missing', 'stage-replaced', 'stage-symlink'):
                    view = parent / 'retained-view'; stage.rename(view)
                    if kind == 'stage-replaced': stage.mkdir(mode=0o700)
                    elif kind == 'stage-symlink': stage.symlink_to(view, target_is_directory=True)
                elif kind == 'anchor-foreign-child': (anchor / 'operator.key').write_bytes(b'forbidden dummy child')
                else: view = anchor / 'originals'; stage.rename(view)
                before = {str(p.relative_to(root)): p.read_bytes() for p in root.rglob('*') if p.is_file()}
                child = self.child(root, request, initialize=True, cache_view=view)
                stdout, _ = child.communicate(timeout=10)
                self.assertEqual(child.returncode, 70)
                self.assertNotIn(b'locked=1', stdout)
                self.assertFalse((root / 'secrets').exists()); self.assertFalse((root / 'instance.json').exists())
                self.assertEqual(before, {str(p.relative_to(root)): p.read_bytes() for p in root.rglob('*')
                    if p.is_file() and p.name != '.install.lock'})


if __name__ == '__main__':
    unittest.main()
