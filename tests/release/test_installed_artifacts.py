"""Installed bookkeeping/FD guard fixtures; NOT cryptographic qualification."""
from __future__ import annotations

import copy
from contextlib import ExitStack
import json
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

from tests.release.initial_pin_fixture import prepared_graph
from uvm.installer import offline_artifacts as artifacts, installed_artifacts as installed


class InstalledArtifactTests(unittest.TestCase):
    def fixture(self, parent, stack):
        root = parent / 'state'; root.mkdir(mode=0o700)
        key = root / 'committed.key'; key.write_bytes(b'dummy component key, no authority'); key.chmod(0o600)
        args, cache, receipt = prepared_graph(parent / 'graph')
        anchor = parent / 'state.installer-artifacts'; anchor.mkdir(mode=0o700)
        stage_name = '.originals.partial.A1b2C3d4'; stage = anchor / stage_name; cache.rename(stage)
        runtime = receipt['runtime']
        admitted = {target: runtime[source] for source, target in {'image_id': 'id', 'image_id_kind': 'id_kind',
            'image_config_id': 'image_config_id', 'selected_descriptor': 'selected_descriptor',
            'source_revision': 'source_revision', 'source_snapshot': 'source_snapshot', 'platform': 'platform'}.items()}
        admitted['version'] = args.version
        info = {'installer_contract_version': 2, 'installer_admission': receipt['offline_artifacts'],
            'installer_cache_stage': stage_name, 'installer_initial_request_sha256': 'sha256:' + 'a' * 64,
            'installer_phase': 'prepared', 'installer_initial_files': installed.initial_inventory(root),
            'image_admission': admitted, 'image': args.reference, 'host_instance_directory': str(root),
            'project': 'owned-instance', 'owner_token': 'f' * 64, 'initialized': True, 'established': False}
        current = parent / 'receipt.json'; current.write_text(json.dumps(receipt)); current.chmod(0o600)
        stack.enter_context(patch.object(artifacts, 'ROOT', stage))
        stack.enter_context(patch.object(installed, 'CACHE_PARENT', anchor))
        stack.enter_context(patch.object(installed, 'CURRENT_RECEIPT', current))
        return root, anchor, stage, current, info, receipt

    def test_custody_reader_cannot_select_crypto_material_or_another_crypto_mount(self):
        with tempfile.TemporaryDirectory() as temporary, ExitStack() as stack:
            _root, _anchor, stage, _current, _info, _receipt = self.fixture(Path(temporary), stack)
            closure = artifacts.Closure(fixture=None)
            with self.assertRaisesRegex(ValueError, 'not independently provisioned'):
                closure.verify_blob('launcher.sh', signer=installed.SIGNER, issuer=installed.ISSUER)
            with self.assertRaisesRegex(ValueError, 'fixed original-closure mount'):
                artifacts.Closure(fixture=True, custody_root=stage)

    def test_strict_pin_rejects_boolean_schema_unknown_fields_and_policy_selection(self):
        with tempfile.TemporaryDirectory() as temporary, ExitStack() as stack:
            *_unused, info, _receipt = self.fixture(Path(temporary), stack)
            pin = info['installer_admission']
            for change in ({'schema_version': True}, {'extra': 'field'}, {'signer': 'cache-selected'},
                    {'issuer': 'fixture'}, {'closure_sha256': 'sha256:bad'}, {'verifier_reference': 'another:tag'}):
                with self.subTest(change=change), self.assertRaises(ValueError):
                    installed.validate_pin({**pin, **change})
            with self.assertRaisesRegex(ValueError, 'no cache adoption or backfill'):
                installed.committed_pin({})

    def test_fresh_receipt_compares_both_child_configs_to_actual_original_bytes(self):
        with tempfile.TemporaryDirectory() as temporary, ExitStack() as stack:
            _root, _anchor, _stage, _current, info, receipt = self.fixture(Path(temporary), stack)
            self.assertEqual(installed.current_receipt(info), info['installer_admission'])
            for case in ('other-config', 'other-child', 'selected-descriptor', 'pin', 'source'):
                changed = copy.deepcopy(receipt)
                if case == 'other-config': changed['runtime']['platform_configs']['linux/arm64'] = 'sha256:' + '0' * 64
                elif case == 'other-child': changed['runtime']['platform_children']['linux/arm64'] = 'sha256:' + '0' * 64
                elif case == 'selected-descriptor': changed['runtime']['selected_descriptor']['size'] += 1
                elif case == 'pin': changed['offline_artifacts']['closure_sha256'] = 'sha256:' + '0' * 64
                else: changed['runtime']['source_revision'] = '0' * 40
                with self.subTest(case=case), self.assertRaises(ValueError):
                    installed.validate_receipt(changed, admitted=info['image_admission'], reference=info['image'],
                        journal_pin=info['installer_admission'])

    def test_original_stage_inode_guard_rejects_detached_view_and_foreign_children(self):
        with tempfile.TemporaryDirectory() as temporary, ExitStack() as stack:
            root, anchor, stage, _current, info, _receipt = self.fixture(Path(temporary), stack)
            installed.durable_stage(str(root), info['installer_cache_stage'])
            retained = Path(temporary) / 'retained-view'; stage.rename(retained)
            with patch.object(artifacts, 'ROOT', retained), self.assertRaises(ValueError):
                installed.durable_stage(str(root), info['installer_cache_stage'])
            retained.rename(stage)
            (anchor / 'operator.key').write_bytes(b'forbidden dummy child')
            with self.assertRaisesRegex(ValueError, 'unknown or contradictory'):
                installed.durable_stage(str(root), info['installer_cache_stage'])

    def test_prepared_fingerprints_never_repair_or_regenerate_missing_keys(self):
        with tempfile.TemporaryDirectory() as temporary, ExitStack() as stack:
            root, _anchor, _stage, _current, info, _receipt = self.fixture(Path(temporary), stack)
            installed.verify_initial_inventory(root, info)
            key = root / 'committed.key'; key.write_bytes(b'changed')
            with self.assertRaisesRegex(ValueError, 'no regeneration or repair'):
                installed.verify_initial_inventory(root, info)
            self.assertEqual(key.read_bytes(), b'changed')
            key.unlink()
            with self.assertRaises(FileNotFoundError): installed.verify_initial_inventory(root, info)
            self.assertFalse(key.exists())

    def test_environment_uses_only_the_existing_durable_current_pending_transition(self):
        with tempfile.TemporaryDirectory() as temporary, ExitStack() as stack:
            root, _anchor, _stage, _current, info, _receipt = self.fixture(Path(temporary), stack)
            environment = root / '.env'; environment.write_bytes(b'ORIGINAL=value\n'); environment.chmod(0o600)
            info['installer_initial_files'] = installed.initial_inventory(root)
            original_fingerprints = copy.deepcopy(info['installer_initial_files'])
            info['env_sha256'] = artifacts.digest(environment.read_bytes())[7:]
            expected = b"ORIGINAL=value\nVOLT_LOCAL_START_RESOURCES_SHA256='" + b'a' * 64 + b"'\n"
            info['local_start_environment_pending_sha256'] = artifacts.digest(expected)[7:]
            environment.write_bytes(expected)
            installed.verify_initial_inventory(root, info)
            info['env_sha256'] = info.pop('local_start_environment_pending_sha256')
            installed.verify_initial_inventory(root, info)
            self.assertEqual(info['installer_initial_files'], original_fingerprints)
            environment.write_bytes(expected + b'UNAUTHORISED=value\n')
            with self.assertRaisesRegex(ValueError, 'current/pending start environment changed'):
                installed.verify_initial_inventory(root, info)
            self.assertEqual(info['installer_initial_files'], original_fingerprints)

    def test_durable_rename_retains_originals_without_granting_new_initialization(self):
        with tempfile.TemporaryDirectory() as temporary, ExitStack() as stack:
            root, anchor, stage, _current, info, _receipt = self.fixture(Path(temporary), stack)
            publication = installed.publish_cache(str(root), stage.name, info['installer_admission'],
                {'containers': [], 'volumes': []})
            self.assertEqual(publication['publication'], 'published_new')
            committed = anchor / 'originals'
            with patch.object(artifacts, 'ROOT', committed):
                self.assertEqual(installed.current_receipt(info), info['installer_admission'])
                self.assertEqual(installed.validate_live_cache(info), 'committed_originals')
                with self.assertRaises(ValueError): installed.durable_stage(str(root), stage.name)
                repeated = installed.publish_cache(str(root), stage.name, info['installer_admission'],
                    {'containers': [], 'volumes': []})
                self.assertEqual(repeated['publication'], 'already_committed_exact_originals')

    def test_actual_bind_and_masked_named_volume_ancestor_overlap_deny(self):
        with tempfile.TemporaryDirectory() as temporary:
            cache = Path(temporary) / 'state.installer-artifacts'
            for kind in ('bind', 'volume'):
                source = str(cache.parent)
                mount = {'Type': kind, 'Source': source, 'Name': 'masked'}
                volumes = [] if kind == 'bind' else [{'Name': 'masked', 'Driver': 'local', 'Options': {}, 'Mountpoint': source}]
                with self.subTest(kind=kind), self.assertRaisesRegex(ValueError, 'overlaps'):
                    installed.reject_mount_overlap(str(cache), {'containers': [{'Mounts': [mount]}], 'volumes': volumes})
