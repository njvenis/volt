from __future__ import annotations
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
import uuid
from unittest.mock import patch
from types import SimpleNamespace

from uvm.installer.start_admission import canonical, private_read, read_host_record, validate_record
from uvm.installer import start_admission


class StartAdmissionTests(unittest.TestCase):
    def record(self):
        return {'schema_version': 1, 'profile': 'volt_local_recovery_v1',
            'document_type': 'local_start_admission_v2', 'installation_id': str(uuid.uuid4()),
            'journal_id': str(uuid.uuid4()), 'restore_generation': 0, 'recovery_epoch_id': None,
            'image_id': 'sha256:' + 'a' * 64, 'resources_sha256': hashlib.sha256(canonical({'owned': True})).hexdigest(),
            'initial_preparation': True, 'local_auth_config_sha256': hashlib.sha256(b'fixed-config').hexdigest()}

    def test_closed_record_rejects_boolean_generation_restore_initial_and_unknown_fields(self):
        value = self.record()
        self.assertEqual(validate_record(value), value)
        for change in ({'restore_generation': False}, {'restore_generation': 1, 'recovery_epoch_id': str(uuid.uuid4())},
                       {'document_type': 'local_start_admission'}, {'local_auth_config_sha256': 'bad'}, {'image_id': 'sha256:loose'}, {'resources_sha256': 'bad'}, {'extra': True}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                validate_record({**value, **change})

    def test_host_crash_after_disarm_only_reconciles_forwards(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); root.chmod(0o700)
            directory = root / 'secrets/local-start-admission'; directory.mkdir(parents=True, mode=0o700)
            value = self.record()
            (root / 'local-auth.json').write_bytes(b'fixed-config'); (root / 'local-auth.json').chmod(0o600)
            metadata = {'local_auth_config_sha256': value['local_auth_config_sha256'], 'established': False, 'image_admission': {'id': value['image_id']},
                'local_recovery_custody': {key: value[key] for key in ('schema_version', 'profile', 'installation_id', 'journal_id', 'restore_generation', 'recovery_epoch_id')},
                'local_start_resources': {'owned': True}, 'local_start_admission': value,
                'local_start_admission_sha256': hashlib.sha256(canonical(value)).hexdigest()}
            target = directory / 'admission.json'
            target.write_bytes(canonical(value)); target.chmod(0o600)
            self.assertTrue(read_host_record(root, metadata)['initial_preparation'])
            disarmed = {**value, 'initial_preparation': False}
            target.write_bytes(canonical(disarmed))
            self.assertFalse(read_host_record(root, metadata)['initial_preparation'])
            metadata['local_start_admission'] = disarmed
            metadata['local_start_admission_sha256'] = hashlib.sha256(canonical(disarmed)).hexdigest()
            target.write_bytes(canonical(value))
            with self.assertRaises(ValueError):
                read_host_record(root, metadata)
            target.write_bytes(canonical(disarmed)); target.unlink()
            metadata['established'] = True
            with self.assertRaises(ValueError):
                read_host_record(root, metadata)

    def test_expected_config_pin_cannot_follow_a_changed_source(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);root.chmod(0o700)
            directory=root/'secrets/local-start-admission';directory.mkdir(parents=True,mode=0o700)
            value=self.record();config=root/'local-auth.json';config.write_bytes(b'fixed-config');config.chmod(0o600)
            target=directory/'admission.json';target.write_bytes(canonical(value));target.chmod(0o600)
            metadata={'established':False,'image_admission':{'id':value['image_id']},
                'local_auth_config_sha256':value['local_auth_config_sha256'],
                'local_recovery_custody':{k:value[k]for k in ('schema_version','profile','installation_id','journal_id','restore_generation','recovery_epoch_id')},
                'local_start_resources':{'owned':True},'local_start_admission':value,
                'local_start_admission_sha256':hashlib.sha256(canonical(value)).hexdigest()}
            before=target.read_bytes();pin=metadata['local_auth_config_sha256']
            self.assertEqual(read_host_record(root,metadata),value)
            config.write_bytes(b'changed-loopback-profile')
            with self.assertRaises(ValueError):read_host_record(root,metadata)
            self.assertEqual(target.read_bytes(),before);self.assertEqual(metadata['local_auth_config_sha256'],pin)
            config.write_bytes(b'fixed-config')
            self.assertEqual(read_host_record(root,metadata),value)
            missing={k:v for k,v in value.items()if k!='local_auth_config_sha256'}
            with self.assertRaises(ValueError):validate_record(missing)

    def test_release_copies_entire_false_record_and_rejects_changed_digest(self):
        # Real private file publication/fsync; runtime admission itself is an
        # explicit fixture, not a ROOT/RO-mount or installed-runtime proof.
        value={**self.record(),'initial_preparation':False}
        with tempfile.TemporaryDirectory() as temporary:
            target=Path(temporary)/'host-start-release.json'
            with patch.object(start_admission,'RELEASE',target),patch.object(start_admission,'load_runtime',return_value=value):
                def invoke(record):
                    read,write=os.pipe()
                    try:os.write(write,canonical(record))
                    finally:os.close(write)
                    with os.fdopen(read,'rb') as stream,patch.object(start_admission.sys,'stdin',SimpleNamespace(buffer=stream)):
                        start_admission.release()
                invoke(value)
                self.assertEqual(target.read_bytes(),canonical(value))
                self.assertEqual(target.stat().st_mode&0o777,0o600)
                self.assertEqual(target.stat().st_nlink,1)
                before=target.read_bytes()
                changed={**value,'local_auth_config_sha256':'f'*64}
                with self.assertRaises(ValueError):invoke(changed)
                self.assertEqual(target.read_bytes(),before)

    def test_root_runtime_delegates_early_reader_with_both_independent_expected_values(self):
        from unittest.mock import Mock
        reader=Mock(return_value=self.record())
        environment={'PATH':'/usr/bin:/bin','LC_ALL':'C','UVM_LOCAL_START_IMAGE_ID':'sha256:'+'a'*64,
            'UVM_LOCAL_START_RESOURCES_SHA256':'b'*64}
        # Protected loader admission is substituted here, never a production
        # source-tree fallback. Actual protected COPY/import needs native proof.
        with patch.object(start_admission,'protected_records',return_value=SimpleNamespace(load_start_admission=reader)),patch.dict(os.environ,environment,clear=True):
            self.assertIs(start_admission.load_runtime(),reader.return_value)
        reader.assert_called_once_with(expected_image_id=environment['UVM_LOCAL_START_IMAGE_ID'],
            expected_resources_sha256=environment['UVM_LOCAL_START_RESOURCES_SHA256'])

    def test_private_projection_fifo_and_symlink_are_nonblocking_denials(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'input'
            os.mkfifo(path, 0o600)
            with self.assertRaises(ValueError):
                private_read(path, os.getuid())
            path.unlink(); path.symlink_to('/dev/null')
            with self.assertRaises(OSError):
                private_read(path, os.getuid())


if __name__ == '__main__':
    unittest.main()
