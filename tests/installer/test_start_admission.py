from __future__ import annotations
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
import uuid

from uvm.installer.start_admission import canonical, private_read, read_host_record, validate_record


class StartAdmissionTests(unittest.TestCase):
    def record(self):
        return {'schema_version': 1, 'profile': 'volt_local_recovery_v1',
            'document_type': 'local_start_admission', 'installation_id': str(uuid.uuid4()),
            'journal_id': str(uuid.uuid4()), 'restore_generation': 0, 'recovery_epoch_id': None,
            'image_id': 'sha256:' + 'a' * 64, 'resources_sha256': hashlib.sha256(canonical({'owned': True})).hexdigest(),
            'initial_preparation': True}

    def test_closed_record_rejects_boolean_generation_restore_initial_and_unknown_fields(self):
        value = self.record()
        self.assertEqual(validate_record(value), value)
        for change in ({'restore_generation': False}, {'restore_generation': 1, 'recovery_epoch_id': str(uuid.uuid4())},
                       {'image_id': 'sha256:loose'}, {'resources_sha256': 'bad'}, {'extra': True}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                validate_record({**value, **change})

    def test_host_crash_after_disarm_only_reconciles_forwards(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); root.chmod(0o700)
            directory = root / 'secrets/local-start-admission'; directory.mkdir(parents=True, mode=0o700)
            value = self.record()
            metadata = {'established': False, 'image_admission': {'id': value['image_id']},
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
