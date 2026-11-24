"""Real host FD/inode restoration for fixed TEST faults; no product admission."""
from pathlib import Path
import fcntl
import json
import os
import tempfile
import unittest

from tools.compose_release_qualification import initial_resume_private_fault


class InitialPrivateFaultTests(unittest.TestCase):
    def fixture(self,parent):
        state=parent/'state';state.mkdir(mode=0o700);(state/'secrets').mkdir(mode=0o700)
        for name,data in [('.install.lock',b''),('secrets/local-auth-key',b'x'*32),
                ('local-auth.json',b'{"public":"component"}'),
                ('instance.json',json.dumps({'installer_admission':{'pin':'component'},'ack':'unchanged-sentinel'}).encode())]:
            path=state/name;path.write_bytes(data);path.chmod(0o600)
        cache=parent/'state.installer-artifacts/originals';cache.mkdir(mode=0o700,parents=True)
        (cache/'original-public-proof').write_bytes(b'proof')
        retention=parent/'private-originals';retention.mkdir(mode=0o700)
        return state,retention

    def snapshot(self,state):
        parent=state.parent
        return {str(p.relative_to(parent)):(p.stat().st_dev,p.stat().st_ino,p.stat().st_mode,p.stat().st_uid,p.stat().st_gid,p.read_bytes())
            for root in (state,parent/'state.installer-artifacts')for p in root.rglob('*')if p.is_file()}

    def test_each_closed_fault_restores_original_bytes_modes_and_same_inode_even_on_caller_failure(self):
        for case in ('missing-key','changed-key','changed-config','missing-journal','missing-pin','missing-originals','unsafe-key-mode'):
            with self.subTest(case=case),tempfile.TemporaryDirectory()as directory:
                state,retention=self.fixture(Path(directory));before=self.snapshot(state)
                with self.assertRaisesRegex(ValueError,'intentional controller failure'):
                    with initial_resume_private_fault(state=state,retention=retention/case,case=case):
                        self.assertNotEqual(self.snapshot(state),before)
                        if case=='missing-pin':self.assertEqual(json.loads((state/'instance.json').read_text())['ack'],'unchanged-sentinel')
                        raise ValueError('intentional controller failure')
                self.assertEqual(self.snapshot(state),before)
                self.assertFalse((retention/case/'original').exists())

    def test_unrelated_exclusive_holder_prevents_any_fault_mutation(self):
        with tempfile.TemporaryDirectory()as directory:
            state,retention=self.fixture(Path(directory));before=self.snapshot(state)
            with(state/'.install.lock').open('r+')as held:
                fcntl.flock(held,fcntl.LOCK_EX|fcntl.LOCK_NB)
                with self.assertRaises(BlockingIOError):
                    with initial_resume_private_fault(state=state,retention=retention/'missing-key',case='missing-key'):pass
            self.assertEqual(self.snapshot(state),before);self.assertEqual(list(retention.iterdir()),[])

    def test_unexpected_recreated_or_replaced_input_is_never_overwritten_or_adopted(self):
        for case in ('missing-key','changed-key'):
            with self.subTest(case=case),tempfile.TemporaryDirectory()as directory:
                state,retention=self.fixture(Path(directory));original=(state/'secrets/local-auth-key').stat().st_ino
                with self.assertRaisesRegex(RuntimeError,'recreated|replacement changed'):
                    with initial_resume_private_fault(state=state,retention=retention/case,case=case):
                        path=state/'secrets/local-auth-key'
                        if path.exists():path.unlink()
                        path.write_bytes(b'unexpected replacement');path.chmod(0o600)
                self.assertEqual((state/'secrets/local-auth-key').read_bytes(),b'unexpected replacement')
                self.assertEqual((retention/case/'original').stat().st_ino,original)
                self.assertEqual((retention/case/'original').read_bytes(),b'x'*32)

    def test_malformed_original_key_or_unknown_case_denies_before_moving_any_original(self):
        with tempfile.TemporaryDirectory()as directory:
            state,retention=self.fixture(Path(directory));(state/'secrets/local-auth-key').write_bytes(b'invalid')
            before=self.snapshot(state)
            for case in ('changed-key','arbitrary-path'):
                with self.assertRaises((RuntimeError,ValueError)):
                    with initial_resume_private_fault(state=state,retention=retention/case,case=case):pass
                self.assertEqual(self.snapshot(state),before);self.assertEqual(list(retention.iterdir()),[])
