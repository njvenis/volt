"""Only the backend's closed nonsecret claimed-state diagnostic is actionable."""
from pathlib import Path
import os
import subprocess
import tempfile
import unittest
ROOT=Path(__file__).resolve().parents[2]
class SetupMaintenanceDiagnosticTests(unittest.TestCase):
    def run_case(self,root,message,code,operation='prepare-setup'):
        body=(ROOT/'deploy/compose/launcher.sh').read_text().split('run_maintenance() {',1)[1].split('\n}',1)[0]
        script='''set -eu
umask 077
fail() { printf 'volt installer: %s\\n' "$*" >&2; exit 1; }
locked_compose() { printf '%s' "$TEST_BACKEND_STDERR" >&2; printf '%s' 'PRIVATE_STDOUT_SENTINEL'; return "$TEST_BACKEND_EXIT"; }
copy_capability() { printf '%s\\n' 'unexpected capability copy'; }
show_capability() { printf '%s\\n' 'unexpected capability display'; }
run_maintenance() {'''+body+'\n}\nrun_maintenance '+operation+'\n'
        return subprocess.run(['sh','-c',script],env={**os.environ,'WORK':str(root),'TEST_BACKEND_STDERR':message,'TEST_BACKEND_EXIT':str(code)},capture_output=True,text=True)
    def test_only_exact_static_complete_line_and_exit_for_setup_can_be_mapped(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);r=self.run_case(root,'maintenance failed: setup_already_claimed\n',1)
            self.assertEqual(r.returncode,1);self.assertEqual(r.stderr,'volt installer: initial setup is already claimed\n');self.assertEqual(r.stdout,'')
            self.assertEqual((root/'maintenance.stderr').stat().st_mode&0o777,0o600)
    def test_generic_secret_extra_partial_or_wrong_operation_are_never_forwarded(self):
        for message,code,operation in [('maintenance failed: RuntimeError\n',1,'prepare-setup'),('PRIVATE_SECRET_SENTINEL\n',1,'prepare-setup'),('maintenance failed: setup_already_claimed\nPRIVATE_SECRET_SENTINEL\n',1,'prepare-setup'),('maintenance failed: setup_already_claimed\n\n',1,'prepare-setup'),('maintenance failed: setup_already_claimed',1,'prepare-setup'),('maintenance failed: setup_already_claimed\n',2,'prepare-setup'),('maintenance failed: setup_already_claimed\n',1,'create-account')]:
            with self.subTest(message=message,code=code,operation=operation),tempfile.TemporaryDirectory() as tmp:
                r=self.run_case(Path(tmp),message,code,operation)
                self.assertEqual(r.returncode,1);self.assertEqual(r.stderr,'volt installer: local maintenance command failed\n');self.assertEqual(r.stdout,'')
