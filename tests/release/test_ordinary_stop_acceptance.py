"""Real POSIX stop/EXIT branches, simulated Docker and injected boundary clock.

Does not claim 600 seconds elapsed, actual Docker timing or native validation.
"""
from pathlib import Path
import os
import subprocess
import tempfile
import unittest
ROOT=Path(__file__).resolve().parents[2]


class OrdinaryStopAcceptanceTests(unittest.TestCase):
    def run_case(self,mode):
        launcher=(ROOT/'deploy/compose/launcher.sh').read_text()
        cleanup=launcher[launcher.index('cleanup() {'):launcher.index('\ntrap cleanup 0 HUP INT TERM')]
        with tempfile.TemporaryDirectory()as tmp:
            parent=Path(tmp);work=parent/'work';work.mkdir(mode=0o700);(work/'seed').write_text('private failure evidence')
            script='''set -eu
umask 077
PARENT=$1;WORK=$2;mode=$3;LOCK_NAME='';INSTALLING=0;CREATED_NETWORK='';OWNER_TOKEN='';RETAIN_STOP_EVIDENCE=0
'''+cleanup+'''
trap cleanup 0
. "$DRIVER"
fail() { printf '%s\\n' "$1" >&2; exit 1; }
clock_calls=0;compose_returned=0;late_audit=0
offline_stop_clock() {
 clock_calls=$((clock_calls+1))
 if [ "$mode" = clock-failure ];then return 1;fi
 OFFLINE_NOW_CS=100
 if [ "$compose_returned" = 1 ];then
  OFFLINE_NOW_CS=200
  if [ "$mode" = late ];then OFFLINE_NOW_CS=60100;fi
 fi
 if [ "$late_audit" = 1 ];then OFFLINE_NOW_CS=60100;fi
}
verify_actual_mounts() { printf 'mount-check\\n' >>"$PARENT/events";if [ "$mode" = audit-late ];then late_audit=1;fi; }
locked_compose() {
 sh -c 'sleep .04; printf "SIMULATED_DOCKER_STOPPED\\n"; printf "private Docker diagnostic\\n" >&2'
 printf 'compose-returned\\n' >>"$PARENT/events"
 compose_returned=1
 [ "$mode" != nonzero ] || return 7
}
offline_snapshot() { printf 'snapshot\\n' >>"$PARENT/events";OFFLINE_STOP_DEADLINE_CS=1500; }
offline_capture_shutdown() { printf 'capture\\n' >>"$PARENT/events"; }
offline_data() { printf 'assembly\\n' >>"$PARENT/events"; printf 'not-authority-unit-data'; }
ensure_lock_owner() { return 0; }
offline_host_start() { printf 'validation-start\\n' >>"$PARENT/events";OFFLINE_JOB=unit-only; }
offline_host_finish() { printf 'validation-complete\\n' >>"$PARENT/events"; }
if [ "$mode" = nonzero ];then
 if run_public_local_stop;then printf 'TEST_CLEAN_ACCEPTANCE\\n';else exit 9;fi
else
 run_public_local_stop
 printf 'TEST_CLEAN_ACCEPTANCE\\n'
fi
'''
            r=subprocess.run(['sh','-c',script,'fixture',str(parent),str(work),mode],
                env=os.environ|{'DRIVER':str(ROOT/'deploy/compose/offline-host.sh')},capture_output=True,timeout=3)
            events=(parent/'events').read_text().splitlines()if(parent/'events').exists()else[]
            retained=work.is_dir();files={p.name:p.read_text()for p in work.iterdir()if p.is_file()}if retained else{}
            return r,events,retained,files

    def test_late_zero_result_has_no_clean_output_proof_or_acceptance_and_retains_private_work(self):
        r,events,retained,files=self.run_case('late')
        self.assertNotEqual(r.returncode,0)
        self.assertIn('compose-returned',events)
        self.assertEqual({'stdout_empty':r.stdout==b'','retained':retained,'snapshot_started':'snapshot'in events,
            'validator_started':'validation-start'in events},{'stdout_empty':True,'retained':True,'snapshot_started':False,'validator_started':False})
        self.assertIn(b'ordinary stop deadline expired',r.stderr)
        self.assertEqual(files['ordinary-compose.exit'].strip(),'0')
        self.assertIn('SIMULATED_DOCKER_STOPPED',files['ordinary-compose.stdout'])

    def test_nonzero_compose_cannot_become_clean_in_conditional_shell_context(self):
        r,events,retained,files=self.run_case('nonzero')
        self.assertNotEqual(r.returncode,0)
        self.assertNotIn('snapshot',events);self.assertNotIn('validation-start',events)
        self.assertNotIn(b'TEST_CLEAN_ACCEPTANCE',r.stdout)
        self.assertTrue(retained)
        self.assertEqual(files['ordinary-compose.exit'].strip(),'7')

    def test_before_cutoff_still_requires_independent_validation_before_success(self):
        r,events,retained,files=self.run_case('before')
        self.assertEqual(r.returncode,0,r.stderr)
        self.assertEqual(events,['mount-check','compose-returned','snapshot','capture','assembly','validation-start','validation-complete'])
        self.assertIn(b'TEST_CLEAN_ACCEPTANCE',r.stdout)
        self.assertFalse(retained)

    def test_missing_clock_retains_evidence_without_dispatch(self):
        r,events,retained,files=self.run_case('clock-failure')
        self.assertNotEqual(r.returncode,0);self.assertEqual(events,[])
        self.assertTrue(retained)

    def test_mount_audit_returning_after_cutoff_cannot_dispatch_new_stop(self):
        r,events,retained,files=self.run_case('audit-late')
        self.assertNotEqual(r.returncode,0)
        self.assertEqual(events,['mount-check'])
        self.assertTrue(retained)
        self.assertEqual(r.stdout,b'')
