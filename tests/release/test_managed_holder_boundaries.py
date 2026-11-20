"""Real POSIX control flow with declared Docker observations substituted.

No actual Docker/container/FD/profile-ACK custody follows from these components.
"""
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[2]
SOURCE=(ROOT/'deploy/compose/launcher.sh').read_text()

def functions(first,following):
    start=SOURCE.index(first);return SOURCE[start:SOURCE.index(following,start)]

class ManagedHolderTests(unittest.TestCase):
    def script(self,body):
        prefix='''set -eu
LOCK_NAME=registered; LOCK_ID=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
OWNER_TOKEN=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
PROJECT=volt-component; IMAGE_REF=registered-image; LOCK_STARTED_AT=''; LOCK_SHAPE=''
ACTUAL_ID=$LOCK_ID; STARTED=2026-11-19T01:02:03.000000001Z
RUNNING=true; PAUSED=false; RESTARTING=false; ROLE=host-lifecycle-lock; SHAPE=declared-recipe
fail() { printf 'denied:%s\\n' "$*" >&2; exit 1; }
docker() {
  for last in "$@"; do :; done
  case "$last" in
    '{{.State.StartedAt}}') printf '%s\\n' "$STARTED" ;;
    '{{json .Config.Entrypoint}}'*) printf '%s\\n' "$SHAPE" ;;
    *) printf '%s\\n' "$ACTUAL_ID|$RUNNING|$OWNER_TOKEN|$PROJECT|$IMAGE_REF|$STARTED|$PAUSED|$RESTARTING|$ROLE" ;;
  esac
}
'''
        return prefix+functions('lock_owner_shape() {','\ntake_lock() {')+'\npin_lock_owner\n'+body

    def test_original_start_and_recipe_required_no_capability_after_loss(self):
        cases=['STARTED=2026-11-19T01:02:04.000000001Z','ACTUAL_ID=changed',
            'RUNNING=false','PAUSED=true','RESTARTING=true','ROLE=other','SHAPE=changed']
        for change in cases:
            with self.subTest(change=change):
                result=subprocess.run(['sh','-c',self.script(change+'\nensure_lock_owner\nprintf forbidden-capability\n')],capture_output=True,timeout=3)
                self.assertEqual(result.returncode,1)
                self.assertEqual(result.stdout,b'')
                self.assertTrue(result.stderr.startswith(b'denied:actual lifecycle FD owner '))
        good=subprocess.run(['sh','-c',self.script('ensure_lock_owner\nprintf admitted\n')],capture_output=True,timeout=3)
        self.assertEqual((good.returncode,good.stdout,good.stderr),(0,b'admitted',b''))

    def test_post_command_loss_stops_and_original_command_failure_is_preserved(self):
        wrapper=functions('locked_compose() {','\nread_instance() {')
        for loss,expected in ((True,1),(False,42)):
            with self.subTest(loss=loss):
                command='_locked_compose_command() { RUNNING=false; return 0; }'if loss else'_locked_compose_command() { return 42; }'
                result=subprocess.run(['sh','-c',self.script(command+'\n'+wrapper+'\nlocked_compose start\nprintf forbidden-capability\n')],capture_output=True,timeout=3)
                self.assertEqual(result.returncode,expected)
                self.assertEqual(result.stdout,b'')

    def test_actual_exit_trap_retains_rejected_holder_and_removes_only_exact_cid(self):
        cleanup=functions('cleanup() {','\ntrap cleanup 0 HUP INT TERM')
        changes=('STARTED=2026-11-19T01:02:04.000000001Z','SHAPE=changed',
            'PAUSED=true','RESTARTING=true','ACTUAL_ID=replacement','RUNNING=false','ROLE=other','LOCK_STARTED_AT=')
        for change in (*changes,'unchanged','unchanged0'):
            with self.subTest(change=change),tempfile.TemporaryDirectory() as directory:
                # Observe the actual signed cleanup function through EXIT,
                # rather than stopping at fail(). Docker remains substituted.
                body='''LOCK_CREATED=1; INSTALLING=0; CREATED_NETWORK=''; WORK=''
original_docker() {
  for last in "$@"; do :; done
  case "$last" in
    '{{.State.StartedAt}}') printf '%s\\n' "$STARTED" ;;
    '{{json .Config.Entrypoint}}'*) printf '%s\\n' "$SHAPE" ;;
    *) printf '%s\\n' "$ACTUAL_ID|$RUNNING|$OWNER_TOKEN|$PROJECT|$IMAGE_REF|$STARTED|$PAUSED|$RESTARTING|$ROLE" ;;
  esac
}
docker() {
  if [ "$1" = rm ]; then
    [ "$#" = 3 ] && [ "$2" = -f ] && [ "$3" = "$LOCK_ID" ] || exit 94
    printf '%s\\n' "$3" >>"$1_placeholder"
  else original_docker "$@"; fi
}
'''.replace('$1_placeholder',directory+'/removed')
                matching=change.startswith('unchanged')
                action=('exit 7' if change=='unchanged' else 'exit 0') if matching else change+'\nensure_lock_owner'
                result=subprocess.run(['sh','-c',self.script(body+'\n'+cleanup+'\ntrap cleanup 0\n'+action+'\n')],capture_output=True,timeout=3)
                removed=Path(directory)/'removed'
                self.assertEqual(result.returncode,(7 if change=='unchanged' else 0) if matching else 1)
                if matching:
                    self.assertEqual(removed.read_text(),'a'*64+'\n')
                    self.assertEqual(result.stderr,b'')
                else:
                    self.assertFalse(removed.exists())
                    self.assertIn(b'lifecycle owner cleanup uncertain; all registered resources and workspace retained',result.stderr)

    def test_exit_trap_installing_without_journal_never_falls_through_uncertain_owner(self):
        cleanup=functions('cleanup() {','\ntrap cleanup 0 HUP INT TERM')
        cases=[(change,status) for change in ('STARTED=2026-11-19T01:02:04.000000001Z','SHAPE=changed',
                'LOCK_STARTED_AT=','LOCK_CREATED=0') for status in (0,7)]
        for change,original_status in cases:
            with self.subTest(change=change,original_status=original_status),tempfile.TemporaryDirectory() as directory:
                state=Path(directory)/'instance';state.mkdir()
                work=Path(directory)/'work';work.mkdir();(work/'retained').write_text('private fixture')
                # Any destructive Docker call or resource-ownership lookup
                # would be evidence that the uncertain-holder barrier fell through.
                body=f'''LOCK_CREATED=1; INSTALLING=1; CREATED_NETWORK=registered-network
STATE='{state}'; WORK='{work}'
docker() {{
  case "$1" in
    rm|volume|network) printf '%s\\n' "$*" >>'{directory}/forbidden'; return 0 ;;
  esac
  for last in "$@"; do :; done
  case "$last" in
    '{{{{json .Config.Entrypoint}}}}'*) printf '%s\\n' "$SHAPE" ;;
    *) printf '%s\\n' "$ACTUAL_ID|$RUNNING|$OWNER_TOKEN|$PROJECT|$IMAGE_REF|$STARTED|$PAUSED|$RESTARTING|$ROLE" ;;
  esac
}}
'''
                result=subprocess.run(['sh','-c',self.script(body+'\n'+cleanup+'\ntrap cleanup 0\n'+change+f'\nexit {original_status}\n')],capture_output=True,timeout=3)
                self.assertEqual(result.returncode,original_status or 1)
                self.assertFalse((Path(directory)/'forbidden').exists())
                self.assertTrue(state.is_dir());self.assertTrue((work/'retained').is_file())
                self.assertIn(b'all registered resources and workspace retained',result.stderr)
