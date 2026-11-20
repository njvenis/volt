"""Actual Bash failure gates/clock; Store/commands explicitly substituted."""
from pathlib import Path
import subprocess
import tempfile
import unittest
ROOT=Path(__file__).resolve().parents[2]
ENTRY=(ROOT/'docker/g7/entrypoint.sh').read_text()
IO_SOURCE=ENTRY[ENTRY.index('api_report() {'):ENTRY.index('\n# Fixed external-command boundaries')]

def section(first,next_marker):
    start=ENTRY.index(first);return IO_SOURCE+'\n'+ENTRY[start:ENTRY.index(next_marker,start)]

class TerminalParentFailures(unittest.TestCase):
    def test_missing_api_progress_never_enters_worker_or_database_teardown(self):
        ordinary=section('stop_all() {','\nstaged_quiesce() {')
        with tempfile.TemporaryDirectory() as directory:
            script='''set -Eeuo pipefail
STATE=$1; PGDATA=fixture; api_terminal_active=1
begin_api_stop() { return 0; }
stop_phase() { printf '%s\n' "$1" >>"$STATE/phases"; }
reconcile_registered_broker() { return 1; }
setpriv() { printf forbidden >>"$STATE/database"; return 0; }
valkey-cli() { printf forbidden >>"$STATE/database"; return 0; }
'''+ordinary+'''
if stop_all; then exit 93; fi
[[ $api_cleanup_poisoned == 1 ]]
'''
            result=subprocess.run(['bash','-c',script,'fixture',directory],capture_output=True,timeout=3)
            self.assertEqual(result.returncode,0,result.stderr)
            self.assertEqual((Path(directory)/'phases').read_text().splitlines(),['writers'])
            self.assertFalse((Path(directory)/'database').exists())

    def test_first_signal_receipt_survives_repeats_and_delayed_cleanup_entry(self):
        handlers=section('record_api_stop_receipt() {','\ncleanup_on_exit() {')
        begin=section('begin_api_stop() {','\napi_stop_progress() {')
        script='''set -Eeuo pipefail
api_terminal_active=1; api_stop_started=0; shutdown_requested=0
api_private_payload() { api_private_result=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa; }
'''+handlers+'\n'+begin+'''
trap handle_shutdown TERM
trap 'if [[ ${api_stop_timer_write:-} ]]; then printf "C\n" >&"$api_stop_timer_write"; exec {api_stop_timer_write}>&-; wait "$api_stop_timer"; fi' EXIT
kill -TERM "$$"
first=$api_stop_t0
sleep 1.1
kill -TERM "$$"
begin_api_stop
[[ $first == "$api_stop_t0" && $api_stop_remaining -le 586 ]]
printf first_receipt_retained
'''
        result=subprocess.run(['bash','-c',script],capture_output=True,timeout=5)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(result.stdout,b'first_receipt_retained')

    def test_service_or_database_failure_is_not_a_recoverable_quiesce_timeout(self):
        quiesce=section('staged_quiesce() {','\nsecret() {')
        for failure in ('producer75','worker','database'):
            with self.subTest(failure=failure),tempfile.TemporaryDirectory() as directory:
                state=Path(directory)
                (state/'quiesce-drain-complete').touch();(state/'quiesce-capture-release').touch()
                # Substitute only fixed service command boundaries. Arbitrary
                # producer75 MUST NOT become the canonical API timeout class.
                script='''set -Eeuo pipefail
STATE=$1; PGDATA=fixture; api_cleanup_poisoned=0; shutdown_requested=0; failure=$2
reconcile_registered_broker() { return 0; }
stop_phase() {
  if [[ $failure == producer75 && $1 == quiesce-producers ]]; then return 75; fi
  if [[ $failure == worker && $1 == quiesce-consumers ]]; then return 1; fi
  return 0
}
setpriv() {
  if [[ ${*: -1} == status ]]; then return 0; fi
  [[ $failure != database ]]
}
valkey-cli() { return 0; }
'''+quiesce+'''
if staged_quiesce; then exit 94; fi
[[ $api_cleanup_poisoned == 1 && $quiesce_recoverable == 0 ]]
'''
                result=subprocess.run(['bash','-c',script,'fixture',directory,failure],capture_output=True,timeout=4)
                self.assertEqual(result.returncode,0,result.stderr)

    def test_marker_io_failures_are_sticky_inside_conditional_callers(self):
        ordinary=section('stop_all() {','\nstaged_quiesce() {')
        quiesce=section('staged_quiesce() {','\nsecret() {')
        for fault in ('ordinary-ready','quiesce-ready','quiesce-writers-stopped','quiesce-services-stopped','quiesce-failed'):
            with self.subTest(fault=fault),tempfile.TemporaryDirectory() as directory:
                state=Path(directory)
                (state/'quiesce-drain-complete').touch();(state/'quiesce-capture-release').touch()
                setup='''set -Eeuo pipefail
STATE=$1; PGDATA=fixture; fault=$2; api_cleanup_poisoned=0; api_terminal_active=0; shutdown_requested=0
begin_api_stop() { return 0; }
reconcile_registered_broker() { return 0; }
stop_phase() { printf '%s\n' "$1" >>"$STATE/phases"; }
setpriv() { if [[ ${*: -1} == status ]]; then return 0; fi; return 0; }
valkey-cli() { return 0; }
rm() { if [[ $fault == *-ready ]]; then return 1; fi; command rm "$@"; }
touch() { if [[ $1 == "$STATE/$fault" ]]; then return 1; fi; command touch "$@"; }
'''
                if fault=='ordinary-ready':action='if stop_all; then exit 93; fi'
                elif fault=='quiesce-failed':action='if api_phase_marker quiesce-failed; then exit 94; fi'
                else:action='if staged_quiesce; then exit 95; fi\n[[ $quiesce_recoverable == 0 ]]'
                script=setup+ordinary+'\n'+quiesce+'\n'+action+'\n[[ $api_cleanup_poisoned == 1 ]]\n'
                result=subprocess.run(['bash','-c',script,'fixture',directory,fault],capture_output=True,timeout=4)
                self.assertEqual(result.returncode,0,result.stderr)
                if fault.endswith('-ready'):
                    self.assertIn('admission' if fault.startswith('quiesce') else 'writers',(state/'phases').read_text())

    def test_unavailable_wait_is_not_stopped_and_exact_retained_result_is_positive(self):
        phase=section('stop_phase() {','\nreconcile_registered_broker() {')
        for retained in (False,True):
            with self.subTest(retained=retained),tempfile.TemporaryDirectory() as directory:
                setup='''set -Eeuo pipefail
STATE=$1; api_cleanup_poisoned=0
CHILD_PIDS=(); CHILD_NAMES=(fixture); declare -A REAPED_CHILDREN=() CHILD_EXIT_STATUS=() UNRESOLVED_CHILDREN=()
sleep .05 & registered=$!; CHILD_PIDS+=("$registered")
'''
                if retained:
                    setup+='''if builtin wait "$registered"; then exact=0; else exact=$?; fi
CHILD_EXIT_STATUS[$registered]=$exact; REAPED_CHILDREN[$registered]=1
'''
                    action='''stop_phase ordinary fixture
[[ $api_cleanup_poisoned == 0 && $exact == 0 && ! ${UNRESOLVED_CHILDREN[$registered]+present} ]]
'''
                else:
                    # Consume ONLY this actual child's completion, then the
                    # no-argument wait discards Bash's cached statuses. There
                    # is deliberately NO retained exact result in the registry.
                    setup+='''builtin wait "$registered"
builtin wait
'''
                    action='''if stop_phase ordinary fixture; then exit 97; fi
[[ $api_cleanup_poisoned == 1 && ${UNRESOLVED_CHILDREN[$registered]+present} && ! ${REAPED_CHILDREN[$registered]+present} ]]
'''
                result=subprocess.run(['bash','-c',setup+phase+'\n'+action,'fixture',directory],capture_output=True,timeout=4)
                self.assertEqual(result.returncode,0,result.stderr)
                self.assertNotIn(b'G7_STOP_CHILD_STOPPED',result.stdout)

    def test_failed_report_cannot_leave_successful_cleanup_eligibility(self):
        script='set -Eeuo pipefail\napi_cleanup_poisoned=0\n'+IO_SOURCE+'''
if api_report G7_FIXED_MARKER 1>&-; then exit 98; fi
[[ $api_cleanup_poisoned == 1 ]]
'''
        result=subprocess.run(['bash','-c',script],capture_output=True,timeout=3)
        self.assertEqual(result.returncode,0,result.stderr)
