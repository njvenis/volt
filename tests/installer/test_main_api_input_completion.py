"""Anonymous input deadline/reap components; not a PID1/container proof."""
import io
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock
from contextlib import redirect_stderr, redirect_stdout

from uvm.installer import route_check as control
from uvm.auth import route_check_records as records

ROOT=Path(__file__).resolve().parents[2]
ENTRY=(ROOT/'docker/g7/entrypoint.sh').read_text()

IO_SOURCE=ENTRY[ENTRY.index('api_report() {'):ENTRY.index('\n# Fixed external-command boundaries')]

def section(first,following):
    start=ENTRY.index(first);return IO_SOURCE+'\n'+ENTRY[start:ENTRY.index(following,start)]

class FiniteEntrypointDispatcherTests(unittest.TestCase):
    def invoke(self,action):
        stdout,stderr=io.StringIO(),io.StringIO()
        with mock.patch.object(sys,'argv',['fixed',action]),mock.patch.dict(os.environ,{'PATH':'/usr/bin:/bin','LC_ALL':'C'},clear=True),mock.patch.object(control.os,'geteuid',return_value=0),redirect_stdout(stdout),redirect_stderr(stderr):
            result=control._run()
        return result,stdout.getvalue(),stderr.getvalue()

    def test_expected_and_unexpected_failures_are_exact_static_nonzero(self):
        failures=[(control.RouteCheckError('identity_mismatch'),'identity_mismatch'),
            (records.RouteCheckError('custody_invalid'),'custody_invalid'),
            (RuntimeError('private-sentinel UUID/path/token'),'cleanup_failed')]
        for error,code in failures:
            with self.subTest(code=code),mock.patch.dict(sys.modules,{'volt_route_check_records':records}),mock.patch.object(control,'entrypoint_ready',side_effect=error):
                self.assertEqual(self.invoke('entrypoint-ready'),(1,'','route_check_failed:'+code+'\n'))
        class Unexpected(RuntimeError):
            @property
            def code(self):raise AssertionError('private-property')
        with mock.patch.object(control,'entrypoint_ready',side_effect=Unexpected('private-sentinel')):
            self.assertEqual(self.invoke('entrypoint-ready'),(1,'','route_check_failed:cleanup_failed\n'))

    def test_closed_actions_boolean_failure_and_pid_output(self):
        with mock.patch.object(control,'entrypoint_launch_pid',return_value=123):
            self.assertEqual(self.invoke('entrypoint-launch-pid'),(0,'123\n',''))
        with mock.patch.object(control,'entrypoint_launch_pid',return_value='private-sentinel'):
            self.assertEqual(self.invoke('entrypoint-launch-pid'),(1,'','route_check_failed:state_inconsistent\n'))
        with mock.patch.object(control,'entrypoint_signal_broker',return_value=False)as signal_call:
            self.assertEqual(self.invoke('entrypoint-signal-stop'),(1,'','route_check_failed:process_not_ready\n'))
            signal_call.assert_called_once_with('stop')
        with mock.patch.object(control,'entrypoint_orphan_cleanup',return_value=False):
            self.assertEqual(self.invoke('entrypoint-orphan-cleanup'),(1,'','route_check_failed:cleanup_failed\n'))
        self.assertEqual(self.invoke('entrypoint-__dict__'),(1,'','route_check_failed:invalid_input\n'))
        result=subprocess.run([sys.executable,'-I','-S',str(ROOT/'docker/g7/route_check_control.py'),'entrypoint-ready'],capture_output=True,timeout=3)
        # Host has no admitted protected COPY; real wrapper fails before import.
        self.assertEqual(result.returncode,1)
        self.assertEqual(result.stdout,b'')
        self.assertEqual(result.stderr,b'route_check_failed:cleanup_failed\n')

class ProducerCompletionTests(unittest.TestCase):
    def fixture(self,directory,emission):
        base=Path(directory);driver=base/'reader'
        driver.write_text('#!/usr/bin/python3\nimport json,sys\njson.load(sys.stdin)\n')
        driver.chmod(0o700)
        block=section('# No filesystem transport is created.','\napi_launch_confirmed=0')
        fixed='/usr/local/bin/python3.14 -I -S /usr/local/libexec/volt-main-api-launcher.py'
        self.assertEqual(block.count(fixed),1)
        helpers=section('close_api_input() {','\ncleanup_on_exit() {')
        prefix='''set -Eeuo pipefail
STATE=$1; CHILD_PIDS=(); CHILD_NAMES=()
shutdown_requested=0; quiesce_requested=0; quiesce_failed_latched=0
'''+helpers+'\nemit_api_request() { '+emission+'; }\n'
        return prefix,block.replace(fixed,str(driver))

    def test_actual_signal_interruption_keeps_registration_until_reap(self):
        for sig in (signal.SIGUSR1,signal.SIGTERM):
            with self.subTest(signal=sig),tempfile.TemporaryDirectory()as directory:
                prefix,block=self.fixture(directory,"printf READY >\"$STATE/released\"; sleep .4; printf '%s' '{\"synthetic\":true}'")
                handler='handle_quiesce'if sig==signal.SIGUSR1 else'handle_shutdown'
                script=prefix+f'''trap '[[ ${{api_input_producer:-}} ]] && printf registered >"$STATE/interrupted"; {handler}' {signal.Signals(sig).name[3:]}
trap 'close_api_input || :' EXIT
'''+block+'''
[[ ! ${api_input_producer:-} && ! ${api_input_deadline_pid:-} ]]
wait "$api_broker_pid"
printf complete
'''
                process=subprocess.Popen(['bash','-c',script,'fixture',directory],stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True)
                try:
                    deadline=time.monotonic()+3
                    while not(Path(directory)/'released').exists():
                        self.assertIsNone(process.poll());self.assertLess(time.monotonic(),deadline);time.sleep(.01)
                    os.kill(process.pid,sig)
                    stdout,stderr=process.communicate(timeout=8)
                    self.assertEqual(process.returncode,0,stderr)
                    self.assertEqual(stdout,b'complete')
                    self.assertEqual((Path(directory)/'interrupted').read_text(),'registered')
                finally:
                    try:os.killpg(process.pid,signal.SIGKILL)
                    except ProcessLookupError:pass
                    if process.poll()is None:process.communicate(timeout=3)

    def test_post_gate_blocked_reader_is_total_deadline_failure_with_registration(self):
        with tempfile.TemporaryDirectory()as directory:
            prefix,block=self.fixture(directory,'''printf READY >"$STATE/released"; printf -v payload '%262144s' ''; printf '%s' "$payload"; printf WRITTEN >"$STATE/written"''')
            # The reader is an exact registered test child holding stdin open,
            # deliberately not consuming it. No product fault switch is added.
            driver=Path(directory)/'reader'
            capacity=Path(directory)/'capacity'
            driver.write_text('#!/usr/bin/python3\nimport fcntl,time\nfcntl.fcntl(0,fcntl.F_SETPIPE_SZ,4096)\n'
                +f'open({str(capacity)!r},"w").write(str(fcntl.fcntl(0,fcntl.F_GETPIPE_SZ)))\n'
                +'time.sleep(60)\n');driver.chmod(0o700)
            split=block.index("printf 'G\\n'")
            # Test instrumentation only: establish the kernel pipe capacity
            # before gate release, rather than assuming host defaults.
            block=block[:split]+'''for attempt in $(seq 1 100); do
  [[ -f "$STATE/capacity" ]] && break
  sleep .01
done
[[ $(cat "$STATE/capacity") == 4096 ]] || exit 96
'''+block[split:]
            script=prefix+'''trap 'printf "%s:%s" "${api_input_uncertain:-0}" "${api_input_producer:-}" >"$STATE/retained"' EXIT
'''+block
            started=time.monotonic()
            process=subprocess.Popen(['bash','-c',script,'fixture',directory],stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True)
            try:
                process.wait(timeout=8)
                elapsed=time.monotonic()-started
                self.assertEqual(process.returncode,70)
                self.assertGreaterEqual(elapsed,4.8);self.assertLess(elapsed,7)
                uncertain,registered=(Path(directory)/'retained').read_text().split(':')
                self.assertEqual(uncertain,'1');self.assertTrue(registered.isdigit())
                self.assertTrue((Path(directory)/'released').exists())
                self.assertEqual(capacity.read_text(),'4096')
                self.assertFalse((Path(directory)/'written').exists())
                self.assertFalse((Path(directory)/'api-launch-input').exists())
            finally:
                # This is a host shell component, not real PID1. The test's own
                # registered process group models kernel container termination.
                try:os.killpg(process.pid,signal.SIGKILL)
                except ProcessLookupError:pass
                _,stderr=process.communicate(timeout=3)
            self.assertNotIn(b'Traceback',stderr)
