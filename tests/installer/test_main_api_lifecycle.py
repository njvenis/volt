"""Delivery lifecycle components: real children, substituted record publishers.

These do not establish the full image entrypoint, shared Store or backup proof.
"""
import importlib.util
import json
import os
from pathlib import Path
import signal
import subprocess
import tempfile
import time
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
ENTRY = (ROOT / 'docker/g7/entrypoint.sh').read_text()
SPEC = importlib.util.spec_from_file_location('lifecycle_broker_fixture', ROOT / 'docker/g7/main_api_launcher.py')
broker = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(broker)


IO_SOURCE=ENTRY[ENTRY.index('api_report() {'):ENTRY.index('\n# Fixed external-command boundaries')]

def functions(first, following):
    return IO_SOURCE+'\n'+ENTRY[ENTRY.index(first):ENTRY.index(following, ENTRY.index(first))]


class EntrypointInputTests(unittest.TestCase):
    def test_shell_encoder_roundtrips_private_bytes_and_limits(self):
        functions_text = functions('api_json_string() {', '\napi_broker_control() {')
        for value in ('plain', 'quote" slash\\ newline\n tab\t', 'é雪', '\x01\x1f', 'x' * 4096):
            with self.subTest(bytes=len(value.encode())):
                result = subprocess.run(['bash', '-c', 'set -eu; ' + functions_text + '\nAPI_INPUT_TOTAL=0; API_INPUT_SEPARATOR=""; emit_api_pair key "$1"', 'fixture', value], capture_output=True, timeout=5)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(json.loads(b'{' + result.stdout + b'}'), {'key': value})
        for value, initial in (('x' * 4097, 0), ('é' * 2049, 0), ('bounded', 65535)):
            result = subprocess.run(['bash', '-c', 'set -eu; ' + functions_text + '\nAPI_INPUT_TOTAL=$2; API_INPUT_SEPARATOR=""; emit_api_pair key "$1"', 'fixture', value, str(initial)], capture_output=True, timeout=5)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(result.stdout, b'')

    def test_ordinary_cleanup_does_not_inherit_quiesce_signal_policy(self):
        ordinary = functions('stop_all() {', '\nstaged_quiesce() {')
        script = """set -eu
STATE=$1
UVM_G7_QUIESCE_NO_KILL=1
PGDATA=fixture
stop_phase() { printf '%s\\n' "$UVM_G7_QUIESCE_NO_KILL" >>"$STATE/policy"; }
setpriv() { return 3; }
valkey-cli() { return 0; }
reconcile_registered_broker() { return 0; }
begin_api_stop() { return 0; }
""" + ordinary + """
stop_all
[[ $UVM_G7_QUIESCE_NO_KILL == 1 ]]
"""
        with tempfile.TemporaryDirectory() as directory:
            result = subprocess.run(['bash', '-c', script, 'fixture', directory], capture_output=True, timeout=5)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual((Path(directory) / 'policy').read_text().splitlines(), ['0', '0'])

    def test_actual_pid1_loop_latches_until_term_and_notices_critical_death(self):
        # Only production loop/handlers are exercised; Store/other services are
        # explicitly substituted. Sleep is a registered real child, not an API.
        loop = functions("trap 'handle_shutdown' TERM INT\nexited_child_pid=", '\napi_remove_ready || { api_cleanup_poisoned=1; shutdown_status=1; }')
        handlers = functions('record_api_stop_receipt() {', '\ncleanup_on_exit() {')
        for terminate_critical in (False, True):
            with self.subTest(critical=terminate_critical), tempfile.TemporaryDirectory() as directory:
                script = '''set -Eeuo pipefail
STATE=$1
CHILD_PIDS=(); CHILD_NAMES=(); declare -A REAPED_CHILDREN=() CHILD_EXIT_STATUS=() UNRESOLVED_CHILDREN=()
shutdown_requested=0; quiesce_requested=0; quiesce_failed_latched=0; cleanup_running=0
''' + handlers + '''
trap handle_quiesce USR1
trap 'kill "$registered" 2>/dev/null || :; wait "$registered" 2>/dev/null || :' EXIT
sleep 60 & registered=$!
CHILD_PIDS+=("$registered"); CHILD_NAMES+=(fixture)
printf '%s' "$registered" >"$STATE/child"
staged_quiesce() { [[ ${UVM_G7_QUIESCE_NO_KILL:-0} == 1 ]] || exit 97; quiesce_recoverable=1; return 1; }
api_broker_control() { printf '%s\\n' "$1" >>"$STATE/control"; return 0; }
''' + loop + '''
if (( shutdown_requested )); then echo TERM >"$STATE/result"; exit 0; fi
echo CRITICAL >"$STATE/result"; exit 70
'''
                process = subprocess.Popen(['bash', '-c', script, 'fixture', directory], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                try:
                    child_file = Path(directory) / 'child'
                    self.wait_for(child_file.exists, process)
                    os.kill(process.pid, signal.SIGUSR1)
                    self.wait_for((Path(directory) / 'quiesce-failed').exists, process)
                    self.wait_for(lambda: (Path(directory) / 'control').exists() and 'quiesce-surviving' in (Path(directory) / 'control').read_text(), process)
                    self.assertIsNone(process.poll())
                    os.kill(process.pid, signal.SIGUSR1)
                    time.sleep(.1)
                    self.assertIsNone(process.poll())
                    if terminate_critical:
                        os.kill(int(child_file.read_text()), signal.SIGTERM)
                    else:
                        os.kill(process.pid, signal.SIGTERM)
                    stdout, stderr = process.communicate(timeout=5)
                    self.assertEqual(process.returncode, 70 if terminate_critical else 0, stderr)
                    self.assertEqual((Path(directory) / 'result').read_text().strip(), 'CRITICAL' if terminate_critical else 'TERM')
                finally:
                    if process.poll() is None:
                        process.kill(); process.communicate(timeout=5)

    @staticmethod
    def wait_for(predicate, process):
        deadline = time.monotonic() + 5
        while not predicate():
            if process.poll() is not None or time.monotonic() >= deadline:
                raise AssertionError('registered component failed before expected boundary')
            time.sleep(.02)


# Retained-session publication-failure/API-reap/EOF behavior now has the real
# child fixture in test_broker_terminal_session.py, replacing old callbacks.
