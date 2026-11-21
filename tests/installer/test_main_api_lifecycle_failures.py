"""Real shell/pipe/child boundaries with explicitly substituted Store/readers.

No image/PID1/crypto/public-lifecycle acceptance follows from these components.
"""
from contextlib import nullcontext
import copy
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

from uvm.auth import route_check_records as records
from uvm.installer import route_check as control

ROOT = Path(__file__).resolve().parents[2]
ENTRY = (ROOT / 'docker/g7/entrypoint.sh').read_text()
SPEC = importlib.util.spec_from_file_location('failure_broker_fixture', ROOT / 'docker/g7/main_api_launcher.py')
broker = importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(broker)


IO_SOURCE=ENTRY[ENTRY.index('api_report() {'):ENTRY.index('\n# Fixed external-command boundaries')]

def section(first, next_marker):
    start = ENTRY.index(first)
    return IO_SOURCE+'\n'+ENTRY[start:ENTRY.index(next_marker, start)]


class ShellFailureTests(unittest.TestCase):
    def test_real_critical_reap_then_term_is_sticky_before_database_shutdown(self):
        loop = section("trap 'handle_shutdown' TERM INT\nexited_child_pid=", '\nif [[ ! -e "$STATE/critical-failed" ]]')
        reconcile = section('reconcile_registered_broker() {', '\nstop_all() {')
        ordinary = section('stop_all() {', '\nstaged_quiesce() {')
        handlers = section('record_api_stop_receipt() {', '\ncleanup_on_exit() {')
        for critical_status in (0,7):
            with self.subTest(critical_status=critical_status),tempfile.TemporaryDirectory() as directory:
                script = '''set -Eeuo pipefail
STATE=$1; PGDATA=fixture
begin_api_stop() { return 0; }
finish_api_terminal() { [[ $api_cleanup_poisoned == 1 ]] || exit 96; return 1; }
CHILD_NAMES=(api-broker); CHILD_PIDS=(); declare -A REAPED_CHILDREN=() CHILD_EXIT_STATUS=() UNRESOLVED_CHILDREN=()
shutdown_requested=0; quiesce_requested=0; quiesce_failed_latched=0; cleanup_running=0; shutdown_status=0
''' + handlers + '''
trap handle_shutdown TERM
( sleep .05; exit "$2" ) & registered=$!; CHILD_PIDS+=("$registered")
# Actual kernel reap followed by actual TERM BEFORE loop exit examination.
wait() { local result=0; builtin wait "$@" || result=$?; kill -TERM "$$"; return "$result"; }
stop_phase() { [[ $api_cleanup_poisoned == 1 ]] || exit 95; printf 'phase:%s\\n' "$1" >>"$STATE/events"; }
api_broker_control() { [[ ${REAPED_CHILDREN[$registered]+yes} ]] || return 91; printf '%s\\n' "$1" >>"$STATE/events"; }
setpriv() { [[ $api_cleanup_poisoned == 1 ]] || exit 94; printf 'database\\n' >>"$STATE/events"; return 3; }
valkey-cli() { return 0; }
''' + reconcile + ordinary + loop
                result = subprocess.run(['bash', '-c', script, 'fixture', directory,str(critical_status)], capture_output=True, timeout=5)
                self.assertEqual(result.returncode,1,result.stderr)
                events=(Path(directory)/'events').read_text().splitlines()
                self.assertEqual(events.count('orphan-terminated'),1)
                self.assertLess(events.index('orphan-terminated'),events.index('database'))
                self.assertNotIn(b'service_cleanup_status=0',result.stdout)

    def test_wait_without_child_identity_stops_once_and_cannot_claim_clean(self):
        loop = section("trap 'handle_shutdown' TERM INT\nexited_child_pid=", '\napi_remove_ready || { api_cleanup_poisoned=1; shutdown_status=1; }')
        with tempfile.TemporaryDirectory() as directory:
            script = '''set -Eeuo pipefail
STATE=$1; CHILD_PIDS=(999999); declare -A REAPED_CHILDREN=() CHILD_EXIT_STATUS=() UNRESOLVED_CHILDREN=()
shutdown_requested=0; quiesce_requested=0; quiesce_failed_latched=0
record_api_stop_receipt() { return 0; }
handle_shutdown() { shutdown_requested=1; }
wait() { printf x >>"$STATE/waits"; return 127; }
''' + loop + '''
[[ $wait_bookkeeping_failed == 1 && $child_status == 70 && ! ${exited_child_pid:-} ]]
exit 70
'''
            result = subprocess.run(['bash', '-c', script, 'fixture', directory], capture_output=True, timeout=2)
            self.assertEqual(result.returncode, 70, result.stderr)
            self.assertEqual((Path(directory) / 'waits').read_bytes(), b'x')
            self.assertEqual(result.stderr, b'G7_WAIT_ERROR=unresolved-child\n')

    def test_registered_process_substitution_is_reaped_live_and_already_completed(self):
        loop = section("trap 'handle_shutdown' TERM INT\nexited_child_pid=", '\napi_remove_ready || { api_cleanup_poisoned=1; shutdown_status=1; }')
        handlers = section('record_api_stop_receipt() {', '\ncleanup_on_exit() {')
        for precompleted in (False, True):
            for code in (0,7):
                with self.subTest(precompleted=precompleted,code=code):
                    script='''set -Eeuo pipefail
CHILD_PIDS=(); declare -A REAPED_CHILDREN=() CHILD_EXIT_STATUS=() UNRESOLVED_CHILDREN=()
shutdown_requested=0; quiesce_requested=0; quiesce_failed_latched=0; shutdown_status=0
'''+handlers+'''
exec 9> >(sleep .05;exit "$1")
broker=$!
(sleep .3;exit 0) 9>&- & other=$!
CHILD_PIDS=("$broker" "$other")
trap 'exec 9>&-; builtin wait "$broker" 2>/dev/null || :; builtin wait "$other" 2>/dev/null || :' EXIT
if [[ $2 == 1 ]];then sleep .1;fi
'''+loop+'''
[[ $exited_child_pid == "$broker" && $child_status == "$1" && $api_cleanup_poisoned == 1 ]]
[[ ${CHILD_EXIT_STATUS[$broker]} == "$1" && ${REAPED_CHILDREN[$broker]} == 1 ]]
[[ $wait_bookkeeping_failed == 0 ]]
'''
                    r=subprocess.run(['bash','-c',script,'fixture',str(code),str(int(precompleted))],capture_output=True,timeout=3)
                    self.assertEqual(r.returncode,0,r.stderr)
                    self.assertNotIn(b'no such job',r.stderr)

    def test_failed_liveness_probe_with_present_process_is_uncertainty_not_reap(self):
        loop=section("trap 'handle_shutdown' TERM INT\nexited_child_pid=", '\napi_remove_ready || { api_cleanup_poisoned=1; shutdown_status=1; }')
        script='''set -Eeuo pipefail
CHILD_PIDS=("$$");declare -A REAPED_CHILDREN=() CHILD_EXIT_STATUS=() UNRESOLVED_CHILDREN=()
shutdown_requested=0;quiesce_requested=0;quiesce_failed_latched=0
record_api_stop_receipt() { return 0; }
handle_shutdown() { shutdown_requested=1; }
kill() { return 1; }
wait() { exit 99; }
'''+loop+'''
[[ $wait_bookkeeping_failed == 1 && $api_cleanup_poisoned == 1 && ! ${exited_child_pid:-} ]]
'''
        r=subprocess.run(['bash','-c',script],capture_output=True,timeout=2)
        self.assertEqual(r.returncode,0,r.stderr)
        self.assertEqual(r.stderr,b'G7_WAIT_ERROR=unresolved-child\n')


def clean_fixture():
    api = {'pid': 30, 'proc_start_ticks': 300}
    launch = {'entrypoint': {'pid': 1, 'proc_start_ticks': 10},
        'supervisor': {'pid': 20, 'proc_start_ticks': 200}, 'api': api,
        'clock_ticks_per_second': os.sysconf('SC_CLK_TCK')}
    status = {**copy.deepcopy(launch), 'phase': 'stopped', 'result': 'clean_stop'}
    supervisor = records.record(supervisor=launch['supervisor'], api=api,
        clock_ticks_per_second=launch['clock_ticks_per_second'], phase='stopped')
    runtime = {'container_id': 'a' * 64, 'started_at': '2026-11-19T00:00:00Z',
        'image': {'kind': 'config', 'id': 'sha256:'+'b'*64, 'config_id': 'sha256:'+'b'*64},
        'resources_sha256': 'c'*64}
    disarmed = records.record(api=api, runtime_boot_nonce=records.new_nonce(), runtime=runtime,
        operation_id='00000000-0000-4000-8000-000000000001', reason='shutdown')
    state = records.record(state='disarmed', arm=None, closing_reason=None, disarmed=disarmed)
    boot = records.record(api=api, runtime_boot_nonce=disarmed['runtime_boot_nonce'],
        published_boottime_ns=1, ready=False, loaded_operation_id=None)
    store = mock.Mock()
    store.read_supervisor.return_value = supervisor
    store.read_state.return_value = state
    store.read_boot.return_value = boot
    store.read_seen.return_value = None
    store.inventory.return_value = ()
    return launch, status, store


class CleanJoinTests(unittest.TestCase):
    def test_complete_clean_join_and_no_route_startup_are_distinct(self):
        launch, status, store = clean_fixture()
        with mock.patch.object(records, 'proc_dead', return_value=True):
            self.assertTrue(control._clean_registered_stop(store, launch, status, records))
            store.read_state.return_value['disarmed'] = records.record(api=None,
                runtime_boot_nonce=None, runtime=None, operation_id=None, reason='startup')
            store.read_boot.return_value = None
            self.assertTrue(control._clean_registered_stop(store, launch, status, records))

    def test_each_identity_companion_and_disarm_contradiction_denies_clean(self):
        cases = ('status_entrypoint', 'status_supervisor', 'status_api', 'status_phase',
            'sup_api', 'sup_supervisor', 'sup_ticks', 'sup_phase', 'sup_missing',
            'state_armed', 'disarm_api', 'disarm_reason', 'disarm_nonce', 'disarm_runtime',
            'boot_api', 'boot_nonce', 'boot_ready', 'boot_loaded', 'seen', 'temporary', 'api_live')
        for case in cases:
            with self.subTest(case=case):
                launch, status, store = clean_fixture()
                if case.startswith('status_'):
                    field = case[7:]
                    status[field] = 'failed' if field == 'phase' else {'pid': 40, 'proc_start_ticks': 400}
                elif case.startswith('sup_'):
                    field = case[4:]
                    if field == 'missing': store.read_supervisor.side_effect = records.RouteCheckError('state_inconsistent')
                    else:
                        field = 'clock_ticks_per_second' if field == 'ticks' else field
                        store.read_supervisor.return_value[field] = 'failed' if field == 'phase' else 1 if field == 'clock_ticks_per_second' else {'pid': 40, 'proc_start_ticks': 400}
                elif case == 'state_armed': store.read_state.return_value['state'] = 'armed'
                elif case.startswith('disarm_'):
                    field = case[7:];field = 'runtime_boot_nonce' if field == 'nonce' else field
                    store.read_state.return_value['disarmed'][field] = 'api_dead' if field == 'reason' else {'pid':40,'proc_start_ticks':400} if field == 'api' else None
                elif case.startswith('boot_'):
                    field = case[5:];field = {'nonce':'runtime_boot_nonce','loaded':'loaded_operation_id'}.get(field,field)
                    store.read_boot.return_value[field] = True if field == 'ready' else {'pid':40,'proc_start_ticks':400} if field == 'api' else records.new_nonce()
                elif case == 'seen': store.read_seen.return_value = {'unexpected': True}
                elif case == 'temporary': store.inventory.return_value = ('temporary',)
                with mock.patch.object(records, 'proc_dead', return_value=case != 'api_live'):
                    with self.assertRaises((control.RouteCheckError, records.RouteCheckError)):
                        control._clean_registered_stop(store, launch, status, records)


class AnonymousTransportTests(unittest.TestCase):
    def test_same_direct_child_pipe_restart_and_legacy_objects_remain_unchanged(self):
        block = section('# No filesystem transport is created.', '\napi_launch_confirmed=0')
        fixed = '/usr/local/bin/python3.14 -I -S /usr/local/libexec/volt-main-api-launcher.py'
        self.assertEqual(block.count(fixed), 1)
        close = section('close_api_input() {', '\nhandle_shutdown() {')
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            environment = {key: '' for key in broker.API_KEYS}; environment.update(broker.FIXED_ENV)
            environment.update(UVM_API_HOST='0.0.0.0', UVM_API_PORT='8000', UVM_DB_URL='component',
                UVM_API_CURSOR_SECRET='component', UVM_AUTH_MODE='bearer', UVM_OIDC_DEPLOYMENT_MODE='external', UVM_UI_ROOT='/opt/uvm/ui')
            value = {'schema_version':1, 'profile':broker.PROFILE, 'main_bind':'0.0.0.0', 'main_port':8000, 'api_environment':environment}
            request = base/'request'; request.write_text(json.dumps(value)); request.chmod(0o600)
            result_file = base/'result'
            driver = base/'reader'
            driver.write_text('#!/usr/bin/python3\nimport importlib.util,sys,os,json\n'
                f's=importlib.util.spec_from_file_location("reader_fixture",{str(ROOT/"docker/g7/main_api_launcher.py")!r}); m=importlib.util.module_from_spec(s);s.loader.exec_module(m)\n'
                'm.read_request(sys.stdin.buffer)\n'
                f'open({str(result_file)!r},"w").write(json.dumps({{"pid":os.getpid(),"ppid":os.getppid()}}))\n')
            driver.chmod(0o700)
            test_block = block.replace(fixed, str(driver))
            script = 'set -Eeuo pipefail\nSTATE=$1; REQUEST=$2; CHILD_PIDS=(); CHILD_NAMES=()\n'+close+'''
emit_api_request() { cat "$REQUEST"; }
trap 'close_api_input || :' EXIT
''' + test_block + '''
wait "$api_broker_pid"
printf '%s:%s' "$$" "$api_broker_pid"
'''
            # Interrupt the exact registered consumer before releasing the
            # producer gate, then start again in the SAME unchanged namespace.
            before_gate = test_block[:test_block.index("printf 'G\\n'")]
            interrupted = 'set -Eeuo pipefail\nSTATE=$1; REQUEST=$2; CHILD_PIDS=(); CHILD_NAMES=()\n' + close + '''
emit_api_request() { cat "$REQUEST"; }
trap 'close_api_input || :' EXIT
''' + before_gate + '''
kill -KILL "$api_broker_pid"
if wait "$api_broker_pid"; then exit 93; fi
if close_api_input; then exit 94; fi
[[ ! ${api_input_producer:-} && ! -e "$STATE/api-launch-input" ]]
'''
            killed = subprocess.run(['bash','-c',interrupted,'fixture',directory,str(request)],capture_output=True,timeout=7)
            self.assertEqual(killed.returncode,0,killed.stderr)
            for _ in range(2):
                result = subprocess.run(['bash','-c',script,'fixture',directory,str(request)],capture_output=True,timeout=8)
                self.assertEqual(result.returncode,0,result.stderr)
                parent,child=map(int,result.stdout.split(b':'))
                self.assertEqual(json.loads(result_file.read_text()),{'pid':child,'ppid':parent})
                self.assertFalse((base/'api-launch-input').exists())
            # Unknown legacy participants are denied, never unlinked/recreated.
            for kind in ('fifo','regular','symlink'):
                path=base/'api-launch-input'
                if kind=='fifo':os.mkfifo(path,0o600)
                elif kind=='regular':path.write_bytes(b'unchanged')
                else:path.symlink_to(request)
                before=path.lstat()
                result=subprocess.run(['bash','-c',script,'fixture',directory,str(request)],capture_output=True,timeout=3)
                self.assertEqual(result.returncode,70,result.stderr)
                after=path.lstat()
                self.assertEqual((before.st_dev,before.st_ino,before.st_mode),(after.st_dev,after.st_ino,after.st_mode))
                path.unlink()

    def test_gate_eof_reaps_producer_and_leaves_no_persistent_transport(self):
        # Production coprocess and close path, interruption before broker launch.
        block = section('# No filesystem transport is created.', '\napi_launch_confirmed=0')
        block = block[:block.index('exec 9> >(')]
        close = section('close_api_input() {', '\nhandle_shutdown() {')
        with tempfile.TemporaryDirectory() as directory:
            script = 'set -Eeuo pipefail\nSTATE=$1\n'+close+'\nemit_api_request() { printf never; }\n'+block+'''
producer=$api_input_producer
close_api_input && exit 91
[[ ! ${api_input_producer:-} ]]
if wait "$producer"; then exit 92; fi
[[ ! -e "$STATE/api-launch-input" ]]
'''
            result=subprocess.run(['bash','-c',script,'fixture',directory],capture_output=True,timeout=7)
            self.assertEqual(result.returncode,0,result.stderr)
