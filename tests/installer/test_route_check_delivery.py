"""Delivery transport/process checks; not shared backend or TLS qualification."""
import io
import json
import os
import signal
import subprocess
import sys
import tarfile
import unittest
from unittest.mock import patch

from uvm.installer.route_check import (RouteCheckError, _process_snapshot,
    parse_proc_stat, stopped_tar_records, supervised_api_identity, _admitted_executable,
    validate_stopped_snapshot, _disarm)


def archive(entries=None):
    entries = entries or [('.', tarfile.DIRTYPE, 0, 1800, 0o710, b''),
        ('api', tarfile.DIRTYPE, 1800, 1800, 0o700, b''),
        ('lock', tarfile.REGTYPE, 0, 1800, 0o640, b''),
        ('supervisor.json', tarfile.REGTYPE, 0, 1800, 0o640, b'{"test":"transport only"}'),
        ('state.json', tarfile.REGTYPE, 0, 1800, 0o640, b'{"test":"transport only"}'),
        ('launch.json', tarfile.REGTYPE, 0, 1800, 0o640, b'{"test":"transport only"}'),
        ('launch-status.json', tarfile.REGTYPE, 0, 1800, 0o640, b'{"test":"transport only"}')]
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode='w', format=tarfile.PAX_FORMAT) as tar:
        for name, kind, uid, gid, mode, data in entries:
            item = tarfile.TarInfo(name); item.type = kind; item.uid = uid; item.gid = gid
            item.mode = mode; item.size = len(data)
            if kind in (tarfile.LNKTYPE, tarfile.SYMTYPE): item.linkname = '/private/sentinel'
            tar.addfile(item, io.BytesIO(data))
    return output.getvalue()


class StoppedTransportTests(unittest.TestCase):
    def test_exact_transport_in_memory_no_extraction(self):
        result = stopped_tar_records(archive())
        self.assertEqual(set(result), {'lock', 'supervisor.json', 'state.json', 'launch.json', 'launch-status.json'})
        self.assertEqual(result['lock'], b'')

    def assert_denied(self, raw):
        with self.assertRaises(RouteCheckError) as error:
            stopped_tar_records(raw)
        self.assertEqual(str(error.exception), 'route_check_failed:cleanup_failed')

    def test_untrusted_tar_records_cannot_escape_or_echo_secret(self):
        for name, kind in [('../sentinel', tarfile.REGTYPE), ('/state.json', tarfile.REGTYPE),
                ('api/seen.json', tarfile.REGTYPE), ('supervisor.json', tarfile.SYMTYPE),
                ('state.json', tarfile.LNKTYPE), ('lock', tarfile.FIFOTYPE)]:
            with self.subTest(name=name, kind=kind):
                self.assert_denied(archive([(name, kind, 0, 1800, 0o640, b'private-sentinel')]))

    def test_duplicate_aliases_and_wrong_modes_owners_deny(self):
        self.assert_denied(archive([('lock', tarfile.REGTYPE, 0, 1800, 0o640, b''),
            ('./lock', tarfile.REGTYPE, 0, 1800, 0o640, b'')]))
        for uid, gid, mode in [(1800, 1800, 0o640), (0, 0, 0o640), (0, 1800, 0o644)]:
            with self.subTest(uid=uid, gid=gid, mode=mode):
                self.assert_denied(archive([('state.json', tarfile.REGTYPE, uid, gid, mode, b'{}')]))

    def test_oversize_entry_archive_trailing_bytes_and_many_headers_deny(self):
        self.assert_denied(archive([('state.json', tarfile.REGTYPE, 0, 1800, 0o640, b'x' * 8193)]))
        self.assert_denied(archive() + b'private-sentinel' + bytes(512 - len(b'private-sentinel')))
        self.assert_denied(bytes(128 * 1024 + 512))
        self.assert_denied(archive([('api', tarfile.DIRTYPE, 1800, 1800, 0o700, b'')] * 33))

    def test_pax_cannot_override_authority(self):
        output = io.BytesIO()
        with tarfile.open(fileobj=output, mode='w', format=tarfile.PAX_FORMAT) as tar:
            item = tarfile.TarInfo('state.json'); item.uid = 0; item.gid = 1800; item.mode = 0o640
            item.size = 2; item.pax_headers = {'uid': '0'}; tar.addfile(item, io.BytesIO(b'{}'))
        self.assert_denied(output.getvalue())


class ProcessBoundaryTests(unittest.TestCase):
    def test_real_current_process_read_uid_gid_and_field22(self):
        value = _process_snapshot(os.getpid(), os.getuid(), os.getgid())
        self.assertEqual(value['pid'], os.getpid())
        self.assertEqual(value['ppid'], os.getppid())
        self.assertGreater(value['proc_start_ticks'], 0)
        with self.assertRaises(RouteCheckError):
            _process_snapshot(os.getpid(), os.getuid() + 123, os.getgid())

    def test_comm_parentheses_and_invalid_process_states(self):
        fields = ['S', '2', '3', '4'] + ['0'] * 15 + ['98765']
        value = parse_proc_stat(b'42 (name ) with spaces)) ' + ' '.join(fields).encode(), 42)
        self.assertEqual(value['proc_start_ticks'], 98765)
        for state in ('Z', 'X', 'T', 't'):
            with self.subTest(state=state), self.assertRaises(RouteCheckError):
                parse_proc_stat(('42 (name) ' + state + ' ' + ' '.join(fields[1:])).encode(), 42)

    def test_actual_stopped_child_is_rejected_then_cleaned(self):
        child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'])
        try:
            original = _process_snapshot(child.pid, os.getuid(), os.getgid())
            os.kill(child.pid, signal.SIGSTOP)
            _, status = os.waitpid(child.pid, os.WUNTRACED)
            self.assertTrue(os.WIFSTOPPED(status))
            with self.assertRaises(RouteCheckError):
                _process_snapshot(child.pid, os.getuid(), os.getgid())
            os.kill(child.pid, signal.SIGCONT)
            self.assertEqual(_process_snapshot(child.pid, os.getuid(), os.getgid())['proc_start_ticks'],
                original['proc_start_ticks'])
        finally:
            if child.poll() is None:
                os.kill(child.pid, signal.SIGCONT); child.terminate()
            child.wait(timeout=10)

    def test_supervision_rejects_wrappers_wrong_session_and_reuse(self):
        sup = {'pid': 10, 'proc_start_ticks': 100, 'ppid': 1, 'pgid': 10, 'sid': 10,
            'command': (b'/bin/bash', b'/usr/local/bin/uvm-g7-entrypoint')}
        api = {'pid': 20, 'proc_start_ticks': 200, 'ppid': 10, 'pgid': 20, 'sid': 20,
            'command': (b'/opt/uvm/venv/bin/python', b'-m', b'uvm.api.main_server',
                b'--host', b'0.0.0.0', b'--port', b'8000', b'--workers', b'1', b'--no-proxy-headers')}
        with patch('uvm.installer.route_check._admitted_executable'), patch('uvm.installer.route_check._process_snapshot', side_effect=[sup, api, api, sup]):
            self.assertEqual(supervised_api_identity(20, 10)['api'], {'pid': 20, 'proc_start_ticks': 200})
        for changed in ({'ppid': 99}, {'sid': 99}, {'pgid': 99}, {'command': (b'setsid',)}):
            with self.subTest(changed=changed), patch('uvm.installer.route_check._process_snapshot',
                    side_effect=[sup, {**api, **changed}]), self.assertRaises(RouteCheckError):
                supervised_api_identity(20, 10)
        with patch('uvm.installer.route_check._admitted_executable'), patch('uvm.installer.route_check._process_snapshot',
                side_effect=[sup, api, {**api, 'proc_start_ticks': 201}]), self.assertRaises(RouteCheckError):
            supervised_api_identity(20, 10)


class FixedExecutableDenialTests(unittest.TestCase):
    def test_permission_failure_cannot_fall_back_to_argv(self):
        with patch('uvm.installer.route_check.os.stat', side_effect=PermissionError), self.assertRaises(RouteCheckError) as error:
            _admitted_executable(123)
        self.assertEqual(str(error.exception), 'route_check_failed:process_not_ready')


def stopped_records(profile='normal_local_https'):
    from uvm.auth import route_check_records as shared
    from datetime import datetime,timezone
    import hashlib
    api = {'pid':3, 'proc_start_ticks':300}
    runtime = {'container_id':'a'*64, 'started_at':'2026-11-19T01:02:03.123456789Z',
        'image':{'kind':'config','id':'sha256:'+'b'*64,'config_id':'sha256:'+'b'*64},
        'resources_sha256':'c'*64}
    disarmed = shared.record(runtime_boot_nonce=shared.new_nonce(),api=api,runtime=runtime,reason='shutdown',
        operation_id='00000000-0000-4000-8000-000000000001')
    if profile=='normal_local_loopback':
        disarmed=shared.record(runtime_boot_nonce=None,api=None,runtime=None,reason='startup',operation_id=None)
    supervisor = shared.record(supervisor={'pid':2,'proc_start_ticks':200},api=api,
        clock_ticks_per_second=os.sysconf('SC_CLK_TCK'),phase='stopped')
    state = shared.record(state='disarmed',arm=None,disarmed=disarmed,closing_reason=None)
    launch={'schema_version':1,'profile':shared.LAUNCH_RECORD_PROFILE,'readiness_profile':profile,
        'recipe':shared.MAIN_API_RECIPE,'entrypoint':{'pid':1,'proc_start_ticks':100},
        'supervisor':supervisor['supervisor'],'api':api,'clock_ticks_per_second':os.sysconf('SC_CLK_TCK'),
        'executable':{'device':1,'inode':2,'mode':0o755,'uid':0,'gid':0,'size':100},
        'exec_utc_ns':int(datetime(2026,11,19,1,2,4,tzinfo=timezone.utc).timestamp())*1_000_000_000,'exec_boottime_ns':1000}
    status={'schema_version':1,'profile':shared.LAUNCH_PROFILE,
        **{key:launch[key] for key in ('entrypoint','supervisor','api')},'phase':'stopped','result':'clean_stop',
        'updated_utc_ns':launch['exec_utc_ns']+1_000_000_000,'updated_boottime_ns':2000}
    completion={'schema_version':1,'profile':shared.COMPLETION_PROFILE,
        **{key:launch[key] for key in ('entrypoint','supervisor','api')},'operation_id':'d'*64,
        'launch_sha256':hashlib.sha256(shared.canonical(launch)).hexdigest(),
        'status_sha256':hashlib.sha256(shared.canonical(status)).hexdigest(),'broker_wait_exit_code':0}
    return {'supervisor.json':supervisor,'state.json':state,'launch.json':launch,'launch-status.json':status},runtime,shared.canonical(completion)


def records_tar(records):
    entries=[('.',tarfile.DIRTYPE,0,1800,0o710,b''),('api',tarfile.DIRTYPE,1800,1800,0o700,b''),
        ('lock',tarfile.REGTYPE,0,1800,0o640,b'')]
    for name,value in records.items():
        api=name.startswith('api/')
        entries.append((name,tarfile.REGTYPE,1800 if api else 0,1800,0o600 if api else 0o640,
            __import__('uvm.auth.route_check_records',fromlist=['canonical']).canonical(value)))
    return archive(entries)


class SharedStoppedSchemaTests(unittest.TestCase):
    def setUp(self):
        # Explicit source fixture only: production requires its protected COPY.
        from uvm.auth import route_check_records as canonical_fixture
        fixture = patch('uvm.installer.route_check._shared',return_value=canonical_fixture)
        fixture.start();self.addCleanup(fixture.stop)
    def test_shared_schema_and_exact_original_runtime_join(self):
        records,runtime,completion=stopped_records()
        self.assertEqual(validate_stopped_snapshot(records_tar(records),runtime,completion,0)['state'],'stopped_disarmed')
        changed={**runtime,'started_at':'2026-11-19T01:02:03.123456788Z'}
        with self.assertRaises(RouteCheckError):validate_stopped_snapshot(records_tar(records),changed,completion,0)
        records['api/boot.json']={'unexpected':'observation'}
        with self.assertRaises(RouteCheckError):validate_stopped_snapshot(records_tar(records),runtime,completion,0)

    def test_loopback_requires_current_completion_without_fabricating_https_observation(self):
        records,runtime,completion=stopped_records('normal_local_loopback')
        self.assertEqual(validate_stopped_snapshot(records_tar(records),runtime,completion,0)['readiness_profile'],'normal_local_loopback')
        for wait_result in (False,1,None,b'0'):
            with self.subTest(wait_result=repr(wait_result)),self.assertRaises(RouteCheckError):
                validate_stopped_snapshot(records_tar(records),runtime,completion,wait_result)
        for envelope in (b'',b'G7_SHUTDOWN=controlled',completion+b'\n',completion.replace(b'"operation_id"',b'"unknown"')):
            with self.subTest(envelope_size=len(envelope)),self.assertRaises(RouteCheckError):
                validate_stopped_snapshot(records_tar(records),runtime,envelope,0)
        with self.assertRaises(RouteCheckError):
            validate_stopped_snapshot(records_tar(records),{**runtime,'started_at':'2026-11-20T01:02:03Z'},completion,0)

    def test_missing_binding_corrupt_records_and_wrong_process_deny_static(self):
        records,runtime,completion=stopped_records();records['state.json']['disarmed']['runtime']=None
        with self.assertRaises(RouteCheckError):validate_stopped_snapshot(records_tar(records),runtime,completion,0)
        records,runtime,completion=stopped_records();records['supervisor.json']['api']={**records['supervisor.json']['api'],'proc_start_ticks':301}
        with self.assertRaises(RouteCheckError):validate_stopped_snapshot(records_tar(records),runtime,completion,0)
        with self.assertRaises(RouteCheckError)as error:validate_stopped_snapshot(archive(),runtime,completion,0)
        self.assertEqual(str(error.exception),'route_check_failed:cleanup_failed')
        records,runtime,completion=stopped_records('verification_local_loopback')
        with self.assertRaises(RouteCheckError):validate_stopped_snapshot(records_tar(records),runtime,completion,0)

    def test_cleanup_failure_leaves_barrier_never_completed_success(self):
        from uvm.auth.route_check_records import record
        from unittest.mock import Mock
        arm={'operation_id':'00000000-0000-4000-8000-000000000001'}
        state=record(state='armed',arm=arm,disarmed=None,closing_reason=None)
        store=Mock();store.cleanup_observations.side_effect=OSError('private-sentinel')
        with self.assertRaises(OSError):_disarm(store,state,'completed')
        self.assertEqual(store.publish_state.call_count,1)
        self.assertEqual(store.publish_state.call_args.args[0]['state'],'closing')
        self.assertEqual(store.method_calls[0][0],'publish_state')
        self.assertEqual(store.method_calls[1][0],'cleanup_observations')
