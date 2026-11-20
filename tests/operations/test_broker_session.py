"""Real owned Linux child waits/Store fixtures; not PID1, FD-exec or Docker proof."""
import copy
import hashlib
import os
from pathlib import Path
import pickle
import secrets
import tempfile
import time
import unittest
from unittest.mock import patch

from uvm.auth import route_check_records as rc
from tests.operations.test_route_check import ProcessFixture


@unittest.skipUnless(os.geteuid()==0,'owned root/UID1800 fixture')
class BrokerSessionTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='volt-session-owned-')
        os.chmod(self.temp.name,0o711)
        self.fixture=ProcessFixture(Path(self.temp.name)/'route').start()
        self.session=self.fixture.session
    def tearDown(self):
        self.fixture.close();self.temp.cleanup()
    def frame(self,**changes):
        value={'schema_version':1,'profile':rc.TERMINAL_PROFILE,
            **{k:self.fixture.launch[k] for k in ('entrypoint','supervisor','api')},
            'operation_id':secrets.token_hex(32),'result':'success','reason':'none'}
        return rc.encode_terminal_frame({**value,**changes})
    def reap(self):
        self.fixture.command('quit')
        # Actual waitpid is exclusively owned by the canonical session.
        result=self.session.reap_api(block=True)
        self.fixture.process.returncode=os.waitstatus_to_exitcode(result[1])
        with rc.locked_store(role='root') as store:store.cleanup_observations(remove_boot=True)
    def test_clean_actual_reap_progress_then_candidate_not_completion(self):
        self.session.register_controlled_request('stop');self.reap()
        self.session.publish_api_stopped()
        with rc.locked_store(role='root') as store:
            progress=store.read_api_stop_progress()
            self.assertEqual(progress['api'],self.fixture.identity)
            self.assertFalse(store.current_state()['backend_ready'])
            self.assertEqual(store.read_launch_status()['phase'],'api_stopped')
        frame=self.frame();self.session.accept_terminal(frame)
        raw=self.session.finish_clean();status=rc.validate_record('launch_status',raw)
        self.assertEqual(status['result'],'clean_stop')
        self.assertIsNone(self.session.failure)
        self.assertEqual(self.session.clean_exit_code(),0)
        request=rc.canonical({'schema_version':1,'profile':rc.COMPLETION_REQUEST_PROFILE,
            **{k:self.fixture.launch[k] for k in ('entrypoint','supervisor','api')},
            'operation_id':self.session.operation_id})
        with rc.locked_store(role='root') as store:
            # Original broker is THIS still-live process; raw candidate cannot
            # become post-reap completion merely by requesting an envelope.
            with self.assertRaises(rc.RouteCheckError):store.read_completion_candidate(request)
        envelope={'schema_version':1,'profile':rc.COMPLETION_PROFILE,
            **{k:self.fixture.launch[k] for k in ('entrypoint','supervisor','api')},
            'operation_id':self.session.operation_id,'launch_sha256':hashlib.sha256(rc.canonical(self.fixture.launch)).hexdigest(),
            'status_sha256':hashlib.sha256(raw).hexdigest(),'broker_wait_exit_code':0}
        self.assertEqual(rc.validate_completion_envelope(rc.canonical(envelope),launch=self.fixture.launch,status=status),envelope)
        with self.assertRaises(rc.RouteCheckError):self.session.finish_clean()
    def test_unrequested_zero_is_sticky_and_truthfully_mapped(self):
        self.reap();self.assertEqual(self.session.failure,'unexpected_api_exit')
        with self.assertRaises(rc.RouteCheckError):self.session.register_controlled_request('stop')
        self.session.publish_api_stopped()
        with rc.locked_store(role='root') as store:
            self.assertEqual(store.read_launch_status()['result'],'cleanup_failed')
        self.session.accept_terminal(self.frame())
        with self.assertRaises(rc.RouteCheckError):self.session.finish_clean()
        self.assertEqual(self.session.failure,'unexpected_api_exit')
    def test_registered_quiesce_late_zero_can_stop_cleanly(self):
        self.session.register_controlled_request('quiesce')
        with rc.locked_store(role='root') as store:base=store.read_launch_status()
        self.session.publish_status({**base,'phase':'quiesce_failed','result':'quiesce_timeout',
            'updated_utc_ns':time.time_ns(),'updated_boottime_ns':rc.boottime_ns()})
        self.reap();self.assertIsNone(self.session.failure)
        self.session.publish_api_stopped();self.session.accept_terminal(self.frame())
        self.assertEqual(rc.validate_record('launch_status',self.session.finish_clean())['result'],'clean_stop')
    def test_no_recreation_serialization_fabricated_reap_or_helper_seal(self):
        with self.assertRaises(rc.RouteCheckError):rc.broker_session(self.fixture.launch)
        for operation in (lambda:copy.copy(self.session),lambda:pickle.dumps(self.session)):
            with self.assertRaises(TypeError):operation()
        with self.assertRaises(rc.RouteCheckError):self.session.note_api_reaped(self.fixture.identity['pid'],0)
        self.assertEqual(self.session.failure,'cleanup_failed')
        with rc.locked_store(role='root') as store:
            base=store.read_launch_status()
            with self.assertRaises(rc.RouteCheckError):store.publish_launch_status({**base,'phase':'stopped','result':'clean_stop'})
    def test_first_io_failure_leaves_old_disk_but_poison_blocks_later_success(self):
        with rc.locked_store(role='root') as store:base=store.read_launch_status()
        self.session.register_controlled_request('stop')
        with patch.object(rc._Store,'_publish',side_effect=OSError('owned injected write failure')):
            with self.assertRaises(rc.RouteCheckError):self.session.publish_status({**base,'phase':'failed','result':'forced_stop',
                'updated_utc_ns':time.time_ns(),'updated_boottime_ns':rc.boottime_ns()})
        self.assertEqual(self.session.failure,'forced_stop')
        with rc.locked_store(role='root') as store:self.assertEqual(store.read_launch_status(),base)
        self.reap();self.session.publish_api_stopped();self.session.accept_terminal(self.frame())
        with self.assertRaises(rc.RouteCheckError):self.session.finish_clean()
    def test_bad_frame_never_replays_into_success(self):
        self.session.register_controlled_request('stop');self.reap();self.session.publish_api_stopped()
        with self.assertRaises(rc.RouteCheckError):self.session.accept_terminal(self.frame()[:-1])
        self.assertEqual(self.session.failure,'terminal_channel_failed')
        self.session.accept_terminal(self.frame())
        with self.assertRaises(rc.RouteCheckError):self.session.finish_clean()

    def test_external_root_child_cannot_write_or_adopt_parent_session(self):
        pid=os.fork()
        if pid==0:
            try:
                with rc.locked_store(role='root') as store:
                    value=store.read_launch_status()
                    try:store.publish_launch_status({**value,'phase':'failed','result':'cleanup_failed'})
                    except rc.RouteCheckError:pass
                    else:os._exit(71)
                try:rc.broker_session(self.fixture.launch)
                except rc.RouteCheckError:os._exit(0)
                os._exit(72)
            except BaseException:os._exit(73)
        self.assertEqual(os.waitstatus_to_exitcode(os.waitpid(pid,0)[1]),0)
        self.assertIsNone(self.session.failure)
        with rc.locked_store(role='root') as store:self.assertEqual(store.read_launch_status()['phase'],'running')
    def test_parent_ready_absence_mode_failure_and_broker_ack(self):
        marker=Path(self.fixture.ready_temp.name)/'ready'
        with rc.locked_store(role='root') as store:self.assertTrue(store.read_broker_ready())
        marker.unlink()
        with rc.locked_store(role='root') as store:self.assertFalse(store.read_broker_ready())
        marker.touch(mode=0o644)
        with self.assertRaises(rc.RouteCheckError):rc.parent_ready_condition()
        marker.chmod(0o600)
        with self.assertRaises(rc.RouteCheckError):rc.parent_ready_condition(require_absent=True)
        (marker.parent/'critical-failed').touch(mode=0o600)
        with self.assertRaises(rc.RouteCheckError):rc.parent_ready_condition()
    def test_first_dirty_all_preterminal_phases_and_fsync_boundaries(self):
        # Each subcase owns a distinct real launch/session. Fault injection is
        # narrowly at actual file/rename/directory-sync boundaries, not wait mocks.
        import contextlib
        for phase in ('starting','ready','quiescing','quiesce_failed','stopping','api_stopped'):
            for boundary in ('before_write','file_fsync','replace','directory_fsync'):
                with self.subTest(phase=phase,boundary=boundary):
                    f=ProcessFixture(Path(self.temp.name)/(phase+'-'+boundary))
                    try:
                        f.start(ready=phase!='starting');s=f.session
                        s.register_controlled_request('quiesce' if phase=='quiesce_failed' else 'stop')
                        if phase not in ('starting','ready'):
                            with rc.locked_store(role='root') as store:base=store.read_launch_status()
                            s.publish_status({**base,'phase':phase if phase!='api_stopped' else 'stopping',
                                'result':'quiesce_timeout' if phase=='quiesce_failed' else 'none',
                                'updated_utc_ns':time.time_ns(),'updated_boottime_ns':rc.boottime_ns()})
                        if phase=='api_stopped':
                            f.command('quit');result=s.reap_api(block=True);f.process.returncode=os.waitstatus_to_exitcode(result[1])
                            with rc.locked_store(role='root') as store:store.cleanup_observations(remove_boot=True)
                            s.publish_api_stopped()
                        with rc.locked_store(role='root') as store:base=store.read_launch_status()
                        fault=OSError('owned injected boundary')
                        if boundary=='before_write':patcher=patch.object(rc._Store,'_publish',side_effect=fault)
                        elif boundary=='file_fsync':patcher=patch.object(rc.os,'fsync',side_effect=fault)
                        elif boundary=='replace':patcher=patch.object(rc.os,'replace',side_effect=fault)
                        else:patcher=patch.object(rc,'_sync',side_effect=fault)
                        with patcher:
                            with self.assertRaises(rc.RouteCheckError):s.publish_status({**base,'phase':'failed','result':'forced_stop',
                                'updated_utc_ns':time.time_ns(),'updated_boottime_ns':rc.boottime_ns()})
                        self.assertEqual(s.failure,'forced_stop')
                        self.assertNotEqual(s.clean_exit_code(),0)
                        if phase!='api_stopped':
                            f.command('quit');result=s.reap_api(block=True);f.process.returncode=os.waitstatus_to_exitcode(result[1])
                            with rc.locked_store(role='root') as store:store.cleanup_observations(remove_boot=True)
                        s.publish_api_stopped()
                        s.accept_terminal(rc.encode_terminal_frame({'schema_version':1,'profile':rc.TERMINAL_PROFILE,
                            **{k:f.launch[k] for k in ('entrypoint','supervisor','api')},
                            'operation_id':secrets.token_hex(32),'result':'success','reason':'none'}))
                        with self.assertRaises(rc.RouteCheckError):s.finish_clean()
                    finally:f.close()
    def test_visible_clean_candidate_fsync_failure_does_not_acknowledge(self):
        self.session.register_controlled_request('stop');self.reap();self.session.publish_api_stopped()
        self.session.accept_terminal(self.frame())
        with patch.object(rc,'_sync',side_effect=OSError('owned post-rename directory fsync')):
            with self.assertRaises(rc.RouteCheckError):self.session.finish_clean()
        with rc.locked_store(role='root') as store:
            self.assertEqual(store.read_launch_status()['result'],'clean_stop')
            self.assertFalse(store.current_state()['backend_ready'])
        self.assertEqual(self.session.failure,'publication_failed')
        self.assertNotEqual(self.session.clean_exit_code(),0)
        with self.assertRaises(rc.RouteCheckError):self.session.finish_clean()

    def test_real_broker_child_exit_then_readonly_candidate_bytes_hash_join(self):
        directory=Path(self.temp.name)/'completed-child';operation=secrets.token_hex(32)
        broker=os.fork()
        if broker==0:
            f=None
            try:
                f=ProcessFixture(directory).start();s=f.session;s.register_controlled_request('stop')
                f.command('quit');reaped=s.reap_api(block=True);f.process.returncode=os.waitstatus_to_exitcode(reaped[1])
                with rc.locked_store(role='root') as store:store.cleanup_observations(remove_boot=True)
                s.publish_api_stopped()
                s.accept_terminal(rc.encode_terminal_frame({'schema_version':1,'profile':rc.TERMINAL_PROFILE,
                    **{k:f.launch[k] for k in ('entrypoint','supervisor','api')},
                    'operation_id':operation,'result':'success','reason':'none'}))
                s.finish_clean();code=s.clean_exit_code();f.close();os._exit(code)
            except BaseException:
                if f:f.close()
                os._exit(71)
        self.assertEqual(os.waitstatus_to_exitcode(os.waitpid(broker,0)[1]),0)
        # Actual original broker has now exited and been reaped by THIS root
        # fixture parent. This is not a Docker/PID1 log/stop consumer substitute.
        with patch.object(rc,'DIRECTORY',directory),rc.locked_store(role='root') as store:
            launch=store.read_launch()
            request=rc.canonical({'schema_version':1,'profile':rc.COMPLETION_REQUEST_PROFILE,
                **{k:launch[k] for k in ('entrypoint','supervisor','api')},'operation_id':operation})
            result=store.read_completion_candidate(request)
            self.assertEqual(result['status_raw'],rc.canonical(result['status']))
            self.assertEqual(result['envelope']['status_sha256'],hashlib.sha256(result['status_raw']).hexdigest())
            self.assertEqual(result['envelope']['operation_id'],operation)
            wrong={**result['envelope'],'status_sha256':'0'*64}
            with self.assertRaises(rc.RouteCheckError):rc.validate_completion_envelope(rc.canonical(wrong),launch=launch,status=result['status'])
            with self.assertRaises(rc.RouteCheckError):rc.validate_completion_request(request+b' ',launch=launch)
    def test_stale_parent_ready_cannot_be_adopted_at_broker_launch(self):
        f=ProcessFixture(Path(self.temp.name)/'stale-ready')
        try:
            (Path(f.ready_temp.name)/'ready').touch(mode=0o600)
            with self.assertRaises(rc.RouteCheckError):f.start()
            with rc.locked_store(role='root') as store:
                with self.assertRaises(rc.RouteCheckError):store.read_launch()
        finally:f.close()

    def test_transient_entry_authority_failure_cannot_recover_clean_authority(self):
        for method in ('register','reap','status','supervisor','progress','terminal','finish','ready','exit'):
            with self.subTest(method=method):
                f=ProcessFixture(Path(self.temp.name)/('authority-'+method))
                try:
                    f.start();s=f.session
                    with rc.locked_store(role='root') as store:status=store.read_launch_status()
                    calls={
                        'register':lambda:s.register_controlled_request('stop'),
                        'reap':lambda:s.reap_api(),
                        'status':lambda:s.publish_status(status),
                        'supervisor':lambda:s.publish_supervisor(f.supervisor),
                        'progress':lambda:s.publish_api_stopped(),
                        'terminal':lambda:s.accept_terminal(b'bad'),
                        'finish':lambda:s.finish_clean(),
                        'ready':lambda:s.acknowledge_parent_ready(),
                        'exit':lambda:s.clean_exit_code()}
                    with patch.object(rc,'_original_broker',side_effect=rc.RouteCheckError('process_not_ready')):
                        if method=='exit':self.assertNotEqual(calls[method](),0)
                        else:
                            with self.assertRaises(rc.RouteCheckError):calls[method]()
                    self.assertEqual(s.failure,'publication_failed')
                    # Restored parent validation permits actual termination and
                    # reap, never restoration of clean eligibility.
                    s.register_controlled_request('stop');f.command('quit')
                    result=s.reap_api(block=True);f.process.returncode=os.waitstatus_to_exitcode(result[1])
                    with rc.locked_store(role='root') as store:store.cleanup_observations(remove_boot=True)
                    s.publish_api_stopped()
                    s.accept_terminal(rc.encode_terminal_frame({'schema_version':1,'profile':rc.TERMINAL_PROFILE,
                        **{k:f.launch[k] for k in ('entrypoint','supervisor','api')},
                        'operation_id':secrets.token_hex(32),'result':'success','reason':'none'}))
                    with self.assertRaises(rc.RouteCheckError):s.finish_clean()
                    self.assertNotEqual(s.clean_exit_code(),0)
                finally:f.close()
    def test_failed_final_parent_check_cannot_reopen_after_clean_candidate(self):
        self.session.register_controlled_request('stop');self.reap();self.session.publish_api_stopped()
        self.session.accept_terminal(self.frame());self.session.finish_clean()
        with patch.object(rc,'_original_broker',side_effect=rc.RouteCheckError('process_not_ready')):
            self.assertNotEqual(self.session.clean_exit_code(),0)
        self.assertEqual(self.session.failure,'publication_failed')
        self.assertNotEqual(self.session.clean_exit_code(),0)
