"""Real fixed-FD3 transport with canonical decoder; no Store/lifecycle authority.

Same-UID host children and synthetic API correlation R; not ROOT/PID1/API proof.
"""
import fcntl
import importlib.util
import os
from pathlib import Path
import select
import signal
import time
import unittest
from uvm.auth import route_check_records as records

ROOT=Path(__file__).resolve().parents[2]
SPEC=importlib.util.spec_from_file_location('channel_broker_fixture',ROOT/'docker/g7/main_api_launcher.py')
broker=importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(broker)


def reaped(pid):
    deadline=time.monotonic()+3
    while time.monotonic()<deadline:
        found,status=os.waitpid(pid,os.WNOHANG)
        if found:return os.waitstatus_to_exitcode(status)
        time.sleep(.01)
    raise AssertionError('registered channel component did not finish')


def cleanup(pid):
    try:
        found,_=os.waitpid(pid,os.WNOHANG)
        if found:return
    except ChildProcessError:return
    descriptor=os.pidfd_open(pid)
    try:signal.pidfd_send_signal(descriptor,signal.SIGKILL,None,0)
    finally:os.close(descriptor)
    os.waitpid(pid,0)


def frame(launch):
    return {'schema_version':1,'profile':records.TERMINAL_PROFILE,**launch,
        'operation_id':'0'*64,'result':'success','reason':'none'}


class TerminalChannelTests(unittest.TestCase):
    def spawn(self, mode):
        parent=records.validated_proc_identity(os.getpid())
        read,write=os.pipe();report_read,report_write=os.pipe();pid=os.fork()
        if pid==0:
            channel=None
            try:
                os.close(write);os.close(report_read)
                if read!=3:os.dup2(read,3);os.close(read)
                launch={'entrypoint':parent,'supervisor':records.validated_proc_identity(os.getpid()),
                    'api':{'pid':parent['pid']+100000000,'proc_start_ticks':1}}
                channel=broker.TerminalChannel(records,parent)
                if not fcntl.fcntl(3,fcntl.F_GETFD)&fcntl.FD_CLOEXEC:os._exit(91)
                os.write(report_write,b'C')
                if mode=='eof':
                    deadline=time.monotonic()+2
                    while time.monotonic()<deadline:
                        if select.select([3],[],[],.01)[0]:
                            if channel.read_complete(launch)is not None:os._exit(92)
                            os.write(report_write,b'P');break
                    else:os._exit(93)
                deadline=time.monotonic()+2
                while time.monotonic()<deadline:
                    if select.select([3],[],[],.01)[0]:
                        raw=channel.read_complete(launch)
                        if raw is not None:
                            if raw!=records.encode_terminal_frame(frame(launch)):os._exit(94)
                            try:channel.read_complete(launch)
                            except broker.LaunchError:pass
                            else:os._exit(95)
                            os.write(report_write,b'S');os._exit(0)
                os._exit(96)
            except (broker.LaunchError,records.RouteCheckError):os._exit(2)
            except BaseException:os._exit(97)
            finally:
                if channel is not None:channel.close()
        os.close(read);os.close(report_write)
        launch={'entrypoint':parent,'supervisor':records.validated_proc_identity(pid),
            'api':{'pid':parent['pid']+100000000,'proc_start_ticks':1}}
        self.assertTrue(select.select([report_read],[],[],2)[0])
        self.assertEqual(os.read(report_read,1),b'C')
        return pid,write,report_read,launch

    def test_complete_bytes_are_pending_until_eof_then_consumed_once(self):
        pid,write,report,launch=self.spawn('eof')
        try:
            os.write(write,records.encode_terminal_frame(frame(launch)))
            self.assertTrue(select.select([report],[],[],2)[0]);self.assertEqual(os.read(report,1),b'P')
            os.close(write);write=None
            self.assertEqual(reaped(pid),0);self.assertEqual(os.read(report,1),b'S')
        finally:
            if write is not None:os.close(write)
            os.close(report);cleanup(pid)

    def test_truncation_extra_frame_and_cross_launch_never_complete(self):
        for case in ('empty','prefix','truncated','extra','wrong-R','oversize'):
            with self.subTest(case=case):
                pid,write,report,launch=self.spawn('reject')
                try:
                    value=frame(launch)
                    if case=='wrong-R':value['api']={**value['api'],'proc_start_ticks':2}
                    raw=records.encode_terminal_frame(value)
                    if case=='empty':raw=b''
                    elif case=='prefix':raw=raw[:3]
                    elif case=='truncated':raw=raw[:-1]
                    elif case=='extra':raw+=records.encode_terminal_frame(value)
                    elif case=='oversize':raw=(2049).to_bytes(4,'big')+b'{}'
                    if raw:os.write(write,raw)
                    os.close(write);write=None
                    self.assertEqual(reaped(pid),2)
                finally:
                    if write is not None:os.close(write)
                    os.close(report);cleanup(pid)
