"""Actual Linux children/FD3/pidfd, with publication and admission substituted.

This tests Delivery control flow, not ROOT native Store/custody/tini authority.
Canonical terminal decoding is real; the fixture session alone reaps its child.
"""
import importlib.util
import json
import os
from pathlib import Path
import select
import signal
import time
import types
import unittest
from unittest.mock import patch
from uvm.auth import route_check_records as canonical

ROOT=Path(__file__).resolve().parents[2]
SPEC=importlib.util.spec_from_file_location('terminal_session_broker',ROOT/'docker/g7/main_api_launcher.py')
broker=importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(broker)


def wait(pid, seconds=4):
    end=time.monotonic()+seconds
    while time.monotonic()<end:
        found,status=os.waitpid(pid,os.WNOHANG)
        if found:return os.waitstatus_to_exitcode(status)
        time.sleep(.01)
    raise AssertionError('registered broker did not finish')


def cleanup(pid):
    try:
        found,_=os.waitpid(pid,os.WNOHANG)
        if found:return
    except ChildProcessError:return
    fd=os.pidfd_open(pid)
    try:signal.pidfd_send_signal(fd,signal.SIGKILL,None,0)
    finally:os.close(fd)
    os.waitpid(pid,0)


class BrokerTerminalSessionTests(unittest.TestCase):
    def start(self,case):
        read,write=os.pipe();report_read,report_write=os.pipe();driver=os.fork()
        if driver==0:
            api_pid=None
            try:
                os.close(write);os.close(report_read)
                if read!=3:os.dup2(read,3);os.close(read)
                # A real original API child, with the protocol FD CLOSED.
                ready_read,ready_write=os.pipe();api_pid=os.fork()
                if api_pid==0:
                    os.close(3);os.close(report_write);os.close(ready_read)
                    signal.signal(signal.SIGTERM,(lambda *_:None) if case=='repeated-term' else (lambda *_:os._exit(0)))
                    os.write(ready_write,b'R');os.close(ready_write)
                    while True:signal.pause()
                os.close(ready_write)
                if os.read(ready_read,1)!=b'R':os._exit(92)
                os.close(ready_read)
                api=canonical.validated_proc_identity(api_pid);api_fd=os.pidfd_open(api_pid)
                entrypoint=canonical.validated_proc_identity(os.getppid())
                supervisor=canonical.validated_proc_identity(os.getpid())
                value={k:v for k,v in [('entrypoint',entrypoint),('supervisor',supervisor),('api',api)]}
                class Session:
                    failure=None;result=None;requested=False;finished=False
                    def note_failure(self,reason):
                        if self.failure is None:self.failure=reason
                    def register_controlled_request(self,kind):
                        if self.reap_api() is None:self.requested=True
                    def publish_status(self,status):
                        if case=='publication-failure':raise OSError('private-sentinel')
                    def publish_supervisor(self,status):pass
                    def reap_api(self,*,block=False):
                        if self.result is None:
                            pid,status=os.waitpid(api_pid,0 if block else os.WNOHANG)
                            if pid:
                                self.result=(pid,status)
                                if os.waitstatus_to_exitcode(status)!=0:self.note_failure('api_nonzero')
                                elif not self.requested:self.note_failure('unexpected_api_exit')
                        return self.result
                    def acknowledge_parent_ready(self):return False
                    def publish_api_stopped(self):
                        if self.result is None:raise AssertionError('not reaped')
                        os.write(report_write,b'P')
                    def accept_terminal(self,raw):
                        got=canonical.decode_terminal_frame(raw,launch=value)
                        if got['result']!='success':self.note_failure('cleanup_failed')
                    def finish_clean(self):
                        if self.failure or not self.requested:raise AssertionError('unclean seal')
                        self.finished=True;os.write(report_write,b'F')
                    def clean_exit_code(self):return 0 if self.finished and not self.failure else 70
                session=Session()
                records=types.SimpleNamespace(**{name:getattr(canonical,name) for name in
                    ('validated_proc_identity','proc_live','proc_metadata','decode_terminal_frame','boottime_ns','record')})
                def derive(request):
                    if request!={'fixture':'validated-bootstrap'}:raise AssertionError('wrong bootstrap')
                    return 'normal_bearer'
                records.derive_launch_readiness=derive
                if case=='repeated-term':
                    # Explicit COMPONENT clock acceleration:30 protocol seconds
                    # equal0.3 host seconds; child/signal/reap are actual Linux.
                    records.boottime_ns=lambda:int(time.monotonic()*100*1_000_000_000)
                def launched(e,s,a,executable,profile):
                    if (e,s,a,profile)!=(entrypoint,supervisor,api,'normal_bearer'):raise AssertionError('wrong launch binding')
                    os.write(report_write,json.dumps(value).encode()+b'\n')
                    if case=='unsolicited-zero':os.kill(api_pid,signal.SIGTERM)
                    return value,session
                control=types.SimpleNamespace(broker_prepare=lambda *_:None,broker_launched=launched,
                    broker_begin=lambda *_:None,broker_disarm=lambda *_:None,
                    _status=lambda r,v,phase,result:{'phase':phase,'result':result})
                with patch.object(broker,'launch',return_value=(api_pid,api_fd,api,{})):
                    result=broker.supervise({'fixture':'validated-bootstrap'},records,control)
                # The API status MUST have been consumed by the fixture session.
                try:os.waitpid(api_pid,os.WNOHANG)
                except ChildProcessError:pass
                else:os._exit(93)
                os._exit(result)
            except BaseException:
                if api_pid is not None:
                    try:os.kill(api_pid,signal.SIGKILL)
                    except ProcessLookupError:pass
                    try:os.waitpid(api_pid,0)
                    except ChildProcessError:pass
                os._exit(70)
        os.close(read);os.close(report_write)
        line=bytearray()
        while not line.endswith(b'\n'):
            self.assertTrue(select.select([report_read],[],[],3)[0])
            block=os.read(report_read,1);self.assertTrue(block);line.extend(block)
        return driver,write,report_read,json.loads(line)

    def test_broker_remains_alive_after_api_reap_until_exact_frame_and_eof(self):
        pid,write,report,launch=self.start('clean')
        try:
            os.kill(pid,signal.SIGTERM)
            self.assertTrue(select.select([report],[],[],3)[0]);self.assertEqual(os.read(report,1),b'P')
            self.assertEqual(os.waitpid(pid,os.WNOHANG),(0,0))
            frame=canonical.encode_terminal_frame({'schema_version':1,'profile':canonical.TERMINAL_PROFILE,
                **launch,'operation_id':'a'*64,'result':'success','reason':'none'})
            os.write(write,frame)
            self.assertFalse(select.select([report],[],[],.1)[0])
            os.close(write);write=None
            self.assertEqual(wait(pid),0);self.assertEqual(os.read(report,1),b'F')
        finally:
            if write is not None:os.close(write)
            os.close(report);cleanup(pid)

    def test_failed_status_or_unsolicited_zero_cannot_clean_seal(self):
        for case in ('publication-failure','unsolicited-zero'):
            with self.subTest(case=case):
                pid,write,report,launch=self.start(case)
                try:
                    if case!='unsolicited-zero':os.kill(pid,signal.SIGTERM)
                    self.assertTrue(select.select([report],[],[],3)[0]);self.assertEqual(os.read(report,1),b'P')
                    if case=='publication-failure':
                        os.write(write,canonical.encode_terminal_frame({'schema_version':1,'profile':canonical.TERMINAL_PROFILE,
                            **launch,'operation_id':'a'*64,'result':'success','reason':'none'}))
                    os.close(write);write=None
                    self.assertEqual(wait(pid),70);self.assertNotIn(b'F',os.read(report,100))
                finally:
                    if write is not None:os.close(write)
                    os.close(report);cleanup(pid)

    def test_repeated_term_does_not_extend_first_grace_deadline(self):
        pid,write,report,launch=self.start('repeated-term')
        try:
            start=time.monotonic();result=None
            while time.monotonic()-start < .8:
                found,status=os.waitpid(pid,os.WNOHANG)
                if found:
                    result=os.waitstatus_to_exitcode(status);break
                os.kill(pid,signal.SIGTERM)
                time.sleep(.025)
            self.assertEqual(result,71,'repeated TERM extended actual forced-stop boundary')
            self.assertLess(time.monotonic()-start,.8)
        finally:
            os.close(write);os.close(report)
            # Exact recorded child only, even if this sensitivity assertion
            # fails before broker cleanup. No descendant/PID-only discovery.
            api=launch['api']
            if not canonical.proc_dead(api):
                self.assertEqual(canonical.validated_proc_identity(api['pid']),api)
                descriptor=os.pidfd_open(api['pid'])
                try:
                    self.assertEqual(canonical.validated_proc_identity(api['pid']),api)
                    signal.pidfd_send_signal(descriptor,signal.SIGKILL,None,0)
                finally:os.close(descriptor)
            cleanup(pid)
