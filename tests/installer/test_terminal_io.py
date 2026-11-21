"""Real Linux FD/parent mechanics; source functions, SAME-UID host components.

These omit protected ROOT admission/canonical terminal schema/Store/PID1 image.
"""
import ctypes
import errno
import fcntl
import importlib.util
import os
from pathlib import Path
import select
import signal
import struct
import time
import unittest
from uvm.auth import route_check_records as records

ROOT=Path(__file__).resolve().parents[2]

def load(name,file):
    spec=importlib.util.spec_from_file_location(name,ROOT/'uvm/installer'/file)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module
writer=load('terminal_writer_source_fixture','terminal_write.py')
completion=load('terminal_log_source_fixture','terminal_completion.py')


def reap(pid,seconds=4):
    deadline=time.monotonic()+seconds
    while time.monotonic()<deadline:
        found,status=os.waitpid(pid,os.WNOHANG)
        if found:return os.waitstatus_to_exitcode(status)
        time.sleep(.01)
    raise AssertionError('registered component did not complete')


def kill_owned(pid):
    # Reaping removes PID ownership. Never open a new pidfd for a PID that
    # this controller has already reaped (it may now identify another process).
    try:
        found,_=os.waitpid(pid,os.WNOHANG)
    except ChildProcessError:
        return
    if found:
        return
    try:
        fd=os.pidfd_open(pid)
        try:signal.pidfd_send_signal(fd,signal.SIGKILL,None,0)
        finally:os.close(fd)
    except ProcessLookupError:pass
    try:os.waitpid(pid,0)
    except ChildProcessError:pass


class TerminalPipeTests(unittest.TestCase):
    def test_hard_boottime_deadline_terminates_a_blocked_helper(self):
        started=time.monotonic();pid=os.fork()
        if pid==0:
            try:
                writer.hard_deadline(writer.now()+200_000_000)
                time.sleep(60)
                os._exit(90)
            except BaseException:os._exit(91)
        try:
            self.assertEqual(reap(pid),1)
            self.assertGreaterEqual(time.monotonic()-started,.18)
            self.assertLess(time.monotonic()-started,1)
        finally:kill_owned(pid)

    def test_exact_length_frame_and_eof_from_original_child(self):
        read,write=os.pipe();expected=records.validated_proc_identity(os.getpid());raw=b'{"component":true}'
        pid=os.fork()
        if pid==0:
            try:
                if read!=write:os.close(read)
                if write!=4:os.dup2(write,4);os.close(write)
                writer.parent_death_guard(records,expected)
                writer.write_frame(raw,writer.now()+2_000_000_000,records,expected)
                os.close(4);os._exit(0)
            except BaseException:os._exit(1)
        os.close(write)
        try:
            self.assertTrue(select.select([read],[],[],3)[0])
            payload=os.read(read,4096)
            self.assertEqual(payload,struct.pack('!I',len(raw))+raw)
            self.assertEqual(reap(pid),0)
            self.assertEqual(os.read(read,1),b'')
        finally:os.close(read);kill_owned(pid)

    def test_full_terminal_pipe_has_one_actual_absolute_deadline(self):
        read,write=os.pipe();fcntl.fcntl(write,fcntl.F_SETPIPE_SZ,4096)
        fcntl.fcntl(write,fcntl.F_SETFL,os.O_NONBLOCK)
        while True:
            try:os.write(write,b'x'*4096)
            except BlockingIOError:break
        expected=records.validated_proc_identity(os.getpid());started=time.monotonic();pid=os.fork()
        if pid==0:
            try:
                os.close(read)
                if write!=4:os.dup2(write,4);os.close(write)
                writer.parent_death_guard(records,expected)
                writer.write_frame(b'{}',writer.now()+2_000_000_000,records,expected)
                os._exit(90)
            except BaseException:os._exit(1)
        try:
            self.assertEqual(reap(pid),1)
            self.assertGreaterEqual(time.monotonic()-started,1.9)
            self.assertLess(time.monotonic()-started,3)
        finally:os.close(read);os.close(write);kill_owned(pid)

    def test_parent_death_kills_original_adapter_and_controller_reaps_it(self):
        # A private controller is subreaper ONLY in its own forked process;
        # the adapter's actual direct parent is then killed after guarded-ready.
        controller=os.fork()
        if controller==0:
            try:
                libc=ctypes.CDLL(None,use_errno=True)
                if libc.prctl(36,1,0,0,0)!=0:os._exit(91)
                ready_read,ready_write=os.pipe();parent=os.fork()
                if parent==0:
                    os.close(ready_read);expected=records.validated_proc_identity(os.getpid());adapter=os.fork()
                    if adapter==0:
                        try:
                            writer.parent_death_guard(records,expected)
                            os.write(ready_write,str(os.getpid()).encode()+b'\n');os.close(ready_write)
                            while True:signal.pause()
                        except BaseException:os._exit(92)
                    os.close(ready_write)
                    while True:signal.pause()
                os.close(ready_write)
                if not select.select([ready_read],[],[],2)[0]:os._exit(93)
                adapter=int(os.read(ready_read,64));os.close(ready_read)
                fd=os.pidfd_open(parent)
                signal.pidfd_send_signal(fd,signal.SIGKILL,None,0);os.close(fd)
                if reap(parent)!=-signal.SIGKILL:os._exit(94)
                if reap(adapter)!=-signal.SIGKILL:os._exit(95)
                os._exit(0)
            except BaseException:os._exit(96)
        try:self.assertEqual(reap(controller,5),0)
        finally:kill_owned(controller)


class IndependentStdoutTests(unittest.TestCase):
    def test_log_output_uses_same_pipe_independent_flags(self):
        read,write=os.pipe();before=fcntl.fcntl(write,fcntl.F_GETFL);raw=b'{"component":true}\n';pid=os.fork()
        if pid==0:
            try:
                os.close(read)
                if write!=1:os.dup2(write,1);os.close(write)
                owned=completion.independent_stdout()
                completion.write_envelope(owned,raw,time.clock_gettime_ns(time.CLOCK_BOOTTIME)+2_000_000_000)
                os.close(owned);os._exit(0)
            except BaseException:os._exit(1)
        try:
            self.assertTrue(select.select([read],[],[],3)[0]);self.assertEqual(os.read(read,4096),raw)
            self.assertEqual(reap(pid),0)
            self.assertEqual(fcntl.fcntl(write,fcntl.F_GETFL),before)
        finally:os.close(read);os.close(write);kill_owned(pid)

    def test_helper_kill_does_not_mutate_parent_stdout_flags(self):
        read,write=os.pipe();ready_read,ready_write=os.pipe();before=fcntl.fcntl(write,fcntl.F_GETFL);pid=os.fork()
        if pid==0:
            try:
                os.close(read);os.close(ready_read)
                if write!=1:os.dup2(write,1);os.close(write)
                owned=completion.independent_stdout()
                os.write(ready_write,b'R');os.close(ready_write)
                while True:signal.pause()
            except BaseException:os._exit(1)
        os.close(ready_write)
        try:
            self.assertTrue(select.select([ready_read],[],[],2)[0]);self.assertEqual(os.read(ready_read,1),b'R')
            fd=os.pidfd_open(pid)
            signal.pidfd_send_signal(fd,signal.SIGKILL,None,0);os.close(fd)
            self.assertEqual(reap(pid),-signal.SIGKILL)
            self.assertEqual(fcntl.fcntl(write,fcntl.F_GETFL),before)
        finally:os.close(read);os.close(write);os.close(ready_read);kill_owned(pid)
