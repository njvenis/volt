#!/usr/local/bin/python3.14
"""Fixed post-reap candidate reader/producer; parent causal waits stay required."""
from __future__ import annotations
import time
import ctypes
import errno
import fcntl
import os
from pathlib import Path
import select
import signal
import stat
import sys
import threading

LIMIT=2048
PROTECTED=Path('/usr/local/lib/volt-private')

def need(condition):
    if not condition:
        raise RuntimeError('terminal_transport_failed')


def now():
    return time.clock_gettime_ns(time.CLOCK_BOOTTIME)


def remaining(deadline):
    value = deadline-now()
    need(value > 0)
    return value/1_000_000_000


def hard_deadline(deadline):
    """Own BOOTTIME timer bounds blocking IO too; no service/authority channel."""
    remaining(deadline)
    class Timespec(ctypes.Structure):
        _fields_=[('seconds',ctypes.c_long),('nanoseconds',ctypes.c_long)]
    class Itimerspec(ctypes.Structure):
        _fields_=[('interval',Timespec),('value',Timespec)]
    libc=ctypes.CDLL(None,use_errno=True)
    create=libc.timerfd_create;create.argtypes=(ctypes.c_int,ctypes.c_int);create.restype=ctypes.c_int
    arm=libc.timerfd_settime;arm.argtypes=(ctypes.c_int,ctypes.c_int,ctypes.POINTER(Itimerspec),ctypes.c_void_p);arm.restype=ctypes.c_int
    descriptor=create(time.CLOCK_BOOTTIME,os.O_CLOEXEC|os.O_NONBLOCK)
    need(descriptor >= 0)
    value=Itimerspec(Timespec(0,0),Timespec(deadline//1_000_000_000,deadline%1_000_000_000))
    try:need(arm(descriptor,1,ctypes.byref(value),None) == 0)
    except BaseException:os.close(descriptor);raise
    def expire():
        try:
            if select.select([descriptor],[],[])[0]:os._exit(1)
        except BaseException:os._exit(1)
    threading.Thread(target=expire,daemon=True).start()


def check_pipe(descriptor, access):
    value=os.fstat(descriptor)
    flags=fcntl.fcntl(descriptor,fcntl.F_GETFL)
    need(stat.S_ISFIFO(value.st_mode) and flags & os.O_ACCMODE == access)
    return value,flags


def read_input(deadline):
    check_pipe(0,os.O_RDONLY)
    output=bytearray()
    while True:
        ready,_,_=select.select([0],[],[],remaining(deadline))
        need(bool(ready))
        block=os.read(0,min(4096,LIMIT+1-len(output)))
        if not block:break
        output.extend(block)
        need(len(output) <= LIMIT)
    need(bool(output));remaining(deadline)
    return bytes(output)


def parent_check(records, expected):
    pid=os.getppid()
    need(pid == expected['pid'] and records.validated_proc_identity(pid) == expected
        and records.proc_live(expected))
    metadata=records.proc_metadata(pid)
    need(metadata['uids'] == (os.geteuid(),)*4 and metadata['gids'] == (os.getegid(),)*4)


def parent_death_guard(records, expected):
    parent_check(records,expected)
    libc=ctypes.CDLL(None,use_errno=True)
    function=libc.prctl
    function.argtypes=(ctypes.c_int,ctypes.c_ulong,ctypes.c_ulong,ctypes.c_ulong,ctypes.c_ulong)
    function.restype=ctypes.c_int
    need(function(1,signal.SIGKILL,0,0,0) == 0)
    parent_check(records,expected)


def independent_stdout():
    original=os.fstat(1)
    original_flags=fcntl.fcntl(1,fcntl.F_GETFL)
    if not stat.S_ISFIFO(original.st_mode) or original_flags & os.O_ACCMODE != os.O_WRONLY:
        raise RuntimeError('completion_transport_failed')
    descriptor=os.open('/proc/self/fd/1',os.O_WRONLY|os.O_NONBLOCK|os.O_CLOEXEC)
    try:
        current=os.fstat(descriptor)
        flags=fcntl.fcntl(descriptor,fcntl.F_GETFL)
        if (not stat.S_ISFIFO(current.st_mode)
                or (current.st_dev,current.st_ino) != (original.st_dev,original.st_ino)
                or flags & os.O_ACCMODE != os.O_WRONLY or not flags & os.O_NONBLOCK
                or fcntl.fcntl(1,fcntl.F_GETFL) != original_flags):
            raise RuntimeError('completion_transport_failed')
        os.close(1)
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def write_envelope(descriptor, payload, deadline):
    if not 1 <= len(payload) <= 2049 or not payload.endswith(b'\n'):
        raise RuntimeError('completion_transport_failed')
    position=0
    while position < len(payload):
        seconds=(deadline-time.clock_gettime_ns(time.CLOCK_BOOTTIME))/1_000_000_000
        if seconds <= 0:raise RuntimeError('completion_transport_failed')
        _,ready,_=select.select([],[descriptor],[],seconds)
        if not ready:raise RuntimeError('completion_transport_failed')
        try:written=os.write(descriptor,payload[position:])
        except BlockingIOError:continue
        if written <= 0:raise RuntimeError('completion_transport_failed')
        position+=written
    if time.clock_gettime_ns(time.CLOCK_BOOTTIME) >= deadline:
        raise RuntimeError('completion_transport_failed')


def protected_records():
    need(os.geteuid() == 0 and sys.flags.isolated and sys.flags.no_site
        and len(sys.argv) == 1 and dict(os.environ) == {'PATH':'/usr/bin:/bin','LC_ALL':'C'})
    for target,mode in ((PROTECTED/'volt_route_check_records.py',0o644),
            (Path('/usr/local/libexec/volt-main-api-completion.py'),0o755),
            (Path('/usr/local/bin/python3.14'),None)):
        for path in (target,*target.parents):
            value=path.lstat()
            need(value.st_uid == 0 and not value.st_mode & 0o022 and not path.is_symlink())
        need(stat.S_ISREG(target.stat().st_mode)
            and (mode is None or stat.S_IMODE(target.stat().st_mode) == mode))
    sys.path.insert(0,str(PROTECTED))
    import volt_route_check_records
    need(Path(volt_route_check_records.__file__) == PROTECTED/'volt_route_check_records.py')
    return volt_route_check_records


def main():
    records=protected_records()
    own=records.validated_proc_identity(os.getpid())
    deadline=own['proc_start_ticks']*1_000_000_000//os.sysconf('SC_CLK_TCK')+2_000_000_000
    remaining(deadline)
    for name in os.listdir('/proc/self/fd'):
        descriptor=int(name)
        if descriptor not in (0,1,2):
            try:os.close(descriptor)
            except OSError as error:
                if error.errno != errno.EBADF:raise
    hard_deadline(deadline)
    null=os.stat('/dev/null');error=os.fstat(2)
    need(stat.S_ISCHR(error.st_mode) and error.st_rdev == null.st_rdev)
    raw=read_input(deadline)
    request=records.validate_record('completion_request',raw)
    need(records.canonical(request) == raw)
    parent_death_guard(records,request['entrypoint'])
    with records.locked_store(role='root') as store:
        candidate=store.read_completion_candidate(raw)
    remaining(deadline)
    parent_check(records,request['entrypoint'])
    output=independent_stdout()
    try:
        payload=candidate['envelope_raw']+b'\n'
        need(len(payload) <= LIMIT+1)
        write_envelope(output,payload,deadline)
        parent_check(records,request['entrypoint'])
    finally:os.close(output)
    remaining(deadline)


if __name__ == '__main__':
    try:main()
    except BaseException:raise SystemExit(1)from None
