#!/usr/local/bin/python3.14
"""ONE protected main-API recipe. Run only with the fixed isolated interpreter.

This is root launch provenance, not live executable/RCE attestation. Application
code is imported only AFTER dropping all IDs to1800 and final FD-bound exec.
"""
from __future__ import annotations
import ctypes
import errno
import fcntl
import ipaddress
import json
import os
from pathlib import Path
import select
import signal
import stat
import struct
import sys
import time

PROFILE = 'volt_main_api_launch_v1'
EXECUTABLE = '/opt/uvm/venv/bin/python-uvm'
PROTECTED = '/usr/local/lib/volt-private'
ENCODED_LIMIT = 524288
ERRORS = frozenset({'invalid_input','unsafe_recipe','unsupported_kernel','exec_failed',
    'process_mismatch','timeout','cleanup_failed'})
FIXED_ENV = {'PATH':'/opt/uvm/venv/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',
    'HOME':'/opt/uvm','PYTHONPATH':'/opt/uvm/app'}
# Generated from the existing main API env-i block; no arbitrary environment key.
API_KEYS = frozenset(('PATH', 'HOME', 'UVM_G7_VERIFICATION_ONLY', 'UVM_G7_CONNECTOR_RECOVERY_ID', 'UVM_API_READ_SNAPSHOT_DIR', 'PYTHONPATH', 'UVM_DB_URL', 'UVM_API_CURSOR_SECRET', 'UVM_API_PRINCIPALS', 'UVM_G3_BOOTSTRAP_PRINCIPAL', 'UVM_NATIVE_BOOTSTRAP_PRINCIPALS', 'UVM_NATIVE_GRANTABLE_ENVELOPE', 'UVM_OBSERVER_DEPLOYMENT_REGISTRY_FILE', 'UVM_G7_INITIAL_MAXIMUM_FUTURE_SKEW_SECONDS', 'UVM_G7_HOST_KEY_ID', 'UVM_G7_CONTROLLER_INSTANCE_ID', 'UVM_G7_RECOVERY_TLS_CERT_FILE', 'UVM_G7_RECOVERY_TLS_KEY_FILE', 'UVM_G7_RECOVERY_TLS_CA_FILE', 'UVM_G7_SOURCE_ADAPTER_PRINCIPAL', 'UVM_G7_DEPLOYMENT_ID', 'UVM_G7_RECOVERY_EPOCH', 'UVM_G7_STORAGE_GENERATION', 'UVM_G7_VOLUME_SET_DIGEST', 'UVM_G7_PRESERVATION_PUBLIC_KEY_FILE', 'UVM_G7_PRESERVATION_KEY_ID', 'UVM_G7_PRESERVATION_REPORT_DIR', 'UVM_G7_PRESERVATION_TRUST_DIR', 'UVM_G7_PRESERVATION_ENVIRONMENT', 'UVM_G7_PRESERVATION_MAX_FUTURE_SKEW_SECONDS', 'UVM_AUTH_MODE', 'UVM_OIDC_CONFIG', 'UVM_LOCAL_AUTH_CONFIG_FILE', 'UVM_LOCAL_RECOVERY_CONFIG_FILE', 'UVM_SCANNER_EVIDENCE_DIR', 'UVM_OIDC_DEPLOYMENT_MODE', 'SSL_CERT_FILE', 'UVM_GITHUB_API_BASE_URL', 'UVM_GITHUB_APP_BASE_URL', 'UVM_CONNECTOR_PUBLIC_BASE_URL', 'UVM_GITHUB_PREVIEW_SECRET', 'UVM_GITHUB_TOKEN_FILE', 'UVM_G7_DISPOSABLE_MODE', 'UVM_G7_TEST_CLOCK_FILE', 'UVM_GITHUB_POLL_INTERVAL_SECONDS', 'UVM_GITHUB_POLL_PRINCIPAL', 'UVM_GITHUB_POLL_COMPLETION_MARKER', 'UVM_GITHUB_WEBHOOK_PRINCIPAL', 'UVM_GITHUB_WEBHOOK_SECRET_DIR', 'UVM_GITHUB_WEBHOOK_SECRET_VERSION_FILE', 'UVM_GITHUB_WEBHOOK_CRASH_AFTER_COMMAND_COMMIT', 'UVM_CONNECTOR_FIXTURE_ID', 'UVM_CONNECTOR_FIXTURE_SOURCE_ID', 'UVM_CONNECTOR_FIXTURE_SOURCE_FAMILY', 'UVM_CONNECTOR_FIXTURE_SOURCE_ACCOUNT_ID', 'UVM_CONNECTOR_FIXTURE_SCOPE_KEY', 'UVM_CONNECTOR_ENVIRONMENT_LABEL', 'UVM_CONNECTOR_LOCAL_KEY_FILE', 'UVM_CONNECTOR_LOCAL_KEY_ID', 'UVM_CONNECTOR_RECOVERY_EPOCH_FILE', 'UVM_CONNECTOR_ISSUER_LEDGER_FILE', 'UVM_CONNECTOR_ISSUER_KEY_FILE', 'UVM_CONNECTOR_OPERATOR_CLEARANCE_FILE', 'UVM_CONNECTOR_OPERATOR_KEY_FILE', 'UVM_CONNECTOR_TEST_SUBMISSION_PAUSE_DIR', 'UVM_EXCEPTION_WARNING_INSTALLATION_ID', 'UVM_EXCEPTION_WARNING_SIGNING_SECRET_FILE', 'UVM_INGRESS_ALLOWED_PEER_CIDRS', 'UVM_INGRESS_ALLOWED_HOSTS', 'UVM_UI_ROOT', 'UVM_API_HOST', 'UVM_API_PORT'))


class LaunchError(RuntimeError):
    def __init__(self, code):
        self.code=code if code in ERRORS else 'cleanup_failed'
        super().__init__('api_launch_failed:'+self.code)


def need(value, code):
    if not value:raise LaunchError(code)


def pairs(items):
    result={}
    for key,value in items:
        need(key not in result,'invalid_input');result[key]=value
    return result


class TerminalChannel:
    """ONE inherited FD3 reader, independent of Store locks and policy derivation."""
    def __init__(self, records, entrypoint):
        self.records=records;self.entrypoint=entrypoint;self.parentfd=None
        self.buffer=bytearray();self.completed=False;self.closed=False
        try:
            info=os.fstat(3);flags=fcntl.fcntl(3,fcntl.F_GETFL)
            need(stat.S_ISFIFO(info.st_mode) and flags&os.O_ACCMODE==os.O_RDONLY,'cleanup_failed')
            fcntl.fcntl(3,fcntl.F_SETFD,fcntl.fcntl(3,fcntl.F_GETFD)|fcntl.FD_CLOEXEC)
            fcntl.fcntl(3,fcntl.F_SETFL,flags|os.O_NONBLOCK)
            self.check_parent()
            self.parentfd=os.pidfd_open(entrypoint['pid'],0)
            self.check_parent()
        except BaseException:
            self.close();raise

    def check_parent(self):
        need(os.getppid()==self.entrypoint['pid']
            and self.records.validated_proc_identity(os.getppid())==self.entrypoint
            and self.records.proc_live(self.entrypoint),'cleanup_failed')
        info=self.records.proc_metadata(os.getppid())
        need(info['uids']==(os.geteuid(),)*4 and info['gids']==(os.getegid(),)*4,'cleanup_failed')
        if self.parentfd is not None:
            need(not select.select([self.parentfd],[],[],0)[0],'cleanup_failed')

    def read_complete(self, launch):
        need(not self.closed and not self.completed,'cleanup_failed')
        self.check_parent()
        while True:
            try:block=os.read(3,2053-len(self.buffer))
            except BlockingIOError:return None
            if not block:
                raw=bytes(self.buffer)
                self.records.decode_terminal_frame(raw,launch=launch)
                self.check_parent();self.completed=True
                return raw
            self.buffer.extend(block)
            need(len(self.buffer)<=2052,'cleanup_failed')
            if len(self.buffer)>=4:
                length=int.from_bytes(self.buffer[:4],'big')
                need(1<=length<=2048 and len(self.buffer)<=length+4,'cleanup_failed')

    def close(self):
        if not self.closed:
            self.closed=True
            for descriptor in (3,self.parentfd):
                if descriptor is not None:
                    try:os.close(descriptor)
                    except OSError:pass


def read_request(stream):
    deadline=time.monotonic()+5;raw=bytearray()
    while True:
        remaining=deadline-time.monotonic();need(remaining>0,'invalid_input')
        ready,_,_=select.select([stream.fileno()],[],[],remaining);need(bool(ready),'invalid_input')
        block=os.read(stream.fileno(),min(8192,ENCODED_LIMIT-len(raw)+1))
        if not block:break
        raw.extend(block);need(len(raw)<=ENCODED_LIMIT,'invalid_input')
    try:value=json.loads(bytes(raw),object_pairs_hook=pairs,parse_constant=lambda _:(_ for _ in ()).throw(LaunchError('invalid_input')))
    except (ValueError,UnicodeError,RecursionError):raise LaunchError('invalid_input')from None
    return validate_request(value)


def validate_request(value):
    need(type(value)is dict and set(value)=={'schema_version','profile','main_bind','main_port','api_environment'},'invalid_input')
    need(type(value['schema_version'])is int and value['schema_version']==1 and value['profile']==PROFILE,'invalid_input')
    need(type(value['main_bind'])is str and '%'not in value['main_bind'],'invalid_input')
    try:address=ipaddress.ip_address(value['main_bind'])
    except ValueError:raise LaunchError('invalid_input')from None
    need(str(address)==value['main_bind']and type(value['main_port'])is int and 1<=value['main_port']<=65535,'invalid_input')
    environment=value['api_environment'];need(type(environment)is dict and set(environment)==API_KEYS and len(environment)<=128,'invalid_input')
    total=0
    for key,item in environment.items():
        need(type(key)is str and len(key)<=128 and type(item)is str and '\0'not in item,'invalid_input')
        try:size=len(item.encode('utf-8'));total+=len(key.encode('utf-8'))+size
        except UnicodeError:raise LaunchError('invalid_input')from None
        need(size<=4096 and total<=65536,'invalid_input')
    need(all(environment[k]==v for k,v in FIXED_ENV.items()),'invalid_input')
    need(environment['UVM_API_HOST']==value['main_bind']and environment['UVM_API_PORT']==str(value['main_port']),'invalid_input')
    need(all(environment[k]for k in ('UVM_DB_URL','UVM_API_CURSOR_SECRET','UVM_AUTH_MODE','UVM_OIDC_DEPLOYMENT_MODE','UVM_UI_ROOT')),'invalid_input')
    need(environment['UVM_AUTH_MODE']in ('local','oidc','bearer')and environment['UVM_OIDC_DEPLOYMENT_MODE']in ('local','external','demo'),'invalid_input')
    if environment['UVM_AUTH_MODE']=='local':
        need(all(environment[k]for k in ('UVM_LOCAL_AUTH_CONFIG_FILE','UVM_LOCAL_RECOVERY_CONFIG_FILE',
            'UVM_CONNECTOR_LOCAL_KEY_FILE','UVM_CONNECTOR_LOCAL_KEY_ID')),'invalid_input')
    return value


def _protected_path(path, *, file=False, mode=None):
    try:
        """Root-owned non-writable ancestors; no symlink directory/path fallback."""
        path=Path(path);need(path.is_absolute(),'unsafe_recipe')
        for part in [Path('/'),*reversed(path.parents[:-1]),path]:
            info=part.lstat();need(info.st_uid==0 and not info.st_mode&0o022 and not stat.S_ISLNK(info.st_mode),'unsafe_recipe')
            if part!=path or not file:need(stat.S_ISDIR(info.st_mode),'unsafe_recipe')
            else:need(stat.S_ISREG(info.st_mode)and(mode is None or stat.S_IMODE(info.st_mode)==mode),'unsafe_recipe')
    except OSError:
        raise LaunchError('unsafe_recipe') from None


def protected_modules():
    need(os.geteuid()==0 and sys.flags.isolated and sys.flags.no_site,'unsafe_recipe')
    need(dict(os.environ)=={'PATH':'/usr/bin:/bin','LC_ALL':'C'},'unsafe_recipe')
    _protected_path('/usr/local/bin/python3.14',file=True)
    _protected_path('/usr/local/libexec/volt-main-api-launcher.py',file=True,mode=0o755)
    _protected_path(PROTECTED)
    for name in ('volt_route_check_records.py','volt_route_check_control.py'):
        _protected_path(PROTECTED+'/'+name,file=True,mode=0o644)
    # Only this literal protected directory is added; never import uvm/__init__.
    sys.path.insert(0,PROTECTED)
    import volt_route_check_records as records
    import volt_route_check_control as control
    return records,control


def open_executable():
    _protected_path(EXECUTABLE,file=True,mode=0o755)
    _protected_path('/opt/uvm/venv/pyvenv.cfg',file=True,mode=0o644)
    fd=os.open(EXECUTABLE,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        info=os.fstat(fd);need(stat.S_ISREG(info.st_mode)and info.st_uid==0 and stat.S_IMODE(info.st_mode)==0o755
            and 0<info.st_size<=67108864 and os.pread(fd,4,0)==b'\x7fELF','unsafe_recipe')
        named=os.stat(EXECUTABLE,follow_symlinks=False)
        need((info.st_dev,info.st_ino,info.st_size,info.st_mtime_ns,info.st_ctime_ns)==
            (named.st_dev,named.st_ino,named.st_size,named.st_mtime_ns,named.st_ctime_ns),'unsafe_recipe')
        return fd,{'device':info.st_dev,'inode':info.st_ino,'mode':493,'uid':0,'gid':info.st_gid,'size':info.st_size}
    except BaseException:os.close(fd);raise


def _libc_execveat():
    libc=ctypes.CDLL(None,use_errno=True)
    try:function=libc.execveat
    except AttributeError:raise LaunchError('unsupported_kernel')from None
    function.argtypes=(ctypes.c_int,ctypes.c_char_p,ctypes.POINTER(ctypes.c_char_p),ctypes.POINTER(ctypes.c_char_p),ctypes.c_int)
    function.restype=ctypes.c_int
    return function


def _child_fail(fd,stage,number):
    try:os.write(fd,b'VAPIERR1'+struct.pack('!II',stage,number if 1<=number<=4095 else errno.EIO))
    except OSError:pass
    os._exit(70)


def _exec_child(executable, error_write, gate_read, request, execveat):
    stage=1
    try:
        keep={0,1,2,executable,error_write,gate_read}
        descriptors=os.listdir('/proc/self/fd');need(len(descriptors)<=128,'unsafe_recipe')
        for name in descriptors:
            number=int(name)
            if number not in keep:
                try:os.close(number)
                except OSError as error:
                    if error.errno!=errno.EBADF:raise
        ready,_,_=select.select([gate_read],[],[],2)
        if not ready or os.read(gate_read,2)!=b'G':_child_fail(error_write,1,errno.ETIMEDOUT)
        os.close(gate_read)
        stage=2;os.setsid()
        stage=3;os.setgroups([]);os.setresgid(1800,1800,1800);os.setresuid(1800,1800,1800)
        if os.getresuid()!=(1800,)*3 or os.getresgid()!=(1800,)*3:_child_fail(error_write,3,errno.EPERM)
        for sig in (signal.SIGTERM,signal.SIGINT,signal.SIGUSR1,signal.SIGCHLD):signal.signal(sig,signal.SIG_DFL)
        argv=[EXECUTABLE,'-m','uvm.api.main_server','--host',request['main_bind'],'--port',str(request['main_port']),'--workers','1','--no-proxy-headers']
        args=(ctypes.c_char_p*(len(argv)+1))(*[v.encode()for v in argv],None)
        items=[(key+'='+value).encode()for key,value in request['api_environment'].items()]
        environment=(ctypes.c_char_p*(len(items)+1))(*items,None)
        stage=4
        if not fcntl.fcntl(error_write,fcntl.F_GETFD)&fcntl.FD_CLOEXEC:_child_fail(error_write,4,errno.EBADF)
        signal.pthread_sigmask(signal.SIG_SETMASK,set())
        execveat(executable,b'',args,environment,0x1000)
        _child_fail(error_write,4,ctypes.get_errno())
    except BaseException as error:_child_fail(error_write,stage,getattr(error,'errno',errno.EIO)or errno.EIO)


def _signal(pidfd, sig):
    try:signal.pidfd_send_signal(pidfd,sig,None,0)
    except ProcessLookupError:pass
    except OSError:raise LaunchError('cleanup_failed')from None


def _reap(pid, pidfd, seconds):
    deadline=time.monotonic()+seconds
    while True:
        found,status=os.waitpid(pid,os.WNOHANG)
        if found:return os.waitstatus_to_exitcode(status)
        remaining=deadline-time.monotonic()
        if remaining<=0:return None
        select.select([pidfd],[],[],min(.05,remaining))


def _error_frame(raw):
    need(len(raw)==16 and raw[:8]==b'VAPIERR1','exec_failed')
    stage,number=struct.unpack('!II',raw[8:]);need(1<=stage<=4 and 1<=number<=4095,'exec_failed')
    raise LaunchError('unsupported_kernel'if number in (errno.ENOSYS,errno.EOPNOTSUPP)else'exec_failed')


def launch(request, records, flags):
    need(hasattr(os,'pidfd_open')and hasattr(signal,'pidfd_send_signal')and len(os.listdir('/proc/self/task'))==1,'unsupported_kernel')
    function=_libc_execveat();executable,metadata=open_executable();error_read=error_write=gate_read=gate_write=pidfd=None;pid=None;reaped=False
    try:
        error_read,error_write=os.pipe2(os.O_CLOEXEC);gate_read,gate_write=os.pipe2(os.O_CLOEXEC)
        signal.signal(signal.SIGCHLD,signal.SIG_DFL);signal.pthread_sigmask(signal.SIG_BLOCK,{signal.SIGCHLD})
        need(not flags['ordinary'],'exec_failed')
        pid=os.fork()
        if pid==0:_exec_child(executable,error_write,gate_read,request,function)
        os.close(error_write);error_write=None;os.close(gate_read);gate_read=None
        try:pidfd=os.pidfd_open(pid,0)
        except OSError:raise LaunchError('unsupported_kernel')from None
        original=records.validated_proc_identity(pid)
        need(not flags['ordinary'],'exec_failed')
        os.write(gate_write,b'G');os.close(gate_write);gate_write=None
        signal.pthread_sigmask(signal.SIG_UNBLOCK,{signal.SIGCHLD})
        deadline=time.monotonic()+10;message=bytearray()
        while True:
            need(not flags['ordinary'],'exec_failed')
            remaining=deadline-time.monotonic();need(remaining>0,'timeout')
            ready,_,_=select.select([error_read,pidfd],[],[],remaining)
            need(bool(ready),'timeout')
            if error_read in ready:
                chunk=os.read(error_read,17-len(message));message.extend(chunk)
                need(len(message)<=16,'exec_failed')
                if not chunk:break
            if pidfd in ready and error_read not in ready:
                # Do not discard a queued16byte errno frame when child exit and
                # pipe readiness occur together; EOF still needs liveness proof.
                raise LaunchError('exec_failed')
        if message:_error_frame(bytes(message))
        found,status=os.waitpid(pid,os.WNOHANG)
        if found:reaped=True;raise LaunchError('exec_failed')
        need(not select.select([pidfd],[],[],0)[0],'process_mismatch')
        after=records.proc_metadata(pid)
        need(after['identity']==original and after['uids']==(1800,)*4 and after['gids']==(1800,)*4
            and after['ppid']==os.getpid()and after['pgrp']==pid and after['session']==pid,'process_mismatch')
        need(records.validated_proc_identity(pid)==original and not select.select([pidfd],[],[],0)[0],'process_mismatch')
        return pid,pidfd,original,metadata
    except BaseException:
        if gate_write is not None:os.close(gate_write);gate_write=None
        if pid and not reaped:
            if pidfd is not None:
                _signal(pidfd,signal.SIGKILL);_reap(pid,pidfd,2)
            else:
                # No gate G was sent; fixed child has a2s exit deadline, and
                # remains our unreaped child. No numeric-PID signal fallback.
                os.waitpid(pid,0)
        if pidfd is not None:os.close(pidfd)
        raise
    finally:
        signal.pthread_sigmask(signal.SIG_UNBLOCK,{signal.SIGCHLD})
        for fd in (executable,error_read,error_write,gate_read,gate_write):
            if fd is not None:
                try:os.close(fd)
                except OSError:pass


def supervise(request, records, control):
    # Derive policy from fixed protected sources BEFORE any API exec. No caller
    # profile selector or app-owned staged file can grant normal admission.
    readiness_profile=records.derive_launch_readiness(request)
    entrypoint=records.validated_proc_identity(os.getppid())
    supervisor=records.validated_proc_identity(os.getpid())
    flags={'ordinary':False,'quiesce':False,'ordinary_at':None}
    def ordinary(_sig,_frame):
        if flags['ordinary_at'] is None:flags['ordinary_at']=records.boottime_ns()
        flags['ordinary']=True
    def quiesce(_sig,_frame):flags['quiesce']=True
    signal.signal(signal.SIGTERM,ordinary);signal.signal(signal.SIGINT,ordinary);signal.signal(signal.SIGUSR1,quiesce)
    control.broker_prepare(entrypoint,supervisor)
    channel=TerminalChannel(records,entrypoint)
    pid=pidfd=session=None;reaped=False
    try:
        pid,pidfd,api,executable=launch(request,records,flags)
        launch_record,session=control.broker_launched(entrypoint,supervisor,api,executable,readiness_profile)
        control.broker_begin(launch_record,session)
        pending=None;api_deadline=None;terminal_deadline=None;quiesce_failed=False
        ready=False;progress=False
        def publish(callback,*args,**kwargs):
            try:
                callback(*args,**kwargs)
                return True
            except Exception:
                # Sticky memory precedes the next attempted write. Even after
                # publication failure the original pidfd must still be stopped.
                session.note_failure('publication_failed')
                print('api_launch_failed:cleanup_failed',file=sys.stderr)
                return False
        while True:
            channel.check_parent()
            now=records.boottime_ns()
            if flags['ordinary']:
                flags['ordinary']=False
                if terminal_deadline is None:
                    # Handler captured FIRST receipt, not a later loop turn.
                    # Repeated TERM cannot reopen or extend either deadline.
                    origin=flags['ordinary_at']
                    terminal_deadline=origin+577_000_000_000
                    pending='stop';api_deadline=origin+30_000_000_000
                    publish(session.register_controlled_request,'stop')
                    if not reaped:
                        publish(session.publish_status,control._status(records,launch_record,'stopping',
                            session.failure if session.failure in ('forced_stop','api_nonzero','cleanup_failed') else 'cleanup_failed' if session.failure else 'none'))
                        _signal(pidfd,signal.SIGTERM)
            elif flags['quiesce']:
                flags['quiesce']=False
                if pending is None and not quiesce_failed and not reaped:
                    pending='quiesce';api_deadline=now+30_000_000_000
                    publish(session.register_controlled_request,'quiesce')
                    publish(session.publish_status,control._status(records,launch_record,'quiescing','none'))
                    _signal(pidfd,signal.SIGTERM)
            observation=session.reap_api()
            if observation is not None:
                reaped=True
                if not progress:
                    publish(control.broker_disarm,entrypoint,supervisor,api)
                    progress=publish(session.publish_api_stopped)
                    # Parent owns all remaining service cleanup. A dead broker
                    # can never manufacture its own terminal-success handoff.
                    if pending is None and not quiesce_failed:return 70
                    if not progress:return 70
            elif not ready and pending is None and not quiesce_failed:
                ready=session.acknowledge_parent_ready()
            if api_deadline is not None and not reaped and now>=api_deadline:
                if pending=='quiesce':
                    publish(session.publish_supervisor,records.record(supervisor=supervisor,api=api,
                        clock_ticks_per_second=launch_record['clock_ticks_per_second'],phase='failed'))
                    publish(session.publish_status,control._status(records,launch_record,'quiesce_failed','quiesce_timeout'))
                    quiesce_failed=True;pending=None;api_deadline=None
                else:
                    session.note_failure('forced_stop')
                    _signal(pidfd,signal.SIGKILL)
                    # Session alone consumes the API wait status after pidfd
                    # readiness. Failure to observe death remains non-clean.
                    need(bool(select.select([pidfd],[],[],2)[0]),'cleanup_failed')
                    session.reap_api(block=True);reaped=True
                    publish(control.broker_disarm,entrypoint,supervisor,api)
                    publish(session.publish_api_stopped)
                    return 71
            frame=channel.read_complete(launch_record)
            if frame is not None:
                need(terminal_deadline is not None and reaped and progress,'cleanup_failed')
                session.accept_terminal(frame)
                if session.failure is not None:return 70
                session.finish_clean()
                return session.clean_exit_code()
            if terminal_deadline is not None and now>=terminal_deadline:
                session.note_failure('terminal_channel_failed')
                return 70
            watched=[channel.parentfd,3]
            if not reaped:watched.append(pidfd)
            select.select(watched,[],[],.05)
    except BaseException:
        if session is not None:session.note_failure('cleanup_failed')
        raise
    finally:
        # Kernel cleanup cannot be skipped by a failed Store/status operation.
        # Once created, ONLY Session may reap the original API.
        if pidfd is not None:
            try:
                if not reaped:
                    _signal(pidfd,signal.SIGKILL)
                    if session is None:_reap(pid,pidfd,2)
                    elif select.select([pidfd],[],[],2)[0]:session.reap_api(block=True)
            finally:os.close(pidfd)
        channel.close()


def main():
    need(len(sys.argv)==1,'invalid_input')
    records,control=protected_modules()
    request=read_request(sys.stdin.buffer)
    raise SystemExit(supervise(request,records,control))


if __name__=='__main__':
    try:main()
    except Exception as error:
        code=error.code if isinstance(error,LaunchError)else'cleanup_failed'
        print('api_launch_failed:'+code,file=sys.stderr)
        raise SystemExit(70)from None
