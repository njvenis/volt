"""Fixed FRESH-IMAGE kernel/COPY component, never a product launch selector.

No DB/account/HTTP/TLS readiness is claimed. The real broker recipe executes
uvicorn; intentionally invalid DB configuration must then fail independently.
A separate fixed FD diagnostic proves venv detection and the UID1800 API bridge.
"""
import ctypes
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import select
import signal
import subprocess
import sys
import time

sys.path.insert(0,'/usr/local/lib/volt-private')
import volt_route_check_records as records
spec=importlib.util.spec_from_file_location('protected_broker','/usr/local/libexec/volt-main-api-launcher.py')
broker=importlib.util.module_from_spec(spec);spec.loader.exec_module(broker)


def need(value,message):
    if not value:raise RuntimeError(message)


def fd_diagnostic():
    """Test-only fixed -c command; production broker remains hardcoded -m uvicorn."""
    executable,metadata=broker.open_executable();read,write=os.pipe2(os.O_CLOEXEC)
    function=broker._libc_execveat();signal.signal(signal.SIGCHLD,signal.SIG_DFL)
    signal.pthread_sigmask(signal.SIG_BLOCK,{signal.SIGCHLD});pid=os.fork()
    if pid==0:
        try:
            os.close(read);os.dup2(write,1);os.close(write)
            os.setsid();os.setgroups([]);os.setresgid(1800,1800,1800);os.setresuid(1800,1800,1800)
            code="import os,sys,json,hashlib;from pathlib import Path;from uvm.auth.route_check import _load_records;m=_load_records();p=Path(m.__file__);s=p.stat();print(json.dumps({'uid':os.geteuid(),'gid':os.getegid(),'executable':sys.executable,'prefix':sys.prefix,'base_prefix':sys.base_prefix,'records_path':str(p),'records_inode':[s.st_dev,s.st_ino],'records_mode':s.st_mode&511,'records_owner':s.st_uid,'records_sha256':hashlib.sha256(p.read_bytes()).hexdigest()}))"
            argv=[broker.EXECUTABLE,'-c',code];env=dict(broker.FIXED_ENV)
            args=(ctypes.c_char_p*(len(argv)+1))(*[x.encode()for x in argv],None)
            values=[(k+'='+v).encode()for k,v in env.items()]
            environment=(ctypes.c_char_p*(len(values)+1))(*values,None)
            signal.pthread_sigmask(signal.SIG_SETMASK,set())
            function(executable,b'',args,environment,0x1000)
        except BaseException:pass
        os._exit(70)
    os.close(write);os.close(executable);pidfd=os.pidfd_open(pid,0)
    signal.pthread_sigmask(signal.SIG_UNBLOCK,{signal.SIGCHLD})
    try:
        deadline=time.monotonic()+10;raw=bytearray()
        while True:
            remaining=deadline-time.monotonic();need(remaining>0,'FD diagnostic timed out')
            ready,_,_=select.select([read],[],[],remaining);need(ready,'FD diagnostic timed out')
            block=os.read(read,8193-len(raw));raw.extend(block);need(len(raw)<=8192,'FD diagnostic output exceeds bound')
            if not block:break
        found,status=os.waitpid(pid,0);need(found==pid and os.waitstatus_to_exitcode(status)==0,'FD diagnostic failed')
        result=json.loads(raw)
        need(result['uid']==1800 and result['gid']==1800 and result['prefix']=='/opt/uvm/venv'
            and result['base_prefix']!=result['prefix'] and result['executable']==broker.EXECUTABLE,'FD venv detection differs')
        path=Path(records.__file__);s=path.stat()
        need(result['records_path']==str(path)and result['records_inode']==[s.st_dev,s.st_ino]
            and result['records_owner']==0 and result['records_mode']==0o644
            and result['records_sha256']==hashlib.sha256(path.read_bytes()).hexdigest(),'API bridge physical canonical COPY differs')
        return result
    finally:
        os.close(read);os.close(pidfd)


def main():
    need(os.geteuid()==0 and sys.flags.isolated and sys.flags.no_site,'isolated root fixture required')
    need(not any(k=='uvm'or k.startswith('uvm.')or k=='sqlalchemy'for k in sys.modules),'ROOT imported API package')
    root=Path('/usr/local/lib/volt-private/volt_route_check_records.py');s=root.stat()
    rootproof={'path':str(root),'inode':[s.st_dev,s.st_ino],'owner':s.st_uid,'mode':s.st_mode&511,
        'sha256':hashlib.sha256(root.read_bytes()).hexdigest(),'no_root_API_import':True}
    audit=subprocess.run(['/usr/local/bin/python3.14','-I','-S','/usr/local/libexec/volt-check-protected-python.py'],
        env={'PATH':'/usr/bin:/bin','LC_ALL':'C'},stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=10)
    need(audit.returncode==0,'protected image audit failed')
    api=fd_diagnostic()
    # Probe required pidfd syscalls before registering a broker; no fallback.
    testfd=os.pidfd_open(os.getpid(),0);signal.pidfd_send_signal(testfd,0,None,0);os.close(testfd)
    environment={key:''for key in broker.API_KEYS};environment.update(broker.FIXED_ENV)
    environment.update(UVM_API_HOST='0.0.0.0',UVM_API_PORT='8000',UVM_DB_URL='component-only',
        UVM_API_CURSOR_SECRET='component-only-cursor-not-an-authority',UVM_AUTH_MODE='bearer',
        UVM_OIDC_DEPLOYMENT_MODE='external',UVM_UI_ROOT='/opt/uvm/ui')
    request={'schema_version':1,'profile':broker.PROFILE,'main_bind':'0.0.0.0','main_port':8000,'api_environment':environment}
    process=subprocess.Popen(['/usr/local/bin/python3.14','-I','-S','/usr/local/libexec/volt-main-api-launcher.py'],
        env={'PATH':'/usr/bin:/bin','LC_ALL':'C'},stdin=subprocess.PIPE,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    pidfd=os.pidfd_open(process.pid,0);launch=None;live=None;status=None
    try:
        process.stdin.write(json.dumps(request).encode());process.stdin.close()
        deadline=time.monotonic()+10
        while time.monotonic()<deadline:
            try:
                with records.locked_store(role='root')as store:
                    launch=store.read_launch()
                    need(launch['entrypoint']==records.validated_proc_identity(os.getpid())
                        and launch['supervisor']['pid']==process.pid,'registered root chain differs')
                    records.validate_launch_processes(launch)
                    meta=records.proc_metadata(launch['api']['pid'])
                    live={'identity':meta['identity'],'uids':meta['uids'],'gids':meta['gids'],
                        'ppid':meta['ppid'],'pgrp':meta['pgrp'],'session':meta['session']}
                break
            except records.RouteCheckError:
                if process.poll()is not None:break
                time.sleep(.005)
        need(launch is not None and live is not None,'actual fixed broker launch/live identity not observed')
        code=process.wait(timeout=15)
        with records.locked_store(role='root')as store:status=store.read_launch_status()
        need(code!=0 and status is not None and status['phase']=='failed','unavailable-backend scope was not separated')
        print(json.dumps({'root_import_copy':rootproof,'API_UID1800_FD_venv_and_physical_copy':api,
            'kernel_pidfd_supported':True,'actual_fixed_broker_launch':launch,'actual_live_API_process':live,
            'broker_exit':code,'final_private_status':status,
            'scope':'FRESH local IMAGE component; fixed -c FD diagnostic supplementary; production broker executes ONLY fixed -m uvicorn. Invalid DB is deliberate, no readiness/account/DB/TLS/public package claim.'},sort_keys=True))
    finally:
        if process.poll()is None:
            signal.pidfd_send_signal(pidfd,signal.SIGTERM,None,0)
            try:process.wait(timeout=35)
            except subprocess.TimeoutExpired:signal.pidfd_send_signal(pidfd,signal.SIGKILL,None,0);process.wait(timeout=5)
        os.close(pidfd)


if __name__=='__main__':
    try:main()
    except Exception as error:
        print('protected_component_failed:'+str(error),file=sys.stderr)
        raise SystemExit(1)from None
