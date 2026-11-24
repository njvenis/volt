"""Owned Linux file/process fixtures for private routing (not Docker/TLS proof)."""
import base64
import copy
import hashlib
import json
import os
from pathlib import Path
import secrets
import select
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

from uvm.auth import route_check_records as rc
from uvm.auth import route_check as api_route

CHILD = r'''
import contextlib,hashlib,json,os,secrets,sys,time
from pathlib import Path
import importlib.util
spec=importlib.util.spec_from_file_location('volt_route_check_records',sys.argv[3]);r=importlib.util.module_from_spec(spec);spec.loader.exec_module(r)
r.DIRECTORY=Path(sys.argv[1]) # Isolated owned test directory, no production override.
client=None;context=None;boot=None
print('child_ready',flush=True)
for line in sys.stdin:
 try:
  command=json.loads(line);action=command['action']
  if action=='start':
   if sys.argv[2]!='-':
    import sqlalchemy as sa
    from fastapi.testclient import TestClient
    from uvm.auth import route_check as bridge
    # Explicit source-build fixture must precede app module's eager factory.
    # Native fixed-path/ancestor admission remains delivery proof.
    bridge.PROTECTED_RECORDS_PATH=Path(sys.argv[3]);bridge._RECORDS=r
    from uvm.api.app import create_app
    engine=sa.create_engine(os.environ['UVM_DB_URL'])
    app=create_app(engine,principals={},cursor_secret=secrets.token_bytes(32))
    context=TestClient(app,base_url='https://127.0.0.1',client=('127.0.0.1',52319));client=context.__enter__()
   else:
    with r.locked_store(role='api') as store:
     launch=store.read_launch()
     if launch['readiness_profile']==r.OBSERVED_READINESS_PROFILE:
      identity=r.validate_supervision(store.read_supervisor(),require_ready=False,own_api=True)
      boot=r.record(runtime_boot_nonce=r.new_nonce(),api=identity,published_boottime_ns=r.boottime_ns(),ready=True,loaded_operation_id=None)
      store.publish_boot(boot)
     else:r.validate_launch_processes(launch,own_api=True)
   result={'ok':True}
  elif action=='load':
   with r.locked_store(role='api') as store:
    state=store.read_state();boot=store.read_boot();boot={**boot,'loaded_operation_id':state['arm']['operation_id']};store.publish_boot(boot)
   result={'ok':True}
  elif action in ('seen','seen_crash'):
   if action=='seen_crash':
    import signal
    original_unlink=r.os.unlink;original_sync=r.os.fsync
    def crash_unlink(name,*args,**kwargs):
     if str(name).startswith('.tmp-seen-') and (r.DIRECTORY/'api'/'seen.json').exists():os.kill(os.getpid(),signal.SIGKILL)
     return original_unlink(name,*args,**kwargs)
    def crash_sync(fd):
     if (r.DIRECTORY/'api'/'seen.json').exists():os.kill(os.getpid(),signal.SIGKILL)
     return original_sync(fd)
    r.os.unlink=crash_unlink;r.os.fsync=crash_sync
   with r.locked_store(role='api') as store:
    r.validate_supervision(store.read_supervisor(),own_api=True);a=store.read_state()['arm'];r.check_fresh(a)
    store.publish_seen(r.record(operation_id=a['operation_id'],runtime_boot_nonce=a['runtime_boot_nonce'],api=a['api'],challenge_sha256=hashlib.sha256(a['challenge'].encode()).hexdigest(),observed_utc_ns=time.time_ns(),observed_boottime_ns=r.boottime_ns()))
   result={'ok':True}
  elif action=='boot_attempt':
   with r.locked_store(role='api') as store:
    store.publish_boot(r.record(runtime_boot_nonce=r.new_nonce(),api=r.validated_proc_identity(os.getpid()),published_boottime_ns=r.boottime_ns(),ready=True,loaded_operation_id=None))
   result={'ok':True}
  elif action=='module_info':
   result={'file':str(Path(r.__file__).resolve()),'sha256':hashlib.sha256(Path(r.__file__).read_bytes()).hexdigest()}
  elif action=='config':
   response=client.get('/api/v1/auth/config',headers=command.get('headers',[]))
   result={'status':response.status_code,'body':response.json(),'headers':dict(response.headers)}
  elif action=='quit':
   if context:context.__exit__(None,None,None);engine.dispose()
   print(json.dumps({'ok':True}),flush=True);break
  else:raise ValueError()
  print(json.dumps(result),flush=True)
 except Exception as e:
  print(json.dumps({'error':getattr(e,'code',type(e).__name__)}),flush=True)
'''


class ProcessFixture:
    """Root parent and actual UID1800/session-leader child; fake image metadata."""
    def __init__(self,directory,config=None,*,python=None,environment=None,readiness_profile='normal_local_https'):
        self.directory=Path(directory);self.config=config;self.process=None;self.python=python;self.environment=environment or {}
        self.readiness_profile=readiness_profile
        self.old_directory=rc.DIRECTORY;rc.DIRECTORY=self.directory
        # Explicit source-build root-readiness fixture; production path/ancestry
        # remains fixed and native validation is not substituted by this loader.
        self.ready_temp=tempfile.TemporaryDirectory(prefix='volt-ready-owned-')
        self.old_readiness=rc._open_readiness_directory
        def owned_readiness():
            fd=os.open(self.ready_temp.name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
            try:rc._directory(fd,0,0,0o700)
            except BaseException:os.close(fd);raise
            return fd
        rc._open_readiness_directory=owned_readiness
        self.protected_temp=tempfile.TemporaryDirectory(prefix='volt-protected-records-')
        os.chmod(self.protected_temp.name,0o755)
        self.protected_file=Path(self.protected_temp.name)/'volt_route_check_records.py'
        self.protected_file.write_bytes(Path(rc.__file__).read_bytes());self.protected_file.chmod(0o644)
        os.chown(self.protected_file,0,0)
        rc.bootstrap_store()
        self.stderr=tempfile.TemporaryFile()
    def line(self):
        if not select.select([self.process.stdout],[],[],15)[0]:raise AssertionError('owned fixture child timeout')
        value=self.process.stdout.readline()
        if not value:raise AssertionError('owned fixture child exited')
        return value.strip()
    def start(self,*,ready=True):
        env=os.environ.copy();env.update(self.environment);env['PYTHONDONTWRITEBYTECODE']='1'
        self.process=subprocess.Popen(['setpriv','--reuid=1800','--regid=1800','--clear-groups',
            (self.python or (sys.executable if self.config else '/usr/bin/python3')),'-u','-c',CHILD,str(self.directory),str(self.config) if self.config else '-',str(self.protected_file)],
            stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=self.stderr,text=True,start_new_session=True,env=env)
        if self.line()!='child_ready':raise AssertionError('bad owned fixture handshake')
        self.identity=rc.validated_proc_identity(self.process.pid)
        self.supervisor=rc.record(supervisor=rc.validated_proc_identity(os.getpid()),api=self.identity,
            clock_ticks_per_second=os.sysconf('SC_CLK_TCK'),phase='starting')
        with rc.locked_store(role='root') as store:
            elf=os.stat('/usr/bin/python3')
            # Artificial launch metadata for the real identity chain, NOT FDexec.
            self.launch={**rc.record(),'profile':rc.LAUNCH_RECORD_PROFILE,'recipe':rc.MAIN_API_RECIPE,'readiness_profile':self.readiness_profile,
                'entrypoint':rc.validated_proc_identity(os.getppid()),'supervisor':self.supervisor['supervisor'],
                'api':self.identity,'clock_ticks_per_second':os.sysconf('SC_CLK_TCK'),
                'executable':{'device':elf.st_dev,'inode':elf.st_ino,'mode':0o755,'uid':0,'gid':elf.st_gid,'size':elf.st_size},
                'exec_utc_ns':time.time_ns(),'exec_boottime_ns':rc.boottime_ns()}
            store.publish_launch(self.launch)
        self.session=rc.broker_session(self.launch)
        with rc.locked_store(role='root') as store:
            store.publish_supervisor(self.supervisor)
            store.publish_state(rc.record(state='disarmed',arm=None,closing_reason=None,
                disarmed=rc.record(runtime_boot_nonce=None,api=None,runtime=None,reason='startup',operation_id=None)))
        self.command('start')
        with rc.locked_store(role='root') as store:
            store.publish_launch_status({**rc.record(),'profile':rc.LAUNCH_PROFILE,
                **{k:self.launch[k] for k in ('entrypoint','supervisor','api')},'phase':'running','result':'none',
                'updated_utc_ns':time.time_ns(),'updated_boottime_ns':rc.boottime_ns()})
        if ready:
            marker=Path(self.ready_temp.name)/'ready';marker.touch(mode=0o600)
            if not self.session.acknowledge_parent_ready():raise AssertionError('owned readiness not acknowledged')
            self.supervisor={**self.supervisor,'phase':'ready'}
        return self
    def command(self,action,**values):
        self.process.stdin.write(json.dumps({'action':action,**values})+'\n');self.process.stdin.flush()
        result=json.loads(self.line())
        if 'error' in result:raise AssertionError('owned child fixed error: '+result['error'])
        return result
    def arm(self,*,installation=None,journal=None,epoch=None,generation=0):
        import uuid
        with rc.locked_store(role='root') as store:
            boot=store.read_boot();now=rc.boottime_ns();utc=time.time_ns()
            self.arm_record=rc.record(operation_id=str(uuid.uuid4()),installation_id=installation or str(uuid.uuid4()),
                journal_id=journal or str(uuid.uuid4()),restore_generation=generation,recovery_epoch_id=epoch,
                container_id='1'*64,started_at='2026-11-19T00:00:00.000000000Z',image={'kind':'config','id':'sha256:'+'2'*64,'config_id':'sha256:'+'2'*64},
                resources_sha256='3'*64,public_origin='https://127.0.0.1',runtime_boot_nonce=boot['runtime_boot_nonce'],api=self.identity,
                challenge=rc.new_nonce(),issued_utc_ns=utc,expires_utc_ns=utc+rc.TTL_NS,issued_boottime_ns=now,expires_boottime_ns=now+rc.TTL_NS)
            store.publish_state(rc.record(state='armed',arm=self.arm_record,disarmed=None,closing_reason=None))
        if not self.config:self.command('load')
        else:
            for _ in range(30):
                with rc.locked_store(role='root') as store:
                    if store.read_boot()['loaded_operation_id']==self.arm_record['operation_id']:break
                time.sleep(0.1)
            else:raise AssertionError('private arm was not loaded')
        return self.arm_record
    def disarm(self,reason='completed'):
        with rc.locked_store(role='root') as store:
            a=store.read_state()['arm']
            store.publish_state(rc.record(state='closing',arm=a,disarmed=None,closing_reason=reason))
            store.cleanup_observations()
            d=rc.record(runtime_boot_nonce=a['runtime_boot_nonce'],api=a['api'],runtime={k:a[k] for k in ('container_id','started_at','image','resources_sha256')},reason=reason,operation_id=a['operation_id'])
            store.publish_state(rc.record(state='disarmed',arm=None,disarmed=d,closing_reason=None))
    def close(self):
        try:
            if self.process:
                if self.process.poll() is None:
                    try:self.command('quit')
                    except Exception:self.process.kill()
                self.process.wait(timeout=10)
                self.process.stdin.close();self.process.stdout.close()
        finally:
            self.stderr.close();rc.DIRECTORY=self.old_directory;self.protected_temp.cleanup()
            rc._open_readiness_directory=self.old_readiness;self.ready_temp.cleanup()


@unittest.skipUnless(os.geteuid()==0,'owned UID1800/process custody fixture requires scoped root')
class RouteCheckProcessTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='volt-route-owned-');os.chmod(self.temp.name,0o711)
        self.fixture=ProcessFixture(Path(self.temp.name)/'route')
    def tearDown(self):self.fixture.close();self.temp.cleanup()
    def test_real_process_one_shot_shared_state_and_closing_cleanup(self):
        f=self.fixture.start();a=f.arm();f.command('seen')
        with rc.locked_store(role='root') as store:
            self.assertEqual(store.current_state()['state'],'observed')
            self.assertEqual(store.current_state()['active_operation_id'],a['operation_id'])
            with self.assertRaises(rc.RouteCheckError):store.publish_state(rc.record(state='disarmed',arm=None,closing_reason=None,
                disarmed=rc.record(runtime_boot_nonce=a['runtime_boot_nonce'],api=a['api'],runtime=None,reason='cancelled',operation_id=a['operation_id'])))
        with self.assertRaises(AssertionError):f.command('seen')
        f.disarm()
        with rc.locked_store(role='root') as store:
            self.assertEqual(store.current_state()['state'],'disarmed');self.assertIsNone(store.read_seen())
    def test_real_process_stopped_and_reused_identity_fail_closed(self):
        import signal
        f=self.fixture.start();f.arm();os.kill(f.process.pid,signal.SIGSTOP)
        try:
            with rc.locked_store(role='root') as store:
                state=store.current_state();self.assertFalse(state['api_live']);self.assertFalse(state['backend_ready'])
            bad={**f.supervisor,'api':{**f.identity,'proc_start_ticks':f.identity['proc_start_ticks']+1}}
            with self.assertRaises(rc.RouteCheckError):rc.validate_supervision(bad)
        finally:os.kill(f.process.pid,signal.SIGCONT)
    def test_stopped_live_process_never_counts_as_proven_dead(self):
        import signal
        f=self.fixture.start();identity=dict(f.identity)
        os.kill(f.process.pid,signal.SIGSTOP)
        try:
            # proc_live is readiness; proc_dead has a DIFFERENT safety meaning.
            self.assertFalse(rc.proc_live(identity));self.assertFalse(rc.proc_dead(identity))
            with rc.locked_store(role='root') as store:
                with self.assertRaises(rc.RouteCheckError):store.cleanup_observations(remove_boot=True)
                self.assertIsNotNone(store.read_boot())
        finally:os.kill(f.process.pid,signal.SIGCONT)
        self.assertEqual(rc.validated_proc_identity(f.process.pid),identity)
        self.assertFalse(rc.proc_dead(identity))
        f.command('quit');f.process.wait(timeout=5)
        self.assertTrue(rc.proc_dead(identity))
        with rc.locked_store(role='root') as store:
            store.cleanup_observations(remove_boot=True);self.assertIsNone(store.read_boot())

    def test_shared_lock_contention_inode_and_unknown_inventory(self):
        self.fixture.start()
        child='''import sys,time;from pathlib import Path;from uvm.auth import route_check_records as r;r.DIRECTORY=Path(sys.argv[1]);\nwith r.locked_store(role='root'):print('locked',flush=True);time.sleep(3)'''
        process=subprocess.Popen([sys.executable,'-u','-c',child,str(self.fixture.directory)],stdout=subprocess.PIPE,text=True)
        try:
            self.assertEqual(process.stdout.readline().strip(),'locked')
            with self.assertRaises(rc.RouteCheckError) as caught:
                with rc.locked_store(role='root'):pass
            self.assertEqual(caught.exception.code,'process_not_ready')
        finally:process.wait(timeout=5);process.stdout.close()
        path=self.fixture.directory/'unknown';path.write_text('not authority')
        try:
            with self.assertRaises(rc.RouteCheckError):
                with rc.locked_store(role='root'):pass
        finally:path.unlink()
    def test_sigkill_publication_boundary_has_single_link_and_remains_cancelable(self):
        import signal
        f=self.fixture.start();a=f.arm()
        with self.assertRaises(AssertionError):f.command('seen_crash')
        self.assertEqual(f.process.wait(timeout=5),-signal.SIGKILL)
        path=f.directory/'api'/'seen.json'
        self.assertEqual(path.stat().st_nlink,1)
        with rc.locked_store(role='root') as store:
            self.assertEqual(store.inventory(),())
            rc.validate_observation(a,store.read_seen())
            store.publish_state(rc.record(state='closing',arm=a,disarmed=None,closing_reason='cancelled'))
            store.cleanup_observations(remove_boot=True)
            d=rc.record(runtime_boot_nonce=a['runtime_boot_nonce'],api=a['api'],runtime={k:a[k] for k in ('container_id','started_at','image','resources_sha256')},reason='cancelled',operation_id=a['operation_id'])
            store.publish_state(rc.record(state='disarmed',arm=None,disarmed=d,closing_reason=None))
            self.assertIsNone(store.read_boot());self.assertIsNone(store.read_seen())

    def test_malformed_boot_cleanup_requires_dead_identity_and_preserves_other_api(self):
        import signal
        f=self.fixture.start();path=f.directory/'api'/'boot.json'
        with rc.locked_store(role='root') as store:original=store.read_boot()
        path.write_bytes(b'malformed owned observation')
        os.kill(f.process.pid,signal.SIGSTOP)
        try:
            for _ in range(100):
                if not rc.proc_live(f.identity):break
                time.sleep(0.01)
            with rc.locked_store(role='root') as store:
                with self.assertRaises(rc.RouteCheckError):store.cleanup_observations(remove_boot=True)
            self.assertTrue(path.exists())
        finally:os.kill(f.process.pid,signal.SIGCONT)
        f.command('quit');f.process.wait(timeout=5)
        with rc.locked_store(role='root') as store:
            store.cleanup_observations(remove_boot=True);self.assertIsNone(store.read_boot())
        # A structurally valid observation naming another live child is not ours.
        other=subprocess.Popen(['setpriv','--reuid=1800','--regid=1800','--clear-groups','/usr/bin/python3','-c','import time;time.sleep(30)'],start_new_session=True)
        try:
            path.write_bytes(rc.canonical({**original,'api':rc.validated_proc_identity(other.pid)}));path.chmod(0o600);os.chown(path,1800,1800)
            with rc.locked_store(role='root') as store:
                with self.assertRaises(rc.RouteCheckError) as caught:store.cleanup_observations(remove_boot=True)
                self.assertEqual(caught.exception.code,'identity_mismatch')
            self.assertTrue(path.exists())
        finally:other.terminate();other.wait(timeout=5)
        path.write_bytes(b'malformed owned observation')
        for mutation,restore in ((lambda:path.chmod(0o644),lambda:path.chmod(0o600)),
                (lambda:os.chown(path,0,1800),lambda:os.chown(path,1800,1800))):
            mutation()
            try:
                with self.assertRaises(rc.RouteCheckError):
                    with rc.locked_store(role='root') as store:store.cleanup_observations(remove_boot=True)
                self.assertTrue(path.exists())
            finally:restore()
        link=Path(self.temp.name)/'owned-extra-link';os.link(path,link)
        try:
            with self.assertRaises(rc.RouteCheckError):
                with rc.locked_store(role='root') as store:store.cleanup_observations(remove_boot=True)
        finally:link.unlink()
        with rc.locked_store(role='root') as store:
            store.cleanup_observations(remove_boot=True);self.assertIsNone(store.read_boot())

    def test_protected_copy_root_isolation_and_api_reader_share_identical_file(self):
        f=self.fixture.start()
        script="""import sys,json,hashlib;from pathlib import Path
sys.path.insert(0,sys.argv[1]);import volt_route_check_records as r
assert not any(x=='uvm' or x.startswith('uvm.') or x.startswith('sqlalchemy') for x in sys.modules)
r.DIRECTORY=Path(sys.argv[2])
with r.locked_store(role='root') as store:
 assert store.read_launch()['recipe']==r.MAIN_API_RECIPE
 assert store.current_state()['backend_ready']
print(json.dumps({'file':str(Path(r.__file__).resolve()),'sha256':hashlib.sha256(Path(r.__file__).read_bytes()).hexdigest()}))
"""
        root=subprocess.run(['/usr/bin/python3','-I','-S','-c',script,str(f.protected_file.parent),str(f.directory)],
            text=True,capture_output=True,timeout=10,check=True)
        self.assertEqual(json.loads(root.stdout),f.command('module_info'))
        self.assertEqual(Path(rc.__file__).read_bytes(),f.protected_file.read_bytes())
        with rc.locked_store(role='root') as store:
            launch=store.read_launch()
            failed={**rc.record(),'profile':rc.LAUNCH_PROFILE,**{k:launch[k] for k in ('entrypoint','supervisor','api')},
                'phase':'quiesce_failed','result':'quiesce_timeout','updated_utc_ns':time.time_ns(),'updated_boottime_ns':rc.boottime_ns()}
            store.publish_launch_status(failed)
            self.assertFalse(store.current_state()['backend_ready'])
            self.assertEqual(store.read_launch_status(),failed)
    def test_launch_wrong_live_parent_and_missing_record_do_not_fallback(self):
        f=self.fixture.start()
        other=subprocess.Popen(['/usr/bin/sleep','10'])
        try:
            wrong={**f.launch,'entrypoint':rc.validated_proc_identity(other.pid)}
            with self.assertRaises(rc.RouteCheckError):rc.validate_launch_processes(wrong)
        finally:other.terminate();other.wait(timeout=5)
        launch_path=f.directory/'launch.json';original=launch_path.read_bytes();launch_path.unlink()
        try:
            with rc.locked_store(role='root') as store:
                with self.assertRaises(rc.RouteCheckError):store.current_state()
                with self.assertRaises(rc.RouteCheckError):rc.validate_supervision(f.supervisor)
        finally:launch_path.write_bytes(original);launch_path.chmod(0o640);os.chown(launch_path,0,1800)

    def test_partial_supervisor_cleanup_uses_complete_launch_only_after_proven_death(self):
        import signal
        f=self.fixture.start();sup=f.directory/'supervisor.json';launch=f.directory/'launch.json';boot=f.directory/'api'/'boot.json'
        original_sup=sup.read_bytes();original_launch=launch.read_bytes();original_boot=boot.read_bytes()
        def write_sup(raw):
            sup.write_bytes(raw);sup.chmod(0o640);os.chown(sup,0,1800)
        def restore_boot():
            boot.write_bytes(original_boot);boot.chmod(0o600);os.chown(boot,1800,1800)
        sup.unlink();os.kill(f.process.pid,signal.SIGSTOP)
        try:
            for _ in range(100):
                if not rc.proc_live(f.identity):break
                time.sleep(0.01)
            with rc.locked_store(role='root') as store:
                with self.assertRaises(rc.RouteCheckError):store.cleanup_observations(remove_boot=True)
            self.assertTrue(boot.exists())
            write_sup(b'partial root supervisor')
            with rc.locked_store(role='root') as store:
                with self.assertRaises(rc.RouteCheckError):store.cleanup_observations(remove_boot=True)
        finally:os.kill(f.process.pid,signal.SIGCONT)
        f.command('quit');f.process.wait(timeout=5)
        for partial in (None,b'partial root supervisor'):
            restore_boot()
            if partial is None:sup.unlink(missing_ok=True)
            else:write_sup(partial)
            with rc.locked_store(role='root') as store:
                store.cleanup_observations(remove_boot=True)
                self.assertIsNone(store.read_boot())
                with self.assertRaises(rc.RouteCheckError):store.read_supervisor()
            self.assertEqual(sup.read_bytes() if sup.exists() else None,partial)
        restore_boot();write_sup(original_sup)
        other=subprocess.Popen(['setpriv','--reuid=1800','--regid=1800','--clear-groups','/usr/bin/python3','-c','import time;time.sleep(30)'],start_new_session=True)
        try:
            write_sup(rc.canonical({**f.supervisor,'api':rc.validated_proc_identity(other.pid)}))
            with rc.locked_store(role='root') as store:
                with self.assertRaises(rc.RouteCheckError) as caught:store.cleanup_observations(remove_boot=True)
                self.assertEqual(caught.exception.code,'identity_mismatch')
            self.assertTrue(boot.exists())
        finally:other.terminate();other.wait(timeout=5)
        write_sup(original_sup);launch.write_bytes(b'partial launch is NOT authority')
        with rc.locked_store(role='root') as store:
            with self.assertRaises(rc.RouteCheckError):store.cleanup_observations(remove_boot=True)
        self.assertTrue(boot.exists());launch.write_bytes(original_launch)
        sup.chmod(0o644)
        try:
            with self.assertRaises(rc.RouteCheckError):
                with rc.locked_store(role='root') as store:store.cleanup_observations(remove_boot=True)
            self.assertTrue(boot.exists())
        finally:sup.chmod(0o640)
        with rc.locked_store(role='root') as store:
            store.cleanup_observations(remove_boot=True);self.assertIsNone(store.read_boot())

    def test_status_failure_latches_both_writers_but_allows_later_ordinary_stop(self):
        f=self.fixture.start();f.session.register_controlled_request('quiesce')
        with rc.locked_store(role='root') as store:
            status=store.read_launch_status()
            for phase,result in (('quiescing','none'),('quiesce_failed','quiesce_timeout')):
                store.publish_launch_status({**status,'phase':phase,'result':result,
                    'updated_utc_ns':time.time_ns(),'updated_boottime_ns':rc.boottime_ns()})
            before=(store.read_supervisor(),store.read_launch_status())
            for operation in (lambda:store.publish_supervisor({**f.supervisor,'phase':'ready'}),
                    lambda:store.publish_launch_status({**status,'updated_utc_ns':time.time_ns(),'updated_boottime_ns':rc.boottime_ns()})):
                with self.assertRaises(rc.RouteCheckError):operation()
                self.assertEqual((store.read_supervisor(),store.read_launch_status()),before)
            with self.assertRaises(rc.RouteCheckError):rc.validate_supervision(store.read_supervisor())
            self.assertFalse(store.current_state()['backend_ready'])
            store.publish_supervisor({**f.supervisor,'phase':'stopping'})
        # A rejected publication is itself sticky: still terminate/reap the
        # actual API, but this launch can no longer claim clean completion.
        f.command('quit');reaped=f.session.reap_api(block=True)
        f.process.returncode=os.waitstatus_to_exitcode(reaped[1])
        with rc.locked_store(role='root') as store:store.cleanup_observations(remove_boot=True)
        f.session.publish_api_stopped()
        self.assertEqual(f.session.failure,'publication_failed')
        with rc.locked_store(role='root') as store:
            self.assertEqual(store.read_launch_status()['result'],'cleanup_failed')
            self.assertFalse(store.current_state()['backend_ready'])
        self.assertNotEqual(f.session.clean_exit_code(),0)

    def test_partial_supervisor_write_latches_status_and_supervisor_readiness(self):
        f=self.fixture.start()
        with rc.locked_store(role='root') as store:
            status=store.read_launch_status()
            # Fault AFTER atomic replace: supervisor is non-ready while status
            # still says running. Neither writer may erase this barrier.
            with patch.object(rc,'_sync',side_effect=OSError('owned fsync failure')):
                with self.assertRaises(rc.RouteCheckError):store.publish_supervisor({**f.supervisor,'phase':'stopping'})
            self.assertEqual(store.read_supervisor()['phase'],'stopping')
            self.assertEqual(store.read_launch_status()['phase'],'running')
            before=(store.read_supervisor(),store.read_launch_status())
            with self.assertRaises(rc.RouteCheckError):store.publish_supervisor(f.supervisor)
            with self.assertRaises(rc.RouteCheckError):store.publish_launch_status({**status,
                'updated_utc_ns':time.time_ns(),'updated_boottime_ns':rc.boottime_ns()})
            self.assertEqual((store.read_supervisor(),store.read_launch_status()),before)
            with self.assertRaises(rc.RouteCheckError):rc.validate_supervision(store.read_supervisor())
            self.assertFalse(store.current_state()['backend_ready'])

    def test_every_dirty_result_survives_direct_and_multihop_downgrades(self):
        def durable(f):
            return tuple((hashlib.sha256(path.read_bytes()).hexdigest(),path.stat().st_ino,path.stat().st_mtime_ns)
                for path in (f.directory/'supervisor.json',f.directory/'launch-status.json'))
        for index,dirty in enumerate(sorted(rc.DIRTY_RESULTS)):
            with self.subTest(dirty=dirty):
                f=ProcessFixture(Path(self.temp.name)/('dirty-'+str(index)))
                try:
                    f.start()
                    with rc.locked_store(role='root') as store:
                        base=store.read_launch_status()
                        def status(phase,result):return {**base,'phase':phase,'result':result,
                            'updated_utc_ns':time.time_ns(),'updated_boottime_ns':rc.boottime_ns()}
                        store.publish_launch_status(status('failed',dirty))
                        self.assertEqual(f.session.failure,dirty)
                        for operation in (lambda:store.publish_launch_status(status('stopping','none')),
                                lambda:store.publish_launch_status(status('stopped','clean_stop')),
                                lambda:store.publish_launch_status(status('running','none')),
                                lambda:store.publish_supervisor(f.supervisor),
                                lambda:store.publish_launch({**f.launch,'exec_utc_ns':time.time_ns()})):
                            before=durable(f)
                            with self.assertRaises(rc.RouteCheckError):operation()
                            self.assertEqual(durable(f),before)
                            self.assertIn(store.read_launch_status()['result'],rc.DIRTY_RESULTS)
                        with self.assertRaises(rc.RouteCheckError):rc.validate_supervision(store.read_supervisor())
                        self.assertFalse(store.current_state()['backend_ready'])
                        store.publish_supervisor({**f.supervisor,'phase':'stopping'})
                        before=durable(f)
                        with self.assertRaises(rc.RouteCheckError):store.publish_launch_status(status('stopping','none'))
                        self.assertEqual(durable(f),before)
                    f.command('quit');f.process.wait(timeout=5)
                    with rc.locked_store(role='root') as store:
                        store.cleanup_observations(remove_boot=True)
                        store.publish_supervisor({**f.supervisor,'phase':'stopped'})
                        if dirty!='api_nonzero':store.publish_launch_status(status('stopped',dirty))
                        # api_nonzero stays failed: the existing stopped enum has
                        # no truthful api_nonzero variant. It is never CLEAN.
                        for phase,result in (('stopped','clean_stop'),('stopping','none'),('running','none')):
                            before=durable(f)
                            with self.assertRaises(rc.RouteCheckError):store.publish_launch_status(status(phase,result))
                            self.assertEqual(durable(f),before)
                        self.assertIn(store.read_launch_status()['result'],rc.DIRTY_RESULTS)
                        self.assertFalse(store.current_state()['backend_ready'])
                finally:f.close()

    def test_dirty_partial_write_and_missing_status_cannot_reconstruct_clean_history(self):
        f=self.fixture.start()
        with rc.locked_store(role='root') as store:
            base=store.read_launch_status()
            def status(phase,result):return {**base,'phase':phase,'result':result,
                'updated_utc_ns':time.time_ns(),'updated_boottime_ns':rc.boottime_ns()}
            original=rc._Store._publish
            def fail_before_status(instance,name,*args,**kwargs):
                if name=='launch-status.json':raise OSError('owned outcome publication failure')
                return original(instance,name,*args,**kwargs)
            with patch.object(rc._Store,'_publish',fail_before_status):
                with self.assertRaises(OSError):store.publish_launch_status(status('failed','cleanup_failed'))
            # First IO failure may leave BOTH old records untouched. Memory
            # poison plus sole original broker authority withholds completion.
            self.assertEqual(store.read_supervisor()['phase'],'ready')
            self.assertEqual(f.session.failure,'cleanup_failed')
            self.assertNotEqual(f.session.clean_exit_code(),0)
            self.assertEqual(store.read_launch_status()['phase'],'running')
            before=(store.read_supervisor(),store.read_launch_status())
            for phase,result in (('stopping','none'),('stopped','clean_stop'),('quiesce_failed','quiesce_timeout')):
                with self.assertRaises(rc.RouteCheckError):store.publish_launch_status(status(phase,result))
                self.assertEqual((store.read_supervisor(),store.read_launch_status()),before)
            store.publish_supervisor({**f.supervisor,'phase':'stopping'})
            store.publish_launch_status(status('failed','cleanup_failed'))
            (f.directory/'launch-status.json').unlink() # Owned corruption/lost-record fixture.
            for phase,result in (('stopping','none'),('stopped','clean_stop'),('running','none')):
                with self.assertRaises(rc.RouteCheckError):store.publish_launch_status(status(phase,result))
                self.assertIsNone(store.read_launch_status())
            self.assertFalse(store.current_state()['backend_ready'])
            store.publish_launch_status(status('failed','cleanup_failed'))
            store.publish_supervisor({**f.supervisor,'phase':'stopping'})
            self.assertEqual(store.read_launch_status()['result'],'cleanup_failed')

    def test_new_launch_retires_dirty_history_only_after_both_old_identities_dead(self):
        f=self.fixture.start()
        dead=[]
        for command in (['/usr/bin/sleep','10'],['setpriv','--reuid=1800','--regid=1800','--clear-groups','/usr/bin/python3','-c','import time;time.sleep(10)']):
            child=subprocess.Popen(command,start_new_session=True)
            identity=rc.validated_proc_identity(child.pid);child.terminate();child.wait(timeout=5);dead.append(identity)
        old={**f.launch,'supervisor':dead[0],'api':dead[1]}
        # Synthetic retired root metadata uses actual dead identities. This is a
        # store reset fixture, NOT an old broker/FDexec provenance assertion.
        def root_file(name,value):
            path=f.directory/name;path.write_bytes(rc.canonical(value));path.chmod(0o640);os.chown(path,0,1800)
        root_file('launch.json',old)
        root_file('supervisor.json',{**f.supervisor,'supervisor':dead[0],'api':dead[1],'phase':'failed'})
        root_file('launch-status.json',{**rc.record(),'profile':rc.LAUNCH_PROFILE,
            **{k:old[k] for k in ('entrypoint','supervisor','api')},'phase':'failed','result':'forced_stop',
            'updated_utc_ns':time.time_ns(),'updated_boottime_ns':rc.boottime_ns()})
        (f.directory/'api'/'boot.json').unlink() # Models new child's pre-boot publication stage.
        (Path(f.ready_temp.name)/'ready').unlink() # New launch must reject prior readiness.
        with rc.locked_store(role='root') as store:
            store.publish_launch(f.launch)
            self.assertIsNone(store.read_launch_status())
            with self.assertRaises(rc.RouteCheckError):store.read_supervisor()
            store.publish_supervisor({**f.supervisor,'phase':'starting'})
            store.publish_launch_status({**rc.record(),'profile':rc.LAUNCH_PROFILE,
                **{k:f.launch[k] for k in ('entrypoint','supervisor','api')},'phase':'running','result':'none',
                'updated_utc_ns':time.time_ns(),'updated_boottime_ns':rc.boottime_ns()})
            self.assertEqual(store.read_supervisor()['phase'],'starting')
            self.assertEqual(store.read_launch_status()['result'],'none')
            # No boot was adopted, so reset alone is NOT backend readiness.
            self.assertFalse(store.current_state()['backend_ready'])

    def test_publish_fsync_failure_cannot_return_success_and_cancel_recovers(self):
        f=self.fixture.start();f.arm();f.command('seen')
        with rc.locked_store(role='root') as store:
            a=store.read_state()['arm']
            store.publish_state(rc.record(state='closing',arm=a,disarmed=None,closing_reason='cancelled'))
            with patch.object(rc.os,'fsync',side_effect=OSError('owned injected failure')):
                with self.assertRaises(OSError):store.cleanup_observations()
            self.assertEqual(store.read_state()['state'],'closing')
        f.disarm('cancelled')
        with rc.locked_store(role='root') as store:self.assertEqual(store.current_state()['state'],'disarmed')


class RouteCheckWireTests(unittest.TestCase):
    def test_canonical_source_is_stdlib_only_and_status_crossfields_are_closed(self):
        import ast
        tree=ast.parse(Path(rc.__file__).read_text())
        names=set()
        for node in ast.walk(tree):
            if isinstance(node,ast.Import):names.update(x.name.split('.')[0] for x in node.names)
            if isinstance(node,ast.ImportFrom):names.add(node.module.split('.')[0])
        self.assertLessEqual(names,sys.stdlib_module_names|{'__future__'})
        r={'pid':1,'proc_start_ticks':1}
        value={**rc.record(),'profile':rc.LAUNCH_PROFILE,'entrypoint':r,
            'supervisor':{'pid':2,'proc_start_ticks':2},'api':{'pid':3,'proc_start_ticks':3},
            'phase':'quiesce_failed','result':'quiesce_timeout','updated_utc_ns':1,'updated_boottime_ns':1}
        self.assertEqual(rc.validate_record('launch_status',rc.canonical(value)),value)
        for changed in ({**value,'result':'clean_stop'},{**value,'updated_utc_ns':True},{**value,'extra':1}):
            with self.assertRaises(rc.RouteCheckError):rc.validate_record('launch_status',rc.canonical(changed))

    def test_closed_duplicate_boolean_nonce_and_clock_validation(self):
        good=rc.record()
        self.assertEqual(rc.validate_record('request',rc.canonical(good)),good)
        for raw in (b'{"schema_version":1,"schema_version":1,"profile":"'+rc.PROFILE.encode()+b'"}',
                    rc.canonical({**good,'schema_version':True}),rc.canonical({**good,'path':'/etc/shadow'})):
            with self.assertRaises(rc.RouteCheckError):rc.validate_record('request',raw)
        now=rc.boottime_ns();utc=time.time_ns();a={'issued_boottime_ns':now,'expires_boottime_ns':now+10,'issued_utc_ns':utc,'expires_utc_ns':utc+10}
        rc.check_fresh(a,mono_ns=now,utc_ns=utc)
        for clocks in ({'mono_ns':now+11,'utc_ns':utc},{'mono_ns':now,'utc_ns':utc+11}):
            with self.assertRaises(rc.RouteCheckError):rc.check_fresh(a,**clocks)

class RouteCheckLifespanTests(unittest.TestCase):
    def setUp(self):
        self.fixture_loader=patch.object(api_route,'_load_records',return_value=rc)
        self.fixture_loader.start()
    def tearDown(self):self.fixture_loader.stop()
    def service(self,mode='https'):
        from uvm.auth.local import LocalAuth
        service=LocalAuth.__new__(LocalAuth)
        service.config={'trusted_ingress':{'mode':mode},'public_origin':'https://127.0.0.1'}
        return service
    def test_outermost_does_not_publish_boot_when_previous_worker_startup_fails(self):
        import asyncio
        from contextlib import asynccontextmanager
        from fastapi import FastAPI
        events=[]
        @asynccontextmanager
        async def previous(app):
            events.append('worker-enter');raise RuntimeError('owned lifecycle failure')
            yield
        app=FastAPI(lifespan=previous)
        with patch.object(api_route._Observer,'start') as start:
            api_route.install_main_route_check(app,self.service())
            async def enter():
                async with app.router.lifespan_context(app):events.append('incorrectly-ready')
            with self.assertRaises(RuntimeError):asyncio.run(enter())
            start.assert_not_called()
        self.assertEqual(events,['worker-enter'])
    def test_outermost_boot_after_enter_and_invalidation_before_previous_exit(self):
        import asyncio
        from contextlib import asynccontextmanager
        from fastapi import FastAPI
        events=[]
        @asynccontextmanager
        async def previous(app):
            events.append('worker-enter')
            try:yield
            finally:events.append('worker-exit')
        async def poll(_):await asyncio.Event().wait()
        app=FastAPI(lifespan=previous)
        with patch.object(api_route._Observer,'start',lambda _:events.append('boot')), \
                patch.object(api_route._Observer,'stop',lambda _:events.append('invalidate')), \
                patch.object(api_route._Observer,'poll',poll):
            api_route.install_main_route_check(app,self.service())
            async def enter():
                async with app.router.lifespan_context(app):events.append('serving')
            asyncio.run(enter())
        self.assertEqual(events,['worker-enter','boot','serving','invalidate','worker-exit'])
    def test_control_verification_and_http_never_install_observer(self):
        from fastapi import FastAPI
        for environment,mode in (({'UVM_G7_RECOVERY_CONTROL_ONLY':'1'},'https'),
                ({'UVM_G7_VERIFICATION_ONLY':'1'},'https'),({},'loopback')):
            app=FastAPI();previous=app.router.lifespan_context;service=self.service(mode)
            with patch.dict(os.environ,environment):api_route.install_main_route_check(app,service)
            self.assertIs(app.router.lifespan_context,previous)
            self.assertFalse(hasattr(service,'_route_check_observer'))
    def test_proven_dead_uncertainty_never_returns_true(self):
        identity=rc.validated_proc_identity(os.getpid())
        for failure in (PermissionError('owned denied'),ValueError('owned malformed')):
            with patch.object(Path,'read_bytes',side_effect=failure):
                with self.assertRaises(rc.RouteCheckError):rc.proc_dead(identity)
