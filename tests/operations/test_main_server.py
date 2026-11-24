"""Source-build Python3.13 runner/kernel fixtures, not native3.14/tini proof."""
import json
import os
from pathlib import Path
import select
import shutil
import signal
import subprocess
import sys
import sysconfig
import tempfile
import time
import unittest

from uvm.auth import route_check_records as records

CHILD=r'''
import asyncio,importlib.util,os,sys,time
from pathlib import Path
spec=importlib.util.spec_from_file_location('volt_route_check_records',sys.argv[3]);r=importlib.util.module_from_spec(spec);spec.loader.exec_module(r)
r.DIRECTORY=Path(sys.argv[2]) # Explicit owned SOURCEBUILD physical-copy fixture.
from uvm.api import main_server as m
scenario=sys.argv[1];witness=int(sys.argv[4]);server_ref=None;retained=[]
import warnings,threading,ctypes
if scenario.startswith('warnings314_'):
 lock=threading.Lock();original_mutated=warnings._filters_mutated
 def mutate_held():
  assert lock.locked(),'held mutation must use3.14lock'
  original_mutated()
 def mutate():
  with lock:mutate_held()
 warnings._lock=lock;warnings._filters_mutated_lock_held=mutate_held;warnings._filters_mutated=mutate
 warnings._get_filters=lambda:warnings.filters
 warnings._use_context=scenario=='warnings314_context'
 if scenario=='warnings314_detached':warnings._get_filters=lambda:[]
if scenario=='coordinator_error':
 original_wait=m.signal.sigtimedwait
 def bad_wait(signals,timeout):
  if threading.current_thread().name=='uvm-main-signals':raise RuntimeError('owned coordinator syscall failure')
  return original_wait(signals,timeout)
 m.signal.sigtimedwait=bad_wait
if scenario=='failure_clock':
 def bad_clock():raise RuntimeError('owned abort clock failure')
 m._boottime=bad_clock
original=m._vendor_types
# Exposes only actual server reference for test synchronization/natural exit;
# actual pinned vendor methods and runner lifecycle remain in use.
def vendor(state):
 Config,Server=original(state)
 class ObservedServer(Server):
  def __init__(self,config):
   global server_ref
   super().__init__(config);server_ref=self
 return Config,ObservedServer
m._vendor_types=vendor
async def ready():
 while server_ref is None or not server_ref.started:await asyncio.sleep(.001)
 os.write(witness,b'R')
 if scenario in ('natural_zero','unrequested_hang','unrequested_complete_hang'):server_ref.should_exit=True
async def sticky_hang():
 while True:
  try:await asyncio.Event().wait()
  except asyncio.CancelledError:continue
async def app(scope,receive,send):
 assert scope['type']=='lifespan'
 while True:
  message=await receive()
  if message['type']=='lifespan.startup':
   if scenario=='startup_failure':raise RuntimeError('owned startup failure')
   if scenario=='startup_failed_hang':await send({'type':'lifespan.startup.failed'});await sticky_hang()
   loop=asyncio.get_running_loop()
   if scenario in ('cancel_error','teardown_failure_hang'):
    async def cancel_bad():
     try:await asyncio.Event().wait()
     except asyncio.CancelledError:raise RuntimeError('owned cancelled task failure')
    retained.append(asyncio.create_task(cancel_bad()))
   if scenario in ('asyncgen_error','teardown_failure_hang'):
    async def generator():
     try:yield 1
     finally:
      if scenario=='teardown_failure_hang':os.write(witness,b'H');await asyncio.Event().wait()
      raise RuntimeError('owned asyncgen close failure')
    gen=generator();await anext(gen);retained.append(gen)
   if scenario in ('executor_warning','executor_ignore','executor_replace','executor_refresh','warnings314_refresh','warnings314_ignore'):
    async def warning_shutdown(timeout=None):
     if scenario in ('executor_refresh','warnings314_refresh'):warnings.simplefilter('always',RuntimeWarning);return
     if scenario=='warnings314_ignore':warnings.simplefilter('ignore',RuntimeWarning)
     if scenario=='executor_ignore':warnings.simplefilter('ignore',RuntimeWarning)
     if scenario=='executor_replace':warnings.filters=[('ignore',None,RuntimeWarning,None,0)]
     warnings.warn('owned executor timeout',RuntimeWarning)
    loop.shutdown_default_executor=warning_shutdown # Explicit warning fault substitution.
   if scenario=='runtime_refresh':warnings.simplefilter('always',RuntimeWarning)
   if scenario=='filter_ignore':warnings.simplefilter('ignore',RuntimeWarning)
   if scenario=='filter_replace':warnings.filters=[('ignore',None,RuntimeWarning,None,0)]
   if scenario=='unrelated_warning_filter':warnings.simplefilter('ignore',DeprecationWarning)
   if scenario=='executor_error':
    import concurrent.futures
    class BrokenExecutor(concurrent.futures.ThreadPoolExecutor):
     def shutdown(self,*args,**kwargs):raise RuntimeError('owned executor shutdown failure')
    loop.set_default_executor(BrokenExecutor(max_workers=1))
   if scenario=='loop_guard':loop.set_exception_handler(lambda loop,context:None)
   if scenario=='warning_guard':warnings.showwarning=lambda *args,**kwargs:None
   if scenario=='handler_guard':m.signal.signal(m.signal.SIGTERM,m.signal.SIG_IGN)
   if scenario=='abort_guard':m.signal.signal(m.signal.SIGALRM,m.signal.SIG_IGN)
   await send({'type':'lifespan.startup.complete'});asyncio.create_task(ready())
  elif message['type']=='lifespan.shutdown':
   if scenario=='lifespan_error':raise RuntimeError('owned shutdown failure')
   if scenario=='lifespan_failed':await send({'type':'lifespan.shutdown.failed'});return
   if scenario=='failed_hang':await send({'type':'lifespan.shutdown.failed'});os.write(witness,b'H');await sticky_hang()
   if scenario in ('unrequested_complete_hang','complete_error_hang'):
    await send({'type':'lifespan.shutdown.complete'});os.write(witness,b'CH')
    if scenario=='complete_error_hang':asyncio.get_running_loop().call_exception_handler({'message':'owned reported failure before hang'})
    await sticky_hang()
   if scenario in ('foreign_hang','foreign_gil','queued','foreign_after_parent','coordinator_error','failure_clock','forced','quiesce','unrequested_hang'):
    os.write(witness,b'H')
    if scenario=='quiesce':await asyncio.sleep(5.5)
    elif scenario=='foreign_gil':ctypes.PyDLL(None).sleep(10)
    else:await asyncio.Event().wait()
   await send({'type':'lifespan.shutdown.complete'});os.write(witness,b'C')
   if scenario=='late_error':raise RuntimeError('owned late lifespan failure')
   return
config=lambda Config:Config(app,loop='asyncio',http='h11',ws='none',lifespan='on',workers=1,proxy_headers=False,log_config=None)
code=m._run(lambda:m._wait_launch(r),config,sockets=[])
os._exit(code)
'''


@unittest.skipUnless(os.geteuid()==0,'owned root broker/UID1800 runner fixture')
class MainServerProcessTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.shared=tempfile.TemporaryDirectory(prefix='volt-main-python-owned-')
        os.chmod(cls.shared.name,0o711)
        cls.runtime=Path(cls.shared.name)/'python'
        shutil.copytree(sys.base_prefix,cls.runtime,symlinks=False)
    @classmethod
    def tearDownClass(cls):cls.shared.cleanup()
    def run_case(self,scenario,*,request=True,foreign=False,queued=False,sent_signal=signal.SIGTERM):
        with tempfile.TemporaryDirectory(prefix='volt-main-runner-owned-') as name,tempfile.TemporaryFile() as stderr:
            root=Path(name);root.chmod(0o711);directory=root/'route'
            old_directory=records.DIRECTORY;records.DIRECTORY=directory
            copy=root/'volt_route_check_records.py';copy.write_bytes(Path(records.__file__).read_bytes());copy.chmod(0o644)
            ready_dir=root/'ready';ready_dir.mkdir(mode=0o700)
            old_ready=records._open_readiness_directory
            def ready_parent():return os.open(ready_dir,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
            records._open_readiness_directory=ready_parent # Explicit fixture ONLY.
            read_fd,write_fd=os.pipe();child=None;pidfd=None;events=bytearray();session=None;raw=None
            try:
                records.bootstrap_store()
                env={**os.environ,'PYTHONHOME':str(self.runtime),'PYTHONPATH':str(Path(__file__).resolve().parents[2])+os.pathsep+sysconfig.get_paths()['purelib'],'PYTHONDONTWRITEBYTECODE':'1'}
                child=subprocess.Popen(['setpriv','--reuid=1800','--regid=1800','--clear-groups',str(self.runtime/'bin'/'python3.13'),'-u','-c',CHILD,scenario,str(directory),str(copy),str(write_fd)],
                    env=env,pass_fds=(write_fd,),stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=stderr,start_new_session=True)
                os.close(write_fd);write_fd=None;pidfd=os.pidfd_open(child.pid)
                deadline=time.monotonic()+5
                while True:
                    try:
                        api=records.proc_metadata(child.pid)
                        if api['uids']==(1800,)*4:break
                    except records.RouteCheckError:pass
                    if time.monotonic()>deadline:raise AssertionError('owned child identity timeout')
                    time.sleep(.001)
                elf=os.stat(str(self.runtime/'bin'/'python3.13'))
                launch={'schema_version':1,'profile':records.LAUNCH_RECORD_PROFILE,'recipe':records.MAIN_API_RECIPE,
                    'readiness_profile':'normal_bearer','entrypoint':records.validated_proc_identity(os.getppid()),
                    'supervisor':records.validated_proc_identity(os.getpid()),'api':api['identity'],
                    'clock_ticks_per_second':os.sysconf('SC_CLK_TCK'),'exec_utc_ns':time.time_ns(),'exec_boottime_ns':records.boottime_ns(),
                    'executable':{'device':elf.st_dev,'inode':elf.st_ino,'mode':0o755,'uid':0,'gid':elf.st_gid,'size':elf.st_size}}
                with records.locked_store(role='root') as store:store.publish_launch(launch)
                session=records.broker_session(launch)
                session.publish_supervisor(records.record(supervisor=launch['supervisor'],api=launch['api'],clock_ticks_per_second=launch['clock_ticks_per_second'],phase='starting'))
                with records.locked_store(role='root') as store:
                    store.publish_state(records.record(state='disarmed',arm=None,closing_reason=None,
                        disarmed=records.record(runtime_boot_nonce=None,api=None,runtime=None,reason='startup',operation_id=None)))
                def until(event,seconds=8):
                    deadline=time.monotonic()+seconds
                    while event not in events:
                        remaining=deadline-time.monotonic()
                        if remaining<=0 or not select.select([read_fd],[],[],remaining)[0]:raise AssertionError('owned runner witness timeout')
                        chunk=os.read(read_fd,32)
                        if not chunk:raise AssertionError('owned runner witness EOF')
                        events.extend(chunk)
                if scenario not in ('startup_failure','startup_failed_hang','warnings314_context','warnings314_detached'):until(ord('R'))
                start=time.monotonic()
                if request:session.register_controlled_request('quiesce' if scenario=='quiesce' else 'stop')
                if queued:
                    from tests.operations.test_signal_sender_custody import FORGER
                    subprocess.run(['setpriv','--reuid=1800','--regid=1800','--clear-groups','/usr/bin/python3','-c',FORGER,str(child.pid),str(os.getpid())],check=True,timeout=3,stdout=subprocess.DEVNULL)
                elif foreign:
                    subprocess.run(['/usr/bin/python3','-c','import os,signal,sys;os.kill(int(sys.argv[1]),signal.SIGTERM)',str(child.pid)],check=True,timeout=3)
                elif scenario not in ('natural_zero','startup_failure','startup_failed_hang','coordinator_error','unrequested_hang','unrequested_complete_hang','warnings314_context','warnings314_detached'):signal.pidfd_send_signal(pidfd,sent_signal)
                if scenario=='foreign_after_parent':
                    until(ord('H'));subprocess.run(['setpriv','--reuid=1800','--regid=1800','--clear-groups','/usr/bin/python3','-c','import os,signal,sys;os.kill(int(sys.argv[1]),signal.SIGTERM)',str(child.pid)],check=True,timeout=3)
                if scenario=='forced':
                    until(ord('H'));session.note_failure('forced_stop');signal.pidfd_send_signal(pidfd,signal.SIGKILL)
                if scenario=='quiesce':
                    until(ord('H'));self.assertFalse(select.select([pidfd],[],[],4.3)[0],'legitimate quiesce self-aborted')
                    session.register_controlled_request('stop');signal.pidfd_send_signal(pidfd,signal.SIGTERM)
                self.assertTrue(select.select([pidfd],[],[],8)[0],'owned runner exit timeout')
                _,raw=session.reap_api(block=True);child.returncode=os.waitstatus_to_exitcode(raw)
                while select.select([read_fd],[],[],0)[0]:
                    chunk=os.read(read_fd,32)
                    if not chunk:break
                    events.extend(chunk)
                elapsed=time.monotonic()-start;stderr.seek(0);log=stderr.read()
                result={'scenario':scenario,'raw_wait_status':raw,'returncode':child.returncode,'session_failure':session.failure,
                    'events':events.decode(),'elapsed':elapsed,'fixture':'real3.13 UID1800/sourcecopy/no listeners; syntheticELF/admission, notnative3.14'}
                print(json.dumps(result,sort_keys=True),flush=True)
                evidence=os.environ.get('UVM_MAIN_RUNNER_EVIDENCE_DIR')
                if evidence:
                    out=Path(evidence);out.mkdir(parents=True,exist_ok=True)
                    (out/(scenario+'.json')).write_text(json.dumps(result,indent=2)+'\n');(out/(scenario+'.stderr')).write_bytes(log)
                return result
            finally:
                if child and child.returncode is None:
                    try:signal.pidfd_send_signal(pidfd,signal.SIGKILL)
                    except ProcessLookupError:pass
                    child.wait(timeout=5)
                for fd in (read_fd,write_fd,pidfd):
                    if fd is not None:os.close(fd)
                records.DIRECTORY=old_directory;records._open_readiness_directory=old_ready
    def test_clean_parent_term_is_actual_zero_and_canonical_clean_eligible(self):
        result=self.run_case('clean');self.assertEqual(result['returncode'],0);self.assertIsNone(result['session_failure']);self.assertIn('C',result['events'])
    def test_lifespan_error_and_late_error_are_nonzero(self):
        for scenario in ('lifespan_error','late_error','lifespan_failed'):
            with self.subTest(scenario=scenario):self.assertNotEqual(self.run_case(scenario)['returncode'],0)
    def test_foreign_signal_hung_shutdown_aborts_without_broker_request(self):
        result=self.run_case('foreign_hang',request=False,foreign=True)
        self.assertNotEqual(result['returncode'],0);self.assertLess(result['elapsed'],5)
    def test_startup_and_unrequested_natural_return_are_nonzero(self):
        for scenario in ('startup_failure','natural_zero'):
            with self.subTest(scenario=scenario):self.assertNotEqual(self.run_case(scenario,request=False)['returncode'],0)
    def test_forced_kill_is_not_clean(self):
        self.assertEqual(self.run_case('forced')['returncode'],-signal.SIGKILL)
    def test_repeated_parent_term_preserves_pending_quiesce(self):
        result=self.run_case('quiesce');self.assertEqual(result['returncode'],0);self.assertIsNone(result['session_failure']);self.assertGreater(result['elapsed'],5)

    def test_queued_forged_root_identity_is_not_controlled(self):
        import platform
        if platform.machine()!='x86_64':self.skipTest('queued syscall fixture ABI x86_64 only')
        result=self.run_case('queued',request=False,queued=True)
        self.assertNotEqual(result['returncode'],0);self.assertLess(result['elapsed'],5)
    def test_coordinator_failure_hung_lifespan_aborts_without_parent_stop(self):
        result=self.run_case('coordinator_error',request=False)
        self.assertNotEqual(result['returncode'],0);self.assertLess(result['elapsed'],5)
    def test_foreign_after_parent_and_gil_block_are_not_clean(self):
        for scenario,request,foreign in (('foreign_after_parent',True,False),('foreign_gil',False,True)):
            with self.subTest(scenario=scenario):
                result=self.run_case(scenario,request=request,foreign=foreign)
                self.assertNotEqual(result['returncode'],0);self.assertLess(result['elapsed'],5)
    def test_loop_cancel_asyncgen_executor_and_restoration_errors_deny_zero(self):
        for scenario in ('cancel_error','asyncgen_error','executor_error','executor_warning','executor_ignore','executor_replace','filter_ignore','filter_replace','loop_guard','warning_guard','handler_guard','abort_guard'):
            with self.subTest(scenario=scenario):self.assertNotEqual(self.run_case(scenario)['returncode'],0)
    def test_known_teardown_failure_then_hang_has_independent_abort(self):
        result=self.run_case('teardown_failure_hang');self.assertNotEqual(result['returncode'],0);self.assertLess(result['elapsed'],5)
    def test_failure_clock_cannot_leave_a_latch_without_abort(self):
        result=self.run_case('failure_clock',request=False,foreign=True);self.assertNotEqual(result['returncode'],0)
    def test_parent_sigint_is_not_normalized_to_clean(self):
        self.assertNotEqual(self.run_case('parent_int',sent_signal=signal.SIGINT)['returncode'],0)

    def test_reported_failure_before_unfinished_lifespan_await_is_bounded(self):
        for scenario,request in (('failed_hang',True),('complete_error_hang',True),('startup_failed_hang',False),('unrequested_hang',False),('unrequested_complete_hang',False)):
            with self.subTest(scenario=scenario):
                result=self.run_case(scenario,request=request)
                self.assertNotEqual(result['returncode'],0);self.assertLess(result['elapsed'],5)
    def test_unrelated_warning_filter_does_not_disable_runtime_guard(self):
        result=self.run_case('unrelated_warning_filter');self.assertEqual(result['returncode'],0);self.assertIsNone(result['session_failure'])

    def test_equivalent_runtime_warning_refresh_remains_clean(self):
        for scenario in ('runtime_refresh','executor_refresh'):
            with self.subTest(scenario=scenario):
                result=self.run_case(scenario);self.assertEqual(result['returncode'],0);self.assertIsNone(result['session_failure'])

    def test_python314_warning_lock_getter_shape_without_native_claim(self):
        # Only3.14module-interface shape is substituted on host3.13; real
        # owned Runner/kernel wait still runs. Actual3.14image required.
        result=self.run_case('warnings314_refresh');self.assertEqual(result['returncode'],0)
        for scenario in ('warnings314_ignore','warnings314_context','warnings314_detached'):
            with self.subTest(scenario=scenario):
                result=self.run_case(scenario,request=scenario=='warnings314_ignore')
                self.assertNotEqual(result['returncode'],0)
