"""Pinned Uvicorn actual process/signal causality; NO network or policy relaxation.

Host Python3.13 fixture, not the image's Python3.14/tini/broker completion proof.
"""
import hashlib
import inspect
import json
import os
from pathlib import Path
import select
import signal
import subprocess
import sys
import tempfile
import time
import unittest

import uvicorn
from uvicorn.server import Server
from uvm.auth import route_check_records as records

PINNED_SERVER_SHA256='c1be9d133467a42ab88d7168e408ef5a90257661a901899426214a3d1fc2d026'
CHILD=r'''
import asyncio,hashlib,inspect,logging,os,resource,sys
import uvicorn
from uvicorn.server import Server
resource.setrlimit(resource.RLIMIT_CORE,(0,0))
assert uvicorn.__version__=='0.54.0'
assert hashlib.sha256(open(inspect.getfile(Server),'rb').read()).hexdigest()=='c1be9d133467a42ab88d7168e408ef5a90257661a901899426214a3d1fc2d026'
scenario=sys.argv[1];witness=int(sys.argv[2])
logging.basicConfig(level=logging.INFO)
async def app(scope,receive,send):
 assert scope['type']=='lifespan'
 while True:
  message=await receive()
  if message['type']=='lifespan.startup':await send({'type':'lifespan.startup.complete'})
  elif message['type']=='lifespan.shutdown':
   if scenario=='term_error':
    os.write(witness,b'F');raise RuntimeError('owned lifespan shutdown error')
   if scenario=='term_nonzero':os.write(witness,b'F');os._exit(7)
   if scenario=='term_forced':os.write(witness,b'H');await asyncio.Event().wait()
   await send({'type':'lifespan.shutdown.complete'});os.write(witness,b'C');return
async def main():
 config=uvicorn.Config(app,loop='asyncio',http='h11',ws='none',lifespan='on',log_config=None,timeout_graceful_shutdown=1)
 server=Server(config)
 async def ready():
  while not server.started:await asyncio.sleep(.001)
  os.write(witness,b'R')
  if scenario=='natural_zero':server.should_exit=True
 task=asyncio.create_task(ready())
 await server.serve(sockets=[]) # Actual installed server; explicitly no listeners.
 await task
asyncio.run(main())
'''


class UvicornSignalExitTests(unittest.TestCase):
    def test_exact_server_actual_pidfd_signals_and_numeric_wait_matrix(self):
        self.assertEqual(uvicorn.__version__,'0.54.0')
        server_path=Path(inspect.getfile(Server))
        self.assertEqual(hashlib.sha256(server_path.read_bytes()).hexdigest(),PINNED_SERVER_SHA256)
        self.assertNotEqual(signal.getsignal(signal.SIGCHLD),signal.SIG_IGN)
        evidence=os.environ.get('UVM_UVICORN_SIGNAL_EVIDENCE_DIR')
        output=Path(evidence) if evidence else None
        if output:output.mkdir(parents=True,exist_ok=True)
        for scenario in ('term_clean','term_error','term_nonzero','term_forced','unrequested_term','fatal_usr2','natural_zero'):
            with self.subTest(scenario=scenario),tempfile.TemporaryFile() as stderr:
                read_fd,write_fd=os.pipe();child=None;pidfd=None;events=bytearray();status=None
                try:
                    child=subprocess.Popen([sys.executable,'-u','-c',CHILD,scenario,str(write_fd)],
                        pass_fds=(write_fd,),stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=stderr)
                    os.close(write_fd);write_fd=None
                    pidfd=os.pidfd_open(child.pid);identity=records.validated_proc_identity(child.pid)
                    def until(event,seconds=5):
                        deadline=time.monotonic()+seconds
                        while event not in events:
                            remaining=deadline-time.monotonic()
                            if remaining<=0 or not select.select([read_fd],[],[],remaining)[0]:raise AssertionError('owned child witness timeout')
                            data=os.read(read_fd,32)
                            if not data:raise AssertionError('owned child premature witness EOF')
                            events.extend(data)
                    until(ord('R'))
                    self.assertEqual(records.validated_proc_identity(child.pid),identity)
                    controlled=scenario.startswith('term_');sent=[]
                    # Observation records request BEFORE sending the exact signal.
                    requested_at=time.monotonic_ns() if controlled else None
                    if scenario!='natural_zero':
                        sig=signal.SIGUSR2 if scenario=='fatal_usr2' else signal.SIGTERM
                        signal.pidfd_send_signal(pidfd,sig);sent.append(int(sig))
                    if scenario=='term_forced':
                        until(ord('H'));signal.pidfd_send_signal(pidfd,signal.SIGKILL);sent.append(int(signal.SIGKILL))
                    self.assertTrue(select.select([pidfd],[],[],5)[0],'owned child exit timeout')
                    actual,status=os.waitpid(child.pid,0);self.assertEqual(actual,child.pid)
                    child.returncode=os.waitstatus_to_exitcode(status)
                    while select.select([read_fd],[],[],0)[0]:
                        data=os.read(read_fd,32)
                        if not data:break
                        events.extend(data)
                    stderr.seek(0);raw_log=stderr.read()
                    result={'scenario':scenario,'python':sys.version.split()[0],'uvicorn':uvicorn.__version__,
                        'server_sha256':PINNED_SERVER_SHA256,'pidfd_identity':identity,
                        'controlled_request_recorded':controlled,'request_before_signal':requested_at is not None,
                        'sent_signals':sent,'raw_wait_status':status,'wifexited':os.WIFEXITED(status),
                        'exit_code':os.WEXITSTATUS(status) if os.WIFEXITED(status) else None,
                        'wifsignaled':os.WIFSIGNALED(status),'term_signal':os.WTERMSIG(status) if os.WIFSIGNALED(status) else None,
                        'fixture_lifespan_witness':events.decode('ascii'),
                        'application_shutdown_complete_log':b'Application shutdown complete' in raw_log,
                        'finished_server_log':b'Finished server process' in raw_log}
                    print(json.dumps(result,sort_keys=True),flush=True)
                    if output:
                        (output/(scenario+'.json')).write_text(json.dumps(result,indent=2)+'\n')
                        (output/(scenario+'.stderr')).write_bytes(raw_log)
                    if scenario in {'term_clean','term_error','unrequested_term'}:
                        self.assertTrue(os.WIFSIGNALED(status));self.assertEqual(os.WTERMSIG(status),signal.SIGTERM)
                    if scenario=='term_clean':self.assertIn(ord('C'),events);self.assertTrue(result['application_shutdown_complete_log'])
                    elif scenario=='term_error':self.assertIn(ord('F'),events);self.assertNotIn(ord('C'),events);self.assertTrue(result['finished_server_log'])
                    elif scenario=='term_nonzero':self.assertTrue(os.WIFEXITED(status));self.assertEqual(os.WEXITSTATUS(status),7)
                    elif scenario=='term_forced':self.assertTrue(os.WIFSIGNALED(status));self.assertEqual(os.WTERMSIG(status),signal.SIGKILL);self.assertNotIn(ord('C'),events)
                    elif scenario=='fatal_usr2':self.assertTrue(os.WIFSIGNALED(status));self.assertEqual(os.WTERMSIG(status),signal.SIGUSR2)
                    elif scenario=='natural_zero':self.assertTrue(os.WIFEXITED(status));self.assertEqual(os.WEXITSTATUS(status),0)
                finally:
                    if child and child.returncode is None:
                        if pidfd is not None:signal.pidfd_send_signal(pidfd,signal.SIGKILL)
                        _,remaining=os.waitpid(child.pid,0);child.returncode=os.waitstatus_to_exitcode(remaining)
                    for fd in (read_fd,write_fd,pidfd):
                        if fd is not None:os.close(fd)
