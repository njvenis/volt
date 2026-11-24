"""Test instrumentation only: real child/session, synthetic Docker records."""
from pathlib import Path
import json
import os
import subprocess
import sys
import tempfile
import time
import unittest

from tools.compose_release_qualification import initial_resume_observer_environment, initial_resume_fd_probe


class InitialResumeObserverTests(unittest.TestCase):
    def test_exact_actual_fd_probe_is_valid_python(self):
        compile(initial_resume_fd_probe(), "<actual-probe>", "exec")

    def fixture(self, root):
        binary=root/'bin';binary.mkdir()
        docker=binary/'docker'
        docker.write_text('#!'+sys.executable+'\n'+'''import os,sys,json
args=sys.argv[1:]
if args[0]=='logs':
 print('locked=1');print('original diagnostic',file=sys.stderr);raise SystemExit(int(os.environ.get('LOG_EXIT','0')))
if args[0]!='inspect':raise SystemExit(97)
if len(args)==2:print(json.dumps([{'Id':'b'*64}]))
else:
 fmt=args[-1]
 if '.Destination "/state"' in fmt:print(os.environ['TEST_STATE']+'|true')
 elif 'request.json' in fmt:print('/tmp/volt-installer.abcdefgh/runtime-init-request.json')
 else:
  pid=os.environ['CALLER_PID'];project='volt-easy-delivery-test'
  print('|'.join(['b'*64,'/volt-lock-'+project+'-'+pid,'admitted-ref','true','a'*64,project,'["/opt/uvm/venv/bin/python"]','["-m","uvm.installer.lock","/state/.install.lock","--initialize-local"]',os.environ.get('FAKE_NETWORK','none'),'true','false','sha256:'+'c'*64,'','','','']))
''')
        docker.chmod(0o700)
        capture=root/'capture'
        env=initial_resume_observer_environment(capture=capture,state=root/'state',
            environment={**os.environ,'PATH':str(binary)+os.pathsep+os.environ['PATH']},
            admission={'image_reference':'admitted-ref','image_id':'sha256:'+'c'*64,'image_id_kind':'config','platform':'linux/amd64'},
            engine_id='sha256:'+'c'*64,selected={'digest':'sha256:'+'d'*64,'mediaType':'manifest','size':20},project_prefix='volt-easy-delivery')
        env['TEST_STATE']=str(root/'state')
        return capture,env

    def child(self,capture,env):
        command='printf "%s\\n" "$$" >"$RESUME_CAPTURE/caller.pid"; export CALLER_PID=$$; exec docker logs "volt-lock-volt-easy-delivery-test-$$"'
        return subprocess.Popen(['sh','-c',command],env=env,start_new_session=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)

    def test_real_session_holds_original_ready_result_then_forwards_exactly(self):
        with tempfile.TemporaryDirectory() as directory:
            capture,env=self.fixture(Path(directory));child=self.child(capture,env)
            try:
                deadline=time.monotonic()+5
                while not (capture/'gate.ready').exists() and time.monotonic()<deadline:
                    if child.poll() is not None:break
                    time.sleep(.01)
                self.assertTrue((capture/'gate.ready').exists())
                self.assertIsNone(child.poll())
                self.assertEqual((capture/'owner.stdout').read_bytes(),b'locked=1\n')
                (capture/'release').touch()
                stdout,stderr=child.communicate(timeout=5)
                self.assertEqual((child.returncode,stdout,stderr),(0,b'locked=1\n',b'original diagnostic\n'))
            finally:
                if child.poll() is None:child.kill();child.communicate()

    def test_contradictory_holder_and_failed_logs_never_announce_ready(self):
        for extra,expected in [({'FAKE_NETWORK':'bridge'},76),({'LOG_EXIT':'7'},7)]:
            with self.subTest(extra=extra),tempfile.TemporaryDirectory() as directory:
                capture,env=self.fixture(Path(directory));child=self.child(capture,{**env,**extra})
                stdout,stderr=child.communicate(timeout=5)
                self.assertEqual(child.returncode,expected)
                self.assertFalse((capture/'gate.ready').exists())
                if expected==7:self.assertEqual((stdout,stderr),(b'locked=1\n',b'original diagnostic\n'))
                else:self.assertEqual((stdout,stderr),(b'',b''))

    def test_unrelated_command_is_forwarded_with_its_exact_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            capture,env=self.fixture(Path(directory))
            result=subprocess.run(['docker','logs','unrelated'],env={**env,'LOG_EXIT':'9'},capture_output=True)
            self.assertEqual((result.returncode,result.stdout,result.stderr),(9,b'locked=1\n',b'original diagnostic\n'))
            self.assertFalse((capture/'gate.ready').exists())
