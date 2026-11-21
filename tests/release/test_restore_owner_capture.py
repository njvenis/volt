"""Substituted Docker verifies observation order/guards and unchanged forwarding."""
from pathlib import Path
import json
import os
import subprocess
import sys
import tempfile
import unittest
from tools.compose_release_qualification import restore_admit_observer_environment
class RestoreOwnerCaptureTests(unittest.TestCase):
    def fixture(self,parent,wrong_owner=False):
        realdir=parent/'installed-bin';realdir.mkdir();real=realdir/'docker';log=parent/'docker-calls.jsonl'
        project='volt-easy-cause';reference='127.0.0.1:46150/volt@sha256:'+'b'*64
        identity='|'.join(['a'*64,'/volt-offline-'+project+'-12345',reference,'e'*64 if wrong_owner else 'f'*64,project,json.dumps(['-m','uvm.installer.lock','/state/.install.lock','--offline-restore-admit'],separators=(',',':')),'sha256:'+'b'*64,'sha256:'+'c'*64,'application/vnd.oci.image.manifest.v1+json','1234','linux/amd64'])
        exchange=Path(tempfile.mkdtemp(prefix='volt-installer.',dir='/tmp'));self.addCleanup(lambda:__import__('shutil').rmtree(exchange));inputdir=exchange/'offline-input';outputdir=exchange/'offline-output';inputdir.mkdir();outputdir.mkdir()
        for directory,name in [(inputdir,'request.json'),(inputdir,'observed.json'),(outputdir,'plan.json')]:p=directory/name;p.write_text('{}');p.chmod(0o600)
        data=parent/'fixture.json';data.write_text(json.dumps({'identity':identity,'input':str(inputdir),'output':str(outputdir)}))
        real.write_text('#!'+sys.executable+'\n'+'''import json,os,sys
from pathlib import Path
a=sys.argv[1:];d=json.loads(Path(os.environ['CAPTURE_DOCKER_FIXTURE']).read_text())
with open(os.environ['CAPTURE_DOCKER_CALLS'],'a') as stream:stream.write(json.dumps(a)+'\\n')
if a[0]=='inspect':
 fmt=a[a.index('--format')+1]
 if fmt.startswith('{{.Id}}|{{.Created}}|'):print(d.get('retained_identity','a'*64+'|2026-11-20T00:00:00Z|2026-11-20T00:01:00Z|2026-11-20T00:02:00Z|false|false|false|70'))
 elif fmt.startswith('{{.Id}}|'):print(d['identity'])
 elif '/run/volt-offline-input' in fmt:print(d['input'])
 elif '/run/volt-offline-output' in fmt:print(d['output'])
 else:print('{"id":"'+('a'*64)+'"}')
elif a[0]=='logs':print('2026-11-19T00:00:00Z offline-lifecycle-failed: offline imports differ from captured store inventories',file=sys.stderr)
elif a[0]=='rm':
 print('ORIGINAL_DOCKER_STDOUT');print('ORIGINAL_DOCKER_STDERR',file=sys.stderr);sys.exit(23)
else:print('ORIGINAL_OTHER_COMMAND')
''');real.chmod(0o700)
        admission={'image_reference':reference,'image_id':'sha256:'+'c'*64,'image_id_kind':'selected_manifest','platform':'linux/amd64'}
        info={'image':reference,'project':project,'owner_token':'f'*64,'image_admission':{'id':admission['image_id'],'engine_image_id':'sha256:'+'b'*64,'selected_descriptor':{'digest':admission['image_id'],'mediaType':'application/vnd.oci.image.manifest.v1+json','size':1234}}}
        capture=parent/'capture';env=restore_admit_observer_environment(capture=capture,environment={**os.environ,'PATH':str(realdir)+os.pathsep+os.environ['PATH'],'CAPTURE_DOCKER_FIXTURE':str(data),'CAPTURE_DOCKER_CALLS':str(log)},info=info,admission=admission);(capture/'caller.pid').write_text('12345\n')
        return capture,env,log,project
    def test_bounded_logs_and_phase_bytes_captured_BEFORE_unchanged_original_rm(self):
        with tempfile.TemporaryDirectory() as tmp:
            capture,env,log,project=self.fixture(Path(tmp));result=subprocess.run(['docker','rm','-f','volt-offline-'+project+'-12345'],env=env,capture_output=True,text=True)
            self.assertEqual(result.returncode,23);self.assertEqual(result.stdout,'ORIGINAL_DOCKER_STDOUT\n');self.assertEqual(result.stderr,'ORIGINAL_DOCKER_STDERR\n')
            self.assertEqual((capture/'guard.status').read_text().strip(),'captured');self.assertIn('offline imports differ', (capture/'owner.stderr').read_text())
            calls=[json.loads(v) for v in log.read_text().splitlines()];self.assertEqual(calls[-1],['rm','-f','volt-offline-'+project+'-12345']);self.assertEqual(calls[-2][:5],['logs','--timestamps','--tail','128','a'*64])
            for name in ('request.json','plan.json','observed.json','owner.stderr'):self.assertEqual((capture/name).stat().st_mode&0o777,0o600)
    def test_wrong_owner_never_captures_logs_but_original_command_result_unchanged(self):
        with tempfile.TemporaryDirectory() as tmp:
            capture,env,log,project=self.fixture(Path(tmp),wrong_owner=True);result=subprocess.run(['docker','rm','-f','volt-offline-'+project+'-12345'],env=env,capture_output=True,text=True)
            self.assertEqual(result.returncode,23);self.assertEqual((capture/'guard.status').read_text().strip(),'contradiction');self.assertFalse((capture/'owner.stderr').exists());self.assertFalse(any(json.loads(v)[0]=='logs' for v in log.read_text().splitlines()))
    def test_nonmatching_or_missing_pid_does_not_inspect_foreign_owner_or_change_command(self):
        with tempfile.TemporaryDirectory() as tmp:
            capture,env,log,project=self.fixture(Path(tmp));(capture/'caller.pid').unlink()
            result=subprocess.run(['docker','rm','-f','unrelated-owner'],env=env,capture_output=True,text=True);self.assertEqual(result.returncode,23)
            self.assertEqual([json.loads(v) for v in log.read_text().splitlines()],[['rm','-f','unrelated-owner']]);self.assertFalse((capture/'guard.status').exists())

    def test_full_cid_removal_captures_only_original_named_owner_then_forwards_exact_argv(self):
        with tempfile.TemporaryDirectory() as tmp:
            capture,env,log,project=self.fixture(Path(tmp))
            result=subprocess.run(['docker','rm','-f','a'*64],env=env,capture_output=True,text=True)
            self.assertEqual(result.returncode,23)
            self.assertEqual((capture/'guard.status').read_text().strip(),'captured')
            self.assertEqual((capture/'capture-timing').read_text().strip(),'before_removal')
            calls=[json.loads(v)for v in log.read_text().splitlines()]
            self.assertEqual(calls[0][1],'volt-offline-'+project+'-12345')
            self.assertEqual(calls[-1],['rm','-f','a'*64])

    def test_retained_original_owner_capture_is_read_only_and_requires_stopped_identity(self):
        for running in (False,True):
            with self.subTest(running=running),tempfile.TemporaryDirectory() as tmp:
                parent=Path(tmp);capture,env,log,project=self.fixture(parent)
                if running:
                    fixture=parent/'fixture.json';d=json.loads(fixture.read_text())
                    d['retained_identity']='a'*64+'|created|started|finished|true|false|false|0'
                    fixture.write_text(json.dumps(d))
                result=subprocess.run([str(capture/'bin/docker'),'--volt-capture-retained-restore-owner'],env=env,capture_output=True,text=True)
                self.assertEqual(result.returncode,1 if running else 0)
                calls=[json.loads(v)for v in log.read_text().splitlines()]
                self.assertTrue(all(c[0]in ('inspect','logs')for c in calls))
                self.assertEqual((capture/'guard.status').read_text().strip(),'not_stopped'if running else'captured')
                if not running:self.assertEqual((capture/'capture-timing').read_text().strip(),'retained_after_caller')
                else:self.assertFalse((capture/'owner.stderr').exists())

    def test_wrong_full_cid_never_captures_logs_or_inspects_foreign_target(self):
        with tempfile.TemporaryDirectory() as tmp:
            capture,env,log,project=self.fixture(Path(tmp))
            result=subprocess.run(['docker','rm','-f','d'*64],env=env,capture_output=True,text=True)
            self.assertEqual(result.returncode,23)
            calls=[json.loads(v)for v in log.read_text().splitlines()]
            self.assertFalse(any(c[0]=='logs'for c in calls))
            self.assertFalse(any(c[0]=='inspect'and c[1]=='d'*64 for c in calls))
            self.assertEqual(calls[-1],['rm','-f','d'*64])
