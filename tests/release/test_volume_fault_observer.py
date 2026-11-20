"""Real caller/session and POSIX producer forwarding; synthetic Docker only."""
from pathlib import Path
import json
import os
import subprocess
import sys
import tempfile
import unittest

from tools.compose_release_qualification import volume_fault_observer_environment


class VolumeFaultObserverTests(unittest.TestCase):
    def fixture(self,root,case):
        state=root/'instance';state.mkdir(mode=0o700);(state/'compose').mkdir(mode=0o700)
        device=root/'device';device.mkdir(mode=0o700);binary=root/'bin';binary.mkdir()
        docker=binary/'docker';docker.write_text('#!'+sys.executable+'\n'+'''import json,os,sys
from pathlib import Path
args=sys.argv[1:];path=Path(os.environ['FAKE_STATE'])
with Path(os.environ['FAKE_CALLS']).open('a')as f:f.write(json.dumps(args)+'\\n')
value=json.loads(path.read_text())if path.exists()else None
if args[:2]==['volume','inspect']:
 if value is None:
  print('[]');print('Error response from daemon: get '+args[2]+': no such volume',file=sys.stderr)
  if os.environ.get('RACE_EXISTS')=='1':path.write_text(json.dumps({'Name':args[2],'Labels':{'foreign':'untouched'}}))
  raise SystemExit(1)
 if '--format'in args:
  labels=value['Labels'];fields=[value['Name'],'local',labels['volt.compose.owner-token'],labels['com.docker.compose.project'],labels['com.docker.compose.volume'],labels['volt.delivery.test-owner'],labels['volt.delivery.case'],json.dumps(value['Options'],separators=(',',':'),sort_keys=True)]
  print('|'.join(fields))
 else:print(json.dumps([value]))
elif args[:2]==['volume','create']:
 labels={};options={}
 for i,arg in enumerate(args):
  if arg in ('--label','--opt'):
   key,v=args[i+1].split('=',1);(labels if arg=='--label'else options)[key]=v
 if 'volt.delivery.test-owner'in labels:
  if value is not None:raise SystemExit('unexpected replacement attempt')
  value={'Name':args[-1],'Driver':'local','Labels':labels,'Options':options,'CreatedAt':'fixed','Mountpoint':'/component-volume'};path.write_text(json.dumps(value));print(args[-1])
 else:
  print('original-create-output');print('original-create-diagnostic',file=sys.stderr);raise SystemExit(int(os.environ.get('ORIGINAL_EXIT','0')))
elif args[0]=='run':print('c'*64)
else:raise SystemExit(97)
''');docker.chmod(0o700)
        environment={**os.environ,'PATH':str(binary)+os.pathsep+os.environ['PATH'],'FAKE_STATE':str(root/'fake-volume.json'),'FAKE_CALLS':str(root/'calls.jsonl')}
        capture=root/'capture';admission={'image_reference':'admitted-ref','platform':'linux/amd64'}
        env=volume_fault_observer_environment(capture=capture,state=state,environment=environment,admission=admission,case=case,device=device if case=='bind-options'else None)
        syntax=subprocess.run(['sh','-n',str(capture/'docker')],capture_output=True,text=True);self.assertEqual(syntax.returncode,0,syntax.stderr)
        return state,device,capture,env

    def child(self,state,capture,env,*,absence=True,wrong_owner=False,request=None):
        owner='a'*64;project='volt-easy-delivery-'+owner[:12];name=project+'_postgres'
        body='printf "%s\\n" "$$" >"$VOLUME_CAPTURE/caller.pid"; '
        if absence:body+='docker volume inspect '+name+' >/dev/null 2>/dev/null; '
        body+='docker volume create --label volt.compose.owner-token='+('b'*64 if wrong_owner else owner)+' --label com.docker.compose.project='+project+' --label com.docker.compose.volume=postgres '+name
        if request:
            body+='; docker run --platform linux/amd64 --pull=never -d --name volt-lock-'+project+'-$$ --network none --read-only --user '+str(os.getuid())+':'+str(os.getgid())+' --label volt.compose.owner-token='+owner+' --label volt.compose.project='+project+' --label org.volt.compose-install.role=host-lifecycle-lock --mount type=bind,src='+str(state)+',dst=/state --mount type=bind,src='+str(request)+',dst=/run/volt-initialization/request.json,readonly --entrypoint /opt/uvm/venv/bin/python admitted-ref -m uvm.installer.lock /state/.install.lock --initialize-local'
        return subprocess.run(['sh','-c',body],env=env,start_new_session=True,capture_output=True,text=True,timeout=10)

    def test_one_exact_absent_create_injected_and_original_streams_status_forwarded(self):
        for case in ('foreign-owner','bind-options'):
            for original_exit in (0,7):
                with self.subTest(case=case,code=original_exit),tempfile.TemporaryDirectory()as directory:
                    root=Path(directory);state,device,capture,env=self.fixture(root,case)
                    result=self.child(state,capture,{**env,'ORIGINAL_EXIT':str(original_exit)})
                    self.assertEqual((result.returncode,result.stdout,result.stderr),(original_exit,'original-create-output\n','original-create-diagnostic\n'))
                    value=json.loads((root/'fake-volume.json').read_text());self.assertTrue((capture/'injected').exists())
                    self.assertEqual(value['Labels']['volt.delivery.case'],case)
                    self.assertEqual(value['Options'],{}if case=='foreign-owner'else{'device':str(device),'o':'bind','type':'none'})
                    self.assertEqual(value['Labels']['volt.compose.owner-token']=='a'*64,case!='foreign-owner')
                    calls=[json.loads(line)for line in(root/'calls.jsonl').read_text().splitlines()];self.assertEqual(sum(c[:2]==['volume','create']for c in calls),2)
                    self.assertEqual(calls[-1],['volume','create','--label','volt.compose.owner-token='+'a'*64,'--label','com.docker.compose.project=volt-easy-delivery-'+'a'*12,'--label','com.docker.compose.volume=postgres','volt-easy-delivery-'+'a'*12+'_postgres'])

    def test_missing_absence_wrong_owner_or_nonempty_device_denies_before_injection(self):
        for fault in ('missing-absence','wrong-owner','device-nonempty'):
            with self.subTest(fault=fault),tempfile.TemporaryDirectory()as directory:
                root=Path(directory);state,device,capture,env=self.fixture(root,'bind-options')
                if fault=='device-nonempty':(device/'foreign').write_text('untouched')
                result=self.child(state,capture,env,absence=fault!='missing-absence',wrong_owner=fault=='wrong-owner')
                self.assertNotEqual(result.returncode,0);self.assertFalse((capture/'injected').exists());self.assertFalse((root/'fake-volume.json').exists())

    def test_new_external_volume_between_absence_and_injection_is_never_replaced(self):
        with tempfile.TemporaryDirectory()as directory:
            root=Path(directory);state,device,capture,env=self.fixture(root,'foreign-owner')
            result=self.child(state,capture,{**env,'RACE_EXISTS':'1'})
            self.assertEqual(result.returncode,76);self.assertEqual(json.loads((root/'fake-volume.json').read_text())['Labels'],{'foreign':'untouched'})
            self.assertFalse((capture/'injected').exists())

    def test_actual_fixed_initial_owner_request_transport_is_copied_without_changing_run_result(self):
        with tempfile.TemporaryDirectory()as directory,tempfile.TemporaryDirectory(prefix='volt-installer.',dir='/tmp')as work:
            root=Path(directory);state,device,capture,env=self.fixture(root,'foreign-owner');request=Path(work)/'runtime-init-request.json';request.write_bytes(b'{"component_only":true}');request.chmod(0o600)
            result=self.child(state,capture,env,request=request)
            self.assertEqual(result.returncode,0,result.stderr);self.assertEqual((capture/'runtime-init-request.json').read_bytes(),request.read_bytes())
            self.assertTrue(result.stdout.endswith('c'*64+'\n'))
