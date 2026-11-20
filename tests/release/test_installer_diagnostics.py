"""Real bounded pipe/filter checks; substituted Docker is explicitly pipeline-only."""
from pathlib import Path
import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch
from uvm.installer import diagnostics as d

ROOT=Path(__file__).resolve().parents[2]
START='2026-11-19T00:00:00.000000001Z'
STAMP='2026-11-19T00:00:01.123456789Z'
VALID=(STAMP+' G7_READINESS=ready\n').encode()

class DiagnosticReaderTests(unittest.TestCase):
    def filtered(self,raw):
        with tempfile.TemporaryFile() as stream:
            stream.write(raw);stream.seek(0);return d.filter_logs(stream,START)
    def test_full_lines_omit_secrets_old_markers_suffixes_and_partial_final_line(self):
        raw=b'PRIVATE_SECRET_SENTINEL\n'+b'2026-11-18T23:59:59Z G7_READINESS=ready\n'+(STAMP+' PRIVATE_SECRET_SENTINEL G7_READINESS=ready\n').encode()+(STAMP+' G7_READINESS=ready PRIVATE_SECRET_SENTINEL\n').encode()+VALID+(STAMP+' G7_SHUTDOWN=controlled').encode()
        value,code=self.filtered(raw);self.assertEqual(code,2);self.assertEqual(value['reader_outcome'],'partial_line');self.assertEqual(value['markers'],[{'timestamp':STAMP,'kind':'readiness_ready','status':None}]);self.assertEqual(value['omitted_lines'],5);self.assertNotIn('PRIVATE_SECRET_SENTINEL',json.dumps(value))
    def test_status_marker_is_full_line_and_bounded_decimal(self):
        raw=(STAMP+' G7_STOP_PHASE=writers status=0\n'+STAMP+' G7_STOP_PHASE=writers status=999\n'+STAMP+' G7_STOP_PHASE=evil status=0\n').encode();value,code=self.filtered(raw);self.assertEqual(code,0);self.assertEqual(value['markers'][0]['kind'],'stop_writers');self.assertEqual(len(value['markers']),1)
    def test_marker_result_count_and_serialized_bytes_are_bounded(self):
        value,code=self.filtered(VALID*257)
        self.assertEqual(code,2);self.assertEqual(value['reader_outcome'],'marker_limit')
        self.assertEqual(len(value['markers']),256);self.assertLess(len(json.dumps(value).encode()),65536)
    def test_no_current_or_incomplete_marker_is_not_success(self):
        for raw in (b'',VALID.rstrip(b'\n'),b'2026-11-18T00:00:00Z G7_READINESS=ready\n'):
            with self.subTest(raw=raw):value,code=self.filtered(raw);self.assertNotEqual(code,0);self.assertEqual(value['reader_outcome'],'no_current_markers')
    def test_byte_line_and_line_length_limits_are_explicit_not_silent_success(self):
        cases=[(b'X'*2049,b'line_length_limit'),(b'\n'*1025,b'line_limit'),(VALID*1024,b'byte_limit')]
        # Use bounded short unknown lines to exceed bytes without long lines.
        cases[-1]=(b'x'*100+b'\n',b'byte_limit')
        for raw,expected in cases:
            if expected==b'byte_limit':raw*=700
            with self.subTest(expected=expected):value,code=self.filtered(raw);self.assertEqual(code,2);self.assertTrue(value['truncated']);self.assertEqual(value['reader_outcome'],expected.decode());self.assertNotIn('X'*100,json.dumps(value))
    def test_actual_open_pipe_absolute_deadline(self):
        reader,writer=os.pipe();start=time.monotonic()
        try:
            with os.fdopen(reader,'rb') as stream,patch.object(d,'READ_SECONDS',.12):value,code=d.filter_logs(stream,START)
            self.assertEqual(code,2);self.assertEqual(value['reader_outcome'],'timeout');self.assertLess(time.monotonic()-start,1)
        finally:os.close(writer)
    def test_failed_actual_reader_fd_is_not_success(self):
        class Broken:
            def fileno(self):raise OSError('PRIVATE_SECRET_SENTINEL')
        value,code=d.filter_logs(Broken(),START);self.assertEqual(code,2);self.assertEqual(value['reader_outcome'],'read_failed');self.assertNotIn('PRIVATE_SECRET_SENTINEL',json.dumps(value))

    def test_posix_pipeline_preserves_docker_failure_even_with_valid_marker(self):
        body=(ROOT/'deploy/compose/offline-host.sh').read_text().split('diagnostic_capture_logs() {',1)[1].rsplit('\n}',1)[0]
        with tempfile.TemporaryDirectory() as temporary:
            parent=Path(temporary);work=parent/'work';work.mkdir(mode=0o700);inputs=parent/'input';inputs.mkdir(mode=0o700)
            script='''set -eu
umask 077
fail() { printf '%s\\n' "$*" >&2; exit 1; }
docker() { if [ "$1" = inspect ]; then printf '%s|%s\\n' "$TEST_CID" "$TEST_STARTED"; return 0; fi; printf '%s\\n' "$TEST_MARKER"; return 17; }
diagnostic_data() { shift; "$TEST_PYTHON" -m uvm.installer.diagnostics filter-logs "$@"; }
diagnostic_capture_logs() {'''+body+'\n}\ndiagnostic_capture_logs\n'
            result=subprocess.run(['sh','-c',script],env={**os.environ,'WORK':str(work),'DIAG_INPUT':str(inputs),'PROJECT':'owned-fixture','TEST_STARTED':START,'TEST_CID':'a'*64,'TEST_MARKER':VALID.decode().strip(),'TEST_PYTHON':sys.executable},capture_output=True,text=True)
            self.assertEqual(result.returncode,0,result.stderr);self.assertEqual(json.loads((inputs/'statuses.json').read_text()),{'producer_exit':17,'reader_exit':0});self.assertEqual(result.stdout,'');self.assertEqual(json.loads((inputs/'logs.json').read_text())['markers'][0]['kind'],'readiness_ready')

class DiagnosticIdentityTests(unittest.TestCase):
    def test_before_after_identity_keeps_fd_owner_image_owner_and_started_at(self):
        base={'Id':'a'*64,'Image':'sha256:'+'b'*64,'ImageManifestDescriptor':None,'Config':{'Labels':{'owner':'private'}},'State':{'StartedAt':START}}
        value={'holder':base,'containers':[base]}
        import copy
        for key in ('Id','Image','Config','State'):
            with self.subTest(key=key):
                other=copy.deepcopy(value)
                if key=='Config':other['containers'][0][key]['Labels']['owner']='changed'
                elif key=='State':other['holder'][key]['StartedAt']=STAMP
                else:other['holder'][key]='changed'
                self.assertNotEqual(d.stable_identity(value),d.stable_identity(other))

class ActualDiagnosticFDTests(unittest.TestCase):
    """Real child FD/exchange/publication; custody+crypto explicitly substituted."""
    def run_holder(self,kind):
        import copy,fcntl,multiprocessing,uuid
        from uvm.installer import offline_lifecycle as lifecycle, installed_artifacts
        from uvm.installer.offline_artifacts import canonical,digest
        context=multiprocessing.get_context('fork')
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);inputs=root/'input';outputs=root/'output'
            for path in (inputs,outputs):path.mkdir(mode=0o700)
            lock=root/'.install.lock';lock.touch(mode=0o600);key=root/'fixture-key';key.write_bytes(b'ORIGINAL_FIXTURE_KEY');key.chmod(0o600)
            setup=root/'setup.py';setup.write_bytes(b'# synthetic admitted setup boundary only\n');setup.chmod(0o600)
            owner='f'*64;project='owned-diagnostic-fixture';image='example@sha256:'+'b'*64
            info={'project':project,'owner_token':owner,'image':image,'image_admission':{'id':'sha256:'+'b'*64,'id_kind':'config','version':'0.1.0-rc.4','source_revision':'a'*40,'source_snapshot':'sha256:'+'c'*64},'subnet':'172.30.0.0/24','gateway':'172.30.0.1','platform':'linux/amd64','installation_id':str(uuid.uuid4()),'installer_phase':'prepared','installer_admission':{'bundle_sha256':'sha256:'+'d'*64},'restore_pending':False}
            value={'holder':{'Id':'e'*64,'Image':'sha256:'+'b'*64,'ImageManifestDescriptor':None,'Config':{'Image':image,'Labels':{'volt.compose.owner-token':owner,'volt.compose.project':project}},'State':{'Running':True,'StartedAt':START}},'containers':[],
              'volumes':[{'Name':project+'_'+store,'Driver':'local','Scope':'local','Mountpoint':'/synthetic/'+store,'Options':None,'Labels':{'volt.compose.owner-token':owner}} for store in ('postgres','media','state')],
              'networks':[{'Name':project+'_network','Id':'1'*64,'Driver':'bridge','Internal':False,'Labels':{'volt.compose.owner-token':owner},'IPAM':{'Config':[{'Subnet':info['subnet'],'Gateway':info['gateway']}]},'Containers':{}}]}
            if kind=='producer-failed':
                info['host_instance_directory']=str(root)
                value['containers']=[{'Id':'d'*64,'Name':'/'+project+'-volt-1','Image':'sha256:'+'b'*64,'ImageManifestDescriptor':None,'Config':{'Labels':{'volt.compose.owner-token':owner,'com.docker.compose.project':project,'com.docker.compose.service':'volt'}},'HostConfig':{'NetworkMode':project+'_network'},'NetworkSettings':{'Networks':{project+'_network':{}}},'Mounts':[],'State':{'Running':False,'Status':'exited','Health':None,'StartedAt':START,'ExitCode':0,'OOMKilled':False}}]
            request={'schema_version':1,'profile':d.REQUEST_PROFILE,'operation':'logs' if kind=='producer-failed' else 'diagnose','operation_id':str(uuid.uuid4()),'setup_sha256':digest(setup.read_bytes())};raw=canonical(request)
            def write(name,obj):
                # Match the exchange's atomic publication: a visible name must
                # never expose an incomplete file to the real child reader.
                p=inputs/name; temporary=inputs/('.'+name+'.tmp')
                descriptor=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
                with os.fdopen(descriptor,'wb') as stream:
                    stream.write(canonical(obj));stream.flush();os.fsync(stream.fileno())
                os.replace(temporary,p)
            write('request.json',request);parent,child=context.Pipe(duplex=False)
            def execute():
                descriptor=os.open(lock,os.O_RDWR);fcntl.flock(descriptor,fcntl.LOCK_EX|fcntl.LOCK_NB)
                def snapshot(_):return copy.deepcopy(info),{'fixture-key':digest(key.read_bytes())}
                receipt_seen=[False]
                def receipt(record,**kwargs):
                    if record!={'fresh_for':request['operation_id']}:raise ValueError('synthetic fresh receipt mismatch')
                    if not receipt_seen[0]:child.send('first-receipt-validated');receipt_seen[0]=True
                try:
                    with patch.object(d,'ROOT',root),patch.object(lifecycle,'ROOT',root),patch.object(d,'INPUT',inputs),patch.object(d,'OUTPUT',outputs),patch.object(d,'SETUP',setup),patch.object(d,'load_snapshot',side_effect=snapshot),patch.object(installed_artifacts,'validate_receipt',side_effect=receipt),patch('uvm.installer.runtime_mounts.validate'),patch.object(d,'SESSION_SECONDS',5):
                        child.send('fd-held');d.serve(descriptor)
                except Exception as exc:child.send(type(exc).__name__+':'+str(exc))
                finally:os.close(descriptor)
            process=context.Process(target=execute);process.start()
            try:
                self.assertTrue(parent.poll(3));self.assertEqual(parent.recv(),'fd-held')
                contender=os.open(lock,os.O_RDWR)
                try:
                    with self.assertRaises(BlockingIOError):fcntl.flock(contender,fcntl.LOCK_EX|fcntl.LOCK_NB)
                finally:os.close(contender)
                if kind=='lock-replaced':lock.rename(root/'old-lock');lock.touch(mode=0o600)
                write('receipt.json',{'fresh_for':request['operation_id']})
                def frame(phase,data):return {'schema_version':1,'profile':'volt_diagnostic_observation_v1','operation_id':request['operation_id'],'request_sha256':digest(raw),'phase':phase,'data':data}
                write('before.json',frame('before',value))
                if kind!='lock-replaced':
                    self.assertTrue(parent.poll(3));self.assertEqual(parent.recv(),'first-receipt-validated')
                after=copy.deepcopy(value)
                if kind=='stale-holder':after['holder']['Id']='2'*64
                if kind=='wrong-operation':
                    after_frame=frame('after',after);after_frame['operation_id']=str(uuid.uuid4())
                else:after_frame=frame('after',after)
                if kind=='key-changed':
                    key.write_bytes(b'CHANGED_FIXTURE_KEY')
                if kind=='producer-failed':
                    write('logs.json',{'schema_version':1,'profile':'volt_filtered_markers_v1','started_at':START,'markers':[{'timestamp':STAMP,'kind':'readiness_ready','status':None}],'omitted_lines':1,'truncated':False,'reader_outcome':'complete'})
                    write('statuses.json',{'producer_exit':17,'reader_exit':0})
                write('after.json',after_frame)
                if kind in ('positive','producer-failed'):
                    deadline=time.monotonic()+3
                    while not (outputs/'result-exit').exists() and time.monotonic()<deadline:time.sleep(.01)
                    self.assertEqual((outputs/'result-exit').read_text(),'1' if kind=='producer-failed' else '0')
                    result=(outputs/'result.json').read_text();self.assertNotIn(owner,result);self.assertNotIn(str(root),result);self.assertNotIn('ORIGINAL_FIXTURE_KEY',result)
                    if kind=='positive':self.assertEqual(json.loads(result)['container']['present'],False)
                    else:self.assertEqual(json.loads(result)['producer_exit'],17);self.assertEqual(json.loads(result)['reader_exit'],0)
                    self.assertEqual((outputs/'identity-lines').stat().st_mode&0o777,0o600)
                    self.assertEqual(key.read_bytes(),b'ORIGINAL_FIXTURE_KEY')
                else:
                    process.join(4);self.assertFalse(process.is_alive());self.assertFalse((outputs/'result.json').exists());self.assertTrue(parent.poll(1));self.assertIn('ValueError',parent.recv())
            finally:
                if process.is_alive():process.terminate()
                process.join(3)
    def test_actual_held_fd_publishes_closed_result_without_private_values(self):self.run_holder('positive')
    def test_actual_fd_cannot_mask_failed_producer_with_successful_reader(self):self.run_holder('producer-failed')
    def test_actual_fd_replacement_stale_holder_crossoperation_and_key_change_deny(self):
        for kind in ('lock-replaced','stale-holder','wrong-operation','key-changed'):
            with self.subTest(kind=kind):self.run_holder(kind)
