"""Closed transport plus real POSIX/Docker-stub producer boundaries, not native proof."""
import base64
import copy
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from uvm.installer import stopped_transport as wire
from uvm.auth import route_check_records as canonical_records
from uvm.installer.offline_artifacts import canonical

ROOT=Path(__file__).resolve().parents[2]
SPEC=importlib.util.spec_from_file_location('stopped_transport_source_fixture',ROOT/'tests/installer/test_route_check_delivery.py')
fixture=importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(fixture)


def context():
    records,runtime,envelope=fixture.stopped_records('normal_local_loopback')
    tar=fixture.records_tar(records)
    item={'Name':'/owned-volt-1','Id':runtime['container_id'],'Image':runtime['image']['id'],
        'ImageManifestDescriptor':None,'Config':{'Labels':{'volt.compose.owner-token':'unit'}},
        'HostConfig':{'NetworkMode':'owned_network'},'NetworkSettings':{'Networks':{'owned_network':{'NetworkID':'9'*64,'DriverOpts':None}}},
        'Mounts':[],'State':{'Running':False,'Paused':False,'Restarting':False,'OOMKilled':False,
            'ExitCode':0,'Error':'','StartedAt':runtime['started_at']}}
    info={'image_admission':{'id_kind':'config','id':runtime['image']['id'],'image_config_id':runtime['image']['config_id']},
        'local_start_admission':{'resources_sha256':runtime['resources_sha256']}}
    return item,info,tar,envelope,runtime


class StoppedTransportTests(unittest.TestCase):
    def test_exact_original_bytes_and_independently_derived_runtime_reach_four_argument_reader(self):
        item,info,tar,envelope,runtime=context()
        raw=wire.encode(item,b'0\n',tar,envelope,item,dict.fromkeys(wire.ZERO_FIELDS,0))
        with patch.object(wire.route_check,'validate_stopped_snapshot',return_value={'purpose':'component'})as reader:
            self.assertEqual(wire.validate(info,item,raw),{'purpose':'component'})
            reader.assert_called_once_with(tar,runtime,envelope,0)
        with patch.object(wire.route_check,'_shared',return_value=canonical_records):
            self.assertEqual(wire.validate(info,item,raw)['readiness_profile'],'normal_local_loopback')


    def test_closed_fields_types_outcomes_base64_and_old_marker_fallback_deny(self):
        item,info,tar,envelope,_=context()
        raw=wire.encode(item,b'0\n',tar,envelope,item,dict.fromkeys(wire.ZERO_FIELDS,0))
        baseline=json.loads(raw)
        mutations=[]
        for key in wire.ZERO_FIELDS:
            for value in (True,1,-1,None):
                row=copy.deepcopy(baseline);row[key]=value;mutations.append((key,canonical(row).decode()))
        for key,value in (('schema_version',True),('profile','old-marker-profile'),('routing_tar_b64','not base64'),
                ('routing_tar_b64',base64.b64encode(b'x'*131073).decode()),('docker_wait_stdout_b64',base64.b64encode(b'0\nextra').decode()),
                ('completion_envelope_b64',base64.b64encode(b'x'*2049).decode()),('post_container',{})):
            row=copy.deepcopy(baseline);row[key]=value;mutations.append((key,canonical(row).decode()))
        row=copy.deepcopy(baseline);row['extra']=0;mutations.append(('unknown',canonical(row).decode()))
        row=copy.deepcopy(baseline);row.pop('docker_logs_producer_exit');mutations.append(('missing',canonical(row).decode()))
        mutations += [('duplicate',raw[:-1]+',"schema_version":1}'),('noncanonical',' '+raw),('old','G7_SHUTDOWN=controlled service_cleanup_status=0')]
        for name,changed in mutations:
            with self.subTest(name=name),patch.object(wire.route_check,'validate_stopped_snapshot')as reader,self.assertRaises((ValueError,KeyError)):
                wire.validate(info,item,changed)
            reader.assert_not_called()

    def test_postinspect_cannot_select_context_or_drop_changed_values(self):
        item,info,tar,envelope,_=context()
        for name in ('cid','StartedAt','mount','state','extra'):
            post=copy.deepcopy(item)
            if name=='cid':post['Id']='d'*64
            elif name=='StartedAt':post['State']['StartedAt']='2026-11-18T01:02:03Z'
            elif name=='state':post['State']['Running']=True
            elif name=='extra':post['unapproved']='value'
            else:post['Mounts']=[dict.fromkeys(('Type','Name','Source','Destination','Driver','RW'),'changed')]
            with self.subTest(name=name),patch.object(wire.route_check,'validate_stopped_snapshot')as reader,self.assertRaises(ValueError):
                raw=wire.encode(item,b'0\n',tar,envelope,post,dict.fromkeys(wire.ZERO_FIELDS,0))
                wire.validate(info,item,raw)
            reader.assert_not_called()

    def test_same_projection_mount_permutation_passes_but_duplicates_deny(self):
        item,info,tar,envelope,_=context()
        item['Mounts']=[{'Type':'bind','Name':None,'Source':'private-a','Destination':'/a','Driver':None,'RW':False},
            {'Type':'bind','Name':None,'Source':'private-b','Destination':'/b','Driver':None,'RW':False}]
        post=copy.deepcopy(item);post['Mounts'].reverse()
        raw=wire.encode(item,b'0\n',tar,envelope,post,dict.fromkeys(wire.ZERO_FIELDS,0))
        with patch.object(wire.route_check,'validate_stopped_snapshot',return_value={}):wire.validate(info,item,raw)
        post['Mounts'].append(copy.deepcopy(post['Mounts'][0]))
        with self.assertRaises(ValueError):wire.encode(item,b'0\n',tar,envelope,post,dict.fromkeys(wire.ZERO_FIELDS,0))

    def test_equal_looking_boolean_integer_and_float_types_are_never_equivalent(self):
        item,info,tar,envelope,_=context()
        mutations=[]
        for key in ('Running','Paused','Restarting','OOMKilled'):
            for bad in (0,0.0,None):
                row=copy.deepcopy(item);row['State'][key]=bad;mutations.append(row)
        for bad in (False,0.0):
            row=copy.deepcopy(item);row['State']['ExitCode']=bad;mutations.append(row)
        row=copy.deepcopy(item);row['Config']['Labels']['wrong']=True;mutations.append(row)
        row=copy.deepcopy(item);row['NetworkSettings']['Networks']['owned_network']['DriverOpts']=False;mutations.append(row)
        row=copy.deepcopy(item);row['Mounts']=[{'Type':'bind','Name':None,'Source':'/private','Destination':'/a','Driver':None,'RW':0}];mutations.append(row)
        for number,row in enumerate(mutations):
            # BOTH sides have identical wrong values: Python == would hide it.
            with self.subTest(number=number),patch.object(wire.route_check,'validate_stopped_snapshot')as reader,self.assertRaises(ValueError):
                wire.encode(row,b'0\n',tar,envelope,copy.deepcopy(row),dict.fromkeys(wire.ZERO_FIELDS,0))
            reader.assert_not_called()


class PosixStoppedAcquisitionTests(unittest.TestCase):
    def test_actual_fifo_preserves_each_failed_docker_producer_and_valid_capture(self):
        item,_info,tar,envelope,_runtime=context()
        for failed in ('none','wait','logs','post'):
            with self.subTest(failed=failed),tempfile.TemporaryDirectory()as tmp:
                root=Path(tmp);obs=root/'observation';obs.mkdir(mode=0o700)
                (root/'tar').write_bytes(tar);(root/'envelope').write_bytes(envelope+b'\n')
                (root/'post').write_bytes(json.dumps([item]).encode())
                (obs/'docker.json').write_bytes(json.dumps({'image':[{}],'containers':[item],'volumes':[],'networks':[]}).encode());(obs/'docker.json').chmod(0o600)
                stub=root/'docker';stub.write_text('#!'+sys.executable+'\n'+'''import json,os,sys
from pathlib import Path
root=Path(os.environ['FIXTURE']);args=sys.argv[1:]
kind={'wait':'wait','cp':'tar','logs':'logs','inspect':'post'}[args[0]]
with(root/'commands').open('a')as f:f.write(json.dumps(args)+'\\n')
assert 'a'*64 in args or any(v.startswith('a'*64+':')for v in args)
if kind=='wait':sys.stdout.buffer.write(b'0\\n')
elif kind=='tar':sys.stdout.buffer.write((root/'tar').read_bytes())
elif kind=='logs':sys.stdout.buffer.write((root/'envelope').read_bytes())
else:sys.stdout.buffer.write((root/'post').read_bytes())
sys.stdout.buffer.flush()
raise SystemExit(17 if kind==os.environ['FAILED']else 0)
''');stub.chmod(0o700)
                script='''set -eu
fail() { printf '%s\\n' "$*" >&2;exit 1; }
. "$DRIVER"
ensure_lock_owner() { printf checked >>"$WORK/owner-checks"; }
_offline_data_exec() {
 exec "$UNIT_PYTHON" -c 'import os;from pathlib import Path;from uvm.installer import route_check,offline_lifecycle;from uvm.auth import route_check_records;route_check._shared=lambda:route_check_records;offline_lifecycle.OBSERVATION=Path(os.environ["OFFLINE_OBSERVATION"]);raise SystemExit(offline_lifecycle.main())' "$@"
}
offline_capture_shutdown
'''
                env={**os.environ,'PATH':str(root)+os.pathsep+os.environ['PATH'],'WORK':str(root),'OFFLINE_OBSERVATION':str(obs),
                    'DRIVER':str(ROOT/'deploy/compose/offline-host.sh'),'FIXTURE':str(root),'UNIT_PYTHON':sys.executable,
                    'FAILED':failed,'STARTED':item['State']['StartedAt'],'CID':item['Id']}
                result=subprocess.run(['sh','-c',script],env=env,capture_output=True,timeout=15)
                self.assertEqual(result.returncode==0,failed=='none',result.stderr)
                statuses=json.loads((obs/'stop-producer-statuses.json').read_bytes())
                if failed=='none':
                    self.assertEqual(statuses,dict.fromkeys(wire.ZERO_FIELDS,0))
                    self.assertEqual((root/'owner-checks').read_text(),'checked'*4)
                    proof=(obs/'shutdown-evidence.json').read_text()
                    with patch.object(wire.route_check,'_shared',return_value=canonical_records):wire.validate(_info,item,proof)
                else:
                    key={'wait':'docker_wait','logs':'docker_logs','post':'post_inspect'}[failed]
                    self.assertEqual(statuses[key+'_producer_exit'],17)
                    self.assertEqual(statuses[key+'_filter_exit'],0)
                    self.assertFalse((obs/'shutdown-evidence.json').exists())


class EarlyRetentionTests(unittest.TestCase):
    def test_actual_exit_trap_preserves_work_on_start_registration_and_early_finish_failure(self):
        launcher=(ROOT/'deploy/compose/launcher.sh').read_text()
        cleanup=launcher[launcher.index('cleanup() {'):launcher.index('\ntrap cleanup 0 HUP INT TERM')]
        for mode in ('clock','child-registration','finish-metadata'):
            with self.subTest(mode=mode),tempfile.TemporaryDirectory()as tmp:
                parent=Path(tmp);work=parent/'work';work.mkdir(mode=0o700);(work/'proof').write_text('retained')
                script='''set -eu
WORK=$1;mode=$2;LOCK_NAME='';INSTALLING=0;CREATED_NETWORK='';RETAIN_STOP_EVIDENCE=0
'''+cleanup+'''
trap cleanup 0
. "$DRIVER"
_offline_data_exec() { printf forbidden >"$WORK/executed";exit 99; }
offline_stop_clock
OFFLINE_STOP_DEADLINE_CS=$((OFFLINE_NOW_CS+25))
if [ "$mode" = clock ];then
 offline_stop_clock() { return 1; }
 if offline_host_start data '' '' "$OFFLINE_STOP_DEADLINE_CS" queried-started-at;then exit 93;fi
elif [ "$mode" = child-registration ];then
 IFS=' ' read -r own_pid own_rest </proc/self/stat
 offline_producer_ticks() {
  [ "$1" = "$own_pid" ] || return 1
  printf 1
 }
 if offline_host_start data '' '' "$OFFLINE_STOP_DEADLINE_CS" queried-started-at;then exit 94;fi
else
 mkdir "$WORK/stop-job-missing"
 if offline_host_finish "$WORK/stop-job-missing";then exit 95;fi
fi
[ "$RETAIN_STOP_EVIDENCE" -eq 1 ]
exit 7
'''
                result=subprocess.run(['sh','-c',script,'unit',str(work),mode],env=os.environ|{'DRIVER':str(ROOT/'deploy/compose/offline-host.sh')},capture_output=True,timeout=3)
                self.assertEqual(result.returncode,7,result.stderr)
                self.assertEqual((work/'proof').read_text(),'retained')
                self.assertFalse((work/'executed').exists())
