"""Closed transport plus real POSIX/Docker-stub producer boundaries, not native proof."""
import base64
import copy
import importlib.util
import io
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


def identity_program():
    source=(ROOT/'deploy/compose/offline-host.sh').read_text()
    return source.split("set -- -c '",1)[1].split("'\n",1)[0]


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
    def test_single_saved_identity_projection_rejects_noncanonical_or_ambiguous_context(self):
        from contextlib import redirect_stdout
        from uvm.installer import offline_lifecycle as data
        item,*_=context()
        started=item['State']['StartedAt']
        baseline={'image':[{}],'containers':[item],'volumes':[],'networks':[]}
        cases=[('valid',baseline)]
        for key,value in (('Id','A'*64),('Id','a'*63),('Id',False),('Id','a'*64+'\n'),
                ('Id','$(private-selector)'),('State',None)):
            changed=copy.deepcopy(baseline);changed['containers'][0][key]=value;cases.append((key,changed))
        for value in ('2026-02-30T00:00:00Z',started+'|extra',started+'\n',None):
            changed=copy.deepcopy(baseline);changed['containers'][0]['State']['StartedAt']=value;cases.append(('StartedAt',changed))
        for key,value in (('containers',[]),('containers',[item,item]),('image',{}),('volumes',[0])):
            changed=copy.deepcopy(baseline);changed[key]=value;cases.append((key,changed))
        changed=copy.deepcopy(baseline);changed['unexpected']=[];cases.append(('unknown-root',changed))
        for label,document in cases:
            with self.subTest(label=label),tempfile.TemporaryDirectory()as temporary:
                root=Path(temporary);path=root/'docker.json';path.write_bytes(json.dumps(document).encode());path.chmod(0o600)
                output=io.StringIO()
                with patch.object(data,'OBSERVATION',root),redirect_stdout(output):
                    if label=='valid':
                        exec(compile(identity_program(),'fixed_saved_identity','exec'),{})
                    else:
                        with self.assertRaises((ValueError,TypeError,KeyError)):
                            exec(compile(identity_program(),'fixed_saved_identity','exec'),{})
                self.assertEqual(output.getvalue(),item['Id']+'|'+started+'\n'if label=='valid'else'')
        with tempfile.TemporaryDirectory()as temporary:
            root=Path(temporary);path=root/'docker.json';path.write_text('{"image":[],"image":[]}');path.chmod(0o600)
            with patch.object(data,'OBSERVATION',root),self.assertRaises(ValueError):
                exec(compile(identity_program(),'fixed_saved_identity','exec'),{})

    def test_actual_fifo_preserves_each_failed_docker_producer_and_valid_capture(self):
        item,_info,tar,envelope,_runtime=context()
        for failed in ('none','wait','logs','post','delayed-start','deadline'):
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
fail() { printf '%s\\n' "$*" >&2;printf '%s' "${RETAIN_STOP_EVIDENCE:-0}" >"$WORK/retained";exit 1; }
. "$DRIVER"
ensure_lock_owner() { printf checked >>"$WORK/owner-checks"; }
_offline_data_exec() {
 printf '%s\\n' "$1" >>"$WORK/data-actions"
 if [ "$1" = queried-stopped-identity ];then
  exec "$UNIT_PYTHON" -c 'import os;from pathlib import Path;from uvm.installer import offline_lifecycle;offline_lifecycle.OBSERVATION=Path(os.environ["OFFLINE_OBSERVATION"]);exec(compile(os.environ["IDENTITY_PROGRAM"],"fixed_saved_identity","exec"))'
 fi
 case "${1:-}" in filter-stop-*) sleep "$FILTER_START_DELAY" ;; esac
 exec "$UNIT_PYTHON" -c 'import os;from pathlib import Path;from uvm.installer import route_check,offline_lifecycle;from uvm.auth import route_check_records;route_check._shared=lambda:route_check_records;offline_lifecycle.OBSERVATION=Path(os.environ["OFFLINE_OBSERVATION"]);raise SystemExit(offline_lifecycle.main())' "$@"
}
if [ "$HOST_BUDGET_CS" != 0 ]; then
 offline_stop_clock
 OFFLINE_STOP_DEADLINE_CS=$((OFFLINE_NOW_CS + HOST_BUDGET_CS))
fi
offline_capture_shutdown
'''
                env={**os.environ,'PATH':str(root)+os.pathsep+os.environ['PATH'],'WORK':str(root),'OFFLINE_OBSERVATION':str(obs),
                    'DRIVER':str(ROOT/'deploy/compose/offline-host.sh'),'FIXTURE':str(root),'UNIT_PYTHON':sys.executable,
                    'FAILED':failed,'STARTED':item['State']['StartedAt'],'CID':item['Id'],
                    'FILTER_START_DELAY':'1.4' if failed=='deadline' else '.65' if failed=='delayed-start' else '0',
                    'HOST_BUDGET_CS':'100' if failed=='deadline' else '0','IDENTITY_PROGRAM':identity_program()}
                result=subprocess.run(['sh','-c',script],env=env,capture_output=True,timeout=15)
                self.assertEqual(result.returncode==0,failed in ('none','delayed-start'),result.stderr)
                statuses=json.loads((obs/'stop-producer-statuses.json').read_bytes())
                if failed in ('none','delayed-start'):
                    self.assertEqual(statuses,dict.fromkeys(wire.ZERO_FIELDS,0))
                    self.assertEqual((root/'owner-checks').read_text(),'checked'*4)
                    proof=(obs/'shutdown-evidence.json').read_text()
                    with patch.object(wire.route_check,'_shared',return_value=canonical_records):wire.validate(_info,item,proof)
                    actions=(root/'data-actions').read_text().splitlines()
                    self.assertEqual(actions.count('queried-stopped-identity'),1)
                    self.assertNotIn('queried-started-at',actions)
                    self.assertNotIn('queried-container-id',actions)
                    for job in root.glob('stop-job-*'):
                        self.assertEqual((job/'child-wait').read_text().strip(),'0')
                        self.assertEqual((job/'guard-wait').read_text().strip(),'0')
                        self.assertEqual((job/'result').read_text().strip(),'0')
                elif failed=='deadline':
                    self.assertEqual((root/'retained').read_text(),'1')
                    self.assertFalse((obs/'shutdown-evidence.json').exists())
                    self.assertTrue(any(v in (124,255) for v in statuses.values()))
                    self.assertTrue(list(root.glob('stop-job-*/registered')))
                else:
                    key={'wait':'docker_wait','logs':'docker_logs','post':'post_inspect'}[failed]
                    self.assertEqual(statuses[key+'_producer_exit'],17)
                    self.assertEqual(statuses[key+'_filter_exit'],0)
                    self.assertFalse((obs/'shutdown-evidence.json').exists())


class FinishCompletionRaceTests(unittest.TestCase):
    def finish(self, mode, child_exit=0):
        source=(ROOT/'deploy/compose/offline-host.sh').read_text()
        dead=source.split('offline_host_dead() {',1)[1].split('\n}',1)[0]
        ticks=source.split('offline_producer_ticks() {',1)[1].split('\n}',1)[0]
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary)
            script='''set -eu
. "$DRIVER"
WORK=$1;mode=$2;child_exit=$3
'''+ 'real_dead() {'+dead+'\n}\nreal_ticks() {'+ticks+'''\n}
job="$WORK/stop-job-real";mkdir "$job"
(
 if [ "$mode" = live ];then sleep .6
 else while [ ! -f "$WORK/release" ];do sleep .001;done;fi
 exit "$child_exit"
) &
test_child=$!;test_ticks=$(real_ticks "$test_child")
(while [ ! -f "$job/cancel" ];do sleep .001;done) &
test_guard=$!;guard_ticks=$(real_ticks "$test_guard")
IFS=' ' read -r parent_pid parent_rest </proc/self/stat
parent_ticks=$(real_ticks "$parent_pid")
offline_stop_clock
deadline=$((OFFLINE_NOW_CS+1000))
if [ "$mode" = deadline ];then deadline=$((OFFLINE_NOW_CS+3));fi
printf '%s|%s|%s|%s|%s|%s|%s\\n' "$test_child" "$test_ticks" "$test_guard" "$guard_ticks" "$parent_pid" "$parent_ticks" "$deadline" >"$job/registered"
offline_host_dead() {
 if [ "$1" = "$test_child" ] && [ "$mode" != live ] && [ ! -f "$WORK/alive-check" ];then
  # Model preemption AFTER observing a live original child, BEFORE the
  # caller reads /proc ticks. Do not reap: the production wait must do it.
  printf checked >"$WORK/alive-check";printf release >"$WORK/release"
  attempts=0
  while ! real_dead "$1";do
   attempts=$((attempts+1));[ "$attempts" -lt 1000 ] || exit 96
   sleep .001
  done
  [ "$mode" != deadline ] || sleep .08
  return 1
 fi
 real_dead "$1"
}
offline_producer_ticks() {
 if [ "$1" = "$test_child" ];then
  if [ "$mode" = mismatch ];then printf '%s' "$((test_ticks+1))";return;fi
  if [ "$mode" = live ];then return 1;fi
 fi
 real_ticks "$1"
}
if offline_host_finish "$job";then result=0;else result=$?;fi
printf '%s' "$result" >"$WORK/actual-result"
printf '%s' "$RETAIN_STOP_EVIDENCE" >"$WORK/retained"
# Test-only cleanup waits for these two real original children; no signals,
# process search, or wait-status fabrication. The live child is finite.
wait "$test_child" || :
wait "$test_guard" || :
'''
            result=subprocess.run(['sh','-c',script,'fixture',str(root),mode,str(child_exit)],
                env=os.environ|{'DRIVER':str(ROOT/'deploy/compose/offline-host.sh')},capture_output=True,timeout=4)
            self.assertEqual(result.returncode,0,result.stderr)
            row={name:(root/'stop-job-real'/name).read_text().strip()
                for name in ('child-wait','guard-wait','reason') if (root/'stop-job-real'/name).exists()}
            row['result']=int((root/'actual-result').read_text())
            row['retained']=(root/'retained').read_text()
            return row

    def test_disappeared_tick_read_resolves_only_with_original_zero_wait(self):
        row=self.finish('race')
        self.assertEqual(row['child-wait'],'0')
        self.assertEqual(row['guard-wait'],'0')
        self.assertEqual(row['result'],0)
        self.assertEqual(row['reason'],'completed_after_tick_read')

    def test_nonzero_127_identity_mismatch_live_uncertainty_and_deadline_stay_failed(self):
        for mode,code,expected,reason in (
                ('race',7,7,'child_nonzero'),('race',127,127,'wait_status_127'),
                ('mismatch',0,255,'identity_mismatch'),('live',0,255,'child_live_uncertain'),
                ('deadline',0,124,'deadline')):
            with self.subTest(mode=mode,code=code):
                row=self.finish(mode,code)
                self.assertEqual(row['result'],expected)
                self.assertEqual(row['reason'],reason)
                self.assertEqual(row['retained'],'1')
                if mode=='live':self.assertNotIn('child-wait',row)


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
