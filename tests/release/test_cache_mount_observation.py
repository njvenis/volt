"""Fixed Compose API versus closed lifecycle-helper mount observations."""
from __future__ import annotations
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from uvm.installer.installed_artifacts import reject_mount_overlap
ROOT=Path(__file__).resolve().parents[2]
HELPER='["/opt/uvm/venv/bin/python"]|["-m","uvm.installer.lock","/state/.install.lock"]|none|true|false|null'
class CacheMountObservationTests(unittest.TestCase):
    def collect(self,parent,containers,volumes=None,*,image_kind="selected_manifest"):
        reference='127.0.0.1:46150/volt@sha256:'+'b'*64
        identity='|'.join(['a'*64,reference,'f'*64,'owned-fixture','sha256:'+'b'*64,'sha256:'+'c'*64,'application/vnd.oci.image.manifest.v1+json','1234','linux/amd64','true'])
        for row in containers.values():row.setdefault('identity',identity)
        data=parent/'observed.json';data.write_text(json.dumps({'containers':containers,'volumes':volumes or {}}))
        binary=parent/'docker';binary.write_text('#!'+sys.executable+'\n'+'''import json,os,sys
from pathlib import Path
a=sys.argv[1:];d=json.loads(Path(os.environ['OBSERVATION_FIXTURE']).read_text())
if a[0]=='ps':
 assert '-aq' in a and 'label=org.volt.compose-install.contract=1' in a
 print('\\n'.join(d['containers']))
elif a[0]=='inspect':
 row=d['containers'][a[1]];fmt=a[a.index('--format')+1]
 if 'com.docker.compose.service' in fmt:print(row['role'])
 elif '.Config.Image' in fmt:
  if row.get('require_optional_descriptor_format'):
   assert '{{with (index . "ImageManifestDescriptor")}}' in fmt and '{{else}}|||{{end}}' in fmt
  print(row['identity'])
 elif '.Config.Entrypoint' in fmt:print(row['shape'])
 elif '.HostConfig.Tmpfs' in fmt:
  print(json.dumps(row.get('tmpfs',{p:('rw,noexec,nosuid,size=8m' if p=='/tmp' else 'rw,noexec,nosuid,nodev,size=1m') for p in ('/app/media','/opt/uvm/state','/tmp','/var/lib/postgresql/data')}),sort_keys=True,separators=(',',':')))
 elif 'printf' in fmt:
  print('\\n'.join('|'.join([m['Type'],m['Source'],m['Destination'],str(m['RW']).lower()]) for m in row['mounts']))
 elif fmt=='{{json .Mounts}}':print(json.dumps(row['mounts']))
 elif 'range .Mounts' in fmt:print('\\n'.join(m['Name'] for m in row['mounts'] if m['Type']=='volume'))
 else:sys.exit(91)
elif a[:2]==['volume','inspect']:print(json.dumps(d['volumes'][a[2]]))
else:sys.exit(92)
''');binary.chmod(0o700)
        work=parent/'work';work.mkdir(mode=0o700)
        body=(ROOT/'deploy/compose/launcher.sh').read_text().split('collect_cache_mounts() {',1)[1].split('\n}',1)[0]
        script='set -eu\nfail() { printf "%s\\n" "$*" >&2; exit 1; }\ncollect_cache_mounts() {'+body+'\n}\ncollect_cache_mounts\n'
        result=subprocess.run(['sh','-c',script],env={**os.environ,'PATH':str(parent)+os.pathsep+os.environ['PATH'],'WORK':str(work),'OBSERVATION_FIXTURE':str(data),'LOCK_ID':'a'*64,'IMAGE_REF':reference,'OWNER_TOKEN':'f'*64,'PROJECT':'owned-fixture','IMAGE_ID':'sha256:'+('b'if image_kind=='config'else'c')*64,'IMAGE_ID_KIND':image_kind,'IMAGE_ENGINE_ID':'sha256:'+'b'*64,'SELECTED_MANIFEST_ID':'sha256:'+'c'*64,'SELECTED_MANIFEST_MEDIA':'application/vnd.oci.image.manifest.v1+json','SELECTED_MANIFEST_SIZE':'1234','PLATFORM':'linux/amd64','STATE':str(parent/'state'),'PACKAGE':str(parent/'package'),'CACHE_DIRECTORY':str(parent/'state.installer-artifacts/originals'),'CACHE_PARENT':str(parent/'state.installer-artifacts')},capture_output=True,text=True)
        target=work/'cache-mounts.json'
        return result,json.loads(target.read_text()) if target.exists() else None
    def test_docker28_missing_descriptor_retains_config_identity_and_running_column(self):
        for kind,allowed in (('config',True),('selected_manifest',False)):
            with self.subTest(kind=kind),tempfile.TemporaryDirectory()as tmp:
                parent=Path(tmp);reference='127.0.0.1:46150/volt@sha256:'+'b'*64
                identity='|'.join(['a'*64,reference,'f'*64,'owned-fixture','sha256:'+'b'*64,'','','','','true'])
                mounts=[{'Type':'bind','Source':str(parent/'state'),'Destination':'/state','RW':True},
                        {'Type':'bind','Source':str(parent/'package'),'Destination':'/package','RW':False},
                        {'Type':'bind','Source':str(parent/'state.installer-artifacts/originals'),'Destination':'/run/volt-offline-artifacts','RW':False}]
                row={'role':'<no value>|host-lifecycle-lock','identity':identity,'shape':HELPER,'mounts':mounts,'require_optional_descriptor_format':True}
                result,observation=self.collect(parent,{'a'*64:row},image_kind=kind)
                if allowed:self.assertEqual(result.returncode,0,result.stderr);self.assertEqual(observation,{'containers':[],'volumes':[]})
                else:self.assertNotEqual(result.returncode,0);self.assertIsNone(observation);self.assertIn('witness',result.stderr)

    def test_same_runtime_fixed_fd_helper_is_not_an_api(self):
        with tempfile.TemporaryDirectory() as tmp:
            parent=Path(tmp);cache=parent/'state.installer-artifacts'
            helper={'role':'<no value>|host-lifecycle-lock','shape':HELPER,'mounts':[{'Type':'bind','Source':str(cache),'Destination':'/run/volt-cache-parent','RW':False},{'Type':'bind','Source':str(parent/'state'),'Destination':'/state','RW':True},{'Type':'bind','Source':str(parent/'package'),'Destination':'/package','RW':False},{'Type':'bind','Source':str(cache/'originals'),'Destination':'/run/volt-offline-artifacts','RW':False}]}
            api={'role':'volt|<no value>','state':'stopped','project':'foreign-instance','mounts':[{'Type':'bind','Source':str(parent/'another-instance/secrets'),'Destination':'/run/keys','RW':False}]}
            result,observation=self.collect(parent,{'a'*64:helper,'b'*64:api});self.assertEqual(result.returncode,0,result.stderr)
            self.assertEqual(observation['containers'],[{'Mounts':api['mounts']}]);reject_mount_overlap(str(cache),observation)
    def test_stopped_foreign_api_bind_and_named_volume_ancestors_still_deny(self):
        for kind in ('bind','volume','bind-backed-volume'):
            with self.subTest(kind=kind),tempfile.TemporaryDirectory() as tmp:
                parent=Path(tmp);cache=parent/'state.installer-artifacts';volumes={}
                if kind=='bind':mount={'Type':'bind','Source':str(parent),'Destination':'/unexpected'}
                else:
                    mount={'Type':'volume','Name':'foreign-state','Destination':'/state'}
                    volumes={'foreign-state':{'Name':'foreign-state','Driver':'local','Options':{} if kind=='volume' else {'type':'none','o':'bind','device':str(parent)},'Mountpoint':str(parent)}}
                api={'role':'volt|<no value>','state':'stopped','project':'foreign-instance','mounts':[mount]}
                result,observation=self.collect(parent,{'b'*64:api},volumes);self.assertEqual(result.returncode,0,result.stderr)
                with self.assertRaises(ValueError):reject_mount_overlap(str(cache),observation)
    def test_unknown_roles_are_potential_apis_and_never_excluded(self):
        for role in ('<no value>|<no value>', 'other-service|<no value>'):
            with self.subTest(role=role),tempfile.TemporaryDirectory() as tmp:
                parent=Path(tmp);cache=parent/'state.installer-artifacts'
                mount={'Type':'bind','Source':str(parent),'Destination':'/unknown'}
                result,observation=self.collect(parent,{'a'*64:{'role':role,'shape':HELPER,'mounts':[mount]}})
                self.assertEqual(result.returncode,0,result.stderr)
                self.assertEqual(observation['containers'],[{'Mounts':[mount]}])
                with self.assertRaises(ValueError):reject_mount_overlap(str(cache),observation)

    def test_unknown_or_contradictory_contract_role_fails_closed(self):
        for role,shape in [('<no value>|host-lifecycle-lock',HELPER.replace('none|true','bridge|true')),('<no value>|host-lifecycle-lock',HELPER.replace('null','{"8000/tcp":[]}')),('<no value>|host-lifecycle-lock',HELPER.replace('uvm.installer.lock','uvm.api.main'))]:
            with self.subTest(role=role,shape=shape),tempfile.TemporaryDirectory() as tmp:
                parent=Path(tmp);result,observation=self.collect(parent,{'a'*64:{'role':role,'shape':shape,'mounts':[]}})
                self.assertNotEqual(result.returncode,0);self.assertIsNone(observation)

    def test_other_labelled_helpers_remain_potential_apis(self):
        with tempfile.TemporaryDirectory() as tmp:
            parent=Path(tmp);cache=parent/'state.installer-artifacts'
            mount={'Type':'bind','Source':str(parent),'Destination':'/state','RW':True}
            identity='|'.join(['b'*64,'unadmitted:tag','other','other','sha256:'+'d'*64,'','','','','true'])
            result,observation=self.collect(parent,{'b'*64:{'role':'<no value>|host-lifecycle-lock','identity':identity,'shape':HELPER,'mounts':[mount]}})
            self.assertEqual(result.returncode,0,result.stderr)
            self.assertEqual(observation['containers'],[{'Mounts':[mount]}])
            with self.assertRaises(ValueError):reject_mount_overlap(str(cache),observation)

    def test_current_helper_requires_admitted_image_witness_owner_and_mounts(self):
        for kind in ('arbitrary-image', 'index-alone', 'wrong-child', 'wrong-owner', 'broad-mount', 'extra-mount', 'wrong-tmpfs'):
            with self.subTest(kind=kind),tempfile.TemporaryDirectory() as tmp:
                parent=Path(tmp);reference='127.0.0.1:46150/volt@sha256:'+'b'*64
                fields=['a'*64,reference,'f'*64,'owned-fixture','sha256:'+'b'*64,'sha256:'+'c'*64,'application/vnd.oci.image.manifest.v1+json','1234','linux/amd64','true']
                if kind=='arbitrary-image':fields[1]='untrusted:tag'
                elif kind=='index-alone':fields[5]=''
                elif kind=='wrong-child':fields[5]='sha256:'+'d'*64
                elif kind=='wrong-owner':fields[2]='other'
                mounts=[{'Type':'bind','Source':str(parent/'state'),'Destination':'/state','RW':True},
                    {'Type':'bind','Source':str(parent/'package'),'Destination':'/package','RW':False},
                    {'Type':'bind','Source':str(parent/'state.installer-artifacts/originals'),'Destination':'/run/volt-offline-artifacts','RW':False}]
                if kind=='broad-mount':mounts[0]['Source']=str(parent)
                elif kind=='extra-mount':mounts.append({'Type':'bind','Source':'/','Destination':'/unexpected','RW':False})
                row={'role':'<no value>|host-lifecycle-lock','identity':'|'.join(fields),'shape':HELPER,'mounts':mounts}
                if kind=='wrong-tmpfs':row['tmpfs']={'/app/media':'size=1g'}
                result,observation=self.collect(parent,{'a'*64:row})
                self.assertNotEqual(result.returncode,0);self.assertIsNone(observation)
                if kind in ('arbitrary-image','index-alone','wrong-child','wrong-owner'):self.assertRegex(result.stderr,'image|witness')
