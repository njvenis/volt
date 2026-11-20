"""Local ceremony guard/public-PKI tests. No containers, signing or ARM run."""
import copy,hashlib,io,json,os,tarfile,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
from tools.release import hosted_arm_fixture as f

class HostedFixtureTests(unittest.TestCase):
    def artifact(self,root,arch='arm64'):
        p='a'*40;u='sha256:'+'b'*64;event='c'*40
        cfg={'os':'linux','architecture':arch,'config':{'Labels':{'org.opencontainers.image.revision':p,'org.volt.compose.source-snapshot':u,
            'org.opencontainers.image.version':'0.1.0-rc.4','org.volt.compose-install.contract':'1','org.volt.oidc-deployment-modes':'demo,external,local'}}}
        raw=json.dumps(cfg).encode();name=hashlib.sha256(raw).hexdigest()+'.json'
        manifest=json.dumps([{'Config':name,'RepoTags':['volt-easy-rc4:'+arch],'Layers':['layer.tar']}]).encode()
        with tarfile.open(root/'runtime.tar','w')as t:
            for path,data in [('manifest.json',manifest),(name,raw),('layer.tar',b'not-executed-unit-layer')]:
                m=tarfile.TarInfo(path);m.size=len(data);t.addfile(m,io.BytesIO(data))
        (root/'runtime.tar.sha256').write_text(f.sha(root/'runtime.tar')+'  runtime.tar\n')
        for path,data in [('source-revision.txt',p),('source-snapshot.txt',u),('source-event-revision.txt',event)]:(root/path).write_text(data+'\n')
        (root/'source-selection.json').write_text(json.dumps({'event_sha':event,'selected_source_sha':p,'checked_out_sha':p,'source_snapshot':u,'event_name':'pull_request'}))
        return p,u,event,f.digest(raw)
    def test_same_run_archive_actual_config_and_checksum_before_load(self):
        with tempfile.TemporaryDirectory()as d:
            root=Path(d);p,u,e,cfg=self.artifact(root)
            result=f.artifact_config(root,'arm64',p,u,e);self.assertEqual(result['config_id'],cfg)
            (root/'source-selection.json').write_text('{}')
            with self.assertRaises(ValueError):f.artifact_config(root,'arm64',p,u,e)
    def test_foreign_platform_tampered_archive_and_wrong_event_deny(self):
        for case in ('platform','bytes','event'):
            with self.subTest(case=case),tempfile.TemporaryDirectory()as d:
                root=Path(d);p,u,e,cfg=self.artifact(root)
                if case=='bytes':
                    with(root/'runtime.tar').open('ab')as s:s.write(b'change')
                with self.assertRaises(ValueError):f.artifact_config(root,'amd64'if case=='platform'else'arm64',p,u,'0'*40 if case=='event'else e)
    def test_boolean_size_and_unknown_platform_cannot_witness_a_child(self):
        row={'digest':'sha256:'+'1'*64,'size':1,'mediaType':'application/vnd.oci.image.manifest.v1+json','platform':{'os':'linux','architecture':'arm64','variant':'v8'}}
        self.assertTrue(f.strict_descriptor(row))
        for key,value in [('size',True),('size',0),('digest','bad'),('platform',{'os':'linux','architecture':'amd64'})]:
            self.assertFalse(f.strict_descriptor(row|{key:value}))
    def test_fresh_in_memory_public_keys_encode_existing_strict_policy_no_signatures(self):
        from cryptography.hazmat.primitives.asymmetric import ec,rsa
        from cryptography.hazmat.primitives import serialization
        def pem(key):return key.public_key().public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo)
        log=pem(ec.generate_private_key(ec.SECP256R1()));signer=pem(ec.generate_private_key(ec.SECP256R1()))
        files,config=f.trust_documents(log,signer,'2026-11-20T00:00:00Z')
        self.assertEqual(set(files),{'fixture-trust.json','fixture.pub','trusted-root.json'})
        self.assertEqual(json.loads(config)['rekorTlogUrls'][0]['url'],f.URL)
        self.assertNotIn(b'PRIVATE',b''.join(files.values()))
        with tempfile.TemporaryDirectory()as d:
            root=Path(d);root.chmod(0o700)
            for name,raw in files.items():(root/name).write_bytes(raw);(root/name).chmod(0o600)
            expected='sha256:'+hashlib.sha256(json.dumps({n:hashlib.sha256(r).hexdigest()for n,r in files.items()},sort_keys=True,separators=(',',':')).encode()).hexdigest()
            self.assertEqual(f.q_builder.public_policy(root,expected)['sha256'],expected)
        with self.assertRaises(ValueError):f.trust_documents(pem(rsa.generate_private_key(public_exponent=65537,key_size=2048)),signer,'2026-11-20T00:00:00Z')
    def test_unnamed_volume_duplicate_bind_and_foreign_source_deny(self):
        tmp={'/tmp':'rw,size=1m'};bind=['type=bind,src=/owned/data,dst=/data']
        good={'Mounts':[{'Type':'bind','Source':'/owned/data','Destination':'/data','RW':True}]}
        f.Ceremony.validate_mounts(good,tmp,bind)
        for extra in ({'Type':'volume','Destination':'/extra','Source':'foreign','RW':True},good['Mounts'][0],{'Type':'tmpfs','Destination':'/tmp','RW':False}):
            with self.assertRaises(ValueError):f.Ceremony.validate_mounts({'Mounts':good['Mounts']+[extra]},tmp,bind)
    def test_created_null_or_absent_and_started_false_share_only_inactive_oom_default(self):
        base={'Id':'c'*64,'Created':'fixed','Image':'sha256:'+'d'*64,'Name':'/owned',
            'Config':{'Labels':{'owner':'exact'}},'HostConfig':{'Memory':0,'CapAdd':None}}
        started=copy.deepcopy(base);started['HostConfig']['OomKillDisable']=False
        for before in (copy.deepcopy(base),base|{'HostConfig':base['HostConfig']|{'OomKillDisable':None}}):
            original=copy.deepcopy(before)
            self.assertEqual(f.stable_recipe(before),f.stable_recipe(started))
            self.assertEqual(before,original)  # No mutation of the actual observed row.
        changed=copy.deepcopy(started);changed['HostConfig']['OomKillDisable']=True
        self.assertNotEqual(f.stable_recipe(started),f.stable_recipe(changed))
        for field,value in (('Memory',16777216),('CapAdd',['SYS_ADMIN']),('NetworkMode','foreign')):
            other=copy.deepcopy(started);other['HostConfig'][field]=value
            self.assertNotEqual(f.stable_recipe(started),f.stable_recipe(other))
        for field,value in (('Id','f'*64),('Created','replacement'),('Image','sha256:'+'f'*64)):
            self.assertNotEqual(f.stable_recipe(started),f.stable_recipe(started|{field:value}))
    def test_malformed_oom_controls_never_alias_false_or_true(self):
        for value in (0,1,0.0,1.0,'false','true',[],{}):
            with self.subTest(value=value),self.assertRaises(ValueError):
                f.stable_recipe({'HostConfig':{'OomKillDisable':value}})
    def test_cleanup_drift_retains_and_uses_only_exact_cid_on_match(self):
        for drift in (False,True):
            with self.subTest(drift=drift),tempfile.TemporaryDirectory()as d:
                c=f.Ceremony(Path(d),'a'*40,'sha256:'+'b'*64)
                row={'Id':'c'*64,'Created':'fixed','Image':'sha256:'+'d'*64,'Name':'/owned','Config':{'Labels':{f.LABEL:c.owner}},'HostConfig':{},'Mounts':[],
                    'State':{'StartedAt':'original','Paused':False,'Restarting':False}}
                record={'cid':row['Id'],'recipe':f.stable_recipe(row),'started_at':'original','role':'own','tmpfs':{},'binds':[]};c.containers=[record]
                current=copy.deepcopy(row)
                if drift:current['State']['StartedAt']='changed'
                calls=[]
                with patch.object(c,'inspection',return_value=current),patch.object(c,'run',side_effect=lambda label,argv,**kw:calls.append(argv)):
                    result=c.cleanup_infra()
                self.assertEqual(result,not drift)
                self.assertEqual(calls,[]if drift else[['docker','rm','--force','c'*64]])
    def test_unvalidated_created_resource_cannot_get_cleanup_success(self):
        with tempfile.TemporaryDirectory()as d:
            c=f.Ceremony(Path(d),'a'*40,'sha256:'+'b'*64);c.uncertain=['unknown-created']
            self.assertFalse(c.cleanup_infra())
    def test_workflow_is_native_read_only_permissions_and_never_recursive_private_upload(self):
        text=(f.ROOT/'.github/workflows/ci.yml').read_text();job=text.split('  hosted-arm-signed-local:',1)[1]
        self.assertIn('runs-on: ubuntu-24.04-arm',job);self.assertIn('contents: read',job)
        self.assertNotIn('id-token:',job);self.assertNotIn('secrets.',job);self.assertNotIn('setup-qemu',job)
        uploads=job.split('path: |',1)[1].split('if-no-files-found:',1)[0]
        self.assertIn('arm-native-original-proofs/',uploads);self.assertNotIn('arm-essential-private',uploads)
        self.assertNotIn('signer',uploads);self.assertNotIn('raw',uploads)
if __name__=='__main__':unittest.main()
