"""CI native architecture/recipe guards, not actual ARM execution evidence."""
import copy
from pathlib import Path
import unittest
from tools.release.native_runtime_probe import MACHINES, TMPFS, checked_identity, create_command, native_context


class NativeRuntimeProbeTests(unittest.TestCase):
    def test_host_and_daemon_must_both_be_native_without_fallback(self):
        for requested,machine in MACHINES.items():
            native_context(requested,machine,requested)
            for host,daemon in [('unknown',requested),(machine,'linux/other')]:
                with self.subTest(platform=requested,host=host,daemon=daemon),self.assertRaises(ValueError):
                    native_context(requested,host,daemon)
        with self.assertRaises(ValueError):native_context('linux/arm64','x86_64','linux/arm64')

    def fixture(self):
        component=Path('/checked-source/component.py');driver=Path('/private-evidence/driver.py')
        cid='a'*64;name='volt-native-protected-test';token='test';image='sha256:'+'b'*64
        command=create_command(image,'linux/arm64',name,token,component,driver)
        row={'Id':cid,'Name':'/'+name,'Image':image,'Config':{'Image':image,'Labels':{'volt.native-probe.owner':token},
            'Entrypoint':['/usr/bin/env'],'User':'0:0','Cmd':command[command.index('--entrypoint')+3:]},
            'HostConfig':{'NetworkMode':'none','ReadonlyRootfs':True,'Privileged':False,'CapAdd':None,
                'CapDrop':None,'PortBindings':None,'Tmpfs':dict(TMPFS),
                'SecurityOpt':['no-new-privileges'],'RestartPolicy':{'Name':'no','MaximumRetryCount':0}},
            'Mounts':[{'Source':str(component),'Destination':'/run/component/protected_launch_component.py','Type':'bind','RW':False},
                {'Source':str(driver),'Destination':'/run/component/driver.py','Type':'bind','RW':False}]}
        params={'cid':cid,'name':name,'token':token,'selected':{'Id':image},'engine':{'Id':image},
            'command':command,'component':component,'driver':driver,'requested':'linux/arm64'}
        return command,row,params

    def test_fixed_no_state_no_network_recipe_and_exact_cleanup_identity(self):
        command,row,params=self.fixture();checked_identity(row,**params)
        self.assertIn('--pull=never',command);self.assertIn('--read-only',command)
        self.assertNotIn('--cap-add',command);self.assertNotIn('--privileged',command)
        self.assertNotIn('--publish',command);self.assertEqual(command.count('--mount'),2)
        for key,value in [('Id','f'*64),('Name','/other')]:
            changed=copy.deepcopy(row);changed[key]=value
            with self.subTest(key=key),self.assertRaises(ValueError):checked_identity(changed,**params)
        for key,value in [('NetworkMode','host'),('ReadonlyRootfs',False),('Privileged',True),
                          ('CapAdd',['SYS_PTRACE']),('PortBindings',{'8000/tcp':[]}),('Tmpfs',{})]:
            changed=copy.deepcopy(row);changed['HostConfig'][key]=value
            with self.subTest(key=key),self.assertRaises(ValueError):checked_identity(changed,**params)
        changed=copy.deepcopy(row);changed['Mounts'][0]['RW']=True
        with self.assertRaises(ValueError):checked_identity(changed,**params)

    def test_engine_parent_requires_same_independent_selected_object_witness(self):
        _,row,params=self.fixture();parent='sha256:'+'c'*64
        row['Image']=parent;params['engine']={'Id':parent}
        with self.assertRaises(ValueError):checked_identity(row,**params)
        descriptor={'digest':'sha256:'+'d'*64,'mediaType':'application/vnd.oci.image.manifest.v1+json',
            'size':1234,'platform':{'os':'linux','architecture':'arm64'}}
        params['selected']['Descriptor']=descriptor;row['ImageManifestDescriptor']=descriptor
        checked_identity(row,**params)
        row['ImageManifestDescriptor']={**descriptor,'digest':'sha256:'+'e'*64}
        with self.assertRaises(ValueError):checked_identity(row,**params)


class PublicFixturePolicyTests(unittest.TestCase):
    """Data-custody tests only: test bytes are not signatures or trusted roots."""
    def fixture(self, directory):
        import base64,hashlib,json
        from tools.release.build_native_fixture_verifier import URL
        key=b'public-test-bytes-not-a-cryptographic-key'
        documents={'fixture-trust.json':json.dumps({'rekor_base_url':URL}).encode(),
            'fixture.pub':b'-----BEGIN PUBLIC KEY-----\n'+base64.b64encode(key)+b'\n-----END PUBLIC KEY-----\n',
            'trusted-root.json':json.dumps({'mediaType':'application/vnd.dev.sigstore.trustedroot+json;version=0.1',
                'tlogs':[{'baseUrl':URL,'hashAlgorithm':'SHA2_256','logId':{'keyId':base64.b64encode(hashlib.sha256(key).digest()).decode()},
                    'publicKey':{'keyDetails':'PKIX_ECDSA_P256_SHA_256','rawBytes':base64.b64encode(key).decode(),'validFor':{'start':'2026-11-20T00:00:00Z'}}}]}).encode()}
        for n,v in documents.items():
            (directory/n).write_bytes(v);(directory/n).chmod(0o600)
        inventory={n:hashlib.sha256(v).hexdigest()for n,v in documents.items()}
        expected='sha256:'+hashlib.sha256(json.dumps(inventory,sort_keys=True,separators=(',',':')).encode()).hexdigest()
        return expected

    def test_exact_public_context_hash_and_no_private_or_extra_material(self):
        import tempfile
        from tools.release.build_native_fixture_verifier import public_policy
        with tempfile.TemporaryDirectory()as tmp:
            path=Path(tmp);expected=self.fixture(path)
            self.assertEqual(public_policy(path,expected)['sha256'],expected)
            with self.assertRaises(ValueError):public_policy(path,'sha256:'+'f'*64)
            (path/'cosign.key').write_text('forbidden private material')
            with self.assertRaises(ValueError):public_policy(path,expected)
            (path/'cosign.key').unlink();(path/'fixture.pub').write_text('PRIVATE MATERIAL')
            with self.assertRaises(ValueError):public_policy(path,expected)

    def test_symlink_and_group_writable_material_rejected(self):
        import tempfile
        from tools.release.build_native_fixture_verifier import public_policy
        with tempfile.TemporaryDirectory()as tmp:
            path=Path(tmp);expected=self.fixture(path)
            (path/'fixture.pub').chmod(0o666)
            with self.assertRaises(ValueError):public_policy(path,expected)
            (path/'fixture.pub').chmod(0o600);(path/'fixture.pub').unlink();(path/'fixture.pub').symlink_to('/dev/null')
            with self.assertRaises(OSError):public_policy(path,expected)

    def test_fifo_is_rejected_without_waiting_for_a_writer(self):
        import os,tempfile,time
        from tools.release.build_native_fixture_verifier import public_policy
        with tempfile.TemporaryDirectory()as tmp:
            path=Path(tmp);expected=self.fixture(path);(path/'fixture.pub').unlink();os.mkfifo(path/'fixture.pub',0o600)
            before=time.monotonic()
            with self.assertRaises(ValueError):public_policy(path,expected)
            self.assertLess(time.monotonic()-before,0.5)

    def test_restage_uses_validated_bytes_after_original_context_changes(self):
        import tempfile
        from tools.release.build_native_fixture_verifier import read_public_policy,stage_public_policy,public_policy
        with tempfile.TemporaryDirectory()as tmp:
            parent=Path(tmp);original=parent/'original';original.mkdir(mode=0o700);expected=self.fixture(original)
            proof,files=read_public_policy(original,expected)
            (original/'fixture.pub').write_text('changed input after validation')
            out=parent/'out';out.mkdir(mode=0o700);staged,staged_proof=stage_public_policy(out,files,expected)
            self.assertEqual(proof,staged_proof)
            self.assertNotEqual(staged,original)
            self.assertEqual(public_policy(staged,expected),proof)
            self.assertEqual((staged/'fixture.pub').read_bytes(),files['fixture.pub'])
            self.assertEqual(staged.stat().st_mode&0o777,0o700)

    def test_same_byte_named_file_replacement_during_read_is_denied(self):
        import os,tempfile
        from unittest.mock import patch
        from tools.release import build_native_fixture_verifier as builder
        with tempfile.TemporaryDirectory()as tmp:
            parent=Path(tmp);path=parent/'policy';path.mkdir(mode=0o700);expected=self.fixture(path)
            original_inode=(path/'fixture.pub').stat().st_ino;original_fdopen=os.fdopen
            class Wrapped:
                def __init__(self,stream):self.stream=stream
                def __enter__(self):return self
                def __exit__(self,*args):return self.stream.__exit__(*args)
                def fileno(self):return self.stream.fileno()
                def read(self,n):
                    raw=self.stream.read(n)
                    (path/'fixture.pub').rename(parent/'old-public')
                    (path/'fixture.pub').write_bytes(raw);(path/'fixture.pub').chmod(0o600)
                    return raw
            def opening(fd,mode):
                stream=original_fdopen(fd,mode)
                return Wrapped(stream)if os.fstat(fd).st_ino==original_inode else stream
            with patch.object(builder.os,'fdopen',side_effect=opening),self.assertRaises(ValueError):
                builder.public_policy(path,expected)


class NativeSourceBindingTests(unittest.TestCase):
    def test_real_git_archive_freeze_and_changed_build_context_deny(self):
        import hashlib,subprocess,tempfile
        from unittest.mock import patch
        from tools.release import native_runtime_probe as probe
        with tempfile.TemporaryDirectory()as tmp:
            parent=Path(tmp);repo=parent/'repo';repo.mkdir();(repo/'code.py').write_text('original exact code\n')
            def git(*args):return subprocess.check_output(['git',*args],cwd=repo,stderr=subprocess.DEVNULL)
            git('init');git('add','code.py');git('-c','user.name=Test','-c','user.email=fixture@example.invalid','-c','commit.gpgsign=false','commit','-m','fixture')
            revision=git('rev-parse','HEAD').decode().strip();snapshot='sha256:'+hashlib.sha256(git('archive','--format=tar',revision)).hexdigest()
            out=parent/'out';out.mkdir(mode=0o700)
            with patch.object(probe,'ROOT',repo):source,binding=probe.frozen_git_source(out,revision,snapshot)
            self.assertEqual((source/'code.py').read_bytes(),(repo/'code.py').read_bytes())
            self.assertEqual(binding['source_snapshot'],snapshot)
            (source/'code.py').write_text('changed context\n')
            with self.assertRaises(ValueError):probe.verify_source_context(source,binding['files'])
            (repo/'code.py').write_text('dirty actual probe/build bytes\n')
            second=parent/'second';second.mkdir(mode=0o700)
            with patch.object(probe,'ROOT',repo),self.assertRaises(ValueError):probe.frozen_git_source(second,revision,snapshot)

    def test_equal_but_untyped_or_incomplete_parent_witnesses_deny(self):
        _,row,params=NativeRuntimeProbeTests().fixture();parent='sha256:'+'c'*64
        row['Image']=parent;params['engine']={'Id':parent}
        valid={'digest':'sha256:'+'d'*64,'mediaType':'application/vnd.oci.image.manifest.v1+json','size':1234,'platform':{'os':'linux','architecture':'arm64'}}
        invalid=[{},dict.fromkeys(valid)]
        for name,values in [('size',[True,False,0,-1,1.0]),('digest',['','sha256:wrong',None]),('mediaType',['','application/vnd.oci.image.index.v1+json',None]),('platform',[{},None,{'os':'linux','architecture':'amd64'}])]:
            invalid.extend({**valid,name:value}for value in values)
        for witness in invalid:
            with self.subTest(witness=witness):
                params['selected']['Descriptor']=witness;row['ImageManifestDescriptor']=witness
                with self.assertRaises(ValueError):checked_identity(row,**params)
