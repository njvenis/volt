"""Host-only stage/denial tests; not native ARM lifecycle or signature proof."""
import copy,hashlib,json,subprocess,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
from tools.release import hosted_arm_essential as h
class HostedArmTests(unittest.TestCase):
    def request(self,stage,root):
        r={'schema_version':1,'profile':h.PROFILE,'source_revision':'a'*40,'source_snapshot':'sha256:'+'b'*64,
            'source_checkout':str(root/'source'),'evidence':str(root/'new-evidence')}
        if stage=='build-q':r.update(public_policy=str(root/'public'),public_policy_sha256='sha256:'+'c'*64)
        elif stage=='prepare-db-context':r['db_source_directory']=str(root/'db')
        else:r.update(bundle=str(root/'bundle'),fixture=str(root/'fixture'),image_id='sha256:'+'d'*64,private=str(root/'private'))
        return r
    def test_closed_request_and_fresh_paths(self):
        with tempfile.TemporaryDirectory()as t:
            root=Path(t)
            for stage in ('build-q','essential','prepare-db-context'):
                r=self.request(stage,root);self.assertEqual(h.validate_request(r,stage),r)
                for key,val in [('schema_version',True),('source_snapshot','bad'),('unknown','selector')]:
                    bad=r|{key:val}
                    with self.assertRaises(ValueError):h.validate_request(bad,stage)
            (root/'new-evidence').mkdir()
            with self.assertRaises(ValueError):h.validate_request(self.request('essential',root),'essential')
    def test_private_output_cannot_overlap_source(self):
        with tempfile.TemporaryDirectory()as t:
            root=Path(t);r=self.request('essential',root)
            for name in ('evidence','private'):
                bad=r|{name:str(root/'source'/'ignored-output')}
                with self.assertRaises(ValueError):h.validate_request(bad,'essential')

    def test_fixed_native_q_has_no_signing_or_optional_platform(self):
        with tempfile.TemporaryDirectory()as t:
            c=h.q_command(self.request('build-q',Path(t)))
            self.assertEqual(c[c.index('--platform')+1],'linux/arm64')
            self.assertTrue(c[1].endswith('tools/release/build_native_fixture_verifier.py'))
            self.assertNotIn('--insecure-ignore-tlog',c)
    def test_non_native_host_never_contacts_docker(self):
        with patch.object(h.platform,'machine',return_value='x86_64'),patch.object(h.subprocess,'run',side_effect=AssertionError('must not contact daemon')):
            with self.assertRaises(ValueError):h.require_native()
    def test_wrong_daemon_and_failed_producer_deny(self):
        with patch.object(h.platform,'machine',return_value='aarch64'),patch.dict(h.os.environ,{'DOCKER_HOST':'unix:///var/run/docker.sock'},clear=True):
            for result in (subprocess.CompletedProcess([],0,'linux/amd64',''),subprocess.CompletedProcess([],7,'linux/arm64','')):
                with patch.object(h.subprocess,'run',return_value=result):
                    with self.assertRaises(ValueError):h.require_native()
    def test_remote_endpoint_denies_without_contacting_daemon(self):
        with patch.object(h.platform,'machine',return_value='aarch64'),patch.dict(h.os.environ,{'DOCKER_HOST':'ssh://not-contacted.invalid'},clear=True),patch.object(h.subprocess,'run',side_effect=AssertionError('no remote contact')):
            with self.assertRaises(ValueError):h.require_native()
    def test_explicit_remote_context_overrides_local_host_before_daemon_contact(self):
        calls=[]
        def run(argv,**kwargs):
            calls.append(argv)
            self.assertEqual(argv,['docker','context','inspect','remote','--format','{{(index .Endpoints "docker").Host}}'])
            return subprocess.CompletedProcess(argv,0,'ssh://not-contacted.invalid\n','')
        with patch.object(h.platform,'machine',return_value='aarch64'),patch.dict(h.os.environ,{'DOCKER_HOST':'unix:///var/run/docker.sock','DOCKER_CONTEXT':'remote'},clear=True),patch.object(h.subprocess,'run',side_effect=run):
            with self.assertRaises(ValueError):h.require_native()
        self.assertEqual(len(calls),1)
    def test_local_endpoint_is_pinned_for_all_following_commands(self):
        for original in ({'DOCKER_HOST':'unix:///var/run/docker.sock'},
                         {'DOCKER_HOST':'ssh://ignored.invalid','DOCKER_CONTEXT':'local'},{}):
            calls=[]
            def run(argv,**kwargs):
                calls.append(argv)
                if argv==['docker','context','show']:return subprocess.CompletedProcess(argv,0,'default\n','')
                if argv[:3]==['docker','context','inspect']:return subprocess.CompletedProcess(argv,0,'unix:///var/run/docker.sock\n','')
                self.assertEqual(argv,['docker','version','--format','{{.Server.Os}}/{{.Server.Arch}}'])
                self.assertNotIn('DOCKER_CONTEXT',h.os.environ)
                self.assertEqual(h.os.environ['DOCKER_HOST'],'unix:///var/run/docker.sock')
                return subprocess.CompletedProcess(argv,0,'linux/arm64\n','')
            with self.subTest(original=original),patch.object(h.platform,'machine',return_value='aarch64'),patch.dict(h.os.environ,original,clear=True),patch.object(h.subprocess,'run',side_effect=run):
                h.require_native()
                self.assertEqual(calls[-1][1],'version')
    def test_stage_observer_forwards_exact_command_and_result_without_private_data(self):
        from types import SimpleNamespace
        from unittest.mock import Mock
        result=subprocess.CompletedProcess([],3,'PRIVATE_STDOUT','PRIVATE_STDERR')
        original=Mock(return_value=result);health=Mock(return_value='private-health')
        q=SimpleNamespace(run=original,wait_for_local=health);record={}
        argv=['private-selector','DSN=PRIVATE'];environment={'PRIVATE':'secret'}
        with h.observe_journey(q,record):
            self.assertIs(q.run('focused-public-install',argv,Path('/private'),env=environment,check=False),result)
            original.assert_called_once_with('focused-public-install',argv,Path('/private'),env=environment,check=False)
            self.assertEqual(record,{'stage':'public-install','producer':'returned','exit_code':3})
            q.run('PRIVATE_UNKNOWN_LABEL',argv,Path('/private'))
            self.assertEqual(record['stage'],'other-qualification-command')
            self.assertNotIn('PRIVATE',json.dumps(record))
        self.assertIs(q.run,original);self.assertIs(q.wait_for_local,health)
    def test_stage_observer_preserves_exception_and_original_numeric_status(self):
        from types import SimpleNamespace
        from unittest.mock import Mock
        error=RuntimeError('PRIVATE_EXCEPTION')
        with tempfile.TemporaryDirectory()as d:
            evidence=Path(d);(evidence/'focused-public-cold-stop.exit').write_text('1\n')
            original=Mock(side_effect=error);q=SimpleNamespace(run=original,wait_for_local=Mock());record={}
            with self.assertRaises(RuntimeError)as caught:
                with h.observe_journey(q,record):q.run('focused-public-cold-stop',['PRIVATE'],evidence)
            self.assertIs(caught.exception,error);self.assertIs(q.run,original)
            self.assertEqual(record,{'stage':'public-cold-stop','producer':'raised','exit_code':1})
            (evidence/'focused-public-cold-stop.exit').unlink()
            with self.assertRaises(RuntimeError):
                with h.observe_journey(q,record):q.run('focused-public-cold-stop',['PRIVATE'],evidence)
            self.assertIsNone(record['exit_code'])
    def test_stage_observer_distinguishes_health_error_and_post_command_assertion(self):
        from types import SimpleNamespace
        from unittest.mock import Mock
        q=SimpleNamespace(run=Mock(return_value=subprocess.CompletedProcess([],0)),wait_for_local=Mock(side_effect=ValueError('PRIVATE')));record={}
        with self.assertRaises(ValueError):
            with h.observe_journey(q,record):q.wait_for_local('PRIVATE',Path('/private'))
        self.assertEqual(record,{'stage':'application-health','producer':'raised','exit_code':None})
        with self.assertRaises(AssertionError):
            with h.observe_journey(q,record):
                q.run('focused-public-install',[],Path('/private'))
                raise AssertionError('PRIVATE')
        self.assertEqual(record,{'stage':'public-install','producer':'returned','exit_code':0})
    def test_request_hash_duplicate_json_and_fifo_deny(self):
        import os,time
        with tempfile.TemporaryDirectory()as t:
            root=Path(t);p=root/'request';r=self.request('build-q',root);raw=json.dumps(r).encode();p.write_bytes(raw)
            with self.assertRaises(ValueError):h.read_request(p,'sha256:'+'0'*64,'build-q')
            raw=b'{"schema_version":1,"schema_version":1}';p.write_bytes(raw)
            with self.assertRaises(ValueError):h.read_request(p,'sha256:'+hashlib.sha256(raw).hexdigest(),'build-q')
            p.unlink();os.mkfifo(p,0o600);start=time.monotonic()
            with self.assertRaises(ValueError):h.read_request(p,'sha256:'+'0'*64,'build-q')
            self.assertLess(time.monotonic()-start,.5)
    def test_db_mismatch_no_partial_context(self):
        with tempfile.TemporaryDirectory()as t:
            root=Path(t);src=root/'source';src.mkdir();out=root/'output'
            for name in h.DB_FILES:
                p=src/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(b'wrong')
            with self.assertRaises(ValueError):h.prepare_db_context(src,out)
            self.assertFalse(out.exists())
    def test_db_context_copies_only_pinned_files_with_unit_injected_digests(self):
        with tempfile.TemporaryDirectory()as t:
            root=Path(t);src=root/'source';src.mkdir();out=root/'output';pins={}
            for name in h.DB_FILES:
                p=src/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(name.encode());pins[name]=hashlib.sha256(p.read_bytes()).hexdigest()
            (src/'not-copied-private.key').write_text('not an input')
            with patch.object(h,'DB_FILES',pins):h.prepare_db_context(src,out)
            self.assertFalse((out/'not-copied-private.key').exists());self.assertEqual(set(pins),set(h.DB_FILES))
            self.assertEqual({str(p.relative_to(out))for p in out.rglob('*')if p.is_file()},set(pins)|{'preparation.json'})
if __name__=='__main__':unittest.main()
