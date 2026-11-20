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
        with patch.object(h.platform,'machine',return_value='aarch64'):
            for result in (subprocess.CompletedProcess([],0,'linux/amd64',''),subprocess.CompletedProcess([],7,'linux/arm64','')):
                with patch.object(h.subprocess,'run',return_value=result):
                    with self.assertRaises(ValueError):h.require_native()
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
