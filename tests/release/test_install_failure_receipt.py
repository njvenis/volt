"""Actual public launcher subprocess boundaries with owned Docker stubs.

These are POSIX control-flow/receipt tests, not crypto, Docker or ARM lifecycle.
"""
import json,os,subprocess,tempfile,unittest
from pathlib import Path
from tools.release import hosted_arm_essential as h
ROOT=Path(__file__).resolve().parents[2]
Q='127.0.0.1:46150/volt-installer-verifier@sha256:'+'a'*64
SIGNER='https://github.com/njvenis/volt/.github/workflows/release-rc4.yml@refs/heads/main'
ISSUER='https://token.actions.githubusercontent.com'
class InstallFailureReceiptTests(unittest.TestCase):
    def environment(self,root):
        return os.environ|{'PATH':str(root)+':'+os.environ['PATH'],'TMPDIR':str(root/'temporary'),
            'DOCKER_HOST':'unix:///var/run/docker.sock','DOCKER_CONTEXT':'',
            'VOLT_EXPECTED_VERIFIER_IMAGE':Q,'VOLT_BOOTSTRAP_VERIFIER_VERIFIED':'1',
            'VOLT_EXPECTED_VERSION':'0.1.0-rc.4','VOLT_EXPECTED_SIGNER':SIGNER,'VOLT_EXPECTED_ISSUER':ISSUER}
    def actual_launcher(self,boundary,*,action='install',trusted=True,fixture=True):
        with tempfile.TemporaryDirectory()as d:
            root=Path(d);(root/'temporary').mkdir();calls=root/'calls';bad=root/'unapproved-call'
            source=(ROOT/'deploy/compose/launcher.sh').read_text()
            if fixture:source=source.replace("VERIFIER_IMAGE='VOLT_VERIFIER_IMAGE_REFERENCE'", "VERIFIER_IMAGE='"+Q+"'")
            launcher=root/'launcher.sh';launcher.write_text(source)
            for name in ('installer.bundle.tar.gz','installer.bundle.sigstore.json'):(root/name).write_text('stub-only no crypto or tar execution permitted')
            docker=root/'docker';docker.write_text('''#!/bin/sh
printf '%s\\n' "$1" >> "$CALLS"
case "$1:$2" in
 compose:version) [ "$BOUNDARY" != host-preflight ] || exit 7 ;;
 version:--format)
  case "$3" in *Client*) printf '1.48|1.48\\n' ;; *) printf 'linux/arm64\\n' ;; esac ;;
 image:inspect) [ "$3" = --help ] || { touch "$BAD"; exit 93; }; printf '      --format string\\n' ;;
 pull:*)
  if [ "$BOUNDARY" = verifier-fetch ]; then exit 7; fi
  case "$3" in linux/arm64) case "$4" in */volt@sha256:*) exit 7 ;; esac ;; esac ;;
 run:*)
  if [ "$BOUNDARY" = bundle-discovery ]; then printf 'PRIVATE_DSNCAPABILITY' >&2; exit 2; fi
  printf 'reference=127.0.0.1:46150/volt@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\\nbundle_sha256=cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc\\n' ;;
 *) touch "$BAD"; exit 93 ;;
esac
''');docker.chmod(0o700)
            env=self.environment(root)|{'BOUNDARY':boundary,'CALLS':str(calls),'BAD':str(bad)}
            if not trusted:env['VOLT_BOOTSTRAP_VERIFIER_VERIFIED']='0'
            result=subprocess.run(['sh',str(launcher),action,'--directory',str(root/'new-instance'),'--port','46180'],env=env,capture_output=True,timeout=10)
            self.assertFalse(bad.exists(),result.stderr)
            self.assertFalse((root/'new-instance').exists())
            self.assertEqual(list((root/'temporary').iterdir()),[])
            return result,calls.read_text().splitlines()if calls.exists()else[]
    def test_actual_public_launcher_distinguishes_reached_failing_subphases(self):
        for phase in ('host-preflight','verifier-fetch','bundle-discovery','runtime-fetch'):
            with self.subTest(phase=phase):
                result,calls=self.actual_launcher(phase)
                self.assertEqual(result.returncode,1,result.stderr)
                record=h.install_phase_receipt(result.stderr)
                self.assertEqual(record,{'phase':phase,'profile':'volt_fixture_install_exit_v1','status':1})
                self.assertNotIn('PRIVATE',json.dumps(record));self.assertNotIn('network',calls);self.assertNotIn('create',calls)
                if phase=='bundle-discovery':self.assertIn(b'PRIVATE_DSNCAPABILITY',result.stderr)
    def test_no_receipt_for_nonfixture_noninstall_or_unvalidated_caller(self):
        for kwargs in ({'action':'start'},{'trusted':False},{'fixture':False}):
            result,_=self.actual_launcher('host-preflight',**kwargs)
            self.assertNotEqual(result.returncode,0);self.assertIsNone(h.install_phase_receipt(result.stderr))
    def test_actual_exit_trap_preserves_original_zero_nonzero_and_reporting_failure(self):
        text=(ROOT/'deploy/compose/launcher.sh').read_text()
        functions=text[text.index('emit_fixture_install_receipt() {'):text.index('\ntrap cleanup 0 HUP INT TERM')]
        with tempfile.TemporaryDirectory()as d:
            root=Path(d)
            for code,broken in ((0,False),(7,False),(7,True)):
                script='set -eu\n'+functions+'''\nINSTALL_RECEIPT_ACTION=install
INSTALL_RECEIPT_PHASE=original-cache-export
VERIFIER_IMAGE='''+Q+'''
VERSION=0.1.0-rc.4
SIGNER='''+SIGNER+'''
ISSUER='''+ISSUER+'''
LOCK_NAME=''
WORK=''
INSTALLING=0
trap cleanup 0
'''+('exec 2>&-\n'if broken else'')+'exit '+str(code)+'\n'
                result=subprocess.run(['sh','-c',script],env=self.environment(root),capture_output=True,timeout=5)
                self.assertEqual(result.returncode,code)
                if not broken:self.assertEqual(h.install_phase_receipt(result.stderr)['status'],code)
    def test_receipt_reader_rejects_forged_shapes_types_duplicates_and_partial_records(self):
        prefix=b'VOLT_FIXTURE_INSTALL_RECEIPT '
        valid={'phase':'api-start','profile':'volt_fixture_install_exit_v1','status':1}
        raw=prefix+json.dumps(valid,sort_keys=True,separators=(',',':')).encode()+b'\n'
        self.assertEqual(h.install_phase_receipt(b'private arbitrary bytes\xff\n'+raw),valid)
        for mutation in (valid|{'status':True},valid|{'status':-1},valid|{'phase':'PRIVATE'},valid|{'extra':'PRIVATE'}):
            self.assertIsNone(h.install_phase_receipt(prefix+json.dumps(mutation,sort_keys=True,separators=(',',':')).encode()+b'\n'))
        for value in (raw+raw,raw[:-1],raw.replace(b'\n',b'\r\n'),b' '+raw,raw+b'x'*(1024*1024)):
            self.assertIsNone(h.install_phase_receipt(value))
if __name__=='__main__':unittest.main()
