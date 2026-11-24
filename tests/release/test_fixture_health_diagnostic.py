"""Real POSIX failure branches and read-only Docker CLI stubs; no native claim."""
import json,os,subprocess,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
from tools.release import hosted_arm_essential as h
from tests.release import test_install_failure_receipt as receipt_test
Q,SIGNER,ISSUER=receipt_test.Q,receipt_test.SIGNER,receipt_test.ISSUER
ROOT=Path(__file__).resolve().parents[2]
class FixtureHealthTests(unittest.TestCase):
    def test_actual_shell_each_failure_branch_both_release_passes_and_gates(self):
        s=(ROOT/'deploy/compose/launcher.sh').read_text();receipt=s[s.index('emit_fixture_install_receipt() {'):s.index('\ntrap cleanup 0 HUP INT TERM')];wait=s[s.index('wait_healthy() {'):s.index('\nacknowledge_start() {')]
        with tempfile.TemporaryDirectory()as d:
            root=Path(d)
            for release in('closed','configured'):
                for cause in h.HEALTH_CAUSES:
                    script='set -eu\n'+receipt+'\n'+wait+'''\nfail(){ printf '%s\\n' PRIVATE_ERROR >&2; exit 1; }
ensure_lock_owner(){ checks=$((checks+1)); if [ "$CAUSE" = owner-before-poll ] || { [ "$CAUSE" = owner-after-healthy ] && [ "$checks" -eq 2 ]; }; then fail PRIVATE_OWNER; fi; }
docker(){ case "$CAUSE" in owner-after-healthy) printf 'healthy\\n';; unhealthy) printf 'unhealthy\\n';; *) printf 'starting\\n';; esac; }
sleep(){ :; }
INSTALL_RECEIPT_ACTION=install
INSTALL_RECEIPT_PHASE=api-release
INSTALL_HEALTH_PASS=$RELEASE
VERIFIER_IMAGE='''+Q+'''\nVERSION=0.1.0-rc.4
SIGNER='''+SIGNER+'''\nISSUER='''+ISSUER+'''\nLOCK_NAME=''
WORK=''
INSTALLING=0
checks=0
PROJECT=owned-stub
trap cleanup 0
wait_healthy
'''
                    for trusted in(True,False):
                        env=receipt_test.InstallFailureReceiptTests().environment(root)|{'CAUSE':cause,'RELEASE':release}
                        if not trusted:env['VOLT_BOOTSTRAP_VERIFIER_VERIFIED']='0'
                        r=subprocess.run(['sh','-c',script],env=env,capture_output=True,timeout=5)
                        self.assertEqual(r.returncode,1,r.stderr)
                        diag=h.health_phase_receipt(r.stderr)
                        self.assertEqual(diag,{'cause':cause,'pass':release,'profile':'volt_fixture_health_exit_v1'}if trusted else None)
                        self.assertNotIn('PRIVATE',json.dumps(diag));self.assertEqual(r.stdout,b'')
    def test_closed_receipt_rejects_unknown_duplicate_partial_and_types(self):
        r={'profile':'volt_fixture_health_exit_v1','pass':'closed','cause':'unhealthy'};prefix=b'VOLT_FIXTURE_HEALTH_RECEIPT '
        raw=prefix+json.dumps(r,sort_keys=True,separators=(',',':')).encode()+b'\n';self.assertEqual(h.health_phase_receipt(raw),r)
        for b in(raw+raw,raw[:-1],raw.replace(b'closed',b'PRIVATE'),raw.replace(b'unhealthy',b'unknown'),prefix+b'{}\n',raw.replace(b'"closed"',b'false')):self.assertIsNone(h.health_phase_receipt(b))
    def fixture(self,root):
        private=root/'private';state=private/'instance';state.mkdir(parents=True);e=root/'evidence';e.mkdir();owner='a'*64;project='volt-easy-delivery-'+owner[:12];digest='sha256:'+'b'*64;revision='c'*40;snapshot='sha256:'+'d'*64;config='sha256:'+'e'*64;index='sha256:'+'f'*64
        runtime={'image_id':digest,'image_config_id':config,'image_index_digest':index,'source_revision':revision,'source_snapshot':snapshot,'platform':'linux/arm64'}
        value={'private':str(private),'image_id':digest,'source_revision':revision,'source_snapshot':snapshot}
        (e/'fixture-full-runtime-admission.exit').write_text('0\n');(e/'fixture-full-runtime-admission.stdout').write_text(json.dumps({'runtime':runtime}));(state/'instance.json').write_text(json.dumps({'owner_token':owner,'project':project,'mode':'local','platform':'linux/arm64','image_admission':{'id':digest,'source_revision':revision,'source_snapshot':snapshot}}))
        row={'id':'1'*64,'name':'/'+project+'-volt-1','created':'2026-01-01T00:00:00Z','started':'2026-01-01T00:00:01Z','image':digest,'reference':'127.0.0.1:46150/volt@'+index,'owner':owner,'project':project,'revision':revision,'snapshot':snapshot,'status':'running','exit':0,'oom':False,'restarting':False,'restarts':0,'health':{'status':'unhealthy','streak':3,'logs':[{'exit':1,'start':'2026-01-01T00:00:02Z','end':'2026-01-01T00:00:03Z','checks':['VOLT_HEALTH_CHECK_V1 broker-readiness']}]}}
        return value,e,row
    def test_actual_cli_projection_and_drift_no_output_or_identity_leak(self):
        with tempfile.TemporaryDirectory()as d:
            root=Path(d);value,e,row=self.fixture(root);bin=root/'bin';bin.mkdir();calls=root/'calls';data=root/'row';data.write_text(json.dumps(row))
            script=bin/'docker';script.write_text('''#!/bin/sh
[ "$1:$2" = container:inspect ] || exit 91
printf '%s\\n' "$3" >> "$CALLS"
cat "$ROW"
''');script.chmod(0o700)
            with patch.dict(os.environ,{'PATH':str(bin)+':'+os.environ['PATH'],'CALLS':str(calls),'ROW':str(data)}):
                r=h.failed_health_projection(value,e);self.assertEqual(r['status'],'observed');self.assertEqual(r['health_exit_codes'],[1]);self.assertEqual(r['health_check_phases'],['broker-readiness']);self.assertEqual(calls.read_text().splitlines(),['volt-easy-delivery-'+('a'*12)+'-volt-1','1'*64])
                self.assertNotIn('aaaa',json.dumps(r));self.assertNotIn('2026',json.dumps(r));self.assertNotIn('sha256',json.dumps(r))
                for key,wrong in [('owner','9'*64),('image','sha256:'+'9'*64),('revision','9'*40),('exit',False),('oom',0)]:
                    data.write_text(json.dumps(row|{key:wrong}));self.assertEqual(h.failed_health_projection(value,e),{'status':'unavailable'})
                for markers in([True],['VOLT_HEALTH_CHECK_V1 PRIVATE'],['VOLT_HEALTH_CHECK_V1 broker-readiness']*2,'PRIVATE'):
                    changed=json.loads(json.dumps(row));changed['health']['logs'][0]['checks']=markers;data.write_text(json.dumps(changed))
                    self.assertEqual(h.failed_health_projection(value,e),{'status':'unavailable'})
                data.write_text(json.dumps(row));(e/'fixture-full-runtime-admission.exit').write_text('2\n');self.assertEqual(h.failed_health_projection(value,e),{'status':'unavailable'})
            self.assertNotIn('Health.Log.Output',h.HEALTH_INSPECT_TEMPLATE);self.assertNotIn('.Config.Env',h.HEALTH_INSPECT_TEMPLATE)
    def test_actual_cli_oversize_and_deadline_are_finite_unavailable(self):
        import time
        with tempfile.TemporaryDirectory()as d:
            root=Path(d);value,e,row=self.fixture(root);bin=root/'bin';bin.mkdir();script=bin/'docker'
            for body in ('exec head -c 20000 /dev/zero','exec sleep 3'):
                script.write_text('#!/bin/sh\n'+body+'\n');script.chmod(0o700)
                start=time.monotonic()
                with patch.dict(os.environ,{'PATH':str(bin)+':'+os.environ['PATH']}):self.assertEqual(h.failed_health_projection(value,e),{'status':'unavailable'})
                self.assertLess(time.monotonic()-start,2.8)
    def test_cli_identity_change_between_queries_denies(self):
        with tempfile.TemporaryDirectory()as d:
            value,e,row=self.fixture(Path(d));counter=[0]
            def run(*args,**kwargs):
                counter[0]+=1;r=row|({'started':'DIFFERENT'}if counter[0]==2 else{});kwargs['stdout'].write(json.dumps(r).encode());return subprocess.CompletedProcess(args,0)
            with patch.object(h.subprocess,'run',side_effect=run):self.assertEqual(h.failed_health_projection(value,e),{'status':'unavailable'})
            self.assertEqual(counter[0],2)
if __name__=='__main__':unittest.main()
