"""Full health shell with private fixed-path service substitutes, not native ARM proof."""
import json,os,subprocess,tempfile,unittest
from pathlib import Path
from tools.release import hosted_arm_essential as h
ROOT=Path(__file__).resolve().parents[2]
class HealthSubcheckTests(unittest.TestCase):
 def run_health(self,root,live,phase=None):
  state=root/'state';state.mkdir();(root/'app').mkdir();bin=root/'bin';bin.mkdir()
  for name in('api','ce-web','ce-worker','ce-beat','exception-warning-worker','recovery-control'):(state/('pid-'+name)).write_text(str(live.pid))
  (state/'ready').touch();(state/'runtime-mode').write_text('runtime')
  identity=root/'identity';identity.write_text('uvm_g7_okta_publisher_healthy(){ return '+('1'if phase=='oidc-publisher'else'0')+'; }\n'+('return 23\n'if phase=='identity-runtime'else''))
  python=root/'python';python.write_text('#!/bin/sh\nexit '+('7'if phase in('broker-readiness','recovery-port','warning-health')else'0')+'\n');python.chmod(0o700)
  for name in('pg_isready','valkey-cli','curl'):
   body='exit 0'
   if name=='pg_isready':body='exit '+('2'if phase=='postgres'else'0')
   if name=='valkey-cli':body="printf '%s\\n' "+('NOTPONG'if phase=='valkey'else'PONG')
   if name=='curl':
    match={'api-http':'8000','web-http':'8081','oidc-provider':'9000','oidc-proxy':'8001'}.get(phase,'NO_MATCH')
    body='case "$*" in *'+match+'*) printf PRIVATE_ERROR >&2; exit 22;; *api/v2/findings*) printf '+('500'if phase=='verification-web'else'401')+';; esac\nexit 0'
   p=bin/name;p.write_text('#!/bin/sh\n'+body+'\n');p.chmod(0o700)
  env=os.environ|{'PATH':str(bin)+':'+os.environ['PATH'],'UVM_AUTH_MODE':'local','UVM_EXCEPTION_WARNING_WORKER':'0'}
  if phase=='ready-marker':(state/'ready').unlink()
  if phase in('critical-marker','quiesce-marker'):(state/phase.replace('-marker','-failed')).touch()
  if phase=='runtime-mode':(state/'runtime-mode').write_text('PRIVATE_INVALID')
  if phase in('recovery-process','recovery-port'):(state/'runtime-mode').write_text('control')
  if phase=='verification-web':(state/'runtime-mode').write_text('verification')
  if phase in('warning-process','warning-health'):env['UVM_EXCEPTION_WARNING_WORKER']='1'
  if phase in('oidc-provider','oidc-proxy','oidc-publisher'):
   env['UVM_AUTH_MODE']='oidc';env['UVM_OIDC_DEPLOYMENT_MODE']='external'if phase=='oidc-publisher'else'demo'
  process={'api-process':'api','web-process':'ce-web','worker-process':'ce-worker','beat-process':'ce-beat','warning-process':'exception-warning-worker','recovery-process':'recovery-control'}.get(phase)
  if process:
   dead=subprocess.Popen(['sh','-c','exit 0']);dead.wait();(state/('pid-'+process)).write_text(str(dead.pid))
  source=(ROOT/'docker/g7/healthcheck.sh').read_text()
  for original,fixed in [('/usr/local/bin/uvm-g7-identity-runtime',str(identity)),('/run/uvm-g7',str(state)),('/opt/uvm/venv/bin/python',str(python)),('/usr/local/bin/python3.14',str(python)),('/opt/uvm/app',str(root/'app'))]:source=source.replace(original,fixed)
  script=root/'health';script.write_text(source)
  return subprocess.run(['bash',str(script)],env=env,capture_output=True,timeout=4)
 def test_real_health_script_each_check_preserves_failure_and_live_process_positive(self):
  live=subprocess.Popen(['sleep','60'])
  try:
   for phase in sorted(h.HEALTH_CHECK_PHASES):
    with self.subTest(phase=phase),tempfile.TemporaryDirectory()as d:
     r=self.run_health(Path(d),live,phase)
     self.assertNotEqual(r.returncode,0)
     lines=[v for v in r.stderr.splitlines()if v.startswith(b'VOLT_HEALTH_CHECK_V1 ')]
     self.assertEqual(lines,[b'VOLT_HEALTH_CHECK_V1 '+phase.encode()])
     expected=23 if phase=='identity-runtime'else 7 if phase in('broker-readiness','recovery-port','warning-health')else 2 if phase=='postgres'else 22 if phase in('api-http','web-http','oidc-provider','oidc-proxy')else 1
     self.assertEqual(r.returncode,expected)
   with tempfile.TemporaryDirectory()as d:
    r=self.run_health(Path(d),live);self.assertEqual(r.returncode,0,r.stderr);self.assertNotIn(b'VOLT_HEALTH_CHECK',r.stderr)
  finally:live.terminate();live.wait(timeout=3)
 def test_docker_template_engine_projects_only_exact_allowlist_without_daemon(self):
  # Uses local context metadata only; no Docker daemon or fixture contact.
  start=h.HEALTH_INSPECT_TEMPLATE.index('{{$sep :=');end=h.HEALTH_INSPECT_TEMPLATE.index(']}{{end}}]}',start)
  fragment=h.HEALTH_INSPECT_TEMPLATE[start:end]
  raw='PRIVATE_SECRET\nVOLT_HEALTH_CHECK_V1 broker-readiness\nVOLT_HEALTH_CHECK_V1 unknown\n'
  template='{{$l := .}}'+fragment.replace('$l.Output',json.dumps(raw))
  r=subprocess.run(['docker','context','inspect','default','--format','['+template+']'],capture_output=True,timeout=5)
  self.assertEqual(r.returncode,0,r.stderr);self.assertEqual(json.loads(r.stdout),['VOLT_HEALTH_CHECK_V1 broker-readiness'])
  self.assertNotIn(b'PRIVATE',r.stdout)
if __name__=='__main__':unittest.main()
