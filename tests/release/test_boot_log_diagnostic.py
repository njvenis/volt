"""Bounded existing boot event projection; no Docker daemon/native runtime claim."""
import json,os,subprocess,tempfile,time,unittest
from pathlib import Path
from unittest.mock import patch
from tools.release import hosted_arm_essential as h
from tests.release import test_fixture_health_diagnostic as fixture
ROOT=Path(__file__).resolve().parents[2]
STAMP=b'2026-11-24T12:01:02.123456789Z '
class BootLogTests(unittest.TestCase):
 def test_existing_event_allowlist_never_exports_private_lines_or_current_phase_claim(self):
  raw=b'PRIVATE_DSN=secret\n'+b''.join(STAMP+v+b'\n'for v in h.BOOT_LOG_EVENTS)+STAMP+b'PRIVATE G7_READINESS=ready\n'+STAMP+b'G7_READINESS=ready PRIVATE\n'
  r=h.boot_log_events(raw)
  self.assertEqual(r,{'status':'observed','scope':'bounded-tail','events':list(h.BOOT_LOG_EVENTS.values())})
  self.assertNotIn('PRIVATE',json.dumps(r));self.assertNotIn('2026',json.dumps(r));self.assertNotIn('current',r)
  source=(ROOT/'docker/g7/entrypoint.sh').read_text()
  for marker in h.BOOT_LOG_EVENTS:self.assertIn("api_report '"+marker.decode()+"'",source)
 def test_parser_overflow_truncation_unknown_and_unstamped_are_closed(self):
  for raw in(b'X'*(1024*1024+1),STAMP+b'G7_READINESS=ready', (STAMP+b'G7_READINESS=ready\n')*33):self.assertEqual(h.boot_log_events(raw),{'status':'unavailable'})
  for raw in(b'G7_READINESS=ready\n',b'PRIVATE G7_READINESS=ready\n',b'\xef\xbb\xbf'+STAMP+b'G7_READINESS=ready\n',STAMP+b'G7_READINESS=unknown\n',STAMP+b'G7_READINESS=ready\rPRIVATE\n',STAMP+b'G7_READINESS=ready\r\n'):
   self.assertEqual(h.boot_log_events(raw)['events'],[])
 def setup(self,root):
  value,e,row=fixture.FixtureHealthTests().fixture(root);bin=root/'bin';bin.mkdir();data=root/'row';data.write_text(json.dumps(row));logs=root/'logs';logs.write_bytes(STAMP+b'G7_LOCAL_START=host-release-validated\n');calls=root/'calls'
  script=bin/'docker';script.write_text('''#!/bin/sh
printf '%s\\n' "$*" >> "$CALLS"
case "$1:$2" in
 container:inspect) cat "$ROW" ;;
 container:logs) [ "$3:$4:$5:$6" = "--timestamps:--tail:2000:$CID" ] || exit 92; cat "$LOG" ;;
 *) exit 91;;
esac
''');script.chmod(0o700)
  return value,e,row,script,logs,calls,{'PATH':str(bin)+':'+os.environ['PATH'],'ROW':str(data),'LOG':str(logs),'CALLS':str(calls),'CID':row['id']}
 def test_actual_cli_full_identity_brackets_log_read_and_no_original_decision_changes(self):
  with tempfile.TemporaryDirectory()as d:
   value,e,row,script,logs,calls,env=self.setup(Path(d))
   with patch.dict(os.environ,env):r=h.failed_health_projection(value,e)
   self.assertEqual(r['boot_log'],{'status':'observed','scope':'bounded-tail','events':['host-release-validated']})
   commands=calls.read_text().splitlines();self.assertEqual(len(commands),3)
   self.assertTrue(commands[0].startswith('container inspect volt-easy-delivery-'))
   self.assertEqual(commands[1],'container logs --timestamps --tail 2000 '+row['id'])
   self.assertTrue(commands[2].startswith('container inspect '+row['id']+' '))
   self.assertNotIn(row['id'],json.dumps(r));self.assertNotIn('PRIVATE',json.dumps(r))
 def test_actual_cli_cr_junk_record_cannot_forge_an_allowlisted_event(self):
  with tempfile.TemporaryDirectory()as d:
   value,e,row,script,logs,calls,env=self.setup(Path(d))
   logs.write_bytes(STAMP+b'G7_READINESS=ready\rPRIVATE_JUNK\n'+STAMP+b'G7_LOCAL_START=host-release-validated\n')
   with patch.dict(os.environ,env):r=h.failed_health_projection(value,e)
   self.assertEqual(r['boot_log'],{'status':'observed','scope':'bounded-tail','events':['host-release-validated']})
   self.assertNotIn('PRIVATE',json.dumps(r));self.assertNotIn('ready',r['boot_log']['events'])
 def test_actual_log_nonzero_oversize_and_blocked_producer_are_finite_unavailable(self):
  with tempfile.TemporaryDirectory()as d:
   root=Path(d);value,e,row,script,logs,calls,env=self.setup(root)
   for body in('exit 2','exec head -c 1100000 /dev/zero','exec sleep 3'):
    script.write_text('#!/bin/sh\n'+body+'\n');script.chmod(0o700)
    start=time.monotonic()
    with patch.dict(os.environ,env):self.assertEqual(h.current_boot_log(row['id']),{'status':'unavailable'})
    self.assertLess(time.monotonic()-start,2.8)
 def test_post_log_identity_drift_discards_all_events(self):
  with tempfile.TemporaryDirectory()as d:
   value,e,row=fixture.FixtureHealthTests().fixture(Path(d));counter=[0]
   def run(argv,**kw):
    if argv[2]=='logs':kw['stdout'].write(STAMP+b'G7_READINESS=ready\n')
    else:
     counter[0]+=1;r=row|({'started':'DIFFERENT'}if counter[0]==2 else{});kw['stdout'].write(json.dumps(r).encode())
    return subprocess.CompletedProcess(argv,0)
   with patch.object(h.subprocess,'run',side_effect=run):self.assertEqual(h.failed_health_projection(value,e),{'status':'unavailable'})
 def test_marker_and_host_release_real_source_order_excludes_uncompleted_initialization(self):
  boot=(ROOT/'docker/g7/entrypoint.sh').read_text();launcher=(ROOT/'deploy/compose/launcher.sh').read_text()
  marker=boot.rindex('api_phase_marker ready')
  self.assertLess(boot.index("api_report 'G7_INIT=CE initialize'"),boot.index("api_report 'G7_INIT=UVM migrations'"))
  for event in("api_report 'G7_LOCAL_START=host-release-validated'","wait_for 'CE web'","wait_for 'uWSGI master FIFO'","wait_for 'UVM API'"):
   self.assertLess(boot.index(event),marker)
  release=launcher[launcher.index('release_start() {'):launcher.index('\nstart_local_instance() {')]
  self.assertLess(release.index('backend acknowledgement differs'),release.index('volt-start-admission.py release'))
  self.assertLess(release.index('volt-start-admission.py release'),release.index('wait_healthy'))
if __name__=='__main__':unittest.main()
