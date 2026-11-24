"""Actual POSIX/child diagnostic boundaries; no Docker or hosted lifecycle claim."""
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch,Mock
import json,os,subprocess,tempfile,unittest
from tools.release import hosted_arm_essential as h
from tools import compose_release_qualification as q
from tests.release import test_install_failure_receipt as f
ROOT=Path(__file__).resolve().parents[2]
class RestoreStageDiagnosticTests(unittest.TestCase):
 def test_actual_signed_launcher_start_receipt_is_gated_and_original_exit_preserved(self):
  # Runs complete public launcher until the owned stub's host-preflight boundary.
  for trusted,fixture in ((True,True),(False,True),(True,False)):
   r,_=f.InstallFailureReceiptTests().actual_launcher('host-preflight',action='start',trusted=trusted,fixture=fixture)
   self.assertEqual(r.returncode,1)
   expected={'phase':'host-preflight','profile':'volt_fixture_start_exit_v1','status':1}if trusted and fixture else None
   self.assertEqual(h.start_phase_receipt(r.stderr),expected);self.assertIsNone(h.install_phase_receipt(r.stderr))
 def test_actual_start_health_exit_is_finite_and_has_no_private_output_in_record(self):
  source=(ROOT/'deploy/compose/launcher.sh').read_text();functions=source[source.index('emit_fixture_install_receipt() {'):source.index('\ntrap cleanup 0 HUP INT TERM')]
  with tempfile.TemporaryDirectory()as d:
   root=Path(d);script='set -eu\n'+functions+'\n'+f'''INSTALL_RECEIPT_ACTION=start
INSTALL_RECEIPT_PHASE=health
INSTALL_HEALTH_PASS=configured
INSTALL_HEALTH_CAUSE=unhealthy
VERIFIER_IMAGE={f.Q}
VERSION=0.1.0-rc.4
SIGNER={f.SIGNER}
ISSUER={f.ISSUER}
LOCK_NAME=''
WORK=''
INSTALLING=0
trap cleanup 0
exit 7
'''
   r=subprocess.run(['sh','-c',script],env=f.InstallFailureReceiptTests().environment(root),capture_output=True,timeout=5)
   self.assertEqual(r.returncode,7);self.assertEqual(h.start_phase_receipt(r.stderr)['status'],7);self.assertEqual(h.health_phase_receipt(r.stderr)['cause'],'unhealthy')
 def test_observer_preserves_start_exception_and_original_status_with_closed_receipt(self):
  with tempfile.TemporaryDirectory()as d:
   evidence=Path(d);name='essential-restored-public-start';(evidence/(name+'.exit')).write_text('1\n');r={'phase':'api-release','profile':'volt_fixture_start_exit_v1','status':1};(evidence/(name+'.stderr')).write_text('PRIVATE\nVOLT_FIXTURE_START_RECEIPT '+json.dumps(r,sort_keys=True,separators=(',',':'))+'\n')
   error=RuntimeError('PRIVATE');fake=SimpleNamespace(run=Mock(side_effect=error),wait_for_local=Mock());record={}
   with self.assertRaises(RuntimeError)as caught:
    with h.observe_journey(fake,record):fake.run(name,['PRIVATE'],evidence)
   self.assertIs(caught.exception,error);self.assertEqual(record['exit_code'],1);self.assertEqual(record['start_receipt'],r);self.assertNotIn('PRIVATE',json.dumps(record))
 def test_real_negative_child_exit_and_unobserved_validation_are_now_distinguished(self):
  for code in (0,1):
   with tempfile.TemporaryDirectory()as d:
    root=Path(d);state=root/'state';state.mkdir();(state/'instance.json').write_text('{}');e=root/'evidence';e.mkdir();launcher=root/'entry';launcher.write_text('#!/bin/sh\nprintf PRIVATE >&2\nexit '+str(code)+'\n');launcher.chmod(0o700)
    def environment(**kw):
     capture=kw['capture'];capture.mkdir();(capture/'guard.status').write_text('captured');return os.environ.copy()
    record={};before=q._inventory_trace
    with patch.object(q,'restore_admit_observer_environment',side_effect=environment),patch.object(q,'validate_inventory_rejection_capture',side_effect=RuntimeError('PRIVATE_CAPTURE')):
     with self.assertRaises(RuntimeError):
      with h.observe_journey(q,record):q.qualify_inventory_rejection(kind='corrupt',launcher=launcher,state=state,private=root,evidence=e,environment=os.environ.copy(),admission={})
    self.assertIs(q._inventory_trace,before);self.assertEqual(record['stage'],'inventory-denial');self.assertEqual(record['inventory_detail']['caller_exit'],code)
    self.assertEqual(record['inventory_detail']['phase'],'caller-identity'if code==0 else'capture-validation');self.assertNotIn('PRIVATE',json.dumps(record));self.assertEqual((e/'inventory-corrupt-specific-denial.exit').read_text(),str(code)+'\n')
 def test_fixed_trace_rejects_unknown_data_and_cannot_change_caller_on_reporting_error(self):
  record={};original=q._inventory_trace
  with h.observe_journey(q,record):
   q._inventory_trace('corrupt','capture-bindings',1);expected=dict(record);q._inventory_trace('PRIVATE','PRIVATE','PRIVATE');self.assertEqual(record,expected)
   q._inventory_trace('empty','caller-returned',True);self.assertIsNone(record['inventory_detail']['caller_exit'])
  self.assertIs(q._inventory_trace,original)
  with patch.object(q,'_inventory_trace',side_effect=ValueError('PRIVATE')):self.assertIsNone(q._inventory_event('corrupt','caller-wait'))
 def test_fresh_existing_auth_status_pair_is_numeric_and_has_no_old_record_adoption(self):
  with tempfile.TemporaryDirectory()as d:
   root=Path(d);auth=root/'public-offline-authentication';auth.mkdir(mode=0o700);old=auth/'entry.aaaaaaaa';old.mkdir(mode=0o700)
   for name in('authentication.exit','reader.exit'):(old/name).write_text('0\n')
   before=h.authentication_status_snapshot({'private':str(root)})
   self.assertEqual(h.fresh_authentication_status(before),{'status':'unavailable'})
   fresh=auth/'entry.bbbbbbbb';fresh.mkdir(mode=0o700)
   for name,value in [('authentication.exit','2\n'),('reader.exit','0\n')]:
    p=fresh/name;p.write_text(value);p.chmod(0o600)
   self.assertEqual(h.fresh_authentication_status(before),{'status':'observed','producer_exit':2,'reader_exit':0})
   (fresh/'reader.exit').write_text('PRIVATE\n');self.assertEqual(h.fresh_authentication_status(before),{'status':'unavailable'})
   (fresh/'reader.exit').write_text('0\n');(auth/'entry.cccccccc').mkdir(mode=0o700);self.assertEqual(h.fresh_authentication_status(before),{'status':'unavailable'})

if __name__=='__main__':unittest.main()
