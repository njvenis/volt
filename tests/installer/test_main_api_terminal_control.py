"""Fixed canonical encoders with substituted Store; real Bash private pipes.

No ROOT native Store, tini, publication, completion or backup authority proof.
"""
from contextlib import nullcontext
import copy
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import Mock,patch
from uvm.auth import route_check_records as records
from uvm.installer import route_check as control

ROOT=Path(__file__).resolve().parents[2]
ENTRY=(ROOT/'docker/g7/entrypoint.sh').read_text()

class PrivateControlTests(unittest.TestCase):
    def test_only_matching_broker_owned_timeout_is_recoverable_cleanup_state(self):
        launch={name:{'pid':pid,'proc_start_ticks':pid*10} for name,pid in
            (('entrypoint',11),('supervisor',12),('api',13))}
        launch['clock_ticks_per_second']=100
        base_status={**{key:launch[key] for key in ('entrypoint','supervisor','api')},
            'phase':'quiesce_failed','result':'quiesce_timeout'}
        base_wire={key:launch[key] for key in ('supervisor','api','clock_ticks_per_second')}
        base_wire['phase']='failed'
        for case in ('matching-stopped-not-dead','status-R','dirty-result','wrong-phase','wire-R','wire-ticks','broker-dead','API-dead'):
            with self.subTest(case=case):
                store=Mock();status=copy.deepcopy(base_status);wire=copy.deepcopy(base_wire)
                if case=='status-R':status['api']={'pid':14,'proc_start_ticks':140}
                if case=='dirty-result':status['result']='cleanup_failed'
                if case=='wrong-phase':status['phase']='api_stopped'
                if case=='wire-R':wire['supervisor']={'pid':14,'proc_start_ticks':140}
                if case=='wire-ticks':wire['clock_ticks_per_second']=999
                store.read_launch_status.return_value=status;store.read_supervisor.return_value=wire
                with patch.object(control,'_shared',return_value=records),patch.object(control,'_entrypoint_writer',return_value=(records,launch)),patch.object(records,'locked_store',side_effect=lambda **_:nullcontext(store)),patch.object(records,'proc_live',return_value=case!='broker-dead'),patch.object(records,'proc_dead',return_value=case=='API-dead'),patch.object(control,'_cleanup_api_identity'):
                    if case=='matching-stopped-not-dead':self.assertTrue(control.entrypoint_quiesce_timeout())
                    else:
                        with self.assertRaises(control.RouteCheckError):control.entrypoint_quiesce_timeout()
                self.assertFalse(any(name.startswith('publish') for name,_,_ in store.mock_calls))

    def test_encoders_bind_three_original_identities_and_one_exact_operation(self):
        launch={name:{'pid':pid,'proc_start_ticks':pid*10} for name,pid in
            (('entrypoint',11),('supervisor',12),('api',13))}
        store=Mock();shared=records
        with patch.object(control,'_shared',return_value=shared),patch.object(control,'_entrypoint_writer',return_value=(shared,launch)),patch.object(shared,'locked_store',side_effect=lambda **_:nullcontext(store)),patch.object(shared,'proc_live',return_value=True):
            operation=control.entrypoint_private_encoding('stop-operation')
            self.assertRegex(operation,b'^[0-9a-f]{64}$')
            for action,kind in (('terminal-success','terminal'),('terminal-failure','terminal'),('completion-request','completion_request')):
                raw=control.entrypoint_private_encoding(action,operation)
                value=records.validate_record(kind,raw)
                self.assertEqual(raw,records.canonical(value))
                self.assertEqual({key:value[key] for key in launch},launch)
                self.assertEqual(value['operation_id'],operation.decode())
            for bad in (b'',operation+b'\n',b'A'*64,b'a'*63,b'a'*65,'a'*64):
                with self.subTest(bad_type=type(bad).__name__,length=len(bad)),self.assertRaises(control.RouteCheckError):
                    control.entrypoint_private_encoding('terminal-success',bad)
            self.assertFalse(any(name.startswith('publish') for name,_,_ in store.mock_calls))

    def test_normal_ready_is_readonly_and_cannot_credit_verification(self):
        store=Mock();shared=records
        with patch.object(control,'_shared',return_value=shared),patch.object(control,'_entrypoint_writer',return_value=(shared,{})),patch.object(shared,'locked_store',side_effect=lambda **_:nullcontext(store)):
            store.read_broker_ready.return_value=False
            store.read_verification_health.return_value=True
            with self.assertRaises(control.RouteCheckError):control.entrypoint_ready()
            control.entrypoint_verification_health()
            self.assertFalse(any(name.startswith('publish') for name,_,_ in store.mock_calls))

    def test_real_coproc_encoder_keeps_direct_parent_and_closes_reserved_writer(self):
        a=ENTRY.index('api_private_payload() {');b=ENTRY.index('\nbegin_api_stop() {',a)
        function=ENTRY[a:b]
        fixed='/usr/bin/env -i PATH=/usr/bin:/bin LC_ALL=C /usr/local/bin/python3.14 -I -S \\\n      /usr/local/libexec/volt-route-check-control.py'
        self.assertIn(fixed,function)
        with tempfile.TemporaryDirectory() as directory:
            driver=Path(directory)/'encoder.py'
            driver.write_text('import os,sys,json\n'
                'try:os.fstat(9)\n'
                'except OSError:pass\n'
                'else:raise SystemExit(91)\n'
                'if sys.argv[1]=="entrypoint-stop-operation":sys.stdout.write("a"*64)\n'
                'else:\n'
                ' raw=sys.stdin.buffer.read(65)\n'
                ' if raw!=b"a"*64:raise SystemExit(92)\n'
                ' sys.stdout.write(json.dumps({"parent":os.getppid(),"operation":raw.decode()},sort_keys=True,separators=(",",":")))\n')
            driver.chmod(0o600)
            function=function.replace(fixed,'/usr/bin/python3 '+str(driver))
            script='set -Eeuo pipefail\nexec 9>"$1/sentinel"\n'+function+'''
api_stop_operation=''
api_private_payload stop-operation
api_stop_operation=$api_private_result
[[ $api_stop_operation == aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa ]]
api_private_payload terminal-success
printf '%s' "$api_private_result"
printf kept >&9
'''
            process=subprocess.Popen(['bash','-c',script,'fixture',directory],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
            stdout,stderr=process.communicate(timeout=7)
            self.assertEqual(process.returncode,0,stderr)
            self.assertEqual(json.loads(stdout),{'parent':process.pid,'operation':'a'*64})
            self.assertEqual((Path(directory)/'sentinel').read_bytes(),b'kept')
