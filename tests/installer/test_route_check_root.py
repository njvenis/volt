"""Root finite-operation logic with REAL shared wire validation.

Store/kernel/admission are explicit unit substitutes; no custody/runtime/TLS
acceptance follows. Real shared storage/process checks have separate evidence.
"""
import copy
from contextlib import nullcontext
import hashlib
import json
import os
import time
import unittest
from unittest.mock import patch

from uvm.auth import route_check_records as shared  # explicit source-build schema fixture
from uvm.installer.route_check import execute, RouteCheckError


class Store:
    def __init__(self):
        self.boot=shared.record(runtime_boot_nonce=shared.new_nonce(),api={'pid':2,'proc_start_ticks':200},
            published_boottime_ns=1,ready=True,loaded_operation_id=None)
        self.supervisor=shared.record(supervisor={'pid':1,'proc_start_ticks':100},api=self.boot['api'],
            clock_ticks_per_second=os.sysconf('SC_CLK_TCK'),phase='ready')
        self.state=shared.record(state='disarmed',arm=None,closing_reason=None,
            disarmed=shared.record(runtime_boot_nonce=None,api=None,runtime=None,reason='startup',operation_id=None))
        self.seen=None;self.events=[];self.cleanup_error=False
    def read_state(self):return copy.deepcopy(self.state)
    def read_boot(self):return copy.deepcopy(self.boot)
    def read_supervisor(self):return copy.deepcopy(self.supervisor)
    def read_seen(self):return copy.deepcopy(self.seen)
    def inventory(self):return ()
    def publish_state(self,value):
        shared.validate_record('state',shared.canonical(value))
        self.events.append(value['state']);self.state=copy.deepcopy(value)
    def cleanup_observations(self,*,remove_boot=False):
        self.events.append('cleanup')
        if self.cleanup_error:raise OSError('private-sentinel')
        self.seen=None
        if remove_boot:self.boot=None


def intent(store):
    return {'operation_id':'00000000-0000-4000-8000-000000000001',
        'installation_id':'00000000-0000-4000-8000-000000000002',
        'journal_id':'00000000-0000-4000-8000-000000000003',
        'restore_generation':0,'recovery_epoch_id':None,'container_id':'a'*64,
        'started_at':'2026-11-19T01:02:03.123456789Z',
        'image':{'kind':'config','id':'sha256:'+'b'*64,'config_id':'sha256:'+'b'*64},
        'resources_sha256':'c'*64,'public_origin':'https://volt.test',
        'runtime_boot_nonce':store.boot['runtime_boot_nonce'],'api':store.boot['api'],
        'challenge':shared.new_nonce(),'ttl_ns':60_000_000_000}


def armed(store):
    i=intent(store);ttl=i.pop('ttl_ns');utc=time.time_ns();mono=shared.boottime_ns()
    arm=shared.record(**i,issued_utc_ns=utc,expires_utc_ns=utc+ttl,
        issued_boottime_ns=mono,expires_boottime_ns=mono+ttl)
    store.state=shared.record(state='armed',arm=arm,disarmed=None,closing_reason=None)
    store.seen=shared.record(operation_id=arm['operation_id'],runtime_boot_nonce=arm['runtime_boot_nonce'],
        api=arm['api'],challenge_sha256=hashlib.sha256(arm['challenge'].encode()).hexdigest(),
        observed_utc_ns=utc,observed_boottime_ns=mono)
    return arm


class RootFiniteOperationTests(unittest.TestCase):
    def setUp(self):
        self.store=Store()
        self.patches=[patch('uvm.installer.route_check._shared',return_value=shared),
            patch('uvm.installer.route_check.os.geteuid',return_value=0),
            patch('uvm.installer.route_check._existing_runtime'),
            patch('uvm.installer.route_check._ready',side_effect=lambda store,arm=None:store.read_boot()),
            patch.object(shared,'locked_store',side_effect=lambda **kw:nullcontext(self.store))]
        for p in self.patches:p.start();self.addCleanup(p.stop)
    def call(self,op,**values):return execute(op,shared.canonical(shared.record(**values)))
    def test_arm_supplies_runtime_clocks_and_requires_loaded_ack(self):
        value=intent(self.store);self.store.boot['loaded_operation_id']=value['operation_id']
        result=self.call('arm',intent=value);arm=result['arm']
        shared.validate_record('arm',shared.canonical(arm))
        self.assertEqual(arm,self.store.state['arm'])
        self.assertEqual(arm['expires_utc_ns']-arm['issued_utc_ns'],value['ttl_ns'])
        self.assertEqual(arm['expires_boottime_ns']-arm['issued_boottime_ns'],value['ttl_ns'])
    def test_no_ack_leaves_discoverable_arm_never_probe_authority(self):
        with patch('time.monotonic',side_effect=[0,.1,3]),patch('time.sleep'),self.assertRaises(RouteCheckError)as error:
            self.call('arm',intent=intent(self.store))
        self.assertEqual(error.exception.code,'process_not_ready');self.assertEqual(self.store.state['state'],'armed')
    def test_observed_success_only_after_barrier_cleanup_and_durable_state(self):
        arm=armed(self.store);seen=copy.deepcopy(self.store.seen)
        result=self.call('read-and-disarm',arm=arm)
        self.assertEqual(result['state'],'observed_and_disarmed');self.assertEqual(result['seen'],seen)
        self.assertEqual(self.store.events,['closing','cleanup','disarmed']);self.assertIsNone(self.store.seen)
    def test_cleanup_failure_never_returns_observed_or_reopens_arm(self):
        arm=armed(self.store);self.store.cleanup_error=True
        with self.assertRaises(OSError):self.call('read-and-disarm',arm=arm)
        self.assertEqual(self.store.state['state'],'closing');self.assertIsNotNone(self.store.seen)
        self.assertEqual(self.store.events,['closing','cleanup'])
    def test_substituted_original_arm_and_missing_seen_never_close(self):
        arm=armed(self.store);changed={**arm,'challenge':shared.new_nonce()}
        with self.assertRaises(RouteCheckError):self.call('read-and-disarm',arm=changed)
        self.assertEqual(self.store.events,[])
        self.store.seen=None
        with self.assertRaises(RouteCheckError):self.call('read-and-disarm',arm=arm)
        self.assertEqual(self.store.events,[])
    def test_lost_work_cancel_cannot_adopt_success_or_cancel_other_operation(self):
        arm=armed(self.store)
        args={k:arm[k]for k in ('operation_id','runtime_boot_nonce','api')}
        with self.assertRaises(RouteCheckError):self.call('cancel',**{**args,'operation_id':'00000000-0000-4000-8000-000000000009'})
        self.assertEqual(self.call('cancel',**args)['state'],'cancelled')
        self.assertEqual(self.call('cancel',**args)['state'],'cancelled')
        with self.assertRaises(RouteCheckError):self.call('read-and-disarm',arm=arm)
        self.store.state['disarmed']['reason']='completed'
        with self.assertRaises(RouteCheckError):self.call('cancel',**args)
    def test_old_api_requires_proved_dead_not_not_ready(self):
        arm=armed(self.store);self.store.supervisor['api']={'pid':3,'proc_start_ticks':300}
        args={k:arm[k]for k in ('operation_id','runtime_boot_nonce','api')}
        with patch.object(shared,'proc_dead',return_value=False),self.assertRaises(RouteCheckError):
            self.call('cancel',**args)
        self.assertEqual(self.store.events,[])
        with patch.object(shared,'proc_dead',return_value=True):self.call('cancel',**args)
        self.assertEqual(self.store.state['state'],'disarmed')
    def test_cli_operation_dispatch_rejects_other_valid_request_shape(self):
        with self.assertRaises(RouteCheckError)as error:self.call('state',api=self.store.boot['api'])
        self.assertEqual(error.exception.code,'invalid_input');self.assertEqual(self.store.events,[])
    def test_caller_clock_fields_are_not_accepted(self):
        value=intent(self.store);value['issued_boottime_ns']=1
        with self.assertRaises(shared.RouteCheckError):self.call('arm',intent=value)
        self.assertEqual(self.store.events,[])
