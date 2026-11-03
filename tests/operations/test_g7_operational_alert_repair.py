"""Actual sender-consumer regressions for the eight retained review batches.

Docker/provider/API I/O is mocked here; process/locks/filesystem are real.
The maintained container journey supplies the separate live transport proof.
"""
import copy
import datetime as dt
import json
import os
import signal
import subprocess
import sys
import threading
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import patch
from tools import g7_operational_alert_sender as s
from tests.operations import test_g7_operational_alert_sender as fixtures


class OperationalAlertRepairTests(unittest.TestCase):
    def setUp(self):
        self.t=fixtures.OperationalAlertSenderTests(); self.t.setUp()
        self.addCleanup(self.t.tearDown); self.addCleanup(self.t.doCleanups)
        self.boot=Path('/proc/sys/kernel/random/boot_id').read_text().strip()

    def provider(self): return patch.object(s,'post_json',return_value=(200,{'ok':True,'channel':'C_FIXTURE','ts':'1.1'}))

    def health_fault(self,t):
        health=s.Journal(t.loaded['health_journal'])
        health.ensure_genesis(allow_empty=True,context=s.health_context(t.loaded))
        health.append('SENDER_HEALTH_EDGE',{'state':'dead','actor':'independent_host_supervisor',
            'context':s.health_context(t.loaded)})
        return health

    def test_health_fences_each_changed_context_before_any_edge_or_io_even_corrupt_main(self):
        for dimension in ('recovery_epoch','image_id','binding_revision','route','producer_id','run_label'):
            with self.subTest(dimension=dimension):
                t=fixtures.OperationalAlertSenderTests();t.setUp()
                try:
                    health=self.health_fault(t)
                    Path(t.loaded['journal']).write_text('{corrupt-main')
                    changed=copy.deepcopy(t.catalog); changed['generation']=2
                    if dimension=='route': changed['route'].update(revision=2,channel_id='C_NEW')
                    elif dimension=='image_id': changed['image_id']='sha256:'+'b'*64
                    elif dimension=='producer_id': changed['producer_id']='new-producer/v2'
                    elif dimension=='run_label': changed['run_label']='new-run'
                    else: changed[dimension]=2
                    current=s.replace_catalog(t.catalog_path,changed)
                    with self.provider() as provider,patch.object(s,'api_post') as api:
                        s.health_only_once(current)
                    records=health._read()['records']
                    self.assertEqual(provider.call_count,0);self.assertEqual(api.call_count,0)
                    self.assertTrue(any(r['kind']=='HELD' for r in records))
                    self.assertFalse(any(r['kind']=='HEALTH_TRANSITION_INTENT' for r in records))
                    self.assertEqual(records[1]['context'],s.health_context(t.loaded))
                finally: t.doCleanups();t.tearDown()

    def test_first_loop_sigstop_after_actual_sending_is_unhealthy_then_dead_and_uncertain(self):
        t=self.t; marker=t.root/'admitted'
        script='''
import os,sys,time
from pathlib import Path
from unittest.mock import patch
from tools import g7_operational_alert_sender as s
c=s.load_catalog(sys.argv[1]);identity=s.process_identity(os.getpid())
s.atomic(Path(c['journal']).with_suffix('.pid'),s.canonical(identity))
def inspected(c):
 return {'state':'exited','container_id':c['container_id'],'image_id':c['image_id'],
  'deployment_label':c['deployment_label'],'run_label':c['run_label'],'boot_id':identity['boot_id'],
  'started_at':'2026-11-01T00:00:00Z','inspect_ended_epoch':time.time()}
def submitted(*a,**k):
 Path(sys.argv[2]).write_text('actual post_json entry');time.sleep(30)
with patch.object(s,'inspect_target',side_effect=inspected),patch.object(s,'post_json',side_effect=submitted),patch.object(s,'api_post',side_effect=OSError('offline')):
 s.run_once(c)
'''
        child=subprocess.Popen([sys.executable,'-B','-c',script,str(t.catalog_path),str(marker)],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        try:
            end=time.monotonic()+5
            while not marker.exists() and child.poll() is None and time.monotonic()<end:time.sleep(.01)
            self.assertTrue(marker.exists(), 'real admission never reached provider entry')
            os.kill(child.pid,signal.SIGSTOP)
            sending=next(r for r in t.journal._read()['records'] if r['kind']=='SENDING')
            with patch.object(s.time,'monotonic_ns',return_value=sending['work_deadline_monotonic_ns']+1):
                self.assertEqual(s.supervise_once(t.loaded),'unhealthy')
            os.kill(child.pid,signal.SIGCONT);child.kill();child.wait(timeout=5)
            self.assertEqual(s.supervise_once(t.loaded),'dead')
            # Do not dispatch health while verifying the main interrupted attempt.
            with patch.object(s,'process_health_stream'),patch.object(s,'inspect_target',return_value={'state':'unknown','reason':'inspect-unavailable'}),self.provider() as provider,patch.object(s,'api_post') as api:
                self.assertEqual(s.run_once(t.loaded),3)
            records=t.journal._read()['records']
            self.assertEqual(sum(r['kind']=='SENDING' for r in records),1)
            self.assertEqual([r['attempt']['outcome'] for r in records if r['kind']=='ATTEMPT_OUTCOME'],['uncertain'])
            self.assertEqual(provider.call_count,0);self.assertEqual(api.call_count,0)
        finally:
            if child.poll() is None: child.kill();child.wait(timeout=5)
            child.communicate(timeout=5)

    def test_first_loop_startup_grace_is_bounded_by_actual_process_start(self):
        t=self.t;identity=s.process_identity(os.getpid())
        t.journal.path.with_suffix('.pid').write_bytes(s.canonical(identity))
        with patch.object(s.time,'clock_gettime',return_value=identity['start_ticks']/os.sysconf('SC_CLK_TCK')+31):
            self.assertEqual(s.supervise_once(t.loaded),'unhealthy')
        with patch.object(s.time,'clock_gettime',return_value=identity['start_ticks']/os.sysconf('SC_CLK_TCK')+1):
            self.assertEqual(s.supervise_once(t.loaded),'starting')

    def test_two_catalog_aliases_share_actual_owner_and_only_one_admitted_sequence(self):
        t=self.t; alias=t.root/'alias.json';alias.write_text(json.dumps(t.catalog))
        other=s.parse_catalog(alias);entered=threading.Event();release=threading.Event()
        def provider(*args,**kw):
            entered.set();self.assertTrue(release.wait(5));return 200,{'ok':True,'channel':'C_FIXTURE','ts':'1.1'}
        with patch.object(s,'post_json',side_effect=provider) as post,patch.object(s,'api_post',side_effect=OSError('offline')):
            with ThreadPoolExecutor(max_workers=2) as pool:
                first=pool.submit(s.run_once,t.loaded);self.assertTrue(entered.wait(5))
                second=pool.submit(s.run_once,other)
                time.sleep(.05);self.assertFalse(second.done());release.set()
                self.assertEqual(first.result(timeout=5),0)
                with self.assertRaisesRegex(ValueError,'catalog-journal-binding-mismatch'):second.result(timeout=5)
        records=t.journal._read()['records']
        self.assertEqual([r['event']['transition_sequence'] for r in records if r['kind']=='TRANSITION_INTENT'],[1])
        self.assertEqual(post.call_count,1)

    def test_target_recovery_at_final_admission_cancels_without_consuming_sequence(self):
        t=self.t; calls=0
        def inspect(c):
            nonlocal calls
            calls+=1
            # run_once initial inspect is exited; project has no rows, then admission.
            return dict(t.inspected,state='exited' if calls<=2 else 'running',inspect_ended_epoch=time.time())
        with patch.object(s,'inspect_target',side_effect=inspect),self.provider() as provider,patch.object(s,'api_post'):
            s.run_once(t.loaded)
        records=t.journal._read()['records']
        self.assertEqual(provider.call_count,0)
        self.assertTrue(any(r['kind']=='CANCELED_BEFORE_SUBMISSION' for r in records))
        self.assertFalse(any(r['kind'] in {'TRANSITION_INTENT','SENDING'} for r in records))
        with self.provider(),patch.object(s,'api_post',side_effect=OSError('offline')):s.run_once(t.loaded)
        self.assertEqual([r['event']['transition_sequence'] for r in t.journal._read()['records'] if r['kind']=='TRANSITION_INTENT'],[1])

    def test_admission_after_real_authority_lock_wait_reinspects_target(self):
        t=self.t;candidate=s.edge(t.loaded,t.journal,'opened',t.inspected,persist=False)
        entered=threading.Event();release=threading.Event();locked=threading.Event()
        def holder():
            with s.stream_locks(t.loaded,'authority'):
                locked.set();self.assertTrue(release.wait(5))
        def inspector(c):
            entered.set();return dict(t.inspected,state='running',started_at='replacement',inspect_ended_epoch=time.time())
        with ThreadPoolExecutor(max_workers=2) as pool:
            held=pool.submit(holder);self.assertTrue(locked.wait(5))
            with patch.object(s,'inspect_target',side_effect=inspector),self.provider() as provider:
                future=pool.submit(s.send_provider,t.loaded,t.journal,candidate,t.inspected)
                time.sleep(.05);self.assertFalse(entered.is_set());release.set()
                self.assertIsNone(future.result(timeout=5));held.result(timeout=5)
                self.assertTrue(entered.is_set());self.assertEqual(provider.call_count,0)
        self.assertFalse(any(r['kind']=='SENDING' for r in t.journal._read()['records']))

    def test_stale_input_or_regressed_dispatch_clock_never_calls_provider(self):
        t=self.t
        with self.provider() as provider:
            stale=dict(t.inspected,inspect_ended_epoch=time.time()-300)
            self.assertIsNone(s.send_provider(t.loaded,t.journal,t.event,stale))
            with patch.object(s,'stamp',return_value='1970-01-01T00:00:00.000000Z'):
                self.assertIsNone(s.send_provider(t.loaded,t.journal,t.event,t.inspected))
        self.assertEqual(provider.call_count,0)
        self.assertFalse(any(r['kind']=='SENDING' for r in t.journal._read()['records']))
        self.assertTrue(any(r['kind']=='HELD' and r['reason']=='dispatch-clock-continuity-invalid' for r in t.journal._read()['records']))

    def test_catalog_load_consumes_higher_watermark_and_interrupted_replace_cannot_rollback(self):
        t=self.t; newer=copy.deepcopy(t.catalog);newer['generation']=2
        t.catalog_path.write_text(json.dumps(newer));self.assertEqual(s.load_catalog(t.catalog_path)['generation'],2)
        t.catalog_path.write_text(json.dumps(t.catalog))
        with self.assertRaisesRegex(ValueError,'catalog-generation-rollback'):s.load_catalog(t.catalog_path)
        t.catalog_path.write_text(json.dumps(newer));third=dict(newer,generation=3)
        real_atomic=s.atomic
        def fail_publication(path,data):
            if Path(path)==t.catalog_path:raise OSError('injected publication interruption')
            return real_atomic(path,data)
        with patch.object(s,'atomic',side_effect=fail_publication):
            with self.assertRaisesRegex(OSError,'publication interruption'):s.replace_catalog(t.catalog_path,third)
        with self.assertRaisesRegex(ValueError,'catalog-generation-rollback'):s.load_catalog(t.catalog_path)
        authorities=[json.loads(Path(t.catalog[k]+'.catalog-authority').read_text()) for k in ('journal','health_journal')]
        self.assertTrue(all(row['generation']==3 for row in authorities))

    def test_atomic_new_intent_sending_publication_has_no_half_admitted_edge(self):
        t=self.t;real_atomic=s.atomic
        def interrupted(path,data):
            if Path(path)==t.journal.path:raise OSError('injected journal replacement failure')
            return real_atomic(path,data)
        with patch.object(s,'atomic',side_effect=interrupted),self.provider() as provider:
            with self.assertRaisesRegex(OSError,'journal replacement failure'):s.send_provider(t.loaded,t.journal,t.event,t.inspected)
        self.assertEqual(provider.call_count,0);self.assertEqual(t.journal._read()['records'],[])

    def test_inspect_rejects_future_stopped_and_order_contradictions_through_actual_parser(self):
        t=self.t
        # Stop fixture patch so this test exercises the production parser.
        t.inspect_patch.stop()
        base={'Id':t.catalog['container_id'],'Image':t.catalog['image_id'],
            'Config':{'Labels':{'uvm.deployment_id':'g7-local','uvm.run_id':'run'}},
            'State':{'Status':'exited','Running':False,'Paused':False,
                'StartedAt':'2026-11-01T00:00:00Z','FinishedAt':'2026-11-02T00:00:00Z'}}
        for changes in ({'StartedAt':'2099-01-01T00:00:00Z','FinishedAt':'2099-01-02T00:00:00Z'},
                {'FinishedAt':'2020-01-01T00:00:00Z'}, {'StartedAt':'invalid'}, {'Running':True},
                {'FinishedAt':'2099-01-01T00:00:00Z'}, {'StartedAt':'2026-11-01T00:00:00'}):
            with self.subTest(changes=changes):
                row=copy.deepcopy(base);row['State'].update(changes)
                with patch.object(s.subprocess,'run',return_value=subprocess.CompletedProcess([],0,json.dumps([row]),'')):
                    self.assertEqual(s.inspect_target(t.loaded),{'state':'unknown','reason':'inspect-state-shape-or-time-invalid'})

    def test_running_inspection_requires_valid_finished_shape_and_zero_or_prior_finish(self):
        t=self.t;t.inspect_patch.stop()
        base={'Id':t.catalog['container_id'],'Image':t.catalog['image_id'],
            'Config':{'Labels':{'uvm.deployment_id':'g7-local','uvm.run_id':'run'}},
            'State':{'Status':'running','Running':True,'Paused':False,
                'StartedAt':'2026-11-02T00:00:00Z'}}
        for finish,expected in [('garbage','unknown'),(None,'unknown'),
                ('2099-01-01T00:00:00Z','unknown'),('0001-01-01T00:00:00Z','running'),
                ('2026-11-01T00:00:00Z','running')]:
            row=copy.deepcopy(base);row['State']['FinishedAt']=finish
            with patch.object(s.subprocess,'run',return_value=subprocess.CompletedProcess([],0,json.dumps([row]),'')):
                self.assertEqual(s.inspect_target(t.loaded)['state'],expected)

    def test_first_loop_health_send_deadline_is_supervised_from_independent_health_journal(self):
        t=self.t;self.health_fault(t);marker=t.root/'health-admitted'
        script="""
import os,sys,time
from pathlib import Path
from unittest.mock import patch
from tools import g7_operational_alert_sender as s
c=s.load_catalog(sys.argv[1]);s.atomic(Path(c['journal']).with_suffix('.pid'),s.canonical(s.process_identity(os.getpid())))
def provider(*a,**kw):
 Path(sys.argv[2]).write_text('admitted health provider');time.sleep(30)
with patch.object(s,'post_json',side_effect=provider):s.run_once(c)
"""
        child=subprocess.Popen([sys.executable,'-B','-c',script,str(t.catalog_path),str(marker)],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        try:
            until=time.monotonic()+5
            while not marker.exists() and child.poll() is None and time.monotonic()<until:time.sleep(.01)
            self.assertTrue(marker.exists())
            os.kill(child.pid,signal.SIGSTOP)
            sending=next(r for r in s.Journal(t.loaded['health_journal'])._read()['records'] if r['kind']=='SENDING')
            with patch.object(s.time,'monotonic_ns',return_value=sending['work_deadline_monotonic_ns']+1):
                self.assertEqual(s.supervise_once(t.loaded),'unhealthy')
            self.assertFalse(any(r['kind']=='SENDER_LOOP_COMPLETED' for r in t.journal._read()['records']))
            self.assertFalse(any(r['kind']=='ATTEMPT_OUTCOME' for r in s.Journal(t.loaded['health_journal'])._read()['records']))
        finally:
            if child.poll() is None:child.kill();child.wait(timeout=5)
            child.communicate(timeout=5)

    def recovery_fixture(self):
        t=self.t;now=time.time();started=s.stamp(dt.datetime.fromtimestamp(now-20,s.UTC))
        t.inspected.update(state='running',boot_id=self.boot,started_at=started)
        t.loaded['observer_pidfile'];Path(t.loaded['observer_pidfile']).write_text(str(os.getpid()))
        active={'revision':1,'digest':'timing-digest','values':{'maximum_future_skew_seconds':0}}
        Path(t.loaded['active_file']).write_text(json.dumps(active))
        for key in ('observer_readback','supervisor_readback'):
            Path(t.loaded[key]).write_text(json.dumps({'observed_at':s.stamp(),'revision':1,'digest':'timing-digest'}))
        Path(t.loaded['supervisor_state']).write_text(json.dumps({'last_completed_loop_at':s.stamp(),'supervision':{'status':'healthy','heartbeat_age_seconds':0}}))
        Path(t.loaded['scheduler_file']).write_text(json.dumps({'loop_sequence':1,'boot_id':self.boot,'monotonic_ns':time.monotonic_ns(),'completed_at':s.stamp()}))
        self.write_loop(2,now-1)
        return {'loop_sequence':1,'barrier_completed_epoch':now-2,'observer_proc':s.observer_identity(t.loaded),
            'boot_id':self.boot,'timing_revision':1,'timing_digest':'timing-digest','future_skew_seconds':0,
            'monotonic_ns':time.monotonic_ns()-2_000_000_000,'started_at':started,'target_started_at':started,
            'outage_observed_epoch':now-3}

    def write_loop(self,seq,at):
        value=s.stamp(dt.datetime.fromtimestamp(at,s.UTC))
        Path(self.t.loaded['observer_state']).write_text(json.dumps({'loop_sequence':seq,'last_completed_loop_at':value,
            'active_revision':1,'active_digest':'timing-digest','last_check':{'at':value,'http_status':200,'error':None,
                'anchor_export':{'status':'healthy'},'incident_projection':{'status':'late'}},'scheduler':{'status':'healthy','loop_sequence':1}}))

    def test_recovery_rechecks_real_observer_identity_after_active_read_and_rejects_process_loss(self):
        t=self.t;prior=self.recovery_fixture();child=subprocess.Popen([sys.executable,'-c','import time;time.sleep(30)'])
        Path(t.loaded['observer_pidfile']).write_text(str(child.pid));prior['observer_proc']=s.observer_identity(t.loaded)
        real_read=s.read_json;active_reads=0
        def kill_during_read(path):
            nonlocal active_reads
            result=real_read(path)
            if path==t.loaded['active_file']:
                active_reads+=1
                if active_reads==2:child.kill();child.wait(timeout=5)
            return result
        try:
            self.assertTrue(s.observer_recovery(t.loaded,prior,t.journal))
            with patch.object(s,'read_json',side_effect=kill_during_read):
                self.assertFalse(s.observer_recovery(t.loaded,prior,t.journal))
            record=t.journal._read()['records'][-1]
            self.assertEqual(record['kind'],'RECOVERY_READ');self.assertFalse(record['stable'])
            self.assertIsNone(record['after'])
        finally:
            if child.poll() is None:child.kill();child.wait(timeout=5)

    def test_delayed_anchor_loop_is_discarded_then_second_restart_and_timing_change_rebase(self):
        t=self.t;prior=self.recovery_fixture()
        # HTTP success before the outage but anchor completion after it is the
        # first newer serial loop; it only creates a discard barrier.
        prior['loop_sequence']=1
        discarded=s.recovery_barrier(t.loaded,prior,t.journal)
        self.assertIsNotNone(discarded)
        self.assertFalse(s.observer_recovery(t.loaded,discarded,t.journal))
        old_started=t.inspected['started_at'];t.inspected['started_at']=s.stamp(dt.datetime.fromtimestamp(time.time()-.5,s.UTC))
        self.write_loop(3,time.time()-.1)
        self.assertFalse(s.observer_recovery(t.loaded,discarded,t.journal))
        self.assertIsNone(s.recovery_barrier(t.loaded,prior,t.journal))
        rebased=dict(prior,target_started_at=t.inspected['started_at'],loop_sequence=3,
            outage_observed_epoch=time.time(),monotonic_ns=time.monotonic_ns())
        rebased.pop('started_at')
        self.write_loop(4,time.time());fresh_discard=s.recovery_barrier(t.loaded,rebased,t.journal)
        self.assertIsNotNone(fresh_discard);self.assertFalse(s.observer_recovery(t.loaded,fresh_discard,t.journal))
        self.write_loop(5,time.time());self.assertTrue(s.observer_recovery(t.loaded,fresh_discard,t.journal))
        active=s.read_json(t.loaded['active_file']);active['revision']=2
        Path(t.loaded['active_file']).write_text(json.dumps(active))
        self.assertFalse(s.observer_recovery(t.loaded,fresh_discard,t.journal))

    def test_reconciliation_keeps_history_and_allows_sequence_three_generation_two(self):
        t=self.t
        first=s.edge(t.loaded,t.journal,'opened',t.inspected)
        s.edge(t.loaded,t.journal,'recovered',t.inspected,first=first['first_detected_at'],episode=first['episode_id'],
            opening_id=first['transition_id'],seq=2,pred=first['transition_id'])
        t.journal.append('HELD',{'reason':'old-context-fence'})
        current=s.replace_catalog(t.catalog_path,dict(t.catalog,generation=2))
        self.assertEqual(s.reconcile_held(current,'local-operator','local:test'),1)
        with self.provider() as provider,patch.object(s,'api_post',side_effect=OSError('offline')):s.run_once(current)
        rows=t.journal._read()['records'];events=[r['event'] for r in rows if r['kind']=='TRANSITION_INTENT']
        self.assertEqual([r['transition_sequence'] for r in events],[1,2,3]);self.assertEqual(events[-1]['episode_generation'],2)
        self.assertEqual(provider.call_count,1);self.assertEqual(sum(r['kind']=='HELD' for r in rows),1)
        self.assertTrue(any(r['kind']=='HELD_RECONCILIATION' for r in rows))

    def test_actual_serial_observer_delayed_anchor_cannot_qualify_across_second_restart(self):
        from tools import g7_host_observer as observer
        from tests.operations.test_g7_host_observer import HostObserverTests, VALUES
        h=HostObserverTests();h.setUp();t=self.t
        self.addCleanup(h.tearDown)
        # Exercise the maintained observer consumer, including its timestamp write
        # after anchor lookup, rather than synthesising its delayed completion.
        h.policy['deployment_id']='g7-local'
        h.policy['host_policy_digest']=observer.digest({k:v for k,v in h.policy.items() if k!='host_policy_digest'})
        observer.atomic_json(Path(h.policy['active_file']),h._desired())
        observer.atomic_json(Path(h.policy['scheduler_file']),{'loop_sequence':1,'boot_id':self.boot,
            'monotonic_ns':time.monotonic_ns(),'completed_at':s.stamp()})
        changed=dict(t.catalog,generation=2)
        for key in ('observer_state','supervisor_state','observer_readback','supervisor_readback','active_file','scheduler_file'):
            changed[key]=h.policy[key]
        c=s.replace_catalog(t.catalog_path,changed)
        Path(c['observer_pidfile']).write_text(str(os.getpid()))
        t.inspected.update(state='running',boot_id=self.boot)
        calls=[];http_returned=threading.Event();release=threading.Event()
        def telemetry(*args):
            calls.append({'http_returned_epoch':time.time()});return 200,{'deployment_id':'g7-local',
                'audit_events':[],'audit_complete':True,'incidents':[],'incidents_complete':True},None
        def delayed_anchor(*args):
            http_returned.set();self.assertTrue(release.wait(5));return {}
        def baseline(seq):
            return {'loop_sequence':seq,'observer_proc':s.observer_identity(c),'boot_id':self.boot,
                'target_started_at':t.inspected['started_at'],'timing_revision':1,
                'timing_digest':h._desired()['digest'],'outage_observed_epoch':time.time(),
                'monotonic_ns':time.monotonic_ns()}
        with patch.object(observer,'_request',side_effect=telemetry),patch.object(observer,'read_anchor_inventory',side_effect=delayed_anchor):
            with ThreadPoolExecutor(max_workers=1) as pool:
                first=pool.submit(observer.consumer_once,'observer',h.policy)
                self.assertTrue(http_returned.wait(5))
                t.inspected['started_at']=s.stamp();first_baseline=baseline(0)
                self.assertLess(calls[-1]['http_returned_epoch'],first_baseline['outage_observed_epoch'])
                release.set();first.result(timeout=5)
                observer.consumer_once('supervisor',h.policy)
                discard=s.recovery_barrier(c,first_baseline,t.journal)
                self.assertIsNotNone(discard);self.assertFalse(s.observer_recovery(c,discard,t.journal))
                http_returned.clear();release.clear()
                second=pool.submit(observer.consumer_once,'observer',h.policy)
                self.assertTrue(http_returned.wait(5))
                t.inspected['started_at']=s.stamp();second_baseline=baseline(1)
                release.set();second.result(timeout=5)
                observer.consumer_once('supervisor',h.policy)
                self.assertFalse(s.observer_recovery(c,discard,t.journal))
                newer_discard=s.recovery_barrier(c,second_baseline,t.journal)
                self.assertIsNotNone(newer_discard);self.assertFalse(s.observer_recovery(c,newer_discard,t.journal))
                observer.consumer_once('observer',h.policy)
                observer.consumer_once('supervisor',h.policy)
                self.assertTrue(s.observer_recovery(c,newer_discard,t.journal))
                self.assertEqual(len(calls),3)

    def test_retry_budget_and_original_deadline_survive_catalog_journal_reload(self):
        from email.message import Message
        import urllib.error
        t=self.t;headers=Message();headers['Retry-After']='0'
        rejected=urllib.error.HTTPError('https://127.0.0.1/provider',429,'fixture',headers,None)
        with patch.object(s,'post_json',side_effect=rejected) as provider:
            for _ in range(t.catalog['retry_count']+3):
                c=s.load_catalog(t.catalog_path);s.send_provider(c,s.Journal(c['journal']),t.event,t.inspected)
        rows=t.journal._read()['records'];schedules=[r for r in rows if r['kind']=='RETRY_SCHEDULE']
        attempts=[r for r in rows if r['kind']=='SENDING']
        self.assertEqual(provider.call_count,t.catalog['retry_count']+1)
        self.assertEqual(len(attempts),t.catalog['retry_count']+1)
        self.assertEqual(len({r['deadline_epoch'] for r in schedules}),1)
        self.assertEqual(len({r['first_attempt_epoch'] for r in schedules}),1)
        self.assertEqual(len({r['attempt']['attempt_id'] for r in attempts}),len(attempts))

    def test_catalog_withdrawal_can_finish_while_admitted_provider_io_is_blocked(self):
        t=self.t;entered=threading.Event();release=threading.Event()
        def provider(*args,**kw):
            entered.set();self.assertTrue(release.wait(5));return 200,{'ok':True,'channel':'C_FIXTURE','ts':'1.1'}
        withdrawn=copy.deepcopy(t.catalog);withdrawn['generation']=2;withdrawn['route'].update(enabled=False,revision=2)
        with patch.object(s,'post_json',side_effect=provider):
            with ThreadPoolExecutor(max_workers=2) as pool:
                sending=pool.submit(s.send_provider,t.loaded,t.journal,t.event,t.inspected)
                self.assertTrue(entered.wait(5))
                replace=pool.submit(s.replace_catalog,t.catalog_path,withdrawn)
                try:self.assertEqual(replace.result(timeout=2)['generation'],2)
                finally:release.set()
                self.assertEqual(sending.result(timeout=5)['outcome'],'accepted')
        self.assertEqual(sum(r['kind']=='SENDING' for r in t.journal._read()['records']),1)

    def test_health_has_separate_explicit_reconciliation_even_when_main_is_corrupt(self):
        t=self.t;health=self.health_fault(t)
        current=s.replace_catalog(t.catalog_path,dict(t.catalog,generation=2))
        Path(t.loaded['journal']).write_text('{broken')
        s.health_only_once(current)
        self.assertEqual(s.reconcile_held(current,'operator','local:health',health_only=True),1)
        with self.provider() as provider,patch.object(s,'api_post',side_effect=OSError('offline')):s.health_only_once(current)
        self.assertEqual(provider.call_count,1)
        self.assertTrue(any(r['kind']=='HELD' for r in health._read()['records']))


if __name__=='__main__':unittest.main()
