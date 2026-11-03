"""Durable provider-attempt, bounded-retry and crash-recovery checks."""
from email.message import Message
import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.error
import uuid
from pathlib import Path
from unittest.mock import patch

from tools import g7_operational_alert_sender as sender


class OperationalAlertSenderTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.catalog_path = self.root / "catalog.json"
        self.token = self.root / "token"
        self.ca = self.root / "ca.pem"
        self.credential = self.root / "provider-token"
        self.token.write_text("dedicated-local-api-token")
        self.credential.write_text("fixture-provider-token")
        self.event = {"transition_id":str(uuid.uuid4()), "episode_id":str(uuid.uuid4()),
            "condition":"container_availability", "transition_kind":"opened",
            "observed_at":"2026-11-02T20:00:00.000000Z"}
        self.catalog = {"generation":1,"deployment_id":"g7-local","subject_id":"container:g7-local:run",
            "principal_id":"g7-host-operational-alert-sender","producer_id":"g7-host-operational-alert-sender/v1",
            "condition":"container_availability","binding_revision":1,"container_id":"container-id",
            "image_id":"sha256:"+"a"*64,"deployment_label":"g7-local","run_label":"run",
            "recovery_epoch":1,"observer_state":str(self.root/"observer.json"),
            "supervisor_state":str(self.root/"supervisor.json"),"observer_pidfile":str(self.root/"observer.pid"),
            "active_file":str(self.root/"active.json"),"scheduler_file":str(self.root/"scheduler.json"),
            "observer_readback":str(self.root/"observer-readback.json"),"supervisor_readback":str(self.root/"supervisor-readback.json"),
            "journal":str(self.root/"journal.json"),"health_journal":str(self.root/"health.json"),
            "api_url":"http://127.0.0.1:8000","api_token_file":str(self.token),"ca_file":str(self.ca),
            "route":{"enabled":True,"revision":1,"destination_ref":"fixture-channel",
                "endpoint":"https://127.0.0.1:9443/api/chat.postMessage","channel_id":"C_FIXTURE",
                "credential_file":str(self.credential),"mentions":[],"installation_id":"local-install",
                "workspace_id":"T_LOCAL","runbook_url":"https://example.invalid/runbook"},
            "retry_count":2,"retry_age_seconds":30,"freshness_seconds":120,
            "request_deadline_seconds":5,"app_stream_absent_verified":True}
        self.catalog_path.write_text(json.dumps(self.catalog))
        self.loaded = sender.load_catalog(self.catalog_path)
        self.journal = sender.Journal(self.catalog["journal"])

    def tearDown(self):
        self.tmp.cleanup()

    def http_error(self, code, headers=None):
        headers = headers or Message()
        return urllib.error.HTTPError("https://127.0.0.1:9443/api/chat.postMessage",code,
            "fixture response",headers,None)

    def test_retry_after_creates_new_attempt_and_stops_on_acceptance(self):
        headers=Message(); headers["Retry-After"]="0"
        with patch.object(sender,"post_json",side_effect=[self.http_error(429,headers),
                (200,{"ok":True,"channel":"C_FIXTURE","ts":"1720000000.000001"})]) as post:
            first=sender.send_provider(self.loaded,self.journal,self.event)
            self.assertEqual(first["failure_detail"],"rate_limited")
            self.assertTrue(any(r["kind"]=="RETRY_SCHEDULE" for r in self.journal._read()["records"]))
            result=sender.send_provider(self.loaded,self.journal,self.event)
        records=self.journal._read()["records"]
        sending=[r for r in records if r["kind"]=="SENDING"]
        outcomes=[r["attempt"] for r in records if r["kind"]=="ATTEMPT_OUTCOME"]
        self.assertEqual(result["outcome"],"accepted")
        self.assertEqual([a["failure_detail"] for a in outcomes],["rate_limited",None])
        self.assertEqual(len(sending),2)
        self.assertEqual(len({a["attempt_id"] for a in outcomes}),2)
        self.assertEqual(sending[0]["request_digest"],sending[1]["request_digest"])
        self.assertEqual(post.call_count,2)

    def test_scheduled_opening_retry_is_superseded_after_recovery_without_send(self):
        opening=dict(self.event,transition_sequence=1,transition_kind='opened',episode_id=str(uuid.uuid4()))
        recovered=dict(self.event,transition_id=str(uuid.uuid4()),transition_sequence=2,
            transition_kind='recovered',episode_id=opening['episode_id'])
        context={'deployment_id':'g7-local','container_id':'container-id'}
        self.journal.append('TRANSITION_INTENT',{'transition_id':opening['transition_id'],'event':opening,'context':context})
        self.journal.append('TRANSITION_INTENT',{'transition_id':recovered['transition_id'],'event':recovered,'context':context})
        self.journal.append('RETRY_SCHEDULE',{'transition_id':opening['transition_id'],'due_epoch':0,
            'deadline_epoch':time.time()+60,'target_started_at':'started','target_boot_id':'boot'})
        current={'state':'running','started_at':'restarted','boot_id':'boot','inspect_ended_epoch':time.time()}
        with patch.object(sender,'send_provider') as send:
            sender.dispatch_scheduled_retries(self.loaded,self.journal,current,context,self.journal._read()['records'])
        self.assertEqual(send.call_count,0)
        self.assertTrue(any(r['kind']=='RETRY_SUPERSEDED' for r in self.journal._read()['records']))

    def test_scheduled_retry_requires_same_started_at_and_recent_inspection(self):
        event=dict(self.event,transition_sequence=1,transition_kind='opened',episode_id=str(uuid.uuid4()))
        context={'deployment_id':'g7-local','container_id':'container-id'}
        intent=self.journal.append('TRANSITION_INTENT',{'transition_id':event['transition_id'],'event':event,'context':context})
        self.journal.append('RETRY_SCHEDULE',{'transition_id':event['transition_id'],'due_epoch':0,
            'deadline_epoch':time.time()+60,'target_started_at':'original-start','target_boot_id':'boot'})
        current={'state':'exited','started_at':'new-start','boot_id':'boot','inspect_ended_epoch':time.time()}
        with patch.object(sender,'send_provider') as send:
            sender.dispatch_scheduled_retries(self.loaded,self.journal,current,context,self.journal._read()['records'])
        self.assertEqual(send.call_count,0)

    def test_permanent_rejection_and_ambiguous_transport_never_retry(self):
        for failure, expected in ((self.http_error(403),"failed"),
                (urllib.error.URLError("connection reset after submit"),"uncertain")):
            with self.subTest(expected=expected):
                path=self.root/f"{expected}-{uuid.uuid4()}.json"
                catalog=dict(self.catalog,journal=str(path))
                catalog_path=self.root/f"{path.stem}-catalog.json"
                catalog_path.write_text(json.dumps(catalog))
                loaded=sender.load_catalog(catalog_path)
                journal=sender.Journal(path)
                with patch.object(sender,"post_json",side_effect=failure) as post:
                    result=sender.send_provider(loaded,journal,self.event)
                self.assertEqual(result["outcome"],expected)
                self.assertEqual(post.call_count,1)
                self.assertEqual(sum(r["kind"]=="SENDING" for r in journal._read()["records"]),1)

    def test_crash_after_sending_recovers_uncertain_without_replay(self):
        attempt={"schema_version":1,"attempt_id":str(uuid.uuid4()),"outcome":"uncertain",
            "attempted_at":"2026-11-02T20:00:00.000000Z","receipt_ref":None,
            "failure_detail":"submission_uncertain"}
        self.journal.append("SENDING",{"transition_id":self.event["transition_id"],"attempt":attempt})
        records=self.journal._read()["records"]
        recovered=sender.record_interrupted_sends(self.journal,records)
        self.assertEqual(len(recovered),1)
        self.assertEqual(recovered[0]["attempt"]["outcome"],"uncertain")
        self.assertTrue(recovered[0]["recovered_sending_after_restart"])
        size=len(self.journal._read()["records"])
        self.assertEqual(sender.record_interrupted_sends(self.journal,self.journal._read()["records"]),[])
        self.assertEqual(len(self.journal._read()["records"]),size)

    def test_killed_process_after_sending_persists_uncertain_before_offline_return(self):
        attempt={"schema_version":1,"attempt_id":str(uuid.uuid4()),"outcome":"failed",
            "attempted_at":"2026-11-02T20:00:00.000000Z","receipt_ref":None,
            "failure_detail":"provider_unavailable"}
        marker=self.root/"sending-durable"
        inspected={"state":"exited","container_id":"container-id",
            "image_id":"sha256:"+"a"*64,"deployment_label":"g7-local",
            "run_label":"run","boot_id":"boot"}
        event=sender.edge(self.loaded,self.journal,"opened",inspected)
        admitted={'transition_id':event['transition_id'],'attempt':attempt,
            'route_revision':self.loaded['route']['revision'],
            'route_digest':sender.sha(sender.canonical(self.loaded['route'])),
            'catalog_generation':self.loaded['generation'],'catalog_digest':self.loaded['_digest'],
            'request_digest':sender.sha(sender.canonical(sender.delivery_body(event,self.loaded['route']))),
            'started_monotonic_ns':time.monotonic_ns(),
            'started_epoch':time.time(),'target_started_at':None,
            'target_boot_id':Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
            'target_inspect_ended_epoch':time.time(),
            'boot_id':Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
            'work_deadline_monotonic_ns':time.monotonic_ns()+5_000_000_000}
        script=("import json, os, sys, time; from tools.g7_operational_alert_sender import Journal; "
            "Journal(sys.argv[1]).append('SENDING', json.loads(sys.argv[2])); "
            "open(sys.argv[3],'w').write('ready'); time.sleep(30)")
        child=subprocess.Popen([sys.executable,"-c",script,str(self.catalog["journal"]),
            json.dumps(admitted),str(marker)])
        try:
            deadline=time.monotonic()+5
            while not marker.exists() and child.poll() is None and time.monotonic()<deadline:
                time.sleep(.01)
            self.assertTrue(marker.exists(),"child did not durably append SENDING")
            child.kill()
            child.wait(timeout=5)
        finally:
            if child.poll() is None:
                child.kill(); child.wait(timeout=5)
        inspected={"state":"unknown","reason":"inspect-unavailable"}
        with patch.object(sender,"inspect_target",return_value=inspected), \
                patch.object(sender,"post_json") as post, \
                patch.object(sender,"api_post") as project:
            sender.run_once(self.loaded)
        records=self.journal._read()["records"]
        outcome=next(r for r in records if r["kind"]=="ATTEMPT_OUTCOME")
        self.assertEqual(outcome["attempt"]["outcome"],"uncertain")
        self.assertEqual(outcome["attempt"]["failure_detail"],"submission_uncertain")
        self.assertEqual([r for r in records if r["kind"]=="HELD"][-1]["reason"],
            "bound-service-context-changed")
        self.assertEqual(post.call_count,0)
        self.assertEqual(project.call_count,0)

    def test_initialized_missing_journal_fails_closed(self):
        self.journal.ensure_genesis(allow_empty=True,context={"test":"initial"})
        self.journal.path.unlink()
        with self.assertRaisesRegex(RuntimeError,"journal-missing-after-genesis"):
            self.journal.ensure_genesis(allow_empty=True,context={"test":"second genesis"})

    def test_concurrent_run_once_admits_one_opening_and_provider_send(self):
        from concurrent.futures import ThreadPoolExecutor
        inspected={"state":"exited","container_id":"container-id",
            "image_id":"sha256:"+"a"*64,"deployment_label":"g7-local",
            "run_label":"run","boot_id":"boot"}
        with patch.object(sender,"inspect_target",return_value=inspected), \
                patch.object(sender,"post_json",return_value=(200,{"ok":True,
                    "channel":"C_FIXTURE","ts":"1720000000.000001"})) as post, \
                patch.object(sender,"api_post",side_effect=OSError("app offline")):
            with ThreadPoolExecutor(max_workers=2) as pool:
                list(pool.map(lambda _index:sender.run_once(self.loaded),range(2)))
        records=self.journal._read()["records"]
        edges=[r for r in records if r["kind"]=="TRANSITION_INTENT"]
        self.assertEqual(len(edges),1)
        self.assertEqual([r["event"]["transition_sequence"] for r in edges],[1])
        self.assertEqual(post.call_count,1)

    def test_public_delivery_ack_lost_then_idempotent_replay_is_consumed(self):
        inspected={"state":"exited","container_id":"container-id",
            "image_id":"sha256:"+"a"*64,"deployment_label":"g7-local",
            "run_label":"run","boot_id":"boot"}
        event=sender.edge(self.loaded,self.journal,"opened",inspected)
        attempt={"schema_version":1,"attempt_id":str(uuid.uuid4()),"outcome":"accepted",
            "attempted_at":event["observed_at"],"receipt_ref":"provider:1","failure_detail":None}
        self.journal.append("ATTEMPT_OUTCOME",{"transition_id":event["transition_id"],"attempt":attempt})
        calls=[]
        def api(_catalog,path,body):
            calls.append(path)
            if path.endswith("/delivery"):
                if sum(item.endswith("/delivery") for item in calls)==1:
                    raise OSError("commit succeeded but acknowledgement was lost")
                return 200,{"schema_version":1,"status":"projected",
                    "transition_id":event["transition_id"],"attempt_id":attempt["attempt_id"],
                    "outcome":"accepted","idempotent":True}
            return 200,{"schema_version":1,"status":"projected",
                "transition_id":event["transition_id"],"transition_sequence":1,
                "episode_id":event["episode_id"],"episode_generation":1,
                "payload_digest":sender.sha(sender.canonical(event))}
        with patch.object(sender,"api_post",side_effect=api):
            sender.project_pending(self.loaded,self.journal,self.journal._read()["records"])
            sender.project_pending(self.loaded,self.journal,self.journal._read()["records"])
        self.assertEqual(sum(item.endswith("/delivery") for item in calls),2)
        self.assertTrue(any(r["kind"]=="ATTEMPT_ACK" and r["attempt_id"]==attempt["attempt_id"]
            for r in self.journal._read()["records"]))

    def test_transition_ack_rejects_boolean_integer_positions(self):
        event={"transition_id":"t","transition_sequence":1,"episode_id":"e",
            "episode_generation":1}
        response={"schema_version":1,"status":"projected","transition_id":"t",
            "transition_sequence":True,"episode_id":"e","episode_generation":True,
            "payload_digest":"d"}
        self.assertFalse(sender.ack_transition(response,event,"d"))

    def test_bound_context_captures_labels_binding_epoch_and_route(self):
        inspected={"container_id":"container-id","image_id":"sha256:"+"a"*64,
            "deployment_label":"g7-local","run_label":"run","boot_id":"boot"}
        context=sender.bound_context(self.loaded,inspected)
        self.assertEqual(context["deployment_label"],"g7-local")
        self.assertEqual(context["run_label"],"run")
        self.assertEqual(context["recovery_epoch"],1)
        self.assertEqual(context["route_revision"],1)
        self.assertEqual(context["route_digest"],sender.sha(sender.canonical(self.loaded["route"])))

    def test_changed_recovery_epoch_holds_old_journal_before_projection(self):
        inspected={"state":"unknown","container_id":"container-id",
            "image_id":"sha256:"+"a"*64,"deployment_label":"g7-local",
            "run_label":"run","boot_id":"boot"}
        old_context=sender.bound_context(self.loaded,inspected)
        self.journal.append("TRANSITION_INTENT",{"transition_id":self.event["transition_id"],
            "event":self.event,"context":old_context})
        changed=dict(self.catalog,recovery_epoch=2)
        self.catalog_path.write_text(json.dumps(changed))
        current=sender.load_catalog(self.catalog_path)
        with patch.object(sender,"inspect_target",return_value=inspected):
            self.assertEqual(sender.run_once(current),3)
        records=self.journal._read()["records"]
        held=next(r for r in reversed(records) if r["kind"]=="HELD")
        self.assertEqual(held["kind"],"HELD")
        self.assertEqual(held["reason"],"bound-service-context-changed")
        self.assertEqual(held["prior_context"],old_context)

    def test_route_withdrawal_serializes_with_dispatch_and_holds_old_work(self):
        withdrawn=dict(self.catalog)
        withdrawn["generation"]=2
        withdrawn["route"]=dict(self.catalog["route"],enabled=False,revision=2)
        sender.replace_catalog(self.catalog_path,withdrawn)
        with patch.object(sender,"post_json") as post:
            result=sender.send_provider(self.loaded,self.journal,self.event)
        records=self.journal._read()["records"]
        self.assertEqual(result["failure_detail"],"submission_uncertain")
        self.assertEqual(post.call_count,0)
        self.assertTrue(any(r["kind"]=="HELD" and r["reason"]=="catalog-or-route-changed-before-dispatch" for r in records))
        self.assertFalse(any(r["kind"]=="SENDING" for r in records))

    def test_catalog_generation_and_privacy_inputs_fail_closed(self):
        newer=dict(self.catalog,generation=2)
        sender.replace_catalog(self.catalog_path,newer)
        with self.assertRaisesRegex(ValueError,"catalog-generation-must-increase"):
            sender.replace_catalog(self.catalog_path,self.catalog)
        unsafe=dict(newer,generation=3,route=dict(newer["route"],
            mentions=["U1> <!channel"],runbook_url="https://operator.invalid/?token=privatevalue"))
        unsafe_path=self.root/"unsafe-catalog.json"
        unsafe_path.write_text(json.dumps(unsafe))
        with self.assertRaisesRegex(ValueError,"catalog-route-invalid"):
            sender.load_catalog(unsafe_path)

    def test_supervisor_journals_fault_and_resumed_sender_sends_then_projects_health(self):
        health=sender.Journal(self.catalog["health_journal"])
        health.append("SENDER_HEALTH_EDGE",{"state":"dead","failure_code":"sender_process_missing",
            "actor":"independent_host_supervisor","deployment_id":"g7-local",
            "subject_id":"host-sender:g7-local:run","producer_id":self.loaded["producer_id"],
            "binding_revision":1,"route_revision":1})
        dead_edge=health._read()["records"][-1]
        api_calls=[]; provider_calls=[]
        def accept(_catalog,path,body):
            api_calls.append((path,body))
            if path.endswith("/delivery"):
                response={"schema_version":1,"status":"projected",
                    "transition_id":body.get("transition_id"),"attempt_id":body["attempt_id"],
                    "outcome":body["outcome"],"idempotent":False,"superseded":False}
                response["transition_id"]=api_calls[-2][1]["transition_id"]
                return 200,response
            return 200,{"schema_version":1,"status":"projected",
                "transition_id":body["transition_id"],
                "transition_sequence":body["transition_sequence"],
                "episode_id":body["episode_id"],"episode_generation":body["episode_generation"],
                "payload_digest":sender.sha(sender.canonical(body))}
        with patch.object(sender,"api_post",side_effect=accept), \
                patch.object(sender,"post_json",side_effect=lambda *a,**k:
                    (provider_calls.append(a[2]) or (200,{"ok":True,"channel":"C_FIXTURE","ts":"1720000000.000001"}))):
            sender.process_health_stream(self.loaded,health)
            health.append("SENDER_HEALTH_EDGE",{"state":"healthy","failure_code":None,
                "actor":"independent_host_supervisor","deployment_id":"g7-local",
                "subject_id":"host-sender:g7-local:run","producer_id":self.loaded["producer_id"],
                "binding_revision":1,"route_revision":1})
            sender.process_health_stream(self.loaded,health)
        records=health._read()["records"]
        intents=[r for r in records if r["kind"]=="HEALTH_TRANSITION_INTENT"]
        self.assertEqual([r["event"]["transition_kind"] for r in intents],["opened","recovered"])
        self.assertEqual(intents[0]["event"]["first_detected_at"],dead_edge["at"])
        self.assertTrue(all(r["event"]["condition"]=="host_sender_health" for r in intents))
        self.assertEqual(len([r for r in records if r["kind"]=="HEALTH_TRANSITION_ACK"]),2)
        self.assertEqual(len(provider_calls),2)
        self.assertEqual(len([r for r in records if r["kind"]=="SENDING"]),2)
        self.assertEqual(len([r for r in records if r["kind"]=="ATTEMPT_OUTCOME"]),2)
        self.assertEqual(len([r for r in records if r["kind"]=="ATTEMPT_ACK"]),2)

    def test_supervisor_only_observes_and_never_calls_sender_transport_or_api(self):
        identity=sender.process_identity(os.getpid())
        Path(self.catalog["journal"]).with_suffix(".pid").write_bytes(
            sender.canonical(identity)+b"\n")
        doc=self.journal._read()
        self.journal.append("SENDER_LOOP_COMPLETED",{'actor':'host_sender',**identity,
            'monotonic_ns':time.monotonic_ns(),'progress_cursor':doc['sequence'],'result_code':0})
        with patch.object(sender,"post_json") as post,patch.object(sender,"api_post") as api:
            self.assertEqual(sender.supervise_once(self.loaded),"healthy")
        records=sender.Journal(self.catalog["health_journal"])._read()["records"]
        self.assertFalse(any(r["kind"] in {"HEALTH_TRANSITION_INTENT","HEALTH_TRANSITION_ACK",
            "SENDING","ATTEMPT_OUTCOME"} for r in records))
        self.assertEqual(post.call_count,0)
        self.assertEqual(api.call_count,0)

    def test_pre_fault_healthy_edge_is_consumed_and_cannot_recover_later_fault(self):
        health=sender.Journal(self.catalog['health_journal'])
        health.ensure_genesis(allow_empty=True,context={'deployment_id':'g7-local','subject_id':'health'})
        health.append('SENDER_HEALTH_EDGE',{'state':'healthy','at':'2026-11-03T00:00:10.000000Z'})
        health.append('SENDER_HEALTH_EDGE',{'state':'dead','at':'2026-11-03T00:00:20.000000Z'})
        with patch.object(sender,'send_provider'),patch.object(sender,'project_pending'):
            sender.process_health_stream(self.loaded,health)
            records=health._read()['records']
            intents=[r for r in records if r['kind']=='HEALTH_TRANSITION_INTENT']
            self.assertEqual([r['event']['transition_kind'] for r in intents],['opened'])
            health.append('SENDER_HEALTH_EDGE',{'state':'healthy','at':'2026-11-03T00:00:30.000000Z'})
            sender.process_health_stream(self.loaded,health)
        intents=[r for r in health._read()['records'] if r['kind']=='HEALTH_TRANSITION_INTENT']
        self.assertEqual([r['event']['transition_kind'] for r in intents],['opened','recovered'])
        self.assertEqual(intents[0]['event']['first_detected_at'],'2026-11-03T00:00:20.000000Z')
        self.assertEqual(intents[1]['event']['recovered_at'],'2026-11-03T00:00:30.000000Z')

    def test_health_sender_resumes_only_persisted_retryable_schedule(self):
        health=sender.Journal(self.catalog['health_journal'])
        health.ensure_genesis(allow_empty=True,context={'deployment_id':'g7-local','subject_id':'health'})
        event={**self.event,'schema_version':1,'transition_id':str(uuid.uuid4()),
            'transition_sequence':1,'predecessor_id':None,'episode_id':str(uuid.uuid4()),
            'opening_transition_id':str(uuid.uuid4()),'episode_generation':1,
            'deployment_id':'g7-local','subject_id':'host-sender:g7-local:run',
            'condition':'host_sender_health','producer_id':self.catalog['producer_id'],
            'configuration_revision':1,'first_detected_at':'2026-11-03T00:00:00.000000Z',
            'observed_at':'2026-11-03T00:00:00.000000Z','recovered_at':None,
            'evidence_refs':['host-supervisor:test']}
        health.append('HEALTH_TRANSITION_INTENT',{'transition_id':event['transition_id'],
            'health_edge_sequence':1,'event':event})
        attempt={'schema_version':1,'attempt_id':str(uuid.uuid4()),'outcome':'failed',
            'attempted_at':event['observed_at'],'receipt_ref':None,'failure_detail':'rate_limited'}
        health.append('ATTEMPT_OUTCOME',{'transition_id':event['transition_id'],'attempt':attempt})
        health.append('RETRY_SCHEDULE',{'transition_id':event['transition_id'],'due_epoch':0,
            'deadline_epoch':time.time()+60,'first_attempt_epoch':time.time()-1,
            'retry_after_seconds':0,'attempt_number':1,'request_digest':'a'*64})
        with patch.object(sender,'send_provider') as send,patch.object(sender,'project_pending'):
            sender.process_health_stream(self.loaded,health)
        self.assertEqual(send.call_count,1)

    def test_supervisor_rejects_live_pid_with_stale_completed_loop(self):
        identity=sender.process_identity(os.getpid())
        Path(self.catalog["journal"]).with_suffix(".pid").write_bytes(
            sender.canonical(identity)+b"\n")
        doc=self.journal._read()
        self.journal.append("SENDER_LOOP_COMPLETED",{'actor':'host_sender',**identity,
            'monotonic_ns':0,'progress_cursor':doc['sequence'],'result_code':0})
        with patch.object(sender,"post_json"),patch.object(sender,"api_post"):
            self.assertEqual(sender.supervise_once(self.loaded),"unhealthy")

    def test_supervisor_uses_independent_health_journal_when_sender_journal_is_corrupt(self):
        identity=sender.process_identity(os.getpid())
        Path(self.catalog["journal"]).with_suffix(".pid").write_bytes(
            sender.canonical(identity)+b"\n")
        Path(self.catalog["journal"]).write_text("{corrupt journal")
        with patch.object(sender,"post_json") as post,patch.object(sender,"api_post") as api:
            self.assertEqual(sender.supervise_once(self.loaded),"unhealthy")
        health=sender.Journal(self.catalog["health_journal"])._read()["records"]
        edge=next(r for r in health if r.get("kind")=="SENDER_HEALTH_EDGE")
        self.assertEqual(edge["state"],"unhealthy")
        self.assertEqual(edge["failure_code"],"sender_journal_invalid")
        self.assertFalse(any(r.get("kind") in {"HEALTH_TRANSITION_INTENT","SENDING","ATTEMPT_OUTCOME"}
            for r in health))
        self.assertEqual(post.call_count,0)
        self.assertEqual(api.call_count,0)

    def test_supervisor_does_not_report_sender_dead_during_pidfile_startup_race(self):
        state=sender.supervise_once(self.loaded)
        self.assertEqual(state,"starting")
        records=sender.Journal(self.catalog["health_journal"])._read()["records"]
        self.assertTrue(any(r["kind"]=="SUPERVISOR_OBSERVATION" and r["state"]=="starting" for r in records))
        self.assertFalse(any(r["kind"] in {"SENDER_HEALTH_EDGE","HEALTH_TRANSITION_INTENT"} for r in records))

    def test_recovery_sample_must_follow_barrier_without_future_clock_skew(self):
        self.assertTrue(sender.causal_sample("1970-01-01T00:01:41.000000Z",100,
            now_epoch=1000,future_skew_seconds=0))
        self.assertFalse(sender.causal_sample("1970-01-01T00:01:40.000000Z",100,
            now_epoch=1000,future_skew_seconds=0))
        self.assertFalse(sender.causal_sample("1970-01-01T00:16:41.000000Z",100,
            now_epoch=1000,future_skew_seconds=0))
        self.assertTrue(sender.causal_sample("1970-01-01T00:16:41.000000Z",100,
            now_epoch=1000,future_skew_seconds=1))
        self.assertFalse(sender.causal_sample("not-a-timestamp",100,now_epoch=1000))


if __name__ == "__main__":
    unittest.main()
