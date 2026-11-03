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
        script=("import json, os, sys, time; from tools.g7_operational_alert_sender import Journal; "
            "Journal(sys.argv[1]).append('SENDING', {'transition_id':sys.argv[3], "
            "'attempt':json.loads(sys.argv[2])}); open(sys.argv[4],'w').write('ready'); time.sleep(30)")
        child=subprocess.Popen([sys.executable,"-c",script,str(self.catalog["journal"]),
            json.dumps(attempt),self.event["transition_id"],str(marker)])
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
        inspected={"state":"unknown","container_id":"container-id",
            "image_id":"sha256:"+"a"*64,"deployment_label":"g7-local",
            "run_label":"run","boot_id":"boot"}
        with patch.object(sender,"inspect_target",return_value=inspected), \
                patch.object(sender,"post_json") as post, \
                patch.object(sender,"api_post") as project:
            sender.run_once(self.loaded)
        records=self.journal._read()["records"]
        outcome=next(r for r in records if r["kind"]=="ATTEMPT_OUTCOME")
        self.assertEqual(outcome["attempt"]["outcome"],"uncertain")
        self.assertEqual(outcome["attempt"]["failure_detail"],"submission_uncertain")
        self.assertEqual(post.call_count,0)
        self.assertEqual(project.call_count,0)

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
        held=records[-1]
        self.assertEqual(held["kind"],"HELD")
        self.assertEqual(held["reason"],"bound-service-context-changed")
        self.assertEqual(held["prior_context"],old_context)

    def test_route_withdrawal_serializes_with_dispatch_and_holds_old_work(self):
        withdrawn=dict(self.catalog)
        withdrawn["route"]=dict(self.catalog["route"],enabled=False,revision=2)
        sender.replace_catalog(self.catalog_path,withdrawn)
        with patch.object(sender,"post_json") as post:
            result=sender.send_provider(self.loaded,self.journal,self.event)
        records=self.journal._read()["records"]
        self.assertEqual(result["failure_detail"],"submission_uncertain")
        self.assertEqual(post.call_count,0)
        self.assertTrue(any(r["kind"]=="HELD" and r["reason"]=="catalog-or-route-changed-before-dispatch" for r in records))
        self.assertFalse(any(r["kind"]=="SENDING" for r in records))

    def test_supervisor_projects_named_health_edges_without_delivery_attempts(self):
        health=sender.Journal(self.catalog["health_journal"])
        health.append("SENDER_HEALTH_EDGE",{"state":"dead","failure_code":"sender_process_missing",
            "actor":"independent_host_supervisor","deployment_id":"g7-local",
            "binding_revision":1,"route_revision":1})
        posted=[]
        def accept(_catalog,path,event):
            self.assertEqual(path,"/api/v1/integrations/incidents")
            posted.append(event)
            ack={"schema_version":1,"status":"projected","transition_id":event["transition_id"],
                "transition_sequence":event["transition_sequence"],"episode_id":event["episode_id"],
                "episode_generation":event["episode_generation"],
                "payload_digest":sender.sha(sender.canonical(event))}
            return 200,ack
        with patch.object(sender,"api_post",side_effect=accept):
            sender.project_supervisor_health(self.loaded,health)
            health.append("SENDER_HEALTH_EDGE",{"state":"healthy","failure_code":None,
                "actor":"independent_host_supervisor","deployment_id":"g7-local",
                "binding_revision":1,"route_revision":1})
            sender.project_supervisor_health(self.loaded,health)
        records=health._read()["records"]
        intents=[r for r in records if r["kind"]=="HEALTH_TRANSITION_INTENT"]
        self.assertEqual([r["event"]["transition_kind"] for r in intents],["opened","recovered"])
        self.assertTrue(all(r["event"]["condition"]=="host_sender_health" for r in intents))
        self.assertEqual(len([r for r in records if r["kind"]=="HEALTH_TRANSITION_ACK"]),2)
        self.assertEqual(len(posted),2)
        self.assertFalse(any(r["kind"] in {"SENDING","ATTEMPT_OUTCOME"} for r in records))

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
