"""Exercise G7 incident authorization, validation and disclosure at real API handlers."""
from datetime import datetime, timedelta, timezone
import hashlib
import json
import tempfile
import unittest
import uuid
import urllib.error
from unittest.mock import patch

import sqlalchemy as sa
from fastapi import HTTPException
from starlette.requests import Request


class IncidentPublicHandlerTests(unittest.TestCase):
    def setUp(self):
        from uvm.persistence.schema import uvm_metadata
        from uvm.persistence.assessment_schema import assessment_policy
        from uvm.persistence.incident_schema import (g7_incident_service_bindings,
            g7_incident_streams, g7_incident_transitions, g7_incident_projection_receipts,
            g7_incident_notification_intents, g7_incident_notification_attempts,
            g7_incident_routes)
        from uvm.persistence.observer_settings_schema import (g7_observer_settings_revisions,
            g7_observer_status)
        self.engine = sa.create_engine("sqlite://")
        self.tables = (assessment_policy, g7_incident_service_bindings, g7_incident_streams,
            g7_incident_transitions, g7_incident_projection_receipts,
            g7_incident_notification_intents, g7_incident_notification_attempts,
            g7_incident_routes, g7_observer_settings_revisions, g7_observer_status)
        for table in self.tables:
            table.create(self.engine, checkfirst=True)
        self.policy_table = assessment_policy
        self.binding = g7_incident_service_bindings
        self.streams = g7_incident_streams
        self.transitions = g7_incident_transitions
        self.receipts = g7_incident_projection_receipts
        self.intents = g7_incident_notification_intents
        self.attempts = g7_incident_notification_attempts
        self.routes = g7_incident_routes
        self.revisions = g7_observer_settings_revisions
        self.status = g7_observer_status
        self.now = datetime.now(timezone.utc).replace(microsecond=0)
        self.deployment, self.other_deployment = "g7-test", "g7-other"
        self.subject, self.producer, self.service = "container:test", "host-sender/v1", "sender"
        self.group, self.reader = "recipient", "alice"
        self.source = ("scanner-x", "account-x", "scope-x")
        values = {"observation_interval_seconds": 10, "request_deadline_seconds": 5,
            "heartbeat_freshness_seconds": 30, "maximum_future_skew_seconds": 60,
            "anchor_export_lag_seconds": 20, "incident_projection_deadline_seconds": 30,
            "scheduler_progress_freshness_seconds": 30}
        digest = hashlib.sha256(json.dumps(values, sort_keys=True,
            separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()
        bounds = {key: {"min": 0 if key == "maximum_future_skew_seconds" else 1,
            "max": 100} for key in values}
        policy = {"principals": {self.reader: {"enabled": True}}, "denies": [],
            "native_authority": {"mode": "uvm_native_v1", "revision": 1,
                "access_groups": {self.group: {"enabled": True,
                    "source_scopes": [dict(zip(("source_family", "source_account_id", "scope_key"), self.source))],
                    "memberships": [{"principal_id": self.reader,
                        "effective_from": "2020-01-01T00:00:00Z", "enabled": True}],
                    "permissions": [{"permission_id": "health-read", "role_id": "reader",
                        "action": "integration.health.read",
                        "target_scope": {"group_ids": ["*"], "source_families": [self.source[0]]}}]}}}}
        with self.engine.begin() as cx:
            cx.execute(self.policy_table.insert().values(policy_id=1, revision=1,
                document=policy, updated_at=self.now, updated_by="test"))
            cx.execute(self.binding.insert().values(principal_id=self.service,
                deployment_id=self.deployment, subject_id=self.subject,
                condition="container_availability", subject_type="container",
                producer_id=self.producer, producer_revision=1,
                configuration_revision=1, enabled=True))
            cx.execute(self.revisions.insert().values(deployment_id=self.deployment,
                revision=1, values=values, digest=digest, command_id=str(uuid.uuid4()),
                actor_id="test", action="configure", copied_from_revision=None,
                rationale="test", evidence_ref=None, created_at=self.now))
            cx.execute(self.status.insert().values(deployment_id=self.deployment,
                effective_revision=1, effective_digest=digest, application_status="applied",
                latest_report_sequence=1, host_policy_revision=1, host_policy_bounds=bounds,
                host_policy_digest="a" * 64, host_policy_key_id="local-test-key",
                host_policy_observed_at=self.now, host_policy_freshness_seconds=3600))
            cx.execute(self.routes.insert().values(route_id="route-a", revision=1,
                deployment_id=self.deployment, subject_id=self.subject,
                recipient_access_group_id=self.group, vulnerability_group_id=None,
                source_family=self.source[0], source_account_id=self.source[1],
                scope_key=self.source[2], enabled=True))
        from uvm.api.app import create_app
        self.app = create_app(self.engine, principals={
            self.service: {"token": "sender-token", "scopes": (self.source,),
                "actor_kind": "service", "origin": "host_sender",
                "role_ids": ("integration.incident.submit",)},
            "wrong-role": {"token": "wrong-token", "scopes": (self.source,),
                "actor_kind": "service", "origin": "host_sender", "role_ids": ("audit.read",)},
            self.reader: {"token": "reader-token", "scopes": (self.source,)},
        }, cursor_secret="incident-handler-test-secret", utc_now=lambda: self.now)
        self.post_route = next(r for r in self.app.routes if getattr(r, "path", None) ==
            "/api/v1/integrations/incidents" and "POST" in getattr(r, "methods", set()))
        self.post = self.post_route.endpoint
        self.delivery = next(r for r in self.app.routes if getattr(r, "path", None) == "/api/v1/integrations/incidents/{transition_id}/delivery").endpoint
        self.get = next(r for r in self.app.routes if getattr(r, "path", None) ==
            "/api/v1/integrations/incidents" and "GET" in getattr(r, "methods", set())).endpoint

    def tearDown(self):
        self.engine.dispose()

    def event(self, *, sequence=1, predecessor=None, deployment=None, tid=None, schema_version=1):
        tid = tid or str(uuid.uuid4())
        stamp = self.now.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        return {"schema_version": schema_version, "deployment_id": deployment or self.deployment,
            "subject_id": self.subject, "condition": "container_availability",
            "transition_id": tid, "transition_sequence": sequence,
            "predecessor_id": predecessor, "episode_id": str(uuid.uuid4()),
            "opening_transition_id": tid if sequence == 1 else str(uuid.uuid4()),
            "episode_generation": 1, "transition_kind": "opened",
            "configuration_revision": 1, "first_detected_at": stamp,
            "observed_at": stamp, "recovered_at": None,
            "evidence_refs": ["host-inspection:test"], "producer_id": self.producer}

    def counts(self):
        with self.engine.connect() as cx:
            return tuple(cx.execute(sa.select(sa.func.count()).select_from(t)).scalar_one()
                for t in (self.streams, self.transitions, self.receipts, self.intents, self.attempts))

    def row_snapshot(self):
        with self.engine.connect() as cx:
            return tuple(tuple(repr(dict(row._mapping)) for row in cx.execute(sa.select(table)).all())
                for table in self.tables)

    def test_public_post_requires_exact_role_and_live_binding_without_writes(self):
        event = self.event()
        before = self.counts()
        for principal in ("forged", "wrong-role"):
            with self.subTest(principal=principal), self.assertRaises(HTTPException) as denied:
                self.post(event, principal=principal)
            self.assertEqual(denied.exception.status_code, 403)
            self.assertEqual(self.counts(), before)
        with self.engine.begin() as cx:
            cx.execute(self.binding.update().values(enabled=False))
        with self.assertRaises(HTTPException) as denied:
            self.post(event, principal=self.service)
        self.assertEqual(denied.exception.status_code, 403)
        self.assertEqual(self.counts(), before)

    def test_http_bearer_auth_rejects_forged_token_and_wrong_role(self):
        event = self.event()
        before = self.counts()
        authenticate = self.post_route.dependant.dependencies[0].call
        request = Request({"type": "http", "method": "POST",
            "path": "/api/v1/integrations/incidents", "query_string": b"",
            "headers": [], "scheme": "http", "server": ("test", 80),
            "client": ("127.0.0.1", 1), "root_path": "", "app": self.app})
        with self.assertRaises(HTTPException) as forged:
            authenticate(request, authorization="Bearer forged-token")
        self.assertEqual(forged.exception.status_code, 401)
        wrong_role = authenticate(request, authorization="Bearer wrong-token")
        with self.assertRaises(HTTPException) as denied:
            self.post(event, principal=wrong_role)
        self.assertEqual(denied.exception.status_code, 403)
        self.assertEqual(self.counts(), before)
        with self.engine.begin() as cx:
            cx.execute(self.binding.update().values(enabled=True, producer_id="reassigned/v2",
                producer_revision=2, configuration_revision=2))
        with self.assertRaises(HTTPException) as denied:
            self.post(event, principal=self.service)
        self.assertEqual(denied.exception.status_code, 403)
        self.assertEqual(self.counts(), before)

    def test_public_post_rejects_cross_deployment_gap_changed_id_and_bad_schema_atomically(self):
        before = self.counts(); content_before = self.row_snapshot()
        future = self.event()
        future["observed_at"] = "2027-01-01T00:00:00.000000Z"
        malformed_ref = self.event()
        malformed_ref["evidence_refs"] = ["x" * 1001]
        for index,event in enumerate((self.event(deployment=self.other_deployment),
                self.event(sequence=2), self.event(schema_version=True), future, malformed_ref)):
            with self.subTest(event=event), self.assertRaises(HTTPException) as denied:
                self.post(event, principal=self.service)
            if index==0:
                self.assertEqual(denied.exception.status_code,403)
                self.assertEqual(denied.exception.detail['code'],'incident_ingestion_forbidden')
            elif index==1:
                self.assertEqual(denied.exception.status_code,409)
                self.assertTrue(denied.exception.detail['details']['retryable'])
                self.assertIn('retryable stream gap',denied.exception.detail['message'])
            else:
                self.assertEqual(denied.exception.status_code,409)
            self.assertEqual(self.counts(), before)
            self.assertEqual(self.row_snapshot(),content_before)
        accepted = self.event()
        # Drop the first handler result to model a lost API acknowledgement.
        self.post(accepted, principal=self.service)
        stable = self.counts()
        replay = self.post(accepted, principal=self.service)
        self.assertEqual(replay["status"], "projected")
        self.assertEqual(self.counts(), stable)
        changed = dict(accepted, evidence_refs=["host-inspection:changed"])
        with self.assertRaises(HTTPException) as denied:
            self.post(changed, principal=self.service)
        self.assertEqual(denied.exception.status_code, 409)
        self.assertEqual(self.counts(), stable)

    def test_public_delivery_rejects_future_attempt_and_exact_id_content_change_without_writes(self):
        event = self.event()
        self.post(event, principal=self.service)
        before = self.counts()
        attempt_id = str(uuid.uuid4())
        observed = datetime.fromisoformat(event["observed_at"].replace("Z", "+00:00"))
        attempt = {"schema_version": 1, "attempt_id": attempt_id, "outcome": "failed",
            "attempted_at": "2027-01-01T00:00:00.000000Z", "receipt_ref": None,
            "failure_detail": "provider_unavailable"}
        with self.assertRaises(HTTPException):
            self.delivery(event["transition_id"], attempt, principal=self.service)
        self.assertEqual(self.counts(), before)
        attempt["attempted_at"] = self.now.isoformat()
        with self.assertRaises(HTTPException):
            self.delivery(event["transition_id"], attempt, principal=self.service)
        self.assertEqual(self.counts(), before)
        attempt["attempted_at"] = event["observed_at"]
        self.delivery(event["transition_id"], attempt, principal=self.service)
        stable = self.counts()
        replay = self.delivery(event["transition_id"], attempt, principal=self.service)
        self.assertTrue(replay["idempotent"])
        self.assertEqual(self.counts(), stable)
        changed = dict(attempt, outcome="uncertain", failure_detail="submission_uncertain")
        with self.assertRaises(HTTPException):
            self.delivery(event["transition_id"], changed, principal=self.service)
        self.assertEqual(self.counts(), stable)
        accepted = {"schema_version": 1, "attempt_id": str(uuid.uuid4()),
            "outcome": "accepted", "attempted_at": (observed + timedelta(seconds=1)).strftime(
                "%Y-%m-%dT%H:%M:%S.%fZ"),
            "receipt_ref": "fixture-receipt-1", "failure_detail": None}
        self.delivery(event["transition_id"], accepted, principal=self.service)
        terminal = {"schema_version": 1, "attempt_id": str(uuid.uuid4()),
            "outcome": "failed", "attempted_at": (observed + timedelta(seconds=2)).strftime(
                "%Y-%m-%dT%H:%M:%S.%fZ"),
            "receipt_ref": None, "failure_detail": "provider_rejected"}
        terminal_counts = self.counts()
        with self.assertRaises(HTTPException):
            self.delivery(event["transition_id"], terminal, principal=self.service)
        self.assertEqual(self.counts(), terminal_counts)

    def test_real_sender_catches_up_lost_transition_and_delivery_acks_without_new_ids(self):
        from tools import g7_operational_alert_sender as sender
        event=self.event(); digest=sender.sha(sender.canonical(event))
        from tests.operations.test_g7_operational_alert_sender import OperationalAlertSenderTests
        fixture=OperationalAlertSenderTests();fixture.setUp()
        try:
            self._exercise_real_sender_catchup(sender,event,digest,fixture.journal,fixture.loaded,fixture.inspected)
        finally:
            fixture.doCleanups();fixture.tearDown()

    def _exercise_real_sender_catchup(self,sender,event,digest,journal,config,inspection):
        journal.append('TRANSITION_INTENT',{'transition_id':event['transition_id'],
            'event':event,'payload_digest':digest,'context':sender.bound_context(config,inspection)})
        attempt={'schema_version':1,'attempt_id':str(uuid.uuid4()),'outcome':'failed',
            'attempted_at':event['observed_at'],'receipt_ref':None,'failure_detail':'provider_rejected'}
        journal.append('ATTEMPT_OUTCOME',{'transition_id':event['transition_id'],'attempt':attempt})
        transition_calls=0; delivery_calls=0
        def real_endpoint(c,path,body):
            nonlocal transition_calls,delivery_calls
            if path=='/api/v1/integrations/incidents':
                transition_calls+=1; result=self.post(body,principal=self.service)
                if transition_calls==1: raise urllib.error.URLError('simulated lost transition ACK')
                return 200,result
            delivery_calls+=1; result=self.delivery(event['transition_id'],body,principal=self.service)
            if delivery_calls==1: raise urllib.error.URLError('simulated lost delivery ACK')
            return 200,result
        with patch.object(sender,'api_post',side_effect=real_endpoint):
            sender.project_pending(config,journal,journal._read()['records'])
            sender.project_pending(config,journal,journal._read()['records'])
            sender.project_pending(config,journal,journal._read()['records'])
        records=journal._read()['records']
        self.assertEqual(transition_calls,2)
        self.assertEqual(delivery_calls,2)
        self.assertEqual(sum(r['kind']=='TRANSITION_INTENT' for r in records),1)
        self.assertEqual(sum(r['kind']=='ATTEMPT_OUTCOME' for r in records),1)
        self.assertEqual(sum(r['kind']=='TRANSITION_ACK' for r in records),1)
        self.assertEqual(sum(r['kind']=='ATTEMPT_ACK' for r in records),1)
        self.assertEqual(self.counts(),(1,1,1,1,1))

    def test_failed_delivery_with_receipt_is_rejected_without_row_mutation(self):
        event = self.event()
        self.post(event, principal=self.service)
        before = self.counts()
        invalid = {"schema_version": 1, "attempt_id": str(uuid.uuid4()),
            "outcome": "failed", "attempted_at": event["observed_at"],
            "receipt_ref": "provider:unexpected", "failure_detail": "provider_rejected"}
        with self.assertRaises(HTTPException) as denied:
            self.delivery(event["transition_id"], invalid, principal=self.service)
        self.assertEqual(denied.exception.status_code, 409)
        self.assertEqual(self.counts(), before)

    def test_last_good_effective_timing_remains_usable_during_failed_desired_apply(self):
        with self.engine.begin() as cx:
            cx.execute(self.status.update().values(application_status="failed"))
        result = self.post(self.event(), principal=self.service)
        self.assertEqual(result["status"], "projected")

    def test_pending_and_uncertain_desired_status_use_only_fresh_coherent_effective_timing(self):
        for state in ("pending", "uncertain"):
            with self.subTest(state=state):
                with self.engine.begin() as cx:
                    effective_digest=cx.execute(sa.select(self.revisions.c.digest).where(
                        self.revisions.c.deployment_id==self.deployment)).scalar_one()
                    cx.execute(self.status.update().values(application_status=state,
                        effective_revision=1, effective_digest=effective_digest,
                        host_policy_observed_at=self.now))
                from uvm.assessment.incidents import verified_future_skew
                self.assertEqual(verified_future_skew(self.engine,self.deployment,self.now),60)
        with self.engine.begin() as cx:
            cx.execute(self.status.update().values(application_status="pending"))
        self.assertEqual(self.post(self.event(),principal=self.service)["status"],"projected")
        with self.engine.begin() as cx:
            cx.execute(self.status.update().values(application_status="pending",
                host_policy_observed_at=self.now-timedelta(hours=2)))
        before=self.counts()
        with self.assertRaises(HTTPException) as denied:
            self.post(self.event(),principal=self.service)
        self.assertEqual(denied.exception.status_code,409)
        self.assertEqual(self.counts(),before)

    def test_public_get_requires_membership_grant_and_exact_source_route(self):
        event = self.event()
        self.post(event, principal=self.service)
        request = Request({"type": "http", "method": "GET",
            "path": "/api/v1/integrations/incidents", "query_string": b"",
            "headers": [], "scheme": "http", "server": ("test", 80),
            "client": ("127.0.0.1", 1), "root_path": "", "app": self.app})
        self.assertEqual(len(self.get(request, limit=50, offset=0, deployment_id=None,
            group_id=None, principal=self.reader)["items"]), 1)
        with self.engine.begin() as cx:
            policy = cx.execute(sa.select(self.policy_table.c.document)).scalar_one()
            # Membership without the complete health-read grant is insufficient.
            policy["native_authority"]["access_groups"][self.group]["permissions"] = []
            cx.execute(self.policy_table.update().where(self.policy_table.c.policy_id == 1)
                .values(document=policy, revision=2))
        self.assertEqual(self.get(request, limit=50, offset=0, deployment_id=None,
            group_id=None, principal=self.reader)["items"], [])
        with self.engine.begin() as cx:
            policy = cx.execute(sa.select(self.policy_table.c.document)).scalar_one()
            policy["native_authority"]["access_groups"][self.group]["permissions"] = [{
                "permission_id": "health-read", "role_id": "reader",
                "action": "integration.health.read",
                "target_scope": {"group_ids": ["*"], "source_families": ["wrong-source"]}}]
            cx.execute(self.policy_table.update().where(self.policy_table.c.policy_id == 1)
                .values(document=policy, revision=3))
        self.assertEqual(self.get(request, limit=50, offset=0, deployment_id=None,
            group_id=None, principal=self.reader)["items"], [])
        with self.engine.begin() as cx:
            policy = cx.execute(sa.select(self.policy_table.c.document)).scalar_one()
            group = policy["native_authority"]["access_groups"][self.group]
            group["permissions"] = [{"permission_id": "health-read", "role_id": "reader",
                "action": "integration.health.read",
                "target_scope": {"group_ids": ["*"], "source_families": [self.source[0]]}}]
            policy["denies"] = [{"principal_id": self.reader,
                "actions": ["integration.health.read"], "target_ids": ["*"]}]
            cx.execute(self.policy_table.update().where(self.policy_table.c.policy_id == 1)
                .values(document=policy, revision=4))
        self.assertEqual(self.get(request, limit=50, offset=0, deployment_id=None,
            group_id=None, principal=self.reader)["items"], [])
        with self.engine.begin() as cx:
            policy = cx.execute(sa.select(self.policy_table.c.document)).scalar_one()
            policy["denies"] = []
            policy["native_authority"]["access_groups"][self.group]["memberships"][0]["enabled"] = False
            cx.execute(self.policy_table.update().where(self.policy_table.c.policy_id == 1)
                .values(document=policy, revision=5))
        self.assertEqual(self.get(request, limit=50, offset=0, deployment_id=None,
            group_id=None, principal=self.reader)["items"], [])
        with self.engine.begin() as cx:
            policy = cx.execute(sa.select(self.policy_table.c.document)).scalar_one()
            group = policy["native_authority"]["access_groups"][self.group]
            group["memberships"][0]["enabled"] = True
            group["source_scopes"] = []
            # The membership and route grant are deliberately split across groups.
            policy["native_authority"]["access_groups"]["scope-only"] = {
                "enabled": True,
                "source_scopes": [dict(zip(("source_family", "source_account_id", "scope_key"), self.source))],
                "memberships": [{"principal_id": self.reader,
                    "effective_from": "2020-01-01T00:00:00Z", "enabled": True}],
                "permissions": []}
            cx.execute(self.policy_table.update().where(self.policy_table.c.policy_id == 1)
                .values(document=policy, revision=6))
        self.assertEqual(self.get(request, limit=50, offset=0, deployment_id=None,
            group_id=None, principal=self.reader)["items"], [])
        with self.engine.begin() as cx:
            policy = cx.execute(sa.select(self.policy_table.c.document)).scalar_one()
            policy["native_authority"]["access_groups"][self.group]["source_scopes"] = [
                dict(zip(("source_family", "source_account_id", "scope_key"), self.source))]
            cx.execute(self.policy_table.update().where(self.policy_table.c.policy_id == 1)
                .values(document=policy, revision=7))
        with self.engine.begin() as cx:
            cx.execute(self.routes.update().values(source_family="wrong-source"))
        self.assertEqual(self.get(request, limit=50, offset=0, deployment_id=None,
            group_id=None, principal=self.reader)["items"], [])
        self.assertEqual(self.get(request, limit=50, offset=0,
            deployment_id=self.other_deployment, group_id=None,
            principal=self.reader)["items"], [])
        with self.engine.begin() as cx:
            cx.execute(self.routes.update().values(source_family=self.source[0], enabled=False))
        self.assertEqual(self.get(request, limit=50, offset=0, deployment_id=None,
            group_id=None, principal=self.reader)["items"], [])


if __name__ == "__main__":
    unittest.main()
