"""Public v1 incident validation and attempt ordering regressions."""
from datetime import datetime, timedelta, timezone
import unittest
import uuid

import sqlalchemy as sa


class OperationalIncidentValidationTests(unittest.TestCase):
    def setUp(self):
        from uvm.persistence.incident_schema import (
            g7_incident_service_bindings, g7_incident_streams, g7_incident_transitions,
            g7_incident_projection_receipts, g7_incident_notification_intents,
            g7_incident_notification_attempts,
        )
        self.engine = sa.create_engine("sqlite://")
        for table in (g7_incident_service_bindings, g7_incident_streams,
                g7_incident_transitions, g7_incident_projection_receipts,
                g7_incident_notification_intents, g7_incident_notification_attempts):
            table.create(self.engine)
        self.tables = (g7_incident_service_bindings, g7_incident_streams,
            g7_incident_transitions, g7_incident_projection_receipts,
            g7_incident_notification_intents, g7_incident_notification_attempts)
        self.now = datetime(2026, 11, 2, 20, 0, 0, tzinfo=timezone.utc)
        self.principal = "host-sender"
        self.deployment = "local-test"
        self.subject = "container:test"
        self.producer = "host-sender/v1"
        with self.engine.begin() as cx:
            cx.execute(self.tables[0].insert().values(principal_id=self.principal,
                deployment_id=self.deployment, subject_id=self.subject,
                condition="container_availability", subject_type="container",
                producer_id=self.producer, producer_revision=1,
                configuration_revision=1, enabled=True))

    def tearDown(self):
        self.engine.dispose()

    def transition(self, *, schema=1, observed=None):
        from uvm.assessment.incidents import TRANSITION_FIELDS
        tid = str(uuid.uuid4())
        stamp = (observed or self.now).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        event = {"schema_version": schema, "deployment_id": self.deployment,
            "subject_id": self.subject, "condition": "container_availability",
            "transition_id": tid, "transition_sequence": 1, "predecessor_id": None,
            "episode_id": str(uuid.uuid4()), "opening_transition_id": tid,
            "episode_generation": 1, "transition_kind": "opened",
            "configuration_revision": 1, "first_detected_at": stamp,
            "observed_at": stamp, "recovered_at": None, "evidence_refs": ["host-inspection:abc"],
            "producer_id": self.producer}
        self.assertEqual(set(event), TRANSITION_FIELDS)
        return tid, event

    def test_json_boolean_schema_version_is_rejected(self):
        from uvm.assessment.incidents import IncidentConflict, ingest_transition
        _, event = self.transition(schema=True)
        with self.assertRaises(IncidentConflict):
            ingest_transition(self.engine, self.principal, event, now=self.now)

    def test_unhashable_enum_values_are_validation_conflicts(self):
        from uvm.assessment.incidents import IncidentConflict, ingest_transition, ingest_delivery_outcome
        _, event = self.transition()
        event["condition"] = ["container_availability"]
        with self.assertRaises(IncidentConflict):
            ingest_transition(self.engine, self.principal, event, now=self.now)
        _, event = self.transition()
        event["transition_kind"] = []
        with self.assertRaises(IncidentConflict):
            ingest_transition(self.engine, self.principal, event, now=self.now)
        attempt = {"schema_version": 1, "attempt_id": str(uuid.uuid4()), "outcome": [],
            "attempted_at": self.now.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
            "receipt_ref": None, "failure_detail": ["provider_rejected"]}
        with self.assertRaises(IncidentConflict):
            ingest_delivery_outcome(self.engine, self.principal, str(uuid.uuid4()), attempt,
                now=self.now)

    def test_attempt_replay_is_exact_and_new_attempts_are_ordered(self):
        from uvm.assessment.incidents import IncidentConflict, ingest_delivery_outcome, ingest_transition
        transition_id, event = self.transition()
        ingest_transition(self.engine, self.principal, event, now=self.now)
        first = {"schema_version": 1, "attempt_id": str(uuid.uuid4()),
            "outcome": "failed", "attempted_at": event["observed_at"],
            "receipt_ref": None, "failure_detail": "provider_unavailable"}
        first_at = self.now + timedelta(seconds=1)
        accepted = ingest_delivery_outcome(self.engine, self.principal, transition_id,
            first, now=first_at)
        self.assertFalse(accepted["idempotent"])
        replay = ingest_delivery_outcome(self.engine, self.principal, transition_id,
            first, now=first_at)
        self.assertTrue(replay["idempotent"])
        second = {"schema_version": 1, "attempt_id": str(uuid.uuid4()),
            "outcome": "accepted", "attempted_at": (self.now + timedelta(seconds=2)).strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
            "receipt_ref": "fixture-accept-001", "failure_detail": None}
        ingest_delivery_outcome(self.engine, self.principal, transition_id, second,
            now=self.now + timedelta(seconds=3))
        stale = {"schema_version": 1, "attempt_id": str(uuid.uuid4()),
            "outcome": "failed", "attempted_at": (self.now + timedelta(seconds=4)).strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
            "receipt_ref": None, "failure_detail": "provider_rejected"}
        with self.assertRaises(IncidentConflict):
            ingest_delivery_outcome(self.engine, self.principal, transition_id, stale,
                now=self.now + timedelta(seconds=5))

    def test_attempt_timestamp_must_be_canonical_and_failure_code_registered(self):
        from uvm.assessment.incidents import IncidentConflict, ingest_delivery_outcome, ingest_transition
        transition_id, event = self.transition()
        ingest_transition(self.engine, self.principal, event, now=self.now)
        bad = {"schema_version": 1, "attempt_id": str(uuid.uuid4()),
            "outcome": "failed", "attempted_at": self.now.isoformat(),
            "receipt_ref": None, "failure_detail": "provider said password is secret"}
        with self.assertRaises(IncidentConflict):
            ingest_delivery_outcome(self.engine, self.principal, transition_id, bad,
                now=self.now + timedelta(seconds=1))


if __name__ == "__main__":
    unittest.main()
