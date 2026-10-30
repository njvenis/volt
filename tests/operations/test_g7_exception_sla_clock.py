"""Focused arithmetic contract for the G7 per atom exception clock."""

import unittest
import uuid
from datetime import datetime, timezone

import sqlalchemy as sa

from uvm.assessment.g7_clock import process_expired_pauses, project_clock
from uvm.assessment.exception_sla import pause_snapshot, state_at
from uvm.persistence.exception_sla_schema import sla_clock_events


UTC = timezone.utc


def instant(hour, minute=0):
    return datetime(2026, 10, 1, hour, minute, tzinfo=UTC)


class ExceptionSlaClockTests(unittest.TestCase):
    def test_late_worker_resumes_from_selected_expiry_and_is_idempotent(self):
        snapshot = pause_snapshot(started_at=instant(8),
            original_deadline_at=instant(10), current_deadline_at=instant(10),
            approved_at=instant(9), expires_at=instant(10), previously_breached=False)
        self.assertEqual(snapshot["remaining_seconds"], 3600)
        before_expiry = state_at(snapshot, instant(9, 59))
        self.assertEqual(before_expiry["state"], "paused")
        at_expiry = state_at(snapshot, instant(10))
        self.assertEqual(at_expiry["state"], "running")
        self.assertEqual(at_expiry["target_at"], instant(11))
        late = state_at(snapshot, instant(12))
        self.assertEqual(late["target_at"], instant(11))
        self.assertTrue(late["currently_breached"])

        events = [{"event_id": "pause", "sequence": 1, "event_type": "paused",
            "effective_at": instant(9), "evaluation_revision": 1,
            "data": {"status": "paused", "expires_at": instant(10),
                "remaining_seconds": 3600}}]
        resumed = project_clock(events, instant(12))
        self.assertEqual(resumed["state"], "running")
        self.assertEqual(resumed["target_at"], instant(11))
        self.assertTrue(resumed["currently_breached"])

    def test_overdue_snapshot_keeps_breach_and_zero_remainder(self):
        snapshot = pause_snapshot(started_at=instant(7),
            original_deadline_at=instant(8), current_deadline_at=instant(8),
            approved_at=instant(9), expires_at=instant(10), previously_breached=True)
        self.assertEqual(snapshot["remaining_seconds"], 0)
        self.assertTrue(snapshot["previously_breached"])
        resumed = state_at(snapshot, instant(10))
        self.assertEqual(resumed["target_at"], instant(10))
        self.assertTrue(resumed["prior_breach"])

    def test_unknown_deadline_stays_a_gap_through_pause_interval(self):
        snapshot = pause_snapshot(started_at=instant(8),
            original_deadline_at=None, current_deadline_at=None,
            approved_at=instant(9), expires_at=instant(10), previously_breached=False)
        self.assertEqual(snapshot["status"], "gap")
        self.assertIsNone(snapshot["remaining_seconds"])
        self.assertEqual(state_at(snapshot, instant(9, 30))["state"], "gap")
        self.assertEqual(state_at(snapshot, instant(11))["state"], "gap")

    def test_exact_deadline_is_not_breached(self):
        snapshot = pause_snapshot(started_at=instant(8),
            original_deadline_at=instant(10), current_deadline_at=instant(10),
            approved_at=instant(9), expires_at=instant(9, 30), previously_breached=False)
        equality = state_at(snapshot, instant(10, 30))
        self.assertEqual(equality["target_at"], instant(10, 30))
        self.assertFalse(equality["currently_breached"])

    def test_expiry_worker_appends_once_using_late_processing_time(self):
        engine = sa.create_engine("sqlite://")
        sla_clock_events.create(engine)
        event_id = str(uuid.uuid4())
        with engine.begin() as connection:
            connection.execute(sla_clock_events.insert().values(
                event_id=event_id, episode_id=str(uuid.uuid4()),
                occurrence_id=str(uuid.uuid4()), sequence=1,
                event_type="paused", effective_at=instant(9), recorded_at=instant(9),
                ingest_receipt_id=None, decision_id=str(uuid.uuid4()),
                membership_ids=["member"], policy_id="fixture", policy_version=1,
                evaluation_revision=1, predecessor_event_id=None,
                data={"expires_at": instant(10).isoformat(), "remaining_seconds": 3600}))

        self.assertEqual(process_expired_pauses(engine, instant(12)), 1)
        self.assertEqual(process_expired_pauses(engine, instant(12)), 0)
        with engine.connect() as connection:
            resumed = connection.execute(sa.select(sla_clock_events).where(
                sla_clock_events.c.event_type == "resumed")).mappings().one()
        self.assertEqual(resumed["effective_at"].replace(tzinfo=UTC), instant(10))
        self.assertEqual(resumed["recorded_at"].replace(tzinfo=UTC), instant(12))
        self.assertEqual(resumed["data"]["resumed_deadline_at"], instant(11).isoformat().replace("+00:00", "Z"))


if __name__ == "__main__":
    unittest.main()
