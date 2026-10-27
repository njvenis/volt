"""Independent expected-run and overdue-run checker (NFR-05)."""
from __future__ import annotations
from datetime import datetime, timedelta, timezone
import sqlalchemy as sa
from sqlalchemy.exc import IntegrityError
from uvm.persistence.health_store import HealthStore, _utc
from uvm.persistence.health_schema import health_events, health_occurrence_configs, notification_deliveries, notification_intents
from uvm.persistence.ingestion_schema import collection_runs, collection_schedules, expected_runs
UTC = timezone.utc

class HealthChecker:
    def __init__(self, engine): self.engine, self.store = engine, HealthStore(engine)

    def _derive(self, conn, as_of):
        """Materialise only explicitly anchored occurrences; uniqueness is the convergence point."""
        for cfg in conn.execute(sa.select(health_occurrence_configs)).mappings():
            interval = timedelta(microseconds=cfg["interval_microseconds"])
            due = cfg["anchor_at"]
            if due < cfg["effective_from"]: due += ((cfg["effective_from"] - due + interval - timedelta(microseconds=1)) // interval) * interval
            while due <= as_of:
                if due >= cfg["effective_from"] and (cfg["effective_until"] is None or due <= cfg["effective_until"]):
                    exists = conn.execute(sa.select(expected_runs.c.expected_run_id).where(expected_runs.c.schedule_id == cfg["schedule_id"], expected_runs.c.schedule_revision == cfg["schedule_revision"], expected_runs.c.due_at == due)).scalar_one_or_none()
                    if exists is None:
                        try:
                            with conn.begin_nested():
                                conn.execute(expected_runs.insert().values(expected_run_id=str(__import__("uuid").uuid4()), schedule_id=cfg["schedule_id"], schedule_revision=cfg["schedule_revision"], scope_key=cfg["scope_key"], due_at=due, grace_deadline=due + timedelta(microseconds=cfg["grace_microseconds"]), state="due", run_id=None))
                        except IntegrityError:
                            pass
                due += interval

    def check(self, *, as_of: datetime):
        as_of = _utc(as_of, "as_of")
        counts = {"missed": 0, "overdue": 0, "recovered": 0}
        with self.engine.begin() as conn:
            self._derive(conn, as_of)
            configs = {(r["schedule_id"], r["schedule_revision"]): r for r in conn.execute(sa.select(health_occurrence_configs)).mappings()}
            expectations = conn.execute(sa.select(expected_runs).where(expected_runs.c.grace_deadline <= as_of).order_by(expected_runs.c.expected_run_id)).mappings().all()
            for expected in expectations:
                cfg = configs.get((expected["schedule_id"], expected["schedule_revision"]))
                subject = f"expected:{expected['schedule_id']}:{expected['schedule_revision']}:{expected['due_at'].isoformat()}"
                if expected["run_id"] is not None:
                    # A claim is permanent, so a claimed expectation needs no
                    # row lock. Locking it would block a later revision's FK
                    # key-share check while that writer holds ROW EXCLUSIVE on
                    # collection_runs, deadlocking with the SHARE lock below.
                    current = expected
                else:
                    # The snapshot may be stale: a claim can commit before we
                    # lock. NO KEY UPDATE still serialises the due -> started
                    # update, but permits a later revision's FK KEY SHARE while
                    # its writer holds ROW EXCLUSIVE on collection_runs. Read
                    # the locked row again before making the missed decision.
                    current = conn.execute(sa.select(expected_runs).where(expected_runs.c.expected_run_id == expected["expected_run_id"]).with_for_update(key_share=True)).mappings().one()
                if current["run_id"] is None and current["state"] == "due":
                    deadline = as_of + timedelta(microseconds=cfg["notification_deadline_microseconds"]) if cfg else as_of + timedelta(hours=1)
                    _, created = self.store._open_condition(conn, subject_key=subject, condition="expected_run_missed", severity="critical", as_of=as_of, expected_run_id=current["expected_run_id"], evidence={"due_at": current["due_at"].isoformat(), "grace_deadline": current["grace_deadline"].isoformat()}, notification_deadline_at=deadline, notification_policy_ref=cfg["notification_policy_ref"] if cfg else "default")
                    counts["missed"] += int(created)
                else:
                    counts["recovered"] += self.store._recover_condition(conn, subject_key=subject, condition="expected_run_missed", as_of=as_of, evidence={"state": current["state"], "run_id": current["run_id"]})
            # Run writers insert revisions under ROW EXCLUSIVE; SHARE waits for
            # in-flight revisions to commit and holds new ones until this
            # transaction ends, so open/recover decisions use the latest
            # committed revision. Taken after unclaimed expected-run row locks,
            # matching the writer's claim-then-insert order.
            if conn.dialect.name == "postgresql":
                conn.execute(sa.text("LOCK TABLE collection_runs IN SHARE MODE"))
            newest = sa.select(collection_runs.c.run_id, sa.func.max(collection_runs.c.revision).label("revision")).group_by(collection_runs.c.run_id).subquery()
            latest = conn.execute(sa.select(collection_runs, collection_schedules.c.total_deadline_microseconds).join(newest, sa.and_(newest.c.run_id == collection_runs.c.run_id, newest.c.revision == collection_runs.c.revision)).join(collection_schedules, sa.and_(collection_schedules.c.schedule_id == collection_runs.c.schedule_id, collection_schedules.c.revision == collection_runs.c.schedule_revision))).mappings().all()
            for run in latest:
                # A run without a start has no overdue deadline, but its latest
                # failed/partial state must still be visible below.
                deadline = None if run["started_at"] is None else run["started_at"] + timedelta(microseconds=run["total_deadline_microseconds"])
                subject = f"run:{run['run_id']}"
                terminal = {"completed", "partial", "failed", "missed"}
                if run["state"] not in terminal and deadline is not None and deadline < as_of:
                    _, created = self.store._open_condition(conn, subject_key=subject, condition="run_overdue", severity="critical", as_of=as_of, run_id=run["run_id"], run_revision=run["revision"], evidence={"deadline": deadline.isoformat(), "state": run["state"], "retrieval_status": run["retrieval_status"], "coverage_status": run["coverage_status"]})
                    counts["overdue"] += int(created)
                else:
                    counts["recovered"] += self.store._recover_condition(conn, subject_key=subject, condition="run_overdue", as_of=as_of, evidence={"state": run["state"], "run_revision": run["revision"], "retrieval_status": run["retrieval_status"], "coverage_status": run["coverage_status"]})
                for failure_state in ("failed", "partial"):
                    failure_condition = f"run_{failure_state}"
                    if run["state"] == failure_state:
                        _, created = self.store._open_condition(conn, subject_key=subject, condition=failure_condition, severity="critical", as_of=as_of, run_id=run["run_id"], run_revision=run["revision"], evidence={"state": run["state"], "run_revision": run["revision"], "retrieval_status": run["retrieval_status"], "coverage_status": run["coverage_status"]})
                        counts["overdue"] += int(created)
                    else:
                        counts["recovered"] += self.store._recover_condition(conn, subject_key=subject, condition=failure_condition, as_of=as_of, evidence={"state": run["state"], "run_revision": run["revision"]})
        return counts

    def watchdog(self, *, as_of: datetime):
        as_of = _utc(as_of, "as_of")
        counts = {"failed": 0, "unattempted_overdue": 0, "recovered": 0}
        with self.engine.begin() as conn:
            intents = conn.execute(sa.select(notification_intents).where(notification_intents.c.state != "cancelled").with_for_update()).mappings().all()
            for intent in intents:
                parent = conn.execute(sa.select(health_events).where(health_events.c.event_id == intent["event_id"])).mappings().one()
                deliveries = conn.execute(sa.select(notification_deliveries).where(notification_deliveries.c.event_id == intent["event_id"])).mappings().all()
                outcomes = {d["outcome"] for d in deliveries}
                if "delivered" in outcomes:
                    counts["recovered"] += self.store._recover_condition(conn, subject_key=f"notification-unattempted:{intent['event_id']}", condition="notification_delivery_unattempted_overdue", as_of=as_of, evidence={"event_id": intent["event_id"], "outcome": "delivered"})
                    counts["recovered"] += self.store._recover_condition(conn, subject_key=f"notification:{intent['event_id']}", condition="notification_delivery_failed", as_of=as_of, evidence={"event_id": intent["event_id"], "outcome": "delivered"})
                elif "failed" in outcomes:
                    _, created = self.store._open_condition(conn, subject_key=f"notification:{intent['event_id']}", condition="notification_delivery_failed", severity="critical", as_of=as_of, expected_run_id=parent["expected_run_id"], run_id=parent["run_id"], run_revision=parent["run_revision"], evidence={"event_id": intent["event_id"], "outcome": "failed"}, notification_deadline_at=intent["deadline_at"], notification_policy_ref=intent["policy_ref"])
                    counts["recovered"] += self.store._recover_condition(conn, subject_key=f"notification-unattempted:{intent['event_id']}", condition="notification_delivery_unattempted_overdue", as_of=as_of, evidence={"event_id": intent["event_id"], "outcome": "failed"})
                    counts["failed"] += int(created)
                elif deliveries:
                    counts["recovered"] += self.store._recover_condition(conn, subject_key=f"notification-unattempted:{intent['event_id']}", condition="notification_delivery_unattempted_overdue", as_of=as_of, evidence={"event_id": intent["event_id"], "outcome": "pending"})
                elif not deliveries and intent["deadline_at"] < as_of:
                    _, created = self.store._open_condition(conn, subject_key=f"notification-unattempted:{intent['event_id']}", condition="notification_delivery_unattempted_overdue", severity="critical", as_of=as_of, expected_run_id=parent["expected_run_id"], run_id=parent["run_id"], run_revision=parent["run_revision"], evidence={"event_id": intent["event_id"], "deadline_at": intent["deadline_at"].isoformat()}, notification_deadline_at=as_of + timedelta(hours=1), notification_policy_ref=intent["policy_ref"])
                    counts["unattempted_overdue"] += int(created)
        return counts
