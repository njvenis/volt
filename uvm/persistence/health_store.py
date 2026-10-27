"""Transactional persistence for independent health checks and delivery outcomes."""
from __future__ import annotations
import uuid
from datetime import datetime, timedelta, timezone
import sqlalchemy as sa
from sqlalchemy.exc import IntegrityError
from uvm.persistence.health_schema import (health_condition_episodes, health_events, health_occurrence_configs, notification_deliveries, notification_intents)
from uvm.persistence.ingestion_schema import collection_runs, collection_schedules, expected_runs
UTC = timezone.utc

def _utc(value, name="timestamp"):
    if value.tzinfo is None or value.utcoffset() is None: raise ValueError(f"{name} must be timezone-aware")
    return value.astimezone(UTC)
def _micros(value): return int(value.total_seconds() * 1_000_000)

class HealthStore:
    def __init__(self, engine): self.engine = engine
    @staticmethod
    def _event_id(): return str(uuid.uuid4())
    @staticmethod
    def _episode_id(): return str(uuid.uuid4())

    def register_occurrence_config(self, *, schedule_id, schedule_revision, source_family, source_account_id, scope_key, anchor_at, effective_from, interval, grace, recorded_at, effective_until=None, notification_deadline=timedelta(hours=1), notification_policy_ref="default"):
        anchor_at, effective_from, recorded_at = _utc(anchor_at, "anchor_at"), _utc(effective_from, "effective_from"), _utc(recorded_at, "recorded_at")
        effective_until = None if effective_until is None else _utc(effective_until, "effective_until")
        if interval <= timedelta(0) or grace < timedelta(0) or notification_deadline <= timedelta(0) or anchor_at < effective_from or (effective_until and effective_until < effective_from): raise ValueError("invalid occurrence configuration")
        values = dict(schedule_id=schedule_id, schedule_revision=schedule_revision, source_family=source_family, source_account_id=source_account_id, scope_key=scope_key, anchor_at=anchor_at, effective_from=effective_from, effective_until=effective_until, interval_microseconds=_micros(interval), grace_microseconds=_micros(grace), notification_deadline_microseconds=_micros(notification_deadline), notification_policy_ref=notification_policy_ref, recorded_at=recorded_at)
        with self.engine.begin() as conn:
            schedule = conn.execute(sa.select(collection_schedules).where(
                collection_schedules.c.schedule_id == schedule_id,
                collection_schedules.c.revision == schedule_revision,
            ).with_for_update()).mappings().first()
            if schedule is None:
                raise ValueError("occurrence configuration schedule does not exist")
            for field in ("source_family", "source_account_id", "scope_key"):
                if schedule[field] != values[field]:
                    raise ValueError("occurrence configuration scope does not match schedule")
            old = conn.execute(sa.select(health_occurrence_configs).where(health_occurrence_configs.c.schedule_id == schedule_id, health_occurrence_configs.c.schedule_revision == schedule_revision).with_for_update()).mappings().first()
            if old:
                if any(old[k] != v for k, v in values.items() if k != "recorded_at"): raise ValueError("occurrence configuration revision is immutable")
                return "duplicate"
            conn.execute(health_occurrence_configs.insert().values(**values))
        return "created"

    def _open_condition(self, conn, *, subject_key, condition, severity, as_of, expected_run_id=None, run_id=None, run_revision=None, evidence=None, notification_deadline_at=None, notification_policy_ref="default"):
        as_of, evidence = _utc(as_of, "as_of"), (evidence or {})
        row = conn.execute(sa.select(health_condition_episodes).where(health_condition_episodes.c.subject_key == subject_key, health_condition_episodes.c.condition == condition, health_condition_episodes.c.state == "open").with_for_update()).mappings().first()
        if row:
            conn.execute(health_condition_episodes.update().where(health_condition_episodes.c.episode_id == row["episode_id"]).values(last_observed_at=as_of, evidence=evidence, expected_run_id=expected_run_id or row["expected_run_id"], run_id=run_id or row["run_id"], run_revision=run_revision or row["run_revision"]))
            return row["episode_id"], False
        episode_id, event_id = self._episode_id(), self._event_id()
        try:
            with conn.begin_nested():
                conn.execute(health_condition_episodes.insert().values(episode_id=episode_id, schema_version=1, subject_key=subject_key, condition=condition, severity=severity, detected_at=as_of, last_observed_at=as_of, recovered_at=None, state="open", expected_run_id=expected_run_id, run_id=run_id, run_revision=run_revision, evidence=evidence))
                conn.execute(health_events.insert().values(event_id=event_id, schema_version=1, episode_id=episode_id, condition=condition, severity=severity, detected_at=as_of, observed_at=as_of, state="open", expected_run_id=expected_run_id, run_id=run_id, run_revision=run_revision, evidence=evidence))
                conn.execute(notification_intents.insert().values(intent_id=self._event_id(), schema_version=1, event_id=event_id, created_at=as_of, state="pending", deadline_at=notification_deadline_at or as_of + timedelta(hours=1), policy_ref=notification_policy_ref))
        except IntegrityError as exc:
            constraint = getattr(getattr(exc, "orig", None), "diag", None)
            constraint = getattr(constraint, "constraint_name", None)
            if constraint not in {"uq_health_condition_active_episode", "uq_health_condition_episodes_subject_key_condition"}:
                raise
            row = conn.execute(sa.select(health_condition_episodes).where(health_condition_episodes.c.subject_key == subject_key, health_condition_episodes.c.condition == condition, health_condition_episodes.c.state == "open").with_for_update()).mappings().first()
            if row is None:
                raise
            conn.execute(health_condition_episodes.update().where(health_condition_episodes.c.episode_id == row["episode_id"]).values(last_observed_at=as_of, evidence=evidence, expected_run_id=expected_run_id or row["expected_run_id"], run_id=run_id or row["run_id"], run_revision=run_revision or row["run_revision"]))
            return row["episode_id"], False
        return episode_id, True

    def _recover_condition(self, conn, *, subject_key, condition, as_of, evidence=None):
        as_of = _utc(as_of, "as_of")
        rows = conn.execute(sa.select(health_condition_episodes).where(health_condition_episodes.c.subject_key == subject_key, health_condition_episodes.c.condition == condition, health_condition_episodes.c.state == "open").with_for_update()).mappings().all()
        for row in rows:
            conn.execute(health_condition_episodes.update().where(health_condition_episodes.c.episode_id == row["episode_id"]).values(state="recovered", recovered_at=as_of, last_observed_at=as_of, evidence=evidence or row["evidence"]))
            conn.execute(health_events.update().where(health_events.c.episode_id == row["episode_id"], health_events.c.state == "open").values(state="recovered"))
        return len(rows)

    def create_notification_intent(self, event_id, *, created_at, deadline_at=None, policy_ref="default"):
        created_at = _utc(created_at, "created_at")
        with self.engine.begin() as conn:
            existing = conn.execute(sa.select(notification_intents.c.intent_id).where(notification_intents.c.event_id == event_id)).scalar_one_or_none()
            if existing: return existing
            intent_id = self._event_id()
            conn.execute(notification_intents.insert().values(intent_id=intent_id, schema_version=1, event_id=event_id, created_at=created_at, state="pending", deadline_at=deadline_at or created_at + timedelta(hours=1), policy_ref=policy_ref))
            return intent_id

    def record_notification_outcome(self, event_id, *, outcome, attempted_at, failure_detail=None, provider_ref=None):
        attempted_at = _utc(attempted_at, "attempted_at")
        if outcome not in {"pending", "delivered", "failed"}: raise ValueError("unknown notification outcome")
        with self.engine.begin() as conn:
            intent = conn.execute(sa.select(notification_intents).where(notification_intents.c.event_id == event_id).with_for_update()).mappings().first()
            if intent is None: raise ValueError("notification intent does not exist")
            parent = conn.execute(sa.select(health_events).where(health_events.c.event_id == event_id)).mappings().one()
            prior = conn.execute(sa.select(notification_deliveries.c.outcome).where(notification_deliveries.c.event_id == event_id)).scalars().all()
            delivery_id = self._event_id()
            conn.execute(notification_deliveries.insert().values(delivery_id=delivery_id, schema_version=1, event_id=event_id, attempted_at=attempted_at, outcome=outcome, failure_detail=failure_detail, provider_ref=provider_ref))
            intent_state = "sent" if outcome == "delivered" or "delivered" in prior else "pending"
            conn.execute(notification_intents.update().where(notification_intents.c.intent_id == intent["intent_id"]).values(state=intent_state))
            subject = f"notification:{event_id}"
            if outcome == "failed" and "delivered" not in prior:
                self._open_condition(conn, subject_key=subject, condition="notification_delivery_failed", severity="critical", as_of=attempted_at, expected_run_id=parent["expected_run_id"], run_id=parent["run_id"], run_revision=parent["run_revision"], evidence={"event_id": event_id, "failure_detail": failure_detail}, notification_deadline_at=intent["deadline_at"], notification_policy_ref=intent["policy_ref"])
            elif outcome == "delivered":
                self._recover_condition(conn, subject_key=subject, condition="notification_delivery_failed", as_of=attempted_at, evidence={"event_id": event_id, "outcome": outcome})
            if "delivered" not in prior and outcome in {"pending", "failed", "delivered"}:
                self._recover_condition(conn, subject_key=f"notification-unattempted:{event_id}", condition="notification_delivery_unattempted_overdue", as_of=attempted_at, evidence={"event_id": event_id, "outcome": outcome})
        return delivery_id

    def _scope_clause(self, source_family, source_account_id, scope_key, table):
        if not all((source_family, source_account_id, scope_key)): raise ValueError("source_family, source_account_id and scope_key are required")
        return sa.or_(table.c.expected_run_id.in_(sa.select(expected_runs.c.expected_run_id).join(collection_schedules, sa.and_(collection_schedules.c.schedule_id == expected_runs.c.schedule_id, collection_schedules.c.revision == expected_runs.c.schedule_revision)).where(collection_schedules.c.source_family == source_family, collection_schedules.c.source_account_id == source_account_id, expected_runs.c.scope_key == scope_key)), sa.exists(sa.select(1).select_from(collection_runs).where(collection_runs.c.run_id == table.c.run_id, collection_runs.c.revision == table.c.run_revision, collection_runs.c.source_family == source_family, collection_runs.c.source_account_id == source_account_id, collection_runs.c.scope_key == scope_key)))

    def list_events(self, *, source_family, source_account_id, scope_key, state=None):
        with self.engine.connect() as conn:
            query = sa.select(health_events).where(self._scope_clause(source_family, source_account_id, scope_key, health_events)).order_by(health_events.c.observed_at)
            if state is not None: query = query.where(health_events.c.state == state)
            return [dict(row) for row in conn.execute(query).mappings()]

    def list_episodes(self, *, source_family, source_account_id, scope_key, state=None):
        with self.engine.connect() as conn:
            query = sa.select(health_condition_episodes).where(self._scope_clause(source_family, source_account_id, scope_key, health_condition_episodes)).order_by(health_condition_episodes.c.detected_at)
            if state is not None: query = query.where(health_condition_episodes.c.state == state)
            return [dict(row) for row in conn.execute(query).mappings()]
