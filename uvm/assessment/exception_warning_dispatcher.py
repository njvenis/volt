"""Bounded durable dispatcher. Ambiguous sends remain uncertain and are never retried."""
from __future__ import annotations

import uuid
import hashlib
import json
import secrets
from datetime import datetime, timedelta, timezone
import time

import sqlalchemy as sa

from uvm.assessment.exception_notifications import dispatch_eligibility, suppress_intent
from uvm.assessment.policy_lock import lock_policy
from uvm.assessment.exception_warning_transports import DeliveryError, DeliveryUncertain, adapter_for
from uvm.persistence.exception_sla_schema import exception_warning_attempts, exception_warning_intents

UTC = timezone.utc


def dispatch_due(engine, *, now: datetime | None = None, limit: int = 20,
                 authority_resolver=None, fixture_adapter=None,
                 intent_ids: list[str] | None = None) -> list[dict]:
    """Dispatch at most ``limit`` due channel intents; each send is independently durable."""
    if not 1 <= limit <= 100:
        raise ValueError("dispatch limit must be between 1 and 100")
    now = now or datetime.now(UTC)
    batch_monotonic = time.monotonic()
    with engine.begin() as connection:
        predicates = [
            sa.or_(exception_warning_intents.c.status == "pending",
                sa.and_(exception_warning_intents.c.status == "failed",
                    exception_warning_intents.c.suppression_reason.is_(None))),
            sa.or_(exception_warning_intents.c.next_attempt_at.is_(None),
                   exception_warning_intents.c.next_attempt_at <= now),
            exception_warning_intents.c.due_at <= now]
        if intent_ids is not None:
            if not intent_ids:
                return []
            predicates.append(exception_warning_intents.c.intent_id.in_(intent_ids))
        due_ids = list(connection.execute(sa.select(exception_warning_intents.c.intent_id).where(
            *predicates
        ).order_by(exception_warning_intents.c.due_at,
                   exception_warning_intents.c.created_at,
                   exception_warning_intents.c.intent_id).limit(limit)).scalars())
    results = []
    for intent_id in due_ids:
        claimed = None
        with engine.begin() as connection:
            # Serialize route/recipient revocation against the authorization
            # snapshot committed with this claim; never hold the lock in I/O.
            lock_policy(connection, shared=True)
            intent = connection.execute(sa.select(exception_warning_intents).where(
                exception_warning_intents.c.intent_id == intent_id).with_for_update()).mappings().one_or_none()
            if intent is None or intent["status"] not in {"pending", "failed"}:
                continue
            # Sample only after obtaining the row lock. Waiting on a concurrent
            # claimant must not let a send begin after the effective expiry.
            claim_now = now + timedelta(seconds=max(0.0, time.monotonic() - batch_monotonic))
            authority_snapshot = {}
            allowed, reason = dispatch_eligibility(connection, intent, claim_now,
                authority_resolver=authority_resolver, authority_snapshot=authority_snapshot,
                require_approved_snapshot=fixture_adapter is None)
            if not allowed:
                if reason == "not_due":
                    continue
                results.append(suppress_intent(connection, intent_id, reason=reason, now=claim_now))
                continue
            count = connection.execute(sa.select(sa.func.count()).select_from(
                exception_warning_attempts).where(exception_warning_attempts.c.intent_id == intent_id)).scalar_one()
            if count >= intent["max_attempts"]:
                connection.execute(exception_warning_intents.update().where(
                    exception_warning_intents.c.intent_id == intent_id).values(
                        status="failed", next_attempt_at=None, updated_at=claim_now,
                        suppression_reason="retry_limit_reached"))
                results.append({"intent_id": intent_id, "status": "failed", "reason": "retry_limit_reached"})
                continue
            attempt_id = str(uuid.uuid4())
            action_token = (intent.get("action_token") or secrets.token_urlsafe(32)) \
                if intent["channel"] == "slack" else None
            action_token_hash = (hashlib.sha256(action_token.encode()).hexdigest()
                if action_token else None)
            payload = {"intent_id": intent_id, "decision_id": intent["decision_id"],
                "expiry_revision": intent["expiry_revision"], "offset_seconds": intent["offset_seconds"],
                "warning": "exception_expiry_approaching", "action_token": action_token,
                "route_revision": intent.get("route_revision"),
                "approved_destination": intent.get("approved_destination")}
            approved = intent.get("approved_destination")
            if not approved and fixture_adapter is not None:
                approved = {"channel": intent["channel"],
                    "destination_ref": intent["destination_ref"],
                    "expires_at": (intent["due_at"] + timedelta(seconds=intent["offset_seconds"])).isoformat(),
                    "link": "https://uvm.example.test/assessment/exception-warnings",
                    "usergroup_ids": []}
            expiry_dt = datetime.fromisoformat(approved["expires_at"].replace("Z", "+00:00")).astimezone(UTC)
            expiry_display = expiry_dt.strftime("%Y-%m-%d %H:%M UTC")
            link = approved.get("link")
            if not isinstance(link, str) or not link.startswith("https://"):
                if fixture_adapter is None:
                    results.append(suppress_intent(connection, intent_id,
                        reason="approved_uvm_link_unavailable", now=claim_now))
                    continue
                link = "https://uvm.example.test/assessment/exception-warnings"
                approved = {**approved, "link": link}
            rendered = {"subject": "UVM exception expiry approaching", "expiry_utc": expiry_display,
                "text": f"An approved exception expires at {expiry_display}. Review it in UVM: {link}",
                "html": f'<p>An approved exception expires at {expiry_display}.</p><p><a href="{link}">Open UVM to review it</a></p>',
                "link": link, "usergroup_ids": approved.get("usergroup_ids", [])}
            payload["rendered"] = rendered
            rendered_digest = hashlib.sha256(json.dumps(rendered, sort_keys=True,
                separators=(",", ":")).encode()).hexdigest()
            payload["rendered_digest"] = rendered_digest
            payload["approved_destination"] = approved
            payload_digest = hashlib.sha256(json.dumps(payload, sort_keys=True,
                separators=(",", ":")).encode()).hexdigest()
            connection.execute(exception_warning_intents.update().where(
                exception_warning_intents.c.intent_id == intent_id).values(
                    action_token=action_token, action_token_hash=action_token_hash,
                    payload_digest=payload_digest, rendered_payload=rendered,
                    rendered_digest=rendered_digest, template_version="g7-warning-v1"))
            connection.execute(exception_warning_attempts.insert().values(
                attempt_id=attempt_id, intent_id=intent_id, attempt_number=count + 1,
                attempted_at=claim_now, outcome="sending",
                evaluated_policy_revision=authority_snapshot.get("policy_revision"),
                evaluated_group_revision=authority_snapshot.get("group_revision"),
                evaluated_route_revision=authority_snapshot.get("route_revision"),
                evaluated_link_revision=authority_snapshot.get("link_revision"),
                evaluated_recipient_revision=authority_snapshot.get("recipient_revision")))
            connection.execute(exception_warning_intents.update().where(
                exception_warning_intents.c.intent_id == intent_id).values(
                    status="sending", next_attempt_at=None, updated_at=claim_now,
                    suppression_reason=None))
            claimed = dict(intent)
            claimed["attempt_id"] = attempt_id
            claimed["action_token"] = action_token
            claimed["approved_destination"] = approved
            claimed["rendered_payload"] = rendered
            claimed["rendered_digest"] = rendered_digest
        if claimed is None:
            continue
        payload = {"intent_id": intent_id, "decision_id": claimed["decision_id"],
            "expiry_revision": claimed["expiry_revision"], "offset_seconds": claimed["offset_seconds"],
            "warning": "exception_expiry_approaching", "action_token": claimed["action_token"],
            "route_revision": claimed.get("route_revision"),
            "approved_destination": claimed.get("approved_destination"),
            "rendered": claimed.get("rendered_payload"),
            "rendered_digest": claimed.get("rendered_digest")}
        delivery_error = None
        try:
            receipt = adapter_for(claimed, fixture_adapter).send(channel=claimed["channel"],
                destination_ref=claimed["destination_ref"], payload=payload)
            outcome, error = "sent", None
        except DeliveryUncertain as exc:
            outcome, receipt, error = "uncertain", None, str(exc)
        except DeliveryError as exc:
            delivery_error = exc
            outcome, receipt, error = "failed", None, str(exc)
        except Exception as exc:  # unknown adapter failure can occur after a send
            outcome, receipt, error = "uncertain", None, f"adapter outcome uncertain ({type(exc).__name__})"
        finished = datetime.now(UTC)
        receipt_basis = None
        provider_channel_id = provider_message_id = None
        if outcome == "sent" and isinstance(receipt, str):
            parts = receipt.split("|", 2)
            if len(parts) == 3 and parts[0] in {"slack_api_accepted", "smtp_accepted"}:
                receipt_basis = parts[0]
                if parts[0] == "slack_api_accepted":
                    provider_channel_id, provider_message_id = parts[1], parts[2]
                else:
                    provider_message_id = parts[2]
        with engine.begin() as connection:
            permanent = delivery_error.permanent if delivery_error is not None else False
            retry_after = delivery_error.retry_after_seconds if delivery_error is not None else None
            connection.execute(exception_warning_attempts.update().where(
                exception_warning_attempts.c.attempt_id == claimed["attempt_id"]).values(
                    outcome=outcome, receipt=receipt, error=(error or "")[:1000] or None,
                    finished_at=finished))
            next_attempt = None
            exhausted = outcome == "failed" and count + 1 >= claimed["max_attempts"]
            if outcome == "failed" and not permanent and not exhausted:
                delay = retry_after if retry_after is not None else min(
                    claimed["retry_base_seconds"] * (2 ** count), 3600)
                next_attempt = finished + timedelta(seconds=max(1, min(int(delay), 3600)))
            suppression_reason = ("permanent_delivery_rejection" if permanent else
                "retry_limit_reached" if exhausted else
                "uncertain_delivery_reconcile_before_retry" if outcome == "uncertain" else None)
            connection.execute(exception_warning_intents.update().where(
                exception_warning_intents.c.intent_id == intent_id).values(
                    status=outcome, next_attempt_at=next_attempt, updated_at=finished,
                    provider_receipt_basis=receipt_basis,
                    provider_channel_id=provider_channel_id,
                    provider_message_id=provider_message_id,
                    suppression_reason=suppression_reason))
            if outcome in {"failed", "uncertain"}:
                from uvm.persistence.assessment_schema import assessment_group_state
                from uvm.persistence.exception_sla_schema import exception_warning_failure_alerts
                for state in connection.execute(sa.select(assessment_group_state)).mappings():
                    if any(item.get("acceptance_id") == claimed["decision_id"]
                            for item in state["document"].get("acceptances", [])):
                        existing = connection.execute(sa.select(exception_warning_failure_alerts.c.alert_id)
                            .where(exception_warning_failure_alerts.c.attempt_id == claimed["attempt_id"])
                            .limit(1)).scalar_one_or_none()
                        if existing is None:
                            connection.execute(exception_warning_failure_alerts.insert().values(
                                alert_id=str(uuid.uuid4()), intent_id=intent_id,
                                attempt_id=claimed["attempt_id"], group_id=state["group_id"],
                                reason=suppression_reason or "transient_delivery_failure",
                                created_at=finished))
                        break
        results.append({"intent_id": intent_id, "attempt_id": claimed["attempt_id"],
            "status": outcome, "next_attempt_at": next_attempt.isoformat() if next_attempt else None})
    return results


def mark_orphaned_sends_uncertain(engine, *, before: datetime) -> int:
    """A process restart cannot determine whether an interrupted request reached its recipient."""
    with engine.begin() as connection:
        finished = datetime.now(UTC)
        attempts = list(connection.execute(sa.select(exception_warning_attempts).where(
            exception_warning_attempts.c.outcome == "sending",
            exception_warning_attempts.c.attempted_at < before).with_for_update()).mappings())
        for attempt in attempts:
            intent = connection.execute(sa.select(exception_warning_intents).where(
                exception_warning_intents.c.intent_id == attempt["intent_id"])
                .with_for_update()).mappings().one_or_none()
            connection.execute(exception_warning_attempts.update().where(
                exception_warning_attempts.c.attempt_id == attempt["attempt_id"]).values(
                    outcome="uncertain", error="dispatcher stopped during send; reconcile before retry",
                    finished_at=finished))
            connection.execute(exception_warning_intents.update().where(
                exception_warning_intents.c.intent_id == attempt["intent_id"],
                exception_warning_intents.c.status == "sending").values(
                status="uncertain", updated_at=finished))
            if intent is not None:
                from uvm.persistence.assessment_schema import assessment_group_state
                from uvm.persistence.exception_sla_schema import exception_warning_failure_alerts
                for state in connection.execute(sa.select(assessment_group_state).with_for_update()).mappings():
                    if any(item.get("acceptance_id") == intent["decision_id"]
                            for item in state["document"].get("acceptances", [])):
                        connection.execute(exception_warning_failure_alerts.insert().values(
                            alert_id=str(uuid.uuid4()), intent_id=intent["intent_id"],
                            attempt_id=attempt["attempt_id"], group_id=state["group_id"],
                            reason="orphaned_send_outcome_uncertain", created_at=finished))
                        break
        return len(attempts)


def warning_health_snapshot(engine, *, now: datetime | None = None,
                            overdue_after_seconds: int = 900,
                            abandoned_after_seconds: int = 60) -> dict:
    """Report worker backlog and durable-failure alert integrity separately from liveness."""
    from uvm.persistence.exception_sla_schema import exception_warning_failure_alerts
    now = now or datetime.now(UTC)
    if not 1 <= overdue_after_seconds <= 86400 or not 1 <= abandoned_after_seconds <= 3600:
        raise ValueError("warning health thresholds are out of bounds")
    with engine.connect() as connection:
        overdue = connection.execute(sa.select(sa.func.count()).select_from(
            exception_warning_intents).where(
                exception_warning_intents.c.status == "pending",
                exception_warning_intents.c.due_at < now - timedelta(seconds=overdue_after_seconds))).scalar_one()
        abandoned = connection.execute(sa.select(sa.func.count()).select_from(
            exception_warning_attempts).where(
                exception_warning_attempts.c.outcome == "sending",
                exception_warning_attempts.c.attempted_at < now - timedelta(seconds=abandoned_after_seconds))).scalar_one()
        missing_alert = connection.execute(sa.select(sa.func.count()).select_from(
            exception_warning_attempts.outerjoin(exception_warning_failure_alerts,
                exception_warning_failure_alerts.c.attempt_id == exception_warning_attempts.c.attempt_id)
            ).where(exception_warning_attempts.c.outcome.in_(["failed", "uncertain"]),
                exception_warning_failure_alerts.c.alert_id.is_(None))).scalar_one()
    result = {"overdue_intents": int(overdue), "abandoned_attempts": int(abandoned),
        "missing_failure_alerts": int(missing_alert)}
    result["status"] = "degraded" if any((overdue, abandoned, missing_alert)) else "healthy"
    return result
