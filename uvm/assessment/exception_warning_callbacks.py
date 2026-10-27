"""Raw-body verification and durable receipt for Slack warning callbacks."""
from __future__ import annotations

import hashlib
import hmac
import json
import re
import time
import uuid
from datetime import datetime, timezone
from urllib.parse import parse_qs

import sqlalchemy as sa

from uvm.persistence.exception_sla_schema import exception_warning_callback_inbox

MAX_CALLBACK_BYTES = 256 * 1024
_SLACK_SIGNATURE = re.compile(r"v0=[0-9a-f]{64}\Z")


class InvalidSlackCallback(ValueError):
    """Malformed, stale or forged callback; no inbox record was written."""


def decode_signed_slack_callback(raw_body: bytes, timestamp: str, signature: str,
                                 signing_secret: str, *, now: float | None = None) -> tuple[dict, str]:
    """Verify Slack's v0 HMAC over bounded raw bytes before decoding form/JSON."""
    if not isinstance(raw_body, bytes) or not 0 < len(raw_body) <= MAX_CALLBACK_BYTES:
        raise InvalidSlackCallback("callback body size is invalid")
    if not isinstance(timestamp, str) or not re.fullmatch(r"[0-9]{1,12}", timestamp):
        raise InvalidSlackCallback("callback timestamp is invalid")
    if not isinstance(signature, str) or not _SLACK_SIGNATURE.fullmatch(signature):
        raise InvalidSlackCallback("callback signature is invalid")
    try:
        parsed_time = int(timestamp)
    except ValueError:
        raise InvalidSlackCallback("callback timestamp is invalid") from None
    if abs((time.time() if now is None else now) - parsed_time) > 300:
        raise InvalidSlackCallback("callback timestamp is stale")
    if not isinstance(signing_secret, str) or not signing_secret:
        raise InvalidSlackCallback("callback signing configuration is unavailable")
    base = b"v0:" + timestamp.encode("ascii") + b":" + raw_body
    expected = "v0=" + hmac.new(signing_secret.encode("utf-8"), base,
        hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, signature):
        raise InvalidSlackCallback("callback signature is invalid")
    try:
        form = parse_qs(raw_body.decode("ascii"), strict_parsing=True,
            keep_blank_values=True, max_num_fields=8)
        payload_values = form.get("payload")
        if set(form) != {"payload"} or payload_values is None or len(payload_values) != 1:
            raise ValueError
        payload = json.loads(payload_values[0])
    except (UnicodeDecodeError, ValueError, json.JSONDecodeError):
        raise InvalidSlackCallback("callback payload is invalid") from None
    if (not isinstance(payload, dict) or not isinstance(payload.get("team"), dict)
            or not isinstance(payload.get("user"), dict)
            or not isinstance(payload.get("actions"), list) or len(payload["actions"]) != 1
            or not isinstance(payload.get("container"), dict)
            or not isinstance(payload.get("message"), dict)):
        raise InvalidSlackCallback("callback interaction shape is invalid")
    action = payload["actions"][0]
    if (not isinstance(action, dict) or action.get("action_id") != "uvm_warning_ack"
            or not all(isinstance(value, str) and value for value in (
                payload["team"].get("id"), payload["user"].get("id"),
                payload["container"].get("channel_id"), payload["message"].get("ts"),
                action.get("value"), payload.get("api_app_id")))):
        raise InvalidSlackCallback("callback action binding is invalid")
    digest = hashlib.sha256(raw_body).hexdigest()
    return payload, digest


def receive_signed_slack_callback(connection, *, raw_body: bytes, timestamp: str,
                                  signature: str, signing_secret: str,
                                  installation_id: str, now: datetime | None = None,
                                  unix_now: float | None = None) -> dict:
    """Insert or read the durable callback inbox row, keyed by signed raw body."""
    payload, digest = decode_signed_slack_callback(raw_body, timestamp, signature,
        signing_secret, now=unix_now)
    if not isinstance(installation_id, str) or not installation_id:
        raise InvalidSlackCallback("callback installation is invalid")
    received_at = now or datetime.now(timezone.utc)
    if received_at.tzinfo is None or received_at.utcoffset() is None:
        raise ValueError("received_at must be timezone-aware")
    row = connection.execute(sa.select(exception_warning_callback_inbox).where(
        exception_warning_callback_inbox.c.installation_id == installation_id,
        exception_warning_callback_inbox.c.body_sha256 == digest
    ).with_for_update()).mappings().one_or_none()
    if row is not None:
        return {"inbox_id": row["inbox_id"], "state": row["state"],
            "duplicate": True, "result": row["result"]}
    inbox_id = str(uuid.uuid4())
    connection.execute(exception_warning_callback_inbox.insert().values(
        inbox_id=inbox_id, installation_id=installation_id, body_sha256=digest,
        payload=payload, state="received", result=None, received_at=received_at,
        processed_at=None))
    return {"inbox_id": inbox_id, "state": "received", "duplicate": False, "result": None}


def process_received_slack_callbacks(engine, *, authority_resolver, installation_id: str,
                                     app_id: str, now: datetime | None = None,
                                     limit: int = 20) -> list[dict]:
    """Apply queued clicks only against current link, route and native authority.

    Inbox state and receipt are committed together. A duplicate delivery sees the
    retained result; it cannot write a second acknowledgement or audit event.
    """
    from uvm.assessment.policy_lock import lock_policy
    from uvm.assessment.api import _complete_target_grants
    from uvm.auth.schema import AUTHORITY_CONTEXT
    from uvm.auth.service import group_scope_covered
    from uvm.persistence.assessment_schema import assessment_group_state, assessment_policy
    from uvm.persistence.exception_sla_schema import exception_warning_actor_links, exception_warning_intents
    from uvm.persistence.schema import exposures, groups, occurrences

    if not 1 <= limit <= 100:
        raise ValueError("callback batch limit must be between 1 and 100")
    now = now or datetime.now(timezone.utc)
    outcomes = []
    for _ in range(limit):
        with engine.begin() as connection:
            lock_policy(connection)
            inbox = connection.execute(sa.select(exception_warning_callback_inbox).where(
                exception_warning_callback_inbox.c.installation_id == installation_id,
                exception_warning_callback_inbox.c.state == "received",
                sa.or_(exception_warning_callback_inbox.c.next_attempt_at.is_(None),
                       exception_warning_callback_inbox.c.next_attempt_at <= now)).order_by(
                    exception_warning_callback_inbox.c.received_at,
                    exception_warning_callback_inbox.c.inbox_id).with_for_update(skip_locked=True)
                .limit(1)).mappings().one_or_none()
            if inbox is None:
                break
            payload = inbox["payload"]
            action = payload["actions"][0]
            team_id, user_id = payload["team"]["id"], payload["user"]["id"]
            channel_id, message_ts = payload["container"]["channel_id"], payload["message"]["ts"]
            token = action["value"]
            link = connection.execute(sa.select(exception_warning_actor_links).where(
                exception_warning_actor_links.c.installation_id == installation_id,
                exception_warning_actor_links.c.workspace_id == team_id,
                exception_warning_actor_links.c.slack_user_id == user_id).order_by(
                    exception_warning_actor_links.c.revision.desc()).limit(1)
                .with_for_update()).mappings().one_or_none()
            intent = connection.execute(sa.select(exception_warning_intents).where(
                exception_warning_intents.c.action_token_hash == hashlib.sha256(
                    token.encode("utf-8")).hexdigest()).with_for_update()).mappings().one_or_none()
            # Slack can deliver a click before the dispatch worker has committed
            # the provider response. Keep that inbox row received; the worker
            # will retry it after the accepted message identity is retained.
            if intent is not None and intent["status"] == "sending":
                break
            result = {"acknowledged": False, "reason": "callback_binding_or_authority_invalid"}
            state = "denied"
            if (payload.get("api_app_id") == app_id and link is not None
                    and link["enabled"] and intent is not None
                    and intent["status"] == "sent" and intent["channel"] == "slack"
                    and intent["provider_receipt_basis"] == "slack_api_accepted"
                    and intent["provider_channel_id"] == channel_id
                    and intent["provider_message_id"] == message_ts
                    and intent["route_revision"] is not None):
                policy_row = connection.execute(sa.select(assessment_policy).where(
                    assessment_policy.c.policy_id == 1).with_for_update()).mappings().one_or_none()
                route = next((item for item in (policy_row["document"].get(
                    "exception_warning_routes", []) if policy_row is not None else [])
                    if item.get("channel") == "slack"
                    and item.get("destination_ref") == intent["destination_ref"]
                    and item.get("recipient_id") == intent["recipient_id"]
                    and item.get("route_id") == intent.get("route_id")
                    and item.get("revision", 1) == intent["route_revision"]
                    and item.get("destination_revision", item.get("revision", 1))
                        == intent.get("destination_revision")
                    and item.get("installation_id") == installation_id
                    and item.get("workspace_id") == team_id
                    and item.get("channel_id") == channel_id
                    and item.get("enabled", True)), None)
                principal = link["principal_id"]
                group_row = None
                if policy_row is not None and route is not None:
                    state_rows = connection.execute(sa.select(assessment_group_state).with_for_update()).mappings().all()
                    for candidate in state_rows:
                        if any(item.get("acceptance_id") == intent["decision_id"]
                                for item in candidate["document"].get("acceptances", [])):
                            group_row = connection.execute(sa.select(groups.c.group_id,
                                groups.c.source_family).select_from(groups.join(exposures,
                                exposures.c.group_id == groups.c.group_id).join(occurrences,
                                occurrences.c.exposure_id == exposures.c.exposure_id)).where(
                                    groups.c.group_id == candidate["group_id"]).limit(1)).mappings().first()
                            if group_row is not None:
                                break
                try:
                    context = (authority_resolver(connection, principal)
                        if link is not None and authority_resolver is not None else None)
                except Exception as exc:
                    # A disabled/revoked actor can never become authorised by
                    # retry. Identity freshness and storage failures can recover.
                    from fastapi import HTTPException
                    error_code = (exc.detail.get("code") if isinstance(exc, HTTPException)
                        and isinstance(exc.detail, dict) else None)
                    error_label = (f"authority_http_{exc.status_code}_{error_code}"
                        if isinstance(exc, HTTPException) else
                        f"authority_{type(exc).__name__}")
                    if isinstance(exc, HTTPException) and exc.status_code in {401, 403}:
                        state = "denied"
                        result = {"acknowledged": False, "reason": "actor_authority_revoked"}
                        connection.execute(exception_warning_callback_inbox.update().where(
                            exception_warning_callback_inbox.c.inbox_id == inbox["inbox_id"]
                        ).values(state=state, result=result, processed_at=now,
                            attempt_count=exception_warning_callback_inbox.c.attempt_count + 1,
                            last_error=(error_label[:200] or "actor_authority_revoked"), next_attempt_at=None))
                        outcomes.append({"inbox_id": inbox["inbox_id"], "state": state, **result})
                        continue
                    delay = min(300, 2 ** min(int(inbox["attempt_count"]), 8))
                    connection.execute(exception_warning_callback_inbox.update().where(
                        exception_warning_callback_inbox.c.inbox_id == inbox["inbox_id"]
                    ).values(attempt_count=exception_warning_callback_inbox.c.attempt_count + 1,
                        next_attempt_at=now + __import__("datetime").timedelta(seconds=delay),
                        last_error=(error_label[:200] or "authority_resolution_temporarily_unavailable")))
                    outcomes.append({"inbox_id": inbox["inbox_id"], "state": "retry", "retry_after_seconds": delay})
                    continue
                token_context = AUTHORITY_CONTEXT.set(context) if context is not None else None
                try:
                    grants = (_complete_target_grants(connection, policy_row["document"], principal,
                        "assessment.read", group_row["group_id"], group_row["source_family"])
                        if policy_row is not None and group_row is not None else [])
                finally:
                    if token_context is not None:
                        AUTHORITY_CONTEXT.reset(token_context)
                scoped = bool(context is not None and grants and group_scope_covered(connection,
                    context, [group_row["group_id"]], granting_identity_groups=[
                        grant.get("principal_id") for grant in grants]))
                if scoped:
                    from uvm.assessment.exception_warning_receipts import acknowledge_warning_receipt
                    retained = acknowledge_warning_receipt(connection,
                        intent_id=intent["intent_id"], principal_id=principal,
                        group_id=group_row["group_id"],
                        policy_revision=int(policy_row["revision"]),
                        authorization_context=context, now=now,
                        origin="slack_signed_callback",
                        evidence_ref="slack_callback:" + inbox["body_sha256"],
                        link_revision=int(link["revision"]))
                    state = "processed"
                    result = {"acknowledged": True, "intent_id": intent["intent_id"],
                        "acknowledged_at": retained["acknowledged_at"].isoformat(),
                        "acknowledged_by": retained["acknowledged_by"], "effect": "receipt_only"}
            connection.execute(exception_warning_callback_inbox.update().where(
                exception_warning_callback_inbox.c.inbox_id == inbox["inbox_id"]).values(
                    state=state, result=result, processed_at=now))
            outcomes.append({"inbox_id": inbox["inbox_id"], "state": state, **result})
    return outcomes
