"""Serialised, idempotent projection of external G7 incident transitions."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import json
import re
import uuid

import sqlalchemy as sa
from sqlalchemy.engine import Engine

from uvm.persistence.incident_schema import (g7_incident_service_bindings,
    g7_incident_streams, g7_incident_transitions,
    g7_incident_projection_receipts, g7_incident_notification_intents,
    g7_incident_notification_attempts)
from uvm.persistence.observer_settings_schema import (
    g7_observer_settings_revisions, g7_observer_status)

UTC = timezone.utc
DELIVERY_FAILURES = frozenset({"provider_rejected", "rate_limited", "provider_unavailable",
    "transport_pre_submit", "response_invalid", "submission_uncertain",
    "local_persistence_failed"})
INCIDENT_CONDITIONS = frozenset({"source_integrity", "siem_integrity", "siem_export",
    "container_availability", "observer_heartbeat", "notification_failure",
    "incident_projection", "host_sender_health"})
TRANSITION_FIELDS = frozenset({"schema_version", "deployment_id", "subject_id",
    "condition", "transition_id", "transition_sequence", "predecessor_id",
    "episode_id", "opening_transition_id", "episode_generation", "transition_kind",
    "configuration_revision", "first_detected_at", "observed_at", "recovered_at",
    "evidence_refs", "producer_id"})


class IncidentConflict(ValueError):
    """A stale, forked, incomplete or conflicting journal transition."""


class IncidentForbidden(PermissionError):
    """The current service identity is not bound to this stream."""


def _uuid(value, label, *, nullable=False):
    if nullable and value is None:
        return None
    try:
        parsed = uuid.UUID(value)
    except (ValueError, TypeError, AttributeError):
        raise IncidentConflict(f"{label} must be a canonical UUID") from None
    if str(parsed) != value:
        raise IncidentConflict(f"{label} must be a canonical UUID")
    return value


def _timestamp(value, label, *, nullable=False, canonical_utc=False):
    if nullable and value is None:
        return None
    if not isinstance(value, str):
        raise IncidentConflict(f"{label} must be an RFC 3339 timestamp")
    if canonical_utc and not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z", value):
        raise IncidentConflict(f"{label} must use canonical UTC microsecond precision")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise IncidentConflict(f"{label} must be an RFC 3339 timestamp") from None
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise IncidentConflict(f"{label} must include a timezone")
    return parsed.astimezone(UTC)


def _digest(payload: dict) -> str:
    body = json.dumps(payload, ensure_ascii=False, sort_keys=True,
        separators=(",", ":"), allow_nan=False).encode("utf-8")
    return hashlib.sha256(body).hexdigest()


def verified_future_skew(engine: Engine, deployment_id: str, now: datetime) -> int:
    """Read only the exact deployment's still-current, verified applied timing revision."""
    from uvm.operations.observer_settings import validate_timing_values, ObserverSettingsError
    with engine.begin() as connection:
        status = connection.execute(sa.select(g7_observer_status).where(
            g7_observer_status.c.deployment_id == deployment_id)).mappings().first()
        if (status is None or status["application_status"] not in
                {"pending", "applied", "failed", "uncertain"}
                or type(status["effective_revision"]) is not int
                or not status["effective_digest"] or not status["host_policy_revision"]
                or not status["host_policy_digest"] or not status["host_policy_key_id"]
                or not isinstance(status["host_policy_bounds"], dict)
                or status["host_policy_observed_at"] is None
                or type(status["host_policy_freshness_seconds"]) is not int
                or status["host_policy_freshness_seconds"] <= 0):
            raise IncidentConflict("exact deployment timing authority is unavailable")
        observed = status["host_policy_observed_at"]
        if observed.tzinfo is None:
            observed = observed.replace(tzinfo=UTC)
        age = (now.astimezone(UTC) - observed.astimezone(UTC)).total_seconds()
        if age < 0 or age > status["host_policy_freshness_seconds"]:
            raise IncidentConflict("exact deployment host timing authority is stale")
        revision = connection.execute(sa.select(g7_observer_settings_revisions).where(
            g7_observer_settings_revisions.c.deployment_id == deployment_id,
            g7_observer_settings_revisions.c.revision == status["effective_revision"]
        )).mappings().first()
        if revision is None or revision["digest"] != status["effective_digest"]:
            raise IncidentConflict("exact deployment effective timing revision is inconsistent")
        try:
            values = validate_timing_values(revision["values"], status["host_policy_bounds"])
        except (ObserverSettingsError, TypeError) as exc:
            raise IncidentConflict("exact deployment timing bounds are invalid") from exc
        if hashlib.sha256(json.dumps(values, sort_keys=True, separators=(",", ":"),
                ensure_ascii=False, allow_nan=False).encode("utf-8")).hexdigest() != revision["digest"]:
            raise IncidentConflict("exact deployment timing digest is inconsistent")
        return values["maximum_future_skew_seconds"]


def _validate_shape(payload: dict, now: datetime, future_skew_seconds: int = 0) -> dict:
    if not isinstance(payload, dict) or set(payload) != TRANSITION_FIELDS:
        raise IncidentConflict("incident transition fields do not match g7-operations-incident/v1")
    if type(payload["schema_version"]) is not int or payload["schema_version"] != 1:
        raise IncidentConflict("unsupported incident transition schema")
    for name in ("deployment_id", "subject_id", "condition", "producer_id"):
        if not isinstance(payload[name], str) or not payload[name] or len(payload[name]) > 200:
            raise IncidentConflict(f"{name} is invalid")
    if not isinstance(payload["condition"], str) or payload["condition"] not in INCIDENT_CONDITIONS:
        raise IncidentConflict("incident condition is not registered")
    for name in ("transition_id", "episode_id", "opening_transition_id"):
        _uuid(payload[name], name)
    _uuid(payload["predecessor_id"], "predecessor_id", nullable=True)
    if type(payload["transition_sequence"]) is not int or payload["transition_sequence"] < 1:
        raise IncidentConflict("transition_sequence must be a positive integer")
    if type(payload["episode_generation"]) is not int or payload["episode_generation"] < 1:
        raise IncidentConflict("episode_generation must be a positive integer")
    if type(payload["configuration_revision"]) is not int or payload["configuration_revision"] < 1:
        raise IncidentConflict("configuration_revision must be a positive integer")
    if (not isinstance(payload["transition_kind"], str)
            or payload["transition_kind"] not in {"opened", "observed", "recovered"}):
        raise IncidentConflict("transition_kind is invalid")
    if (not isinstance(payload["evidence_refs"], list) or len(payload["evidence_refs"]) > 100
            or any(not isinstance(item, str) or not item or len(item) > 1000
                   for item in payload["evidence_refs"])):
        raise IncidentConflict("evidence_refs must be a bounded list of non-empty strings")
    first = _timestamp(payload["first_detected_at"], "first_detected_at")
    observed = _timestamp(payload["observed_at"], "observed_at")
    recovered = _timestamp(payload["recovered_at"], "recovered_at", nullable=True)
    latest = now.astimezone(UTC) + timedelta(seconds=future_skew_seconds)
    if (first > observed or observed > latest
            or (recovered and (recovered < observed or recovered > latest))):
        raise IncidentConflict("incident timestamps are not causally ordered or are future-dated")
    if (payload["transition_kind"] == "recovered") != (recovered is not None):
        raise IncidentConflict("only a recovery transition may carry recovered_at")
    return {**payload, "first_detected_at": first, "observed_at": observed,
        "recovered_at": recovered, "payload_digest": _digest(payload)}


def _lock_key(deployment_id: str, subject_id: str, condition: str) -> int:
    raw = f"g7-incident-stream\0{deployment_id}\0{subject_id}\0{condition}".encode()
    return int.from_bytes(hashlib.sha256(raw).digest()[:8], "big", signed=True)


def ingest_transition(engine: Engine, principal_id: str, payload: dict, *,
                      now: datetime | None = None, future_skew_seconds: int = 0) -> dict:
    """Apply one authorised contiguous journal transition in a single commit."""
    now = (now or datetime.now(UTC)).astimezone(UTC)
    if type(future_skew_seconds) is not int or not 0 <= future_skew_seconds <= 86400:
        raise IncidentConflict("trusted future timestamp allowance is invalid")
    event = _validate_shape(payload, now, future_skew_seconds)
    stream_key = (event["deployment_id"], event["subject_id"], event["condition"])
    with engine.begin() as connection:
        if connection.dialect.name == "postgresql":
            connection.execute(sa.text("SELECT pg_advisory_xact_lock(:key)"),
                               {"key": _lock_key(*stream_key)})
        binding = connection.execute(sa.select(g7_incident_service_bindings).where(
            g7_incident_service_bindings.c.principal_id == principal_id,
            g7_incident_service_bindings.c.deployment_id == event["deployment_id"],
            g7_incident_service_bindings.c.subject_id == event["subject_id"],
            g7_incident_service_bindings.c.condition == event["condition"],
            g7_incident_service_bindings.c.enabled.is_(True)).with_for_update()).mappings().first()
        if (binding is None or binding["producer_id"] != event["producer_id"]
                or int(binding["configuration_revision"]) != event["configuration_revision"]):
            raise IncidentForbidden("current incident service binding does not authorise this stream")

        prior = connection.execute(sa.select(g7_incident_projection_receipts).where(
            g7_incident_projection_receipts.c.transition_id == event["transition_id"])
            .with_for_update()).mappings().first()
        if prior is not None:
            if prior["payload_digest"] != event["payload_digest"]:
                raise IncidentConflict("transition ID is already bound to different content")
            return dict(prior["result"])

        stream = connection.execute(sa.select(g7_incident_streams).where(
            g7_incident_streams.c.deployment_id == event["deployment_id"],
            g7_incident_streams.c.subject_id == event["subject_id"],
            g7_incident_streams.c.condition == event["condition"])
            .with_for_update()).mappings().first()
        last_sequence = int(stream["last_sequence"]) if stream else 0
        last_id = stream["last_transition_id"] if stream else None
        expected_sequence = last_sequence + 1
        if event["transition_sequence"] != expected_sequence or event["predecessor_id"] != last_id:
            raise IncidentConflict(f"retryable stream gap: expected sequence {expected_sequence} "
                                   f"after {last_id or 'null'}")
        if stream is not None and last_id is not None:
            prior_transition = connection.execute(sa.select(g7_incident_transitions.c.observed_at)
                .where(g7_incident_transitions.c.transition_id == last_id)).scalar_one_or_none()
            if prior_transition is None:
                raise IncidentConflict("current stream head has no retained predecessor")
            if prior_transition.tzinfo is None:
                prior_transition = prior_transition.replace(tzinfo=UTC)
            if event["observed_at"] <= prior_transition.astimezone(UTC):
                raise IncidentConflict("new transition observation must follow its predecessor")

        kind = event["transition_kind"]
        if stream is None:
            if (kind != "opened" or event["episode_generation"] != 1
                    or event["predecessor_id"] is not None
                    or event["opening_transition_id"] != event["transition_id"]):
                raise IncidentConflict("first stream transition must open generation 1")
            active_episode = None
            generation = 0
        elif stream["producer_id"] != event["producer_id"]:
            # A replacement producer resumes an existing stream only after a
            # current binding revision has advanced, fencing the old producer.
            if event["configuration_revision"] <= int(stream["producer_revision"]):
                raise IncidentForbidden("stale producer is fenced from this stream")
            active_episode = stream["active_episode_id"]
            generation = int(stream["episode_generation"])
        else:
            active_episode = stream["active_episode_id"]
            generation = int(stream["episode_generation"])

        opening_id = event["opening_transition_id"]
        if kind == "opened":
            if active_episode is not None or event["episode_generation"] != generation + 1:
                raise IncidentConflict("opening transition does not start the next episode generation")
            if opening_id != event["transition_id"]:
                raise IncidentConflict("opening transition must name itself as its opening ID")
            active_episode = event["episode_id"]
            generation = event["episode_generation"]
        else:
            if active_episode is None or event["episode_id"] != active_episode:
                raise IncidentConflict("transition does not name the active episode")
            if event["episode_generation"] != generation:
                raise IncidentConflict("transition episode generation is stale")
            opening = connection.execute(sa.select(g7_incident_transitions).where(
                g7_incident_transitions.c.transition_id == opening_id,
                g7_incident_transitions.c.episode_id == active_episode,
                g7_incident_transitions.c.transition_kind == "opened")).mappings().first()
            opening_detected = opening["first_detected_at"] if opening else None
            if opening_detected is not None and opening_detected.tzinfo is None:
                opening_detected = opening_detected.replace(tzinfo=UTC)
            if opening is None or opening_detected.astimezone(UTC) != event["first_detected_at"]:
                raise IncidentConflict("transition does not reference the active opening transition")
            if kind == "recovered":
                active_episode = None

        # A producer reassignment bumps the binding revision. It starts a new
        # producer fence without resetting stream order or episode generation.
        if stream is None:
            connection.execute(g7_incident_streams.insert().values(
                deployment_id=event["deployment_id"], subject_id=event["subject_id"],
                condition=event["condition"], last_sequence=0,
                last_transition_id=None, active_episode_id=None, episode_generation=0,
                producer_id=event["producer_id"], producer_revision=event["configuration_revision"],
                updated_at=now))
        connection.execute(g7_incident_transitions.insert().values(
            transition_id=event["transition_id"], deployment_id=event["deployment_id"],
            subject_id=event["subject_id"], condition=event["condition"],
            transition_sequence=event["transition_sequence"], predecessor_id=event["predecessor_id"],
            episode_id=event["episode_id"], opening_transition_id=opening_id,
            episode_generation=event["episode_generation"], transition_kind=kind,
            configuration_revision=event["configuration_revision"],
            first_detected_at=event["first_detected_at"], observed_at=event["observed_at"],
            recovered_at=event["recovered_at"], evidence_refs=event["evidence_refs"],
            payload_digest=event["payload_digest"], producer_id=event["producer_id"]))
        values = {"last_sequence": event["transition_sequence"],
            "last_transition_id": event["transition_id"],
            "active_episode_id": active_episode, "episode_generation": generation,
            "producer_id": event["producer_id"],
            "producer_revision": event["configuration_revision"], "updated_at": now}
        if stream is None:
            connection.execute(g7_incident_streams.update().where(
                g7_incident_streams.c.deployment_id == event["deployment_id"],
                g7_incident_streams.c.subject_id == event["subject_id"],
                g7_incident_streams.c.condition == event["condition"]).values(**values))
        else:
            connection.execute(g7_incident_streams.update().where(
                g7_incident_streams.c.deployment_id == event["deployment_id"],
                g7_incident_streams.c.subject_id == event["subject_id"],
                g7_incident_streams.c.condition == event["condition"]).values(**values))
        result = {"schema_version": 1, "status": "projected",
            "transition_id": event["transition_id"],
            "transition_sequence": event["transition_sequence"],
            "episode_id": event["episode_id"], "episode_generation": generation,
            "payload_digest": event["payload_digest"]}
        connection.execute(g7_incident_projection_receipts.insert().values(
            transition_id=event["transition_id"], payload_digest=event["payload_digest"],
            received_at=now, result=result))
        connection.execute(g7_incident_notification_intents.insert().values(
            transition_id=event["transition_id"], state="pending", created_at=now,
            updated_at=now, receipt_basis=event["transition_id"]))
        return result


def ingest_delivery_outcome(engine: Engine, principal_id: str, transition_id: str,
                            payload: dict, *, now: datetime | None = None,
                            future_skew_seconds: int = 0) -> dict:
    """Project an external delivery attempt into the UVM intent idempotently."""
    if not isinstance(payload, dict) or set(payload) != {
            "schema_version", "attempt_id", "outcome", "attempted_at",
            "receipt_ref", "failure_detail"} or type(payload["schema_version"]) is not int or payload["schema_version"] != 1:
        raise IncidentConflict("delivery outcome fields do not match g7-incident-delivery/v1")
    _uuid(transition_id, "transition_id")
    _uuid(payload["attempt_id"], "attempt_id")
    if not isinstance(payload["outcome"], str) or payload["outcome"] not in {"accepted", "failed", "uncertain"}:
        raise IncidentConflict("delivery outcome is invalid")
    attempted_at = _timestamp(payload["attempted_at"], "attempted_at", canonical_utc=True)
    if type(future_skew_seconds) is not int or not 0 <= future_skew_seconds <= 86400:
        raise IncidentConflict("trusted future timestamp allowance is invalid")
    receipt = payload["receipt_ref"]
    failure = payload["failure_detail"]
    if receipt is not None and (not isinstance(receipt, str)
            or re.fullmatch(r"[A-Za-z0-9._:-]{1,256}", receipt) is None):
        raise IncidentConflict("receipt_ref must be a sanitized opaque provider reference")
    if failure is not None and (not isinstance(failure, str) or failure not in DELIVERY_FAILURES):
        raise IncidentConflict("failure_detail is not a registered failure code")
    if payload["outcome"] == "accepted" and not payload["receipt_ref"]:
        raise IncidentConflict("accepted delivery requires its provider receipt")
    if payload["outcome"] == "accepted" and failure is not None:
        raise IncidentConflict("accepted delivery cannot include a failure code")
    if payload["outcome"] != "accepted" and receipt is not None:
        raise IncidentConflict("failed or uncertain delivery cannot include a provider receipt")
    if payload["outcome"] != "accepted" and failure is None:
        raise IncidentConflict("failed or uncertain delivery requires a failure code")
    now = (now or datetime.now(UTC)).astimezone(UTC)
    if attempted_at > now + timedelta(seconds=future_skew_seconds):
        raise IncidentConflict("attempted_at exceeds the current verified future-skew bound")
    with engine.begin() as connection:
        transition = connection.execute(sa.select(g7_incident_transitions).where(
            g7_incident_transitions.c.transition_id == transition_id).with_for_update()
            ).mappings().first()
        if transition is None:
            raise IncidentForbidden("delivery attempt is not bound to a projected transition")
        binding = connection.execute(sa.select(g7_incident_service_bindings).where(
            g7_incident_service_bindings.c.principal_id == principal_id,
            g7_incident_service_bindings.c.deployment_id == transition["deployment_id"],
            g7_incident_service_bindings.c.subject_id == transition["subject_id"],
            g7_incident_service_bindings.c.condition == transition["condition"],
            g7_incident_service_bindings.c.enabled.is_(True)).with_for_update()).mappings().first()
        if (binding is None or binding["producer_id"] != transition["producer_id"]
                or int(binding["configuration_revision"]) != transition["configuration_revision"]):
            raise IncidentForbidden("current incident service binding is required for delivery outcome")
        prior = connection.execute(sa.select(g7_incident_notification_attempts).where(
            g7_incident_notification_attempts.c.attempt_id == payload["attempt_id"])
            .with_for_update()).mappings().first()
        values = {"transition_id": transition_id, "outcome": payload["outcome"],
            "attempted_at": attempted_at, "receipt_ref": payload["receipt_ref"],
            "failure_detail": payload["failure_detail"]}
        if prior:
            prior_attempted = prior["attempted_at"]
            if prior_attempted.tzinfo is None:
                prior_attempted = prior_attempted.replace(tzinfo=UTC)
            same = (prior["transition_id"] == transition_id
                and prior["outcome"] == values["outcome"]
                and prior_attempted.astimezone(UTC) == attempted_at
                and prior["receipt_ref"] == values["receipt_ref"]
                and prior["failure_detail"] == values["failure_detail"])
            if not same:
                raise IncidentConflict("delivery attempt ID is already bound to different content")
            return {"schema_version": 1, "status": "projected",
                "transition_id": transition_id, "attempt_id": payload["attempt_id"],
                "outcome": payload["outcome"], "idempotent": True}
        intent = connection.execute(sa.select(g7_incident_notification_intents).where(
            g7_incident_notification_intents.c.transition_id == transition_id)
            .with_for_update()).mappings().first()
        if intent is None:
            raise IncidentConflict("notification intent is missing")
        transition_observed = transition["observed_at"]
        if transition_observed.tzinfo is None:
            transition_observed = transition_observed.replace(tzinfo=UTC)
        if attempted_at < transition_observed.astimezone(UTC):
            raise IncidentConflict("attempted_at precedes its incident transition")
        if intent["state"] in {"accepted", "uncertain"}:
            raise IncidentConflict("terminal delivery outcome cannot be overwritten")
        previous = connection.execute(sa.select(g7_incident_notification_attempts).where(
            g7_incident_notification_attempts.c.transition_id == transition_id)
            .order_by(g7_incident_notification_attempts.c.attempted_at.desc())
            .with_for_update()).mappings().first()
        if previous is not None:
            previous_at = previous["attempted_at"]
            if previous_at.tzinfo is None:
                previous_at = previous_at.replace(tzinfo=UTC)
            if attempted_at <= previous_at.astimezone(UTC):
                raise IncidentConflict("new delivery attempt must be strictly later than every prior attempt")
        connection.execute(g7_incident_notification_attempts.insert().values(
            attempt_id=payload["attempt_id"], **values))
        latest = connection.execute(sa.select(g7_incident_notification_attempts.c.attempt_id)
            .where(g7_incident_notification_attempts.c.transition_id == transition_id)
            .order_by(g7_incident_notification_attempts.c.attempted_at.desc(),
                g7_incident_notification_attempts.c.attempt_id.desc()).limit(1)
            ).scalar_one()
        superseded = latest != payload["attempt_id"]
        if not superseded:
            connection.execute(g7_incident_notification_intents.update().where(
                g7_incident_notification_intents.c.transition_id == transition_id).values(
                    state=payload["outcome"], updated_at=now,
                    receipt_basis=payload["attempt_id"]))
        return {"schema_version": 1, "status": "projected",
            "transition_id": transition_id, "attempt_id": payload["attempt_id"],
            "outcome": payload["outcome"], "idempotent": False,
            "superseded": superseded}
