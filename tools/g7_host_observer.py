#!/usr/bin/env python3
"""Independent host controller and observer/supervisor consumers for G7.

All policy, credentials, signing material, journal state and readbacks belong
to the host-owned state directory. Nothing in this process has a Docker API
connection. The only application boundary is the versioned UVM HTTP contract.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import signal
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from datetime import datetime, timezone
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

UTC = timezone.utc
FIELDS = (
    "observation_interval_seconds", "request_deadline_seconds",
    "heartbeat_freshness_seconds", "maximum_future_skew_seconds",
    "anchor_export_lag_seconds", "incident_projection_deadline_seconds",
    "scheduler_progress_freshness_seconds",
)
CONTRACT = "g7-observer-settings/v1"
STOP = False


def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
        ensure_ascii=False, allow_nan=False).encode("utf-8")


def digest(value: object) -> str:
    return "sha256:" + hashlib.sha256(canonical(value)).hexdigest()


def utc_now() -> str:
    return datetime.now(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")


def atomic_json(path: Path, value: object, mode: int = 0o600) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if path.is_symlink():
        raise ValueError("refusing symlink state path")
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "wb") as stream:
            stream.write(canonical(value) + b"\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    except Exception:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise


def read_json(path: Path, default=None):
    try:
        if path.is_symlink() or not path.is_file():
            return default
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return default


def validate_policy(policy: object) -> dict:
    required = {"schema_version", "deployment_id", "revision", "bounds",
        "freshness_seconds", "poll_seconds", "controller_request_timeout_seconds",
        "apply_deadline_seconds", "endpoint", "token_file", "sink_id",
        "anchor_read_dsn",
        "signing_key_file", "state_dir", "active_file", "scheduler_file",
        "observer_readback", "supervisor_readback", "observer_state",
        "supervisor_state", "host_policy_digest"}
    if not isinstance(policy, dict) or set(policy) != required:
        raise ValueError("host policy fields do not match v1")
    if (type(policy["schema_version"]) is not int or policy["schema_version"] != 1
            or not isinstance(policy["deployment_id"], str) or not policy["deployment_id"]
            or type(policy["revision"]) is not int or policy["revision"] < 1
            or type(policy["freshness_seconds"]) is not int or policy["freshness_seconds"] < 1
            or type(policy["poll_seconds"]) is not int or policy["poll_seconds"] < 1
            or type(policy["controller_request_timeout_seconds"]) is not int
            or policy["controller_request_timeout_seconds"] < 1
            or type(policy["apply_deadline_seconds"]) is not int
            or policy["apply_deadline_seconds"] < 1
            or not isinstance(policy["sink_id"], str)
            or not policy["sink_id"] or len(policy["sink_id"]) > 100
            or not isinstance(policy["anchor_read_dsn"], str)
            or not policy["anchor_read_dsn"]):
        raise ValueError("host policy identity or timing is invalid")
    bounds = policy["bounds"]
    if not isinstance(bounds, dict) or set(bounds) != set(FIELDS):
        raise ValueError("host policy must bound all timing fields")
    for field in FIELDS:
        limit = bounds[field]
        floor = 0 if field == "maximum_future_skew_seconds" else 1
        if (not isinstance(limit, dict) or set(limit) != {"min", "max"}
                or type(limit["min"]) is not int or type(limit["max"]) is not int
                or limit["min"] < floor or limit["max"] < limit["min"]):
            raise ValueError(f"invalid host bound: {field}")
    unsigned = {key: value for key, value in policy.items() if key != "host_policy_digest"}
    if policy["host_policy_digest"] != digest(unsigned):
        raise ValueError("host policy digest is invalid")
    endpoint = policy["endpoint"]
    if not isinstance(endpoint, str) or not endpoint.startswith(("https://", "http://127.0.0.1", "http://localhost")):
        raise ValueError("host endpoint must be HTTPS or loopback HTTP")
    return policy


def validate_values(values: object, bounds: dict) -> dict:
    if not isinstance(values, dict) or set(values) != set(FIELDS):
        raise ValueError("desired values must contain all v1 timing fields")
    for field in FIELDS:
        value, limit = values[field], bounds[field]
        if type(value) is not int or not limit["min"] <= value <= limit["max"]:
            raise ValueError(f"host policy rejected {field}")
    return dict(values)


def load_private_key(path: Path) -> Ed25519PrivateKey:
    data = path.read_bytes()
    try:
        key = serialization.load_pem_private_key(data, password=None)
    except ValueError:
        key = Ed25519PrivateKey.from_private_bytes(data)
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError("host report key must be Ed25519")
    return key


def request_json(url: str, token: str, timeout: float, body: dict | None = None) -> dict:
    data = None if body is None else canonical(body)
    request = urllib.request.Request(url, data=data,
        method="GET" if body is None else "POST",
        headers={"Authorization": "Bearer " + token, "Accept": "application/json",
            **({"Content-Type": "application/json"} if data is not None else {})})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        value = json.loads(response.read())
    if not isinstance(value, dict) or type(value.get("schema_version")) is not int or value["schema_version"] != 1:
        raise ValueError("host API response does not match schema v1")
    return value


def _http_error_code(error: urllib.error.HTTPError) -> str | None:
    try:
        payload = json.loads(error.read())
    except (OSError, ValueError):
        return None
    error._uvm_g7_payload = payload
    detail = payload.get("detail", payload.get("error")) if isinstance(payload, dict) else None
    return detail.get("code") if isinstance(detail, dict) and isinstance(detail.get("code"), str) else None


def _http_error_summary(error: urllib.error.HTTPError) -> dict:
    payload = getattr(error, "_uvm_g7_payload", None)
    detail = payload.get("detail", payload.get("error")) if isinstance(payload, dict) else None
    return {"response_type": type(payload).__name__,
        "response_keys": sorted(payload) if isinstance(payload, dict) else [],
        "response_code": detail.get("code") if isinstance(detail, dict) and isinstance(detail.get("code"), str) else None,
        "response_error": detail.get("message")[:160] if isinstance(detail, dict) and isinstance(detail.get("message"), str) else None,
        "response_message": payload.get("message")[:160] if isinstance(payload, dict) and isinstance(payload.get("message"), str) else None,
        "detail_type": type(detail).__name__,
        "detail_keys": sorted(detail) if isinstance(detail, dict) else [],
        "detail_message": detail.get("message")[:160] if isinstance(detail, dict) and isinstance(detail.get("message"), str) else None}


def signed_report(policy: dict, unsigned: dict) -> dict:
    signature = load_private_key(Path(policy["signing_key_file"])).sign(canonical(unsigned))
    return {**unsigned, "signature": base64.urlsafe_b64encode(signature).decode("ascii").rstrip("=")}


def readback(path: Path) -> dict:
    value = read_json(path)
    if not isinstance(value, dict):
        # The API requires a parseable timestamp even for a missing consumer
        # observation. This fixed stale sentinel never implies a current read.
        return {"revision": None, "digest": None,
            "observed_at": "1970-01-01T00:00:00Z"}
    return {"revision": value.get("revision"), "digest": value.get("digest"),
        "observed_at": value.get("observed_at") or "1970-01-01T00:00:00Z"}


def _consumer_readbacks_fresh(consumers: dict, freshness_seconds: int,
                              now: datetime | None = None) -> bool:
    now = now or datetime.now(UTC)
    for item in consumers.values():
        stamp = _timestamp(item.get("observed_at"))
        if (stamp is None or (now - stamp).total_seconds() > freshness_seconds
                or (stamp - now).total_seconds() > 1):
            return False
    return True


def _root(policy: dict) -> str:
    return policy["endpoint"].rstrip("/") + "/api/v1/operations/observer-settings/" + urllib.parse.quote(policy["deployment_id"], safe="")


def _report(policy: dict, journal: dict, requested: dict | None,
            outcome: str, failure: str | None) -> dict:
    observer = readback(Path(policy["observer_readback"]))
    supervisor = readback(Path(policy["supervisor_readback"]))
    last_good = journal.get("last_good") or {}
    active_revision = last_good.get("revision")
    active_digest = last_good.get("digest")
    requested_revision = requested.get("revision") if requested else None
    requested_digest = requested.get("digest") if requested else None
    # An applied acknowledgement is permitted only after both processes have
    # published matching effective readbacks, rather than merely seeing a file.
    if outcome == "applied":
        expected = (requested_revision, requested_digest)
        if any((item["revision"], item["digest"]) != expected for item in (observer, supervisor)):
            outcome, failure = "uncertain", "consumer_readback_mismatch"
        elif not _consumer_readbacks_fresh({"observer": observer, "supervisor": supervisor},
                policy["freshness_seconds"]):
            outcome, failure = "uncertain", "consumer_readback_stale"
        else:
            active_revision, active_digest = expected
    sequence = int(journal.get("sequence", 0)) + 1
    report = {"schema_version": 1, "deployment_id": policy["deployment_id"],
        "report_id": str(uuid.uuid4()), "sequence": sequence,
        "controller_instance": journal.setdefault("controller_instance", str(uuid.uuid4())),
        "requested_revision": requested_revision, "requested_digest": requested_digest,
        "active_revision": active_revision, "active_digest": active_digest,
        "consumers": {"observer": observer, "supervisor": supervisor},
        "host_policy": {"revision": policy["revision"], "bounds": policy["bounds"],
            "digest": policy["host_policy_digest"], "freshness_seconds": policy["freshness_seconds"]},
        "outcome": outcome, "observed_at": utc_now(), "failure_code": failure}
    journal["sequence"] = sequence
    return signed_report(policy, report)


def _controller_once_unlocked(policy: dict) -> dict:
    policy = validate_policy(policy)
    state_dir = Path(policy["state_dir"])
    journal_path = state_dir / "journal.json"
    journal = read_json(journal_path, default={}) or {}
    token = Path(policy["token_file"]).read_text(encoding="utf-8").strip()
    if not token:
        raise ValueError("host service token is empty")
    root = _root(policy)
    active = read_json(Path(policy["active_file"]))
    timeout = (active.get("values", {}).get("request_deadline_seconds")
        if isinstance(active, dict) else policy["controller_request_timeout_seconds"])
    timeout = float(timeout)

    pending = journal.get("pending_report")
    if pending:
        superseded = False
        try:
            acknowledgement = request_json(root + "/host/reports", token, timeout, pending)
        except urllib.error.HTTPError as error:
            error_code = _http_error_code(error)
            if error.code == 409 and error_code == "report_superseded":
                # A newer desired revision overtook a report that was never
                # admitted. An accepted report would have taken the exact
                # idempotency path before this stale-revision check.
                journal.pop("pending_report", None)
                journal["superseded_report"] = pending
                atomic_json(journal_path, journal)
                superseded = True
            elif error.code == 400 and error_code == "report_expired":
                # Refresh the controller timestamp, but retain the consumers'
                # real timestamps. New consumer work is required before an
                # applied report can become fresh enough for admission.
                unsigned = {key: value for key, value in pending.items()
                    if key != "signature"}
                unsigned["observed_at"] = utc_now()
                consumer_stamps = {name: readback(Path(policy[name + "_readback"]))
                    for name in ("observer", "supervisor")}
                unsigned["consumers"] = consumer_stamps
                pending = signed_report(policy, unsigned)
                journal["pending_report"] = pending
                atomic_json(journal_path, journal)
                if (pending.get("outcome") == "applied"
                        and not _consumer_readbacks_fresh(consumer_stamps,
                            policy["freshness_seconds"])):
                    return {"status": "uncertain", "failure_code": "consumer_readback_stale"}
                try:
                    acknowledgement = request_json(root + "/host/reports", token, timeout, pending)
                except urllib.error.HTTPError as retry_error:
                    if retry_error.code == 400 and _http_error_code(retry_error) == "report_expired":
                        return {"status": "uncertain", "failure_code": "consumer_readback_stale"}
                    raise
                except (urllib.error.URLError, TimeoutError, OSError):
                    return {"status": "uncertain", "failure_code": "report_acknowledgement_lost"}
            else:
                return {"status": "uncertain", "failure_code": "host_report_rejected",
                    "report_http_status": error.code, "report_error_code": error_code,
                    "report_error_summary": _http_error_summary(error)}
        except (urllib.error.URLError, TimeoutError, OSError):
            return {"status": "uncertain", "failure_code": "report_acknowledgement_lost"}
        if not superseded:
            journal.pop("pending_report", None)
            journal["last_acknowledgement"] = acknowledgement
            atomic_json(journal_path, journal)

    desired_response = request_json(root + "/host/desired", token, timeout)
    if desired_response.get("deployment_id") != policy["deployment_id"]:
        raise ValueError("cross-deployment desired response")
    desired = desired_response.get("desired")
    last_good = journal.get("last_good")
    active_path = Path(policy["active_file"])
    if last_good and read_json(active_path) != last_good:
        atomic_json(active_path, last_good)

    if desired is None:
        report = _report(policy, journal, None, "uncertain", "not_configured")
        journal["pending_report"] = report
        atomic_json(journal_path, journal)
        return {"status": "uncertain", "failure_code": "not_configured"}

    try:
        if set(desired) != {"revision", "digest", "values", "command_id", "intent_id", "expected_host_policy_revision"}:
            raise ValueError("desired document has unknown or missing fields")
        if (type(desired["revision"]) is not int or desired["revision"] < 1
                or desired["expected_host_policy_revision"] != policy["revision"]):
            raise ValueError("desired revision or host policy is stale")
        values = validate_values(desired["values"], policy["bounds"])
        expected_digest = digest(values)
        if desired["digest"] != expected_digest:
            raise ValueError("desired digest does not match values")
        if last_good and desired["revision"] < last_good["revision"]:
            raise ValueError("desired revision regressed")
        candidate = {"schema_version": 1, "revision": desired["revision"],
            "digest": expected_digest, "values": values, "intent_id": desired["intent_id"]}
    except (KeyError, TypeError, ValueError):
        report = _report(policy, journal, desired, "failed", "host_policy_rejected")
        journal["pending_report"] = report
        atomic_json(journal_path, journal)
        return {"status": "failed", "failure_code": "host_policy_rejected"}

    # Keep candidate and verified last-good in different journal slots. A
    # controller crash during replacement leaves last-good recoverable.
    journal["candidate"] = candidate
    journal["phase"] = "installing"
    atomic_json(journal_path, journal)
    if not last_good or (candidate["revision"], candidate["digest"]) != (last_good["revision"], last_good["digest"]):
        atomic_json(active_path, candidate, mode=0o644)

    apply_started_at = datetime.now(UTC)
    already_verified = bool(last_good and
        (candidate["revision"], candidate["digest"]) ==
        (last_good["revision"], last_good["digest"]))
    deadline_at = time.monotonic() + policy["apply_deadline_seconds"]
    while time.monotonic() < deadline_at:
        observer, supervisor = (readback(Path(policy[key])) for key in
            ("observer_readback", "supervisor_readback"))
        expected = (candidate["revision"], candidate["digest"])
        matching = all((item["revision"], item["digest"]) == expected
            for item in (observer, supervisor))
        current = (already_verified and _consumer_readbacks_fresh(
            {"observer": observer, "supervisor": supervisor}, policy["freshness_seconds"])) or all(
                (_timestamp(item.get("observed_at")) or datetime.min.replace(tzinfo=UTC))
                    >= apply_started_at for item in (observer, supervisor))
        if matching and current:
            journal["last_good"] = candidate
            journal.pop("candidate", None)
            journal["phase"] = "verified"
            report = _report(policy, journal, desired, "applied", None)
            journal["pending_report"] = report
            atomic_json(journal_path, journal)
            return {"status": "applied", "revision": candidate["revision"], "digest": candidate["digest"]}
        time.sleep(0.1)

    # Partial consumer agreement is uncertain. Reinstall last-good (if any)
    # and preserve all consumer work journals and heartbeat sequence numbers.
    if last_good:
        atomic_json(active_path, last_good, mode=0o644)
    else:
        try:
            active_path.unlink()
        except FileNotFoundError:
            pass
    journal.pop("candidate", None)
    journal["phase"] = "reconcile"
    report = _report(policy, journal, desired, "uncertain", "partial_application")
    journal["pending_report"] = report
    atomic_json(journal_path, journal)
    return {"status": "uncertain", "failure_code": "partial_application"}


def controller_once(policy: dict) -> dict:
    """Serialize report sequence and snapshot transitions across restarts."""
    import fcntl
    policy = validate_policy(policy)
    state_dir = Path(policy["state_dir"])
    state_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    lock_path = state_dir / "controller.lock"
    if lock_path.is_symlink():
        raise ValueError("refusing symlink controller lock")
    descriptor = os.open(lock_path, os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        os.fchmod(descriptor, 0o600)
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        return _controller_once_unlocked(policy)
    finally:
        os.close(descriptor)


def _request(url: str, token: str, timeout: int) -> tuple[int, dict | None, str | None]:
    request = urllib.request.Request(url, headers={"Authorization": "Bearer " + token,
        "Accept": "application/json"})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            body = json.loads(response.read())
        return response.status, body, None
    except urllib.error.HTTPError as error:
        return error.code, None, "http_error"
    except (urllib.error.URLError, TimeoutError, OSError, ValueError):
        return 0, None, "request_failed"


def read_anchor_inventory(dsn: str, deployment_id: str, sink_id: str,
                          event_ids: list[str], timeout_seconds: int) -> dict[str, dict]:
    """Read the independent host anchor inventory with a read-only DB session."""
    if len(event_ids) > 1000:
        raise ValueError("anchor lookup exceeds telemetry bound")
    if not event_ids:
        return {}
    import psycopg
    from psycopg.rows import dict_row
    with psycopg.connect(dsn, row_factory=dict_row, connect_timeout=timeout_seconds,
            options=("-c default_transaction_read_only=on "
                f"-c statement_timeout={timeout_seconds * 1000}")) as connection:
        rows = connection.execute("""SELECT event_id, payload_sha256, sink_receipt,
            anchored_at FROM uvm_audit_anchor.inventory
            WHERE deployment_id=%s AND sink_id=%s AND event_id = ANY(%s)""",
            (deployment_id, sink_id, event_ids)).fetchall()
    return {str(row["event_id"]): dict(row) for row in rows}


def _timestamp(value: object) -> datetime | None:
    if isinstance(value, datetime):
        if value.tzinfo is None:
            return None
        return value.astimezone(UTC)
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed.astimezone(UTC) if parsed.tzinfo is not None else None


def measure_lag(telemetry: dict, anchors: dict[str, dict], values: dict,
                now: datetime | None = None) -> dict:
    """Measure pending/slow anchor and incident projections without payloads."""
    now = (now or datetime.now(UTC)).astimezone(UTC)
    anchor_pending_ages: list[float] = []
    anchor_export_lags: list[float] = []
    anchor_mismatch_count = 0
    anchor_timestamp_anomalies = 0
    anchor_missing_receipt_count = 0
    anchor_pending_count = 0
    audit_events = telemetry.get("audit_events")
    audit_complete = telemetry.get("audit_complete") is True
    if not isinstance(audit_events, list):
        audit_complete = False
        audit_events = []
    for event in audit_events:
        if not isinstance(event, dict):
            audit_complete = False
            continue
        event_id = event.get("event_id")
        anchor = anchors.get(event_id) if isinstance(event_id, str) else None
        receipt = event.get("sink_receipt")
        if not isinstance(receipt, str) or not receipt:
            anchor_missing_receipt_count += 1
        valid_anchor = bool(anchor and receipt and anchor.get("sink_receipt") == receipt
            and anchor.get("payload_sha256") == event.get("event_digest"))
        received = _timestamp(event.get("received_at"))
        if valid_anchor:
            anchored = _timestamp(anchor.get("anchored_at"))
            if (received is None or anchored is None
                    or received > now + __import__("datetime").timedelta(
                        seconds=values["maximum_future_skew_seconds"])
                    or anchored > now + __import__("datetime").timedelta(
                        seconds=values["maximum_future_skew_seconds"])
                    or anchored < received - __import__("datetime").timedelta(
                        seconds=values["maximum_future_skew_seconds"])):
                anchor_timestamp_anomalies += 1
            else:
                anchor_export_lags.append(max(0.0, (anchored - received).total_seconds()))
        else:
            anchor_pending_count += 1
            if received is None or received > now + __import__("datetime").timedelta(
                    seconds=values["maximum_future_skew_seconds"]):
                anchor_timestamp_anomalies += 1
            else:
                anchor_pending_ages.append(max(0.0, (now - received).total_seconds()))
            if anchor and (receipt is None or anchor.get("sink_receipt") != receipt
                    or anchor.get("payload_sha256") != event.get("event_digest")):
                anchor_mismatch_count += 1
    anchor_pending_lag = max(anchor_pending_ages, default=0.0) if audit_complete else None
    anchor_export_lag = (max(anchor_export_lags, default=0.0)
        if audit_complete and anchor_timestamp_anomalies == 0 else None)
    anchor_state = ("unknown" if not audit_complete else
        "unknown" if anchor_timestamp_anomalies or anchor_missing_receipt_count else
        "late" if anchor_pending_lag is None or anchor_export_lag is None
            or anchor_pending_lag > values["anchor_export_lag_seconds"]
            or anchor_export_lag > values["anchor_export_lag_seconds"] else "healthy")

    incidents = telemetry.get("incidents")
    incidents_complete = telemetry.get("incidents_complete") is True
    if not isinstance(incidents, list):
        incidents_complete = False
        incidents = []
    projection_ages: list[float] = []
    pending_projections = 0
    projection_anomalies = 0
    for item in incidents:
        if not isinstance(item, dict):
            incidents_complete = False
            continue
        observed = _timestamp(item.get("observed_at"))
        projected = _timestamp(item.get("projected_at"))
        if observed is None or observed > now + __import__("datetime").timedelta(
                seconds=values["maximum_future_skew_seconds"]):
            projection_anomalies += 1
            continue
        if projected is None:
            pending_projections += 1
            projection_ages.append(max(0.0, (now - observed).total_seconds()))
        elif (projected < observed - __import__("datetime").timedelta(
                seconds=values["maximum_future_skew_seconds"])
                or projected > now + __import__("datetime").timedelta(
                    seconds=values["maximum_future_skew_seconds"])):
            projection_anomalies += 1
        else:
            projection_ages.append(max(0.0, (projected - observed).total_seconds()))
    projection_lag = max(projection_ages, default=0.0) if incidents_complete else None
    projection_state = ("unknown" if not incidents_complete or projection_anomalies else
        "late" if pending_projections and projection_lag is not None
            and projection_lag > values["incident_projection_deadline_seconds"] else
        "healthy" if projection_lag is not None
            and projection_lag <= values["incident_projection_deadline_seconds"] else "late")
    return {"anchor_export": {"status": anchor_state,
            "maximum_pending_lag_seconds": anchor_pending_lag,
            "maximum_export_lag_seconds": anchor_export_lag,
            "pending_or_unanchored_count": anchor_pending_count,
            "missing_receipt_count": anchor_missing_receipt_count,
            "timestamp_anomaly_count": anchor_timestamp_anomalies,
            "receipt_or_digest_mismatch_count": anchor_mismatch_count,
            "timestamp_anomaly_count": anchor_timestamp_anomalies,
            "limit_seconds": values["anchor_export_lag_seconds"]},
        "incident_projection": {"status": projection_state,
            "maximum_projection_lag_seconds": projection_lag,
            "pending_projection_count": pending_projections,
            "timestamp_anomaly_count": projection_anomalies,
            "deadline_seconds": values["incident_projection_deadline_seconds"]}}


def consumer_once(role: str, policy: dict) -> dict:
    policy = validate_policy(policy)
    active = read_json(Path(policy["active_file"]))
    state_file = Path(policy[role + "_state"])
    state = read_json(state_file, default={}) or {}
    if not isinstance(active, dict):
        return {"status": "unconfigured"}
    values = validate_values(active.get("values"), policy["bounds"])
    if active.get("digest") != digest(values) or type(active.get("revision")) is not int:
        state["health"] = "invalid_snapshot"
        atomic_json(state_file, state)
        return {"status": "invalid_snapshot"}
    token = Path(policy["token_file"]).read_text(encoding="utf-8").strip()
    now = datetime.now(UTC)
    if role == "observer":
        # This is real HTTP work on every interval. Both network timeout and
        # schedule come from the active desired snapshot.
        url = (_root(policy) + "/host/telemetry?limit=1000&sink_id="
            + urllib.parse.quote(policy["sink_id"], safe=""))
        status, payload, error = _request(url, token, values["request_deadline_seconds"])
        if error:
            state["last_check"] = {"at": utc_now(), "http_status": status,
                "error": error,
                "anchor_export": {"status": "unknown", "maximum_pending_lag_seconds": None},
                "incident_projection": {"status": "unknown", "maximum_projection_lag_seconds": None}}
        else:
            if not isinstance(payload, dict) or payload.get("deployment_id") != policy["deployment_id"]:
                telemetry = {"audit_complete": False, "incidents_complete": False}
            else:
                telemetry = payload
            try:
                event_ids = [item["event_id"] for item in telemetry.get("audit_events", [])
                    if isinstance(item, dict) and isinstance(item.get("event_id"), str)]
                anchors = read_anchor_inventory(policy["anchor_read_dsn"],
                    policy["deployment_id"], policy["sink_id"], event_ids,
                    values["request_deadline_seconds"])
                lag = measure_lag(telemetry, anchors, values, now)
            except Exception as exc:
                lag = {"anchor_export": {"status": "unknown",
                        "maximum_pending_lag_seconds": None,
                        "measurement_error": type(exc).__name__},
                    "incident_projection": {"status": "unknown",
                        "maximum_projection_lag_seconds": None}}
            state["last_check"] = {"at": utc_now(), "http_status": status,
                "error": None, **lag}
        progress = read_json(Path(policy["scheduler_file"]))
        now_mono = time.monotonic_ns()
        prior_seq = state.get("scheduler_loop_sequence")
        try:
            host_boot_id = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
        except OSError:
            host_boot_id = None
        valid_progress = (isinstance(progress, dict) and type(progress.get("loop_sequence")) is int
            and isinstance(progress.get("boot_id"), str) and type(progress.get("monotonic_ns")) is int)
        sample_age = (now_mono - progress["monotonic_ns"]) / 1e9 if valid_progress else None
        progressed = valid_progress and (prior_seq is None or progress["loop_sequence"] > prior_seq)
        last_progress_ns = state.get("scheduler_last_progress_monotonic_ns")
        if progressed:
            last_progress_ns = progress["monotonic_ns"]
            state["scheduler_last_progress_monotonic_ns"] = last_progress_ns
        progress_age = ((now_mono - last_progress_ns) / 1e9
            if type(last_progress_ns) is int else None)
        sequence_valid = prior_seq is None or progress["loop_sequence"] >= prior_seq if valid_progress else False
        progress_ok = bool(valid_progress and progress.get("boot_id") == host_boot_id
            and sample_age is not None and sample_age >= 0 and sequence_valid
            and progress_age is not None and 0 <= progress_age <= values["scheduler_progress_freshness_seconds"])
        state["scheduler"] = {"status": "healthy" if progress_ok else "stale_or_nonprogressing",
            "loop_sequence": progress.get("loop_sequence") if valid_progress else None,
            "age_seconds": progress_age, "sample_age_seconds": sample_age,
            "freshness_seconds": values["scheduler_progress_freshness_seconds"]}
        if valid_progress and (prior_seq is None or progress["loop_sequence"] >= prior_seq):
            state["scheduler_loop_sequence"] = progress["loop_sequence"]
        state["last_completed_loop_at"] = utc_now()
        state["loop_sequence"] = int(state.get("loop_sequence", 0)) + 1
    else:
        # Supervisor evaluates host observation freshness and future skew from
        # the persistent observer heartbeat. Configuration replacement never
        # rewrites or resets that heartbeat.
        observer = read_json(Path(policy["observer_state"]), default={}) or {}
        heartbeat = observer.get("last_completed_loop_at")
        freshness = values["heartbeat_freshness_seconds"]
        age = None
        healthy = False
        if isinstance(heartbeat, str):
            try:
                stamp = datetime.fromisoformat(heartbeat.replace("Z", "+00:00"))
                if stamp.tzinfo is not None:
                    age = (now - stamp.astimezone(UTC)).total_seconds()
                    healthy = -values["maximum_future_skew_seconds"] <= age <= freshness
            except ValueError:
                pass
        state["supervision"] = {"status": "healthy" if healthy else "stale_or_future",
            "heartbeat_age_seconds": age, "freshness_seconds": freshness,
            "maximum_future_skew_seconds": values["maximum_future_skew_seconds"]}
        state["last_completed_loop_at"] = utc_now()
        state["loop_sequence"] = int(state.get("loop_sequence", 0)) + 1
    state["active_revision"] = active["revision"]
    state["active_digest"] = active["digest"]
    state["configuration_contract"] = CONTRACT
    atomic_json(state_file, state)
    atomic_json(Path(policy[role + "_readback"]), {"revision": active["revision"],
        "digest": active["digest"], "observed_at": utc_now()}, mode=0o644)
    return {"status": "completed", "role": role, "revision": active["revision"],
        "digest": active["digest"], "loop_sequence": state["loop_sequence"]}


def stop(_signum, _frame):
    global STOP
    STOP = True


def main() -> int:
    global STOP
    STOP = False
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("controller", "observer", "supervisor"))
    parser.add_argument("--policy", required=True, type=Path)
    parser.add_argument("--once", action="store_true")
    args = parser.parse_args()
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    policy = validate_policy(read_json(args.policy))
    if args.once:
        result = controller_once(policy) if args.mode == "controller" else consumer_once(args.mode, policy)
        print(json.dumps(result, sort_keys=True))
        return 0 if result.get("status") in {"completed", "applied", "failed", "uncertain", "unconfigured"} else 1
    while not STOP:
        began = time.monotonic()
        if args.mode == "controller":
            try:
                print(json.dumps(controller_once(policy), sort_keys=True), flush=True)
            except Exception as error:
                print(json.dumps({"status": "error", "error_type": type(error).__name__,
                    "http_status": error.code if isinstance(error, urllib.error.HTTPError) else None,
                    "api_error_code": _http_error_code(error) if isinstance(error, urllib.error.HTTPError) else None}, sort_keys=True), flush=True)
            cadence = policy["poll_seconds"]
        else:
            try:
                active = read_json(Path(policy["active_file"]))
                cadence = active["values"]["observation_interval_seconds"] if isinstance(active, dict) else policy["poll_seconds"]
                print(json.dumps(consumer_once(args.mode, policy), sort_keys=True), flush=True)
            except Exception as error:
                print(json.dumps({"status": "error", "role": args.mode, "error_type": type(error).__name__}), flush=True)
                cadence = policy["poll_seconds"]
        STOP = STOP or False
        delay = max(0.05, float(cadence) - (time.monotonic() - began))
        until = time.monotonic() + delay
        while not STOP and time.monotonic() < until:
            time.sleep(min(0.1, until - time.monotonic()))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
