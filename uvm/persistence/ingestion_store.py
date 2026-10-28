"""Transactional append-only store for the G2 ingestion accounting contract."""
from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import asdict, is_dataclass
from datetime import datetime, timedelta, timezone

import sqlalchemy as sa

from uvm.ingestion.run import (AttemptFact, CollectionRunV1, CollectionScheduleV1,
                               ExpectedRunV1, PageFact)
from uvm.persistence.ingestion_schema import (collection_runs, collection_schedules,
    collection_request_reservations, expected_run_events, expected_runs, import_context_revisions, ingestion_evidence,
    run_attempts, run_pages)
from uvm.persistence.engine_operation_schema import (ce_context_registrations,
    ce_context_verifications, ce_context_test_bindings)

UTC = timezone.utc

class IngestionWriteError(ValueError):
    pass

class IngestionConflictError(IngestionWriteError):
    pass

def _instant(v, name):
    if v is None: return None
    if v.tzinfo is None or v.utcoffset() is None: raise IngestionWriteError(f"{name} must be timezone-aware")
    return v.astimezone(UTC)

def _id(v, name):
    try:
        parsed = uuid.UUID(v)
    except (ValueError, TypeError, AttributeError):
        raise IngestionWriteError(f"{name} must be a UUID") from None
    if str(parsed) != v: raise IngestionWriteError(f"{name} must be canonical")
    return v

def _same(existing, values):
    def normal(value):
        if isinstance(value, datetime):
            return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)
        return value
    return all(normal(existing[k]) == normal(v) for k, v in values.items())

def _jsonable(value):
    if is_dataclass(value):
        return _jsonable(asdict(value))
    if isinstance(value, dict):
        return {str(k): _jsonable(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_jsonable(v) for v in value]
    if isinstance(value, datetime):
        return _instant(value, "snapshot timestamp").isoformat()
    if isinstance(value, timedelta):
        return {"microseconds": value.days * 86400000000 + value.seconds * 1000000 + value.microseconds}
    if isinstance(value, uuid.UUID):
        return str(value)
    return value

def _fact_key(value):
    return json.dumps(_jsonable(value), sort_keys=True, separators=(",", ":"))

def _microseconds(value: timedelta) -> int:
    return value.days * 86400000000 + value.seconds * 1000000 + value.microseconds

class IngestionStore:
    def __init__(self, engine): self.engine = engine

    @staticmethod
    def _append_expected_event(connection, expected_run_id, state, run_id,
                               run_revision, effective_at, recorded_at):
        revision = int(connection.execute(sa.select(sa.func.coalesce(
            sa.func.max(expected_run_events.c.revision), 0)).where(
                expected_run_events.c.expected_run_id == expected_run_id)).scalar_one()) + 1
        connection.execute(expected_run_events.insert().values(
            event_id=str(uuid.uuid4()), expected_run_id=expected_run_id,
            revision=revision, state=state, run_id=run_id,
            run_revision=run_revision, effective_at=_instant(effective_at, "expected_event.effective_at"),
            recorded_at=_instant(recorded_at, "expected_event.recorded_at")))

    @staticmethod
    def _schedule_values(schedule, recorded_at):
        return dict(schedule_id=schedule.schedule_id, revision=schedule.revision,
            source_family=schedule.source_family, source_account_id=schedule.source_account_id,
            scope_key=schedule.scope_key, enabled=schedule.enabled, timezone_name=schedule.timezone_name,
            cadence=schedule.cadence, expected_run_grace_microseconds=_microseconds(schedule.expected_run_grace),
            max_attempts=schedule.max_attempts, max_page_attempts=schedule.max_page_attempts,
            total_deadline_microseconds=_microseconds(schedule.total_deadline),
            freshness_rule_ref=schedule.freshness_rule_ref, recorded_at=recorded_at)

    def save_schedule(self, schedule: CollectionScheduleV1, recorded_at):
        recorded_at = _instant(recorded_at, "recorded_at")
        values = self._schedule_values(schedule, recorded_at)
        with self.engine.begin() as c:
            row = c.execute(sa.select(collection_schedules).where(collection_schedules.c.schedule_id == schedule.schedule_id,
                                                                  collection_schedules.c.revision == schedule.revision)).mappings().first()
            if row:
                if not _same(row, values): raise IngestionConflictError("schedule revision differs")
                return "duplicate"
            c.execute(collection_schedules.insert().values(**values))
        return "created"

    def save_expected_run(self, expected: ExpectedRunV1):
        _id(expected.expected_run_id, "expected_run_id")
        if expected.state != "due" or expected.run_id is not None:
            raise IngestionWriteError("expected run registration must be due and unclaimed")
        values = dict(expected_run_id=expected.expected_run_id, schedule_id=expected.schedule_id,
            schedule_revision=expected.schedule_revision, scope_key=expected.scope_key,
            due_at=_instant(expected.due_at, "due_at"), grace_deadline=_instant(expected.grace_deadline, "grace_deadline"),
            state=expected.state, run_id=expected.run_id)
        with self.engine.begin() as c:
            row = c.execute(sa.select(expected_runs).where(expected_runs.c.expected_run_id == expected.expected_run_id)).mappings().first()
            if row:
                immutable = {k: v for k, v in values.items() if k not in ("state", "run_id")}
                if not _same(row, immutable): raise IngestionConflictError("expected run differs")
                return "duplicate"
            c.execute(expected_runs.insert().values(**values))
            self._append_expected_event(c, expected.expected_run_id, "due", None, None,
                expected.due_at, datetime.now(UTC))
        return "created"

    @staticmethod
    def _run_values(run: CollectionRunV1, created_at):
        _id(run.run_id, "run_id")
        q = run.quality
        facts = {
            "attempts": sorted((_jsonable(a) for a in run.attempts), key=_fact_key),
            "pages": sorted((_jsonable(p) for p in run.pages.values()), key=_fact_key),
            "evidence": [],
        }
        provenance = {
            "expected_cohort": _jsonable(run.expected_cohort),
            "freshness_rule": _jsonable(run.freshness_rule),
            "observations": _jsonable(run.observations),
            "conflicts": sorted(run.conflicts),
            "quality_inputs": {
                "scope_coverage": _jsonable(run.scope_coverage),
                "freshness": _jsonable(run.freshness),
            },
        }
        return dict(run_id=run.run_id, revision=run.revision, schema_version=1,
            expected_run_id=run.expected_run_id, manual_origin=run.manual_origin,
            schedule_id=run.schedule.schedule_id, schedule_revision=run.schedule.revision,
            source_family=run.source_family, source_account_id=run.source_account_id, scope_key=run.scope_key,
            source_report_id=run.source_report_id, expected_at=_instant(run.expected_at, "expected_at"),
            started_at=run.started_at, ended_at=run.ended_at, state=run.state,
            retrieval_status=q[0].status, retrieval_reasons=list(q[0].reason_codes),
            coverage_status=q[1].status, coverage_reasons=list(q[1].reason_codes),
            freshness_status=q[2].status, freshness_reasons=list(q[2].reason_codes), created_at=created_at)

    def save_run_transition(self, run: CollectionRunV1, attempts=(), pages=(), evidence=(), created_at=None,
                            reservation=None):
        """Insert one immutable run revision and its local facts atomically."""
        created_at = _instant(created_at or run.started_at, "created_at")
        attempts = tuple(attempts); pages = tuple(pages); evidence = tuple(evidence)
        reservation_row = None
        if reservation is not None:
            if (not isinstance(reservation, dict)
                    or set(reservation) != {"attempt_no", "page_ordinal", "request_identity_sha256", "reserved_at"}
                    or type(reservation["attempt_no"]) is not int or reservation["attempt_no"] < 1
                    or type(reservation["page_ordinal"]) is not int or reservation["page_ordinal"] < 1
                    or not isinstance(reservation["request_identity_sha256"], str)
                    or len(reservation["request_identity_sha256"]) != 64
                    or any(ch not in "0123456789abcdef" for ch in reservation["request_identity_sha256"])):
                raise IngestionWriteError("request reservation shape is invalid")
            reservation_row = dict(reservation_id=str(uuid.uuid5(uuid.UUID(run.run_id),
                    f"request-reservation:{reservation['attempt_no']}")),
                run_id=run.run_id, run_revision=run.revision,
                attempt_no=reservation["attempt_no"], page_ordinal=reservation["page_ordinal"],
                request_identity_sha256=reservation["request_identity_sha256"],
                reserved_at=_instant(reservation["reserved_at"], "reserved_at"))
        expected_attempts = tuple(run.attempts)
        expected_pages = tuple(run.pages.values())
        if attempts != expected_attempts:
            raise IngestionWriteError("supplied attempts do not equal evaluated run facts")
        if pages != expected_pages:
            raise IngestionWriteError("supplied pages do not equal evaluated run facts")
        if any(len(e) not in (3, 4) for e in evidence):
            raise IngestionWriteError("evidence is (id, ref, digest[, byte_size])")
        if any(len(e) == 4 and (type(e[3]) is not int or not 0 <= e[3] <= 16 * 1024 * 1024)
                for e in evidence):
            raise IngestionWriteError("evidence byte size exceeds the bounded range")
        evidence_by_ref_digest = {(e[1], e[2]): (e[0], e[3] if len(e) == 4 else None) for e in evidence}
        if len(evidence_by_ref_digest) != len(evidence):
            raise IngestionWriteError("evidence entries must be exact (id, ref, digest) tuples")
        for p in pages:
            if (p.page_ref, p.evidence_digest) not in evidence_by_ref_digest:
                raise IngestionWriteError("page has no matching retained evidence ref/digest")
        if len(evidence) != len(pages):
            raise IngestionWriteError("evidence must exactly cover evaluated pages")
        values = self._run_values(run, created_at)
        values["facts_snapshot"] = {
            "attempts": [_jsonable(a) for a in expected_attempts],
            "pages": [_jsonable(p) for p in expected_pages],
            "evidence": sorted((_jsonable(e) for e in evidence), key=_fact_key),
        }
        values["provenance_snapshot"] = {
            "expected_cohort": _jsonable(run.expected_cohort),
            "freshness_rule": _jsonable(run.freshness_rule),
            "observations": _jsonable(run.observations),
            "conflicts": sorted(run.conflicts),
            "quality_inputs": {"scope_coverage": _jsonable(run.scope_coverage), "freshness": _jsonable(run.freshness)},
        }
        with self.engine.begin() as c:
            from uvm.assessment.policy_lock import lock_policy
            lock_policy(c)
            schedule_row = c.execute(sa.select(collection_schedules).where(
                collection_schedules.c.schedule_id == run.schedule.schedule_id,
                collection_schedules.c.revision == run.schedule.revision)).mappings().first()
            if schedule_row is None:
                raise IngestionWriteError("run schedule revision is not stored")
            # recorded_at identifies when a schedule revision was registered;
            # it is not run identity and must not be compared with created_at.
            schedule_values = self._schedule_values(run.schedule, schedule_row["recorded_at"])
            schedule_values.pop("recorded_at")
            schedule_row_values = dict(schedule_row)
            schedule_row_values.pop("recorded_at", None)
            if not _same(schedule_row_values, schedule_values):
                raise IngestionConflictError("run schedule configuration differs")
            expected_claimed_at = None
            if run.expected_run_id:
                expected = c.execute(sa.select(expected_runs).where(expected_runs.c.expected_run_id == run.expected_run_id)).mappings().first()
                if expected is None:
                    raise IngestionWriteError("expected run is not stored")
                claim = {"schedule_id": run.schedule.schedule_id, "schedule_revision": run.schedule.revision,
                         "scope_key": run.scope_key, "due_at": _instant(run.expected_at, "expected_at")}
                if not _same(expected, claim):
                    raise IngestionConflictError("expected run claim differs")
                if expected["run_id"] not in (None, run.run_id):
                    raise IngestionConflictError("expected run is already claimed by another run")
                if expected["run_id"] is None:
                    result = c.execute(expected_runs.update().where(
                        expected_runs.c.expected_run_id == run.expected_run_id,
                        expected_runs.c.run_id.is_(None), expected_runs.c.state == "due"
                    ).values(run_id=run.run_id, state="started"))
                    if result.rowcount != 1:
                        owner = c.execute(sa.select(expected_runs.c.run_id).where(
                            expected_runs.c.expected_run_id == run.expected_run_id)).scalar_one()
                        if owner != run.run_id:
                            raise IngestionConflictError("expected run was concurrently claimed")
                    else:
                        expected_claimed_at = run.started_at
            history = c.execute(sa.select(collection_runs).where(collection_runs.c.run_id == run.run_id).order_by(collection_runs.c.revision)).mappings().all()
            immutable = ("expected_run_id", "manual_origin", "schedule_id", "schedule_revision", "source_family", "source_account_id", "scope_key", "source_report_id", "expected_at")
            for old in history:
                if not _same(old, {k: values[k] for k in immutable}):
                    raise IngestionConflictError("run identity differs across revisions")
            existing = c.execute(sa.select(collection_runs).where(
                collection_runs.c.run_id == run.run_id,
                collection_runs.c.revision == run.revision)).mappings().first()
            if existing:
                if not _same(existing, values):
                    raise IngestionConflictError("run revision differs")
                if existing["facts_snapshot"] != values["facts_snapshot"]:
                    raise IngestionConflictError("run facts differ")
                if reservation_row is not None:
                    prior_reservation = c.execute(sa.select(collection_request_reservations).where(
                        collection_request_reservations.c.run_id == run.run_id,
                        collection_request_reservations.c.attempt_no == reservation_row["attempt_no"])).mappings().one_or_none()
                    if prior_reservation is None or any(prior_reservation[key] != value
                            for key, value in reservation_row.items() if key != "reservation_id"):
                        raise IngestionConflictError("request reservation replay differs")
                return "duplicate"
            if history and run.revision != history[-1]["revision"] + 1:
                raise IngestionConflictError("run revisions must be strictly ordered")
            if not history and run.revision != 1:
                raise IngestionConflictError("first run revision must be one")
            c.execute(collection_runs.insert().values(**values))
            if reservation_row is not None:
                prior_reservation = c.execute(sa.select(collection_request_reservations).where(
                    collection_request_reservations.c.run_id == run.run_id,
                    collection_request_reservations.c.attempt_no == reservation_row["attempt_no"])).mappings().one_or_none()
                if prior_reservation is None:
                    c.execute(collection_request_reservations.insert().values(**reservation_row))
                elif any(prior_reservation[key] != value for key, value in reservation_row.items()
                         if key != "reservation_id"):
                    raise IngestionConflictError("request reservation replay differs")
            if run.expected_run_id:
                history_rows = c.execute(sa.select(expected_run_events.c.event_id).where(
                    expected_run_events.c.expected_run_id == run.expected_run_id).limit(1)).first()
                if expected_claimed_at is not None:
                    self._append_expected_event(c, run.expected_run_id, "started", run.run_id,
                        run.revision, expected_claimed_at, created_at)
                elif not history_rows:
                    # Adopt a legacy claim at its first observable transition;
                    # no earlier scheduler timestamp is fabricated.
                    self._append_expected_event(c, run.expected_run_id, "started", run.run_id,
                        run.revision, run.started_at, created_at)
                terminal_state = run.state if run.state in {"completed", "failed", "missed"} else None
                if terminal_state:
                    self._append_expected_event(c, run.expected_run_id, terminal_state, run.run_id,
                        run.revision, run.ended_at or run.started_at, created_at)
            for a in attempts:
                av = dict(run_id=run.run_id, run_revision=run.revision, attempt_no=a.attempt_no,
                    started_at=_instant(a.started_at, "attempt.started_at"), finished_at=_instant(a.finished_at, "attempt.finished_at"),
                    response_class=a.response_class, success=a.success,
                    retry_after_microseconds=None if a.retry_after is None else _microseconds(a.retry_after), error_code=a.error_code)
                c.execute(run_attempts.insert().values(**av))
            for p in pages:
                pv = dict(run_id=run.run_id, run_revision=run.revision, ordinal=p.ordinal, cursor=p.cursor,
                    page_ref=p.page_ref, attempt_no=p.attempt_no, response_class=p.response_class, record_count=p.record_count,
                    evidence_digest=p.evidence_digest, next_cursor=p.next_cursor, is_terminal=p.is_terminal,
                    failed=p.failed, request_identity=p.request_identity, report_id=p.report_id, query_scope=p.query_scope,
                    evidence_ref=evidence_by_ref_digest[(p.page_ref, p.evidence_digest)][0])
                c.execute(run_pages.insert().values(**pv))
            for e in evidence:
                if len(e) not in (3, 4): raise IngestionWriteError("evidence is (id, ref, digest[, byte_size])")
                eid, ref, digest = e[:3]
                byte_size = e[3] if len(e) == 4 else None
                if len(digest) != 64 or digest.lower() != digest or any(ch not in "0123456789abcdef" for ch in digest):
                    raise IngestionWriteError("evidence digest must be lowercase sha256")
                c.execute(ingestion_evidence.insert().values(evidence_id=_id(eid, "evidence_id"), schema_version=1,
                    run_id=run.run_id, run_revision=run.revision, evidence_ref=ref, sha256=digest,
                    byte_size=byte_size, kind="page", registered_at=created_at))
            from uvm.persistence.assessment_schema import assessment_audit_events, assessment_policy
            event_id = str(uuid.uuid5(uuid.UUID(run.run_id), f"scanner-checkpoint:{run.revision}"))
            sequence = c.execute(sa.select(sa.func.coalesce(sa.func.max(
                assessment_audit_events.c.event_sequence), 0) + 1)).scalar_one()
            policy_revision = c.execute(sa.select(assessment_policy.c.revision).where(
                assessment_policy.c.policy_id == 1)).scalar_one_or_none() or 0
            c.execute(assessment_audit_events.insert().values(
                event_id=event_id, event_sequence=sequence, actor_id="scanner-collector",
                actor_kind="service", origin="scanner_collection", action="scanner.checkpoint",
                target_id=run.run_id, before_value={"revision": run.revision - 1},
                after_value={"revision": run.revision, "state": run.state,
                    "facts_sha256": hashlib.sha256(_fact_key(values["facts_snapshot"]).encode()).hexdigest(),
                    "provenance_sha256": hashlib.sha256(_fact_key(values["provenance_snapshot"]).encode()).hexdigest()},
                membership_ids=[], membership_revision=run.revision,
                rationale="Durable scanner checkpoint", evidence_ref="scanner-checkpoint:" + event_id,
                policy_revision=policy_revision, identity_revision=0,
                occurred_at=created_at, received_at=created_at,
                correlation_id=run.run_id, command_id=event_id,
                authorization_context={"source_scope": {"source_family": run.source_family,
                    "source_account_id": run.source_account_id, "scope_key": run.scope_key},
                    "service": "scanner-collector"}))
        return "created"

    def read_run(self, run_id, revision=None):
        _id(run_id, "run_id")
        with self.engine.connect() as c:
            q = sa.select(collection_runs).where(collection_runs.c.run_id == run_id)
            if revision is not None: q = q.where(collection_runs.c.revision == revision)
            row = c.execute(q.order_by(collection_runs.c.revision.desc())).mappings().first()
            if not row: return None
            attempts = c.execute(sa.select(run_attempts).where(run_attempts.c.run_id == run_id, run_attempts.c.run_revision == row.revision).order_by(run_attempts.c.attempt_no)).mappings().all()
            pages = c.execute(sa.select(run_pages).where(run_pages.c.run_id == run_id, run_pages.c.run_revision == row.revision).order_by(run_pages.c.ordinal)).mappings().all()
            evidence = c.execute(sa.select(ingestion_evidence).where(ingestion_evidence.c.run_id == run_id, ingestion_evidence.c.run_revision == row.revision).order_by(ingestion_evidence.c.evidence_id)).mappings().all()
            return {"run": dict(row), "attempts": [dict(x) for x in attempts], "pages": [dict(x) for x in pages], "evidence": [dict(x) for x in evidence]}

    def read_request_reservations(self, run_id):
        _id(run_id, "run_id")
        with self.engine.connect() as connection:
            rows = connection.execute(sa.select(collection_request_reservations).where(
                collection_request_reservations.c.run_id == run_id).order_by(
                    collection_request_reservations.c.attempt_no)).mappings().all()
        return [dict(row) for row in rows]

    def save_import_context(self, values: dict):
        required = ("context_key", "revision", "source_family", "source_account_id", "scope_key", "parser_config_version", "product_ref", "engagement_ref", "mapping_history", "registered_at")
        if any(k not in values for k in required): raise IngestionWriteError("incomplete import context")
        values = dict(values); values["registered_at"] = _instant(values["registered_at"], "registered_at")
        with self.engine.begin() as c:
            registration_id = values.get("g1_registration_id") or values.get("registration_id")
            verification_id = values.get("g1_verification_id") or values.get("verification_id")
            binding_id = values.get("g1_test_binding_id") or values.get("test_binding_id")
            if registration_id or verification_id or binding_id:
                if not (registration_id and verification_id):
                    raise IngestionWriteError("G2 context needs exact G1 registration and verification")
                registration = c.execute(sa.select(ce_context_registrations).where(
                    ce_context_registrations.c.registration_id == registration_id)).mappings().first()
                verification = c.execute(sa.select(ce_context_verifications).where(
                    ce_context_verifications.c.verification_id == verification_id,
                    ce_context_verifications.c.registration_id == registration_id)).mappings().first()
                if not registration or not verification:
                    raise IngestionConflictError("G1 context registration/verification mismatch")
                if values["context_key"] != registration["context_key"]:
                    raise IngestionConflictError("G1 context key mismatch")
                if values.get("deployment_key") not in (None, registration["deployment_key"]):
                    raise IngestionConflictError("G1 deployment context mismatch")
                if verification["deployment_key"] != registration["deployment_key"]:
                    raise IngestionConflictError("G1 verification deployment mismatch")
                if values.get("deployment_config_revision") not in (None, verification["deployment_config_revision"]):
                    raise IngestionConflictError("G1 deployment configuration mismatch")
                if values.get("product_ref") not in (str(registration["product_id"]), registration["product_id"]):
                    raise IngestionConflictError("Product does not match G1 registration")
                if values.get("engagement_ref") not in (str(registration["engagement_id"]), registration["engagement_id"]):
                    raise IngestionConflictError("Engagement does not match G1 registration")
                caller_test_id = values.get("test_id")
                values.update(g1_registration_id=registration_id, g1_verification_id=verification_id,
                              deployment_key=registration["deployment_key"],
                              deployment_config_revision=verification["deployment_config_revision"])
                if binding_id:
                    binding = c.execute(sa.select(ce_context_test_bindings).where(
                        ce_context_test_bindings.c.binding_id == binding_id,
                        ce_context_test_bindings.c.registration_id == registration_id)).mappings().first()
                    if (not binding or binding["deployment_key"] != registration["deployment_key"]
                            or binding["deployment_config_revision"] != verification["deployment_config_revision"]):
                        raise IngestionConflictError("G1 Test binding does not match registration")
                    if caller_test_id is not None and caller_test_id != binding["test_id"]:
                        raise IngestionConflictError("caller Test ID is not the bound G1 Test")
                    values["test_id"] = binding["test_id"]
                    values["g1_test_binding_id"] = binding_id
                else:
                    if caller_test_id is not None and caller_test_id != registration["test_id"]:
                        raise IngestionConflictError("caller Test ID is not registered for G1 context")
                    values["test_id"] = registration["test_id"]
            else:
                if values.get("test_id") is not None:
                    raise IngestionConflictError("caller Test ID lacks a G1 registration/binding")
                values.setdefault("g1_registration_id", None)
                values.setdefault("g1_verification_id", None)
                values.setdefault("g1_test_binding_id", None)
                values.setdefault("deployment_key", None)
                values.setdefault("deployment_config_revision", None)
            for alias in ("registration_id", "verification_id", "test_binding_id"):
                values.pop(alias, None)
            row = c.execute(sa.select(import_context_revisions).where(
                import_context_revisions.c.context_key == values["context_key"],
                import_context_revisions.c.revision == values["revision"])).mappings().first()
            if row:
                if not _same(row, values):
                    raise IngestionConflictError("import context revision differs")
                return "duplicate"
            history = c.execute(sa.select(import_context_revisions).where(
                import_context_revisions.c.context_key == values["context_key"]
            ).order_by(import_context_revisions.c.revision)).mappings().all()
            if history:
                if values["revision"] != history[-1]["revision"] + 1:
                    raise IngestionConflictError("import context revisions must be strictly ordered")
                immutable = ("source_family", "source_account_id", "scope_key")
                if any(old[key] != values[key] for old in history for key in immutable):
                    raise IngestionConflictError("import context ownership differs across revisions")
            elif values["revision"] != 1:
                raise IngestionConflictError("first import context revision must be one")
            c.execute(import_context_revisions.insert().values(**values))
        return "created"

    def read_import_context(self, context_key, revision=None):
        with self.engine.connect() as c:
            q = sa.select(import_context_revisions).where(import_context_revisions.c.context_key == context_key)
            if revision is not None: q = q.where(import_context_revisions.c.revision == revision)
            row = c.execute(q.order_by(import_context_revisions.c.revision.desc())).mappings().first()
            return None if row is None else dict(row)
