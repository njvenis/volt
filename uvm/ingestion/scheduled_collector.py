"""Fixture-backed scheduled source collection for the G2 vertical slice.

The clients in this module deliberately model source-shaped pages only.  They
do not encode live Qualys or Sysdig pagination, scope, timestamp, or identity
semantics.  Raw bytes are registered as page evidence before their records are
turned into ``SourceObservationV1`` values.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import secrets
import stat
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Callable, Mapping, Protocol, Sequence

import sqlalchemy as sa

from uvm.identity.observations import (
    MISSING_NOT_SUPPLIED,
    MissingField,
    SourceObservationV1,
)
from uvm.ingestion.run import (
    AttemptFact,
    CollectionRunV1,
    CollectionScheduleV1,
    ExpectedRunV1,
    PageFact,
    QualityResult,
    RUN_COMPLETED,
    RUN_FAILED,
    RUN_PARTIAL,
    RUN_RUNNING,
)
from uvm.persistence.ingestion_schema import collection_schedules
from uvm.persistence.ingestion_store import IngestionConflictError

UTC = timezone.utc
_NAMESPACE = uuid.UUID("f1d10a2b-e9b4-4c4b-9f8b-6c7f3c0d3e7d")


@dataclass(frozen=True)
class FixtureResponse:
    """One configured response, including failures and raw response bytes."""

    raw: bytes
    response_class: str = "200"
    records: tuple[Mapping[str, object], ...] = ()
    next_cursor: str | None = None
    terminal: bool = False
    retry_after: timedelta | None = None
    error_code: str | None = None
    success: bool = True
    report_id: str | None = None
    query_scope: str | None = None


class SourceClient(Protocol):
    source_family: str

    def fetch(self, cursor: str | None) -> FixtureResponse:
        ...


class FixtureEvidenceSink(Protocol):
    """Durable byte retention used by the configured fixture adapter."""

    def put(self, ref: str, raw: bytes, digest: str) -> None:
        ...

    def read(self, ref: str, digest: str) -> bytes:
        ...


class FileFixtureEvidenceSink:
    """Small content-addressed sink for offline fixture evidence.

    The reference is deliberately the caller's stable page reference; the
    digest is checked on both write and read so a replay cannot silently swap
    bytes behind an existing page fact.
    """

    def __init__(self, root: str | Path):
        self.root = Path(root)

    def _path(self, ref: str) -> Path:
        return self.root / hashlib.sha256(ref.encode("utf-8")).hexdigest()

    def _open_root(self) -> int:
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        directory = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        info = os.fstat(directory)
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) != 0o700):
            os.close(directory)
            raise ValueError("fixture evidence directory is unsafe")
        return directory

    def put(self, ref: str, raw: bytes, digest: str) -> None:
        if not isinstance(raw, bytes) or len(raw) > 16 * 1024 * 1024:
            raise ValueError("fixture evidence exceeds the bounded byte limit")
        if _digest(raw) != digest:
            raise ValueError("fixture evidence digest does not match bytes")
        directory = self._open_root()
        final_name = self._path(ref).name
        temporary = ".stage-" + secrets.token_hex(16)
        try:
            fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                0o600, dir_fd=directory)
            try:
                view = memoryview(raw)
                while view:
                    written = os.write(fd, view)
                    if written <= 0:
                        raise OSError("short evidence write")
                    view = view[written:]
                os.fsync(fd)
            finally:
                os.close(fd)
            try:
                os.link(temporary, final_name, src_dir_fd=directory,
                    dst_dir_fd=directory, follow_symlinks=False)
            except FileExistsError:
                existing = os.open(final_name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=directory)
                try:
                    info = os.fstat(existing)
                    if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                            or stat.S_IMODE(info.st_mode) != 0o600 or info.st_size != len(raw)):
                        raise ValueError("conflicting or unsafe fixture evidence object")
                    chunks, remaining = [], len(raw) + 1
                    while remaining:
                        part = os.read(existing, min(65536, remaining))
                        if not part:
                            break
                        chunks.append(part); remaining -= len(part)
                    if b"".join(chunks) != raw:
                        raise ValueError("conflicting fixture evidence object")
                finally:
                    os.close(existing)
            os.unlink(temporary, dir_fd=directory)
            os.fsync(directory)
        except BaseException:
            try:
                os.unlink(temporary, dir_fd=directory)
            except FileNotFoundError:
                pass
            raise
        finally:
            os.close(directory)

    def read(self, ref: str, digest: str) -> bytes:
        directory = self._open_root()
        try:
            fd = os.open(self._path(ref).name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=directory)
            try:
                info = os.fstat(fd)
                if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                        or stat.S_IMODE(info.st_mode) != 0o600
                        or info.st_size > 16 * 1024 * 1024):
                    raise ValueError("fixture evidence object is unsafe")
                chunks, remaining = [], info.st_size + 1
                while remaining:
                    part = os.read(fd, min(65536, remaining))
                    if not part:
                        break
                    chunks.append(part); remaining -= len(part)
                raw = b"".join(chunks)
                if len(raw) != info.st_size:
                    raise ValueError("fixture evidence object changed while reading")
            finally:
                os.close(fd)
        finally:
            os.close(directory)
        if _digest(raw) != digest:
            raise ValueError(f"fixture evidence digest mismatch for {ref}")
        return raw


class MemoryFixtureEvidenceSink:
    """Deterministic sink for unit tests; its API matches the durable sink."""

    def __init__(self):
        self._values: dict[str, bytes] = {}

    def put(self, ref: str, raw: bytes, digest: str) -> None:
        if _digest(raw) != digest:
            raise ValueError("fixture evidence digest does not match bytes")
        prior = self._values.get(ref)
        if prior is not None and prior != raw:
            raise ValueError(f"conflicting fixture evidence for {ref}")
        self._values[ref] = raw

    def read(self, ref: str, digest: str) -> bytes:
        raw = self._values[ref]
        if _digest(raw) != digest:
            raise ValueError(f"fixture evidence digest mismatch for {ref}")
        return raw


class ConfiguredFixtureClient:
    """A source-shaped client with explicit per-cursor response scripts."""

    source_family = "fixture"

    def __init__(self, responses: Mapping[str | None, Sequence[FixtureResponse]]):
        self._responses = {cursor: list(values) for cursor, values in responses.items()}
        self.calls: list[str | None] = []

    def fetch(self, cursor: str | None) -> FixtureResponse:
        self.calls.append(cursor)
        values = self._responses.get(cursor)
        if not values:
            raise KeyError(f"no fixture response configured for cursor {cursor!r}")
        return values.pop(0)


class QualysFixtureClient(ConfiguredFixtureClient):
    source_family = "qualys"


class SysdigFixtureClient(ConfiguredFixtureClient):
    source_family = "sysdig"


def _digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _uuid(value: str) -> str:
    return str(uuid.uuid5(_NAMESPACE, value))


def _parse_time(value: object) -> datetime | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError("fixture observed_at must be an ISO timestamp")
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("fixture observed_at must be timezone-aware")
    return parsed.astimezone(UTC)


def _observation(
    *, run: CollectionRunV1, ordinal: int, record: Mapping[str, object],
    page_ref: str, digest: str, collected_at: datetime, status: str,
) -> SourceObservationV1:
    names = (
        "observed_at", "native_id_scheme", "native_id_authority", "native_id_value",
        "asset_locator", "component_locator", "source_record_locator", "source_rating",
        "vulnerability_refs", "source_first_seen_at", "report_id", "coverage_scope",
    )
    observed_at = _parse_time(record.get("observed_at"))
    native = record.get("native_id_value")
    if native is None:
        native = record.get("qid") or record.get("vulnerability_id")
    refs = record.get("vulnerability_refs")
    if refs is not None:
        refs = tuple(str(item) for item in refs)  # type: ignore[arg-type]
    values = {
        "observed_at": observed_at,
        "native_id_scheme": record.get("native_id_scheme"),
        "native_id_authority": record.get("native_id_authority"),
        "native_id_value": None if native is None else str(native),
        "asset_locator": record.get("asset_locator"),
        "component_locator": record.get("component_locator"),
        "source_record_locator": record.get("source_record_locator"),
        "source_rating": record.get("source_rating"),
        "vulnerability_refs": refs,
        "source_first_seen_at": _parse_time(record.get("source_first_seen_at")),
        "report_id": record.get("report_id"),
        "coverage_scope": record.get("coverage_scope"),
    }
    missing = tuple(MissingField(name, MISSING_NOT_SUPPLIED)
                    for name in names if values[name] is None)
    return SourceObservationV1(
        schema_version=1,
        observation_id=_uuid(f"observation:{run.run_id}:{ordinal}"),
        revision=1,
        source_family=run.source_family,
        source_account_id=run.source_account_id,
        run_id=run.run_id,
        source_record_ordinal=ordinal,
        collection_status=status,
        collected_at=collected_at,
        raw_evidence_ref=page_ref,
        raw_evidence_sha256=digest,
        missing_fields=missing,
        observed_at=values["observed_at"],
        native_id_scheme=values["native_id_scheme"],
        native_id_authority=values["native_id_authority"],
        native_id_value=values["native_id_value"],
        asset_locator=values["asset_locator"],
        component_locator=values["component_locator"],
        source_record_locator=values["source_record_locator"],
        source_rating=values["source_rating"],
        vulnerability_refs=values["vulnerability_refs"],
        source_first_seen_at=values["source_first_seen_at"],
        report_id=values["report_id"],
        coverage_scope=values["coverage_scope"],
    )


class ScheduledCollector:
    """Run one schedule occurrence and persist its complete accounting."""

    def __init__(self, store, schedule: CollectionScheduleV1,
                 client: SourceClient, *, clock: Callable[[], datetime],
                 wait: Callable[[timedelta], None] | None = None,
                 evidence_sink: FixtureEvidenceSink | None = None):
        if client.source_family != schedule.source_family:
            raise ValueError("client and schedule source families differ")
        self.store = store
        self.schedule = schedule
        self.client = client
        self.clock = clock
        self.wait = wait or (lambda duration: time.sleep(duration.total_seconds()))
        if evidence_sink is None:
            raise ValueError("collector requires an explicit evidence sink")
        self.evidence_sink = evidence_sink

    @staticmethod
    def _envelope(raw: bytes) -> tuple[tuple[Mapping[str, object], ...], str | None, bool] | None:
        """Decode only the explicitly synthetic fixture envelope."""
        try:
            value = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return None
        if not isinstance(value, dict) or value.get("fixture_schema") != "uvm.synthetic.fixture.v1":
            return None
        if "records" not in value or "terminal" not in value:
            raise ValueError("synthetic fixture requires records and terminal")
        records = value["records"]
        if not isinstance(records, list) or any(not isinstance(item, dict) for item in records):
            raise ValueError("synthetic fixture envelope records must be objects")
        next_cursor = value.get("next_cursor")
        if next_cursor is not None and (not isinstance(next_cursor, str) or not next_cursor):
            raise ValueError("synthetic fixture next_cursor must be a non-empty string")
        terminal = value["terminal"]
        if not isinstance(terminal, bool):
            raise ValueError("synthetic fixture terminal must be boolean")
        if terminal and next_cursor is not None:
            raise ValueError("synthetic fixture terminal page cannot have next_cursor")
        if not terminal and next_cursor is None:
            raise ValueError("synthetic fixture nonterminal page requires next_cursor")
        return tuple(records), next_cursor, terminal

    @staticmethod
    def _instant(value: object) -> datetime | None:
        if value is None:
            return None
        if isinstance(value, datetime):
            return (value.replace(tzinfo=UTC) if value.tzinfo is None
                    else value.astimezone(UTC))
        if not isinstance(value, str):
            raise ValueError("stored timestamp is not an ISO timestamp")
        return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(UTC)

    @staticmethod
    def _duration(value: object) -> timedelta | None:
        if value is None:
            return None
        if not isinstance(value, dict) or set(value) != {"microseconds"}:
            raise ValueError("stored duration is malformed")
        return timedelta(microseconds=int(value["microseconds"]))

    def _restore_run(self, stored: Mapping[str, object], run_id: str) -> CollectionRunV1:
        row = stored["run"]
        facts = row["facts_snapshot"]
        provenance = row["provenance_snapshot"]
        attempts = tuple(
            AttemptFact(
                item["attempt_no"], self._instant(item["started_at"]),
                self._instant(item.get("finished_at")), item["response_class"],
                item["success"], self._duration(item.get("retry_after")), item.get("error_code"),
            ) for item in facts["attempts"]
        )
        pages = tuple(
            PageFact(
                item["ordinal"], item.get("cursor"), item["page_ref"], item["attempt_no"],
                item["response_class"], item["record_count"], item["evidence_digest"],
                item.get("next_cursor"), item.get("is_terminal", False), item.get("failed", False),
                item.get("request_identity", ""), item.get("report_id"), item.get("query_scope"),
            ) for item in facts["pages"]
        )
        observations = []
        for item in provenance.get("observations", []):
            values = dict(item)
            values["missing_fields"] = tuple(MissingField(**field) for field in values.get("missing_fields", []))
            values["vulnerability_refs"] = (None if values.get("vulnerability_refs") is None
                                              else tuple(values["vulnerability_refs"]))
            for name in ("collected_at", "observed_at", "source_first_seen_at"):
                values[name] = self._instant(values.get(name))
            observations.append(SourceObservationV1(**values))
        return CollectionRunV1.from_facts(
            schedule=self.schedule, run_id=run_id, revision=int(row["revision"]),
            expected_run_id=row.get("expected_run_id"), manual_origin=row.get("manual_origin"),
            attempts=attempts, pages=pages, observations=observations,
            expected_at=self._instant(row.get("expected_at")),
            started_at=self._instant(row.get("started_at")), ended_at=self._instant(row.get("ended_at")),
            state=row["state"],
            scope_coverage=QualityResult(row["coverage_status"], tuple(row["coverage_reasons"])),
            freshness=QualityResult(row["freshness_status"], tuple(row["freshness_reasons"])),
        )

    def _check_attribution(self, stored: Mapping[str, object] | None,
                           due_at: datetime, expected_id: str) -> None:
        """Reject a stored run that belongs to another schedule occurrence.

        Run facts are restored under ``self.schedule``, so a run recorded for
        another source, account, scope, revision or due time must never be
        resumed or replayed here.
        """
        if stored is None:
            return
        row = stored["run"]
        schedule = self.schedule
        actual = (row["schedule_id"], row["schedule_revision"], row["source_family"],
                  row["source_account_id"], row["scope_key"], row.get("expected_run_id"),
                  row.get("manual_origin"), self._instant(row.get("expected_at")))
        wanted = (schedule.schedule_id, schedule.revision, schedule.source_family,
                  schedule.source_account_id, schedule.scope_key, expected_id, None, due_at)
        if actual != wanted:
            raise IngestionConflictError(
                "stored run belongs to another schedule occurrence or scope")

    def _resume_or_start(self, due_at: datetime, run_id: str, expected_id: str,
                         stored: Mapping[str, object] | None) -> CollectionRunV1:
        if stored is None:
            return CollectionRunV1.from_facts(
                schedule=self.schedule, run_id=run_id, revision=1,
                expected_run_id=expected_id, expected_at=due_at,
                state="running", started_at=self.clock().astimezone(UTC),
            )
        run = self._restore_run(stored, run_id)
        if run.state == RUN_COMPLETED:
            return run
        run.revision += 1
        run.state = "running"
        run.ended_at = None
        return run

    @staticmethod
    def _replace_pending_page(run: CollectionRunV1, page: PageFact) -> None:
        key = (page.ordinal, page.cursor)
        prior = run.pages.get(key)
        if prior is not None:
            if not prior.failed:
                raise ValueError("accepted page cannot be replaced")
            del run.pages[key]
        result = run.replay_page(page)
        if result.status == "conflict":
            raise ValueError("page replacement conflicted")

    def _read_page_records(self, page: PageFact) -> tuple[Mapping[str, object], ...]:
        raw = self.evidence_sink.read(page.page_ref, page.evidence_digest)
        decoded = self._envelope(raw)
        if decoded is None:
            raise ValueError("retained page evidence is not a supported fixture envelope")
        records, next_cursor, terminal = decoded
        if (next_cursor, terminal) != (page.next_cursor, page.is_terminal):
            raise ValueError("retained page evidence contradicts its page fact")
        if len(records) != page.record_count:
            raise ValueError("retained page evidence contradicts its record count")
        return records

    def _wait_until(self, earliest: datetime, deadline: datetime) -> bool:
        now = self.clock().astimezone(UTC)
        if earliest > deadline or now > deadline:
            return False
        delay = earliest - now
        if delay > timedelta(0):
            monotonic_end = time.monotonic() + delay.total_seconds()
            self.wait(delay)
            if self.clock().astimezone(UTC) < earliest:
                remaining = monotonic_end - time.monotonic()
                if remaining > 0:
                    time.sleep(remaining)
        return self.clock().astimezone(UTC) <= deadline

    def _checkpoint(self, run, evidence, *, at: datetime, advance: bool = True,
                    reservation: dict | None = None) -> None:
        """Persist the current revision before another request or parsing."""
        # A byte reference/digest identifies the retained source bytes, but it
        # is not the identity of an immutable registration.  Every checkpoint
        # is a new run revision and therefore needs its own evidence row ID;
        # keeping the ref/digest stable preserves replay and conflict checks.
        revision_evidence = []
        for item in evidence:
            _, ref, digest = item[:3]
            size = item[3] if len(item) == 4 else len(self.evidence_sink.read(ref, digest))
            revision_evidence.append((_uuid(
                f"evidence:{run.run_id}:revision:{run.revision}:{ref}:{digest}"), ref, digest, size))
        revision_evidence = tuple(revision_evidence)
        self.store.save_run_transition(
            run, run.attempts, run.pages.values(), revision_evidence, at,
            reservation=reservation,
        )
        if advance:
            run.revision += 1

    def _registered_at(self) -> datetime | None:
        with self.store.engine.connect() as c:
            value = c.execute(sa.select(collection_schedules.c.recorded_at).where(
                collection_schedules.c.schedule_id == self.schedule.schedule_id,
                collection_schedules.c.revision == self.schedule.revision)).scalar()
        return self._instant(value)

    def _register_schedule(self, registered_at: datetime) -> None:
        """Register the schedule revision once and reuse it for later occurrences.

        ``recorded_at`` is the collector clock at first registration, not the
        due time of an occurrence.  Reusing the stored value lets the store's
        full-row comparison still reject changed configuration at the same
        revision.
        """
        recorded_at = self._registered_at()
        if recorded_at is not None:
            self.store.save_schedule(self.schedule, recorded_at)
            return
        try:
            self.store.save_schedule(self.schedule, registered_at)
        except (IngestionConflictError, sa.exc.IntegrityError):
            # A concurrent first registration won, either before our read of
            # the row or between our read and insert (unique violation).
            # Compare once against the stored registration; changed
            # configuration still conflicts.
            recorded_at = self._registered_at()
            if recorded_at is None:
                raise
            self.store.save_schedule(self.schedule, recorded_at)

    def collect(self, due_at: datetime, *, run_id: str | None = None) -> CollectionRunV1:
        registered_at = self.clock().astimezone(UTC)
        due_at = due_at.astimezone(UTC)
        expected_id = _uuid(f"expected:{self.schedule.schedule_id}:{self.schedule.revision}:{due_at.isoformat()}")
        run_id = run_id or _uuid(f"run:{expected_id}")
        # Attribution is checked before any registration, expectation or fetch.
        stored = self.store.read_run(run_id)
        self._check_attribution(stored, due_at, expected_id)
        self._register_schedule(registered_at)
        expected = ExpectedRunV1(
            expected_id, self.schedule.schedule_id, self.schedule.revision,
            self.schedule.scope_key, due_at, due_at + self.schedule.expected_run_grace,
        )
        # The expectation is durable before the first source request.
        self.store.save_expected_run(expected)
        run = self._resume_or_start(due_at, run_id, expected_id, stored)
        if run.state == RUN_COMPLETED:
            if not run.pages or run.quality[0].status != "complete":
                raise ValueError("completed run has no complete retained page chain")
            for page in sorted(run.pages.values(), key=lambda item: item.ordinal):
                if page.failed:
                    raise ValueError("completed run retains a failed page")
                self._read_page_records(page)
            return run
        deadline = run.started_at + self.schedule.total_deadline
        evidence = [
            (_uuid(f"evidence:{run_id}:{page.page_ref}:{page.evidence_digest}"), page.page_ref, page.evidence_digest)
            for page in sorted(run.pages.values(), key=lambda item: item.ordinal)
        ]
        reservations = (self.store.read_request_reservations(run_id)
            if hasattr(self.store, "read_request_reservations") else [])
        raw_pages = []
        for page in sorted(run.pages.values(), key=lambda item: item.ordinal):
            if not page.failed:
                raw_pages.append((page.ordinal, page.page_ref, page.evidence_digest, self._read_page_records(page)))
        pending = next((page for page in sorted(run.pages.values(), key=lambda item: item.ordinal)
                        if page.failed), None)
        if pending is not None:
            cursor, ordinal = pending.cursor, pending.ordinal
        elif run.pages:
            last = max(run.pages.values(), key=lambda item: item.ordinal)
            cursor, ordinal = last.next_cursor, last.ordinal + 1
        else:
            cursor, ordinal = None, 1
        failed = False
        completed_from_receipt = bool(
            pending is None and run.pages
            and max(run.pages.values(), key=lambda item: item.ordinal).is_terminal
        )
        if pending is not None and run.attempts[-1].success:
            if pending.attempt_no != run.attempts[-1].attempt_no:
                raise ValueError("successful receipt does not match last attempt")
            raw = self.evidence_sink.read(pending.page_ref, pending.evidence_digest)
            envelope = self._envelope(raw)
            if envelope is None:
                raise ValueError("successful receipt has invalid retained evidence")
            records, next_cursor, terminal = envelope
            page = PageFact(
                ordinal, cursor, pending.page_ref, pending.attempt_no,
                pending.response_class, len(records), pending.evidence_digest,
                next_cursor=next_cursor, is_terminal=terminal,
                request_identity=pending.request_identity,
                report_id=pending.report_id, query_scope=pending.query_scope,
            )
            self._replace_pending_page(run, page)
            self._checkpoint(run, evidence, at=self.clock().astimezone(UTC))
            raw_pages.append((ordinal, page.page_ref, page.evidence_digest, records))
            completed_from_receipt = terminal
            if not terminal:
                cursor, ordinal = next_cursor, ordinal + 1
                pending = None
        while not completed_from_receipt:
            response = None
            previous_attempt = max(
                (page.attempt_no for page in run.pages.values()
                 if not page.failed and page.ordinal < ordinal), default=0,
            )
            prior_reserved = sum(1 for item in reservations if item["page_ordinal"] == ordinal
                and item["attempt_no"] > previous_attempt)
            page_attempt = max(len(run.attempts) - previous_attempt, prior_reserved) if pending is not None else prior_reserved
            if pending is not None and page_attempt:
                last_attempt = run.attempts[-1]
                if last_attempt.attempt_no != pending.attempt_no:
                    raise ValueError("pending page does not match last attempt")
                retry_after = last_attempt.retry_after or timedelta(0)
                earliest = (last_attempt.finished_at or last_attempt.started_at) + retry_after
                if not self._wait_until(earliest, deadline):
                    failed = True
                    break
            while page_attempt < self.schedule.max_page_attempts:
                now = self.clock().astimezone(UTC)
                if now > deadline or len(run.attempts) >= self.schedule.max_attempts:
                    failed = True
                    break
                page_attempt += 1
                attempt_no = max([len(run.attempts), *(int(item["attempt_no"]) for item in reservations)], default=0) + 1
                attempt_started = self.clock().astimezone(UTC)
                request_identity = json.dumps({"source_family": run.source_family,
                    "source_account_id": run.source_account_id, "scope_key": run.scope_key,
                    "run_id": run.run_id, "run_revision": run.revision,
                    "schedule_revision": run.schedule.revision, "page_ordinal": ordinal,
                    "cursor": cursor}, sort_keys=True, separators=(",", ":"),
                    ensure_ascii=False, allow_nan=False).encode("utf-8")
                reservation = {"attempt_no": attempt_no, "page_ordinal": ordinal,
                    "request_identity_sha256": hashlib.sha256(request_identity).hexdigest(),
                    "reserved_at": attempt_started}
                self._checkpoint(run, evidence, at=attempt_started, reservation=reservation)
                reservations.append({**reservation, "run_revision": run.revision - 1})
                received_response = True
                try:
                    response = self.client.fetch(cursor)
                except Exception:  # no received HTTP object exists on transport failure
                    received_response = False
                    response = FixtureResponse(b"", "transport_error",
                        error_code="other", success=False)
                attempt_finished = self.clock().astimezone(UTC)
                run.record_attempt(AttemptFact(
                    attempt_no, attempt_started, attempt_finished,
                    response.response_class, response.success,
                    retry_after=response.retry_after, error_code=response.error_code,
                ))
                if not received_response:
                    self._checkpoint(run, evidence, at=attempt_finished)
                    failed = True
                    break
                digest = _digest(response.raw)
                attempt_ref = f"fixture://{self.schedule.source_family}/{run_id}/page/{ordinal}/attempt/{attempt_no}/{digest}"
                self.evidence_sink.put(attempt_ref, response.raw, digest)
                ref = attempt_ref
                self.evidence_sink.put(ref, response.raw, digest)
                prior_page = run.pages.get((ordinal, cursor))
                if prior_page is not None:
                    evidence = [item for item in evidence if item[1] != prior_page.page_ref]
                evidence.append((_uuid(f"evidence:{run_id}:{ref}:{digest}"), ref, digest, len(response.raw)))
                # A received response is first recorded as a pending/failed
                # page.  Parsing and pagination interpretation happen only
                # after this immutable receipt checkpoint.
                receipt_page = PageFact(
                    ordinal, cursor, ref, attempt_no, response.response_class, 0,
                    digest, failed=True, request_identity=hashlib.sha256(request_identity).hexdigest(),
                    report_id=response.report_id, query_scope=response.query_scope,
                )
                self._replace_pending_page(run, receipt_page)
                self._checkpoint(run, evidence, at=attempt_finished)
                if response.success:
                    try:
                        envelope = self._envelope(response.raw)
                    except ValueError:
                        envelope = None
                    records: tuple[Mapping[str, object], ...] = ()
                    next_cursor = None
                    terminal = False
                    valid = envelope is not None
                    if valid:
                        records, next_cursor, terminal = envelope
                    if not valid:
                        run.conflicts.append(f"fixture-bytes:{ordinal}:invalid-envelope")
                        failed = True
                        break
                    page = PageFact(
                        ordinal, cursor, ref, attempt_no, response.response_class,
                        len(records), digest, next_cursor=next_cursor,
                        is_terminal=terminal, request_identity=hashlib.sha256(request_identity).hexdigest(),
                        report_id=response.report_id, query_scope=response.query_scope,
                    )
                    self._replace_pending_page(run, page)
                    # Replace the pending receipt in the next cumulative
                    # revision; the original receipt remains immutable.
                    self._checkpoint(run, evidence, at=attempt_finished)
                    raw_pages = [item for item in raw_pages if item[0] != ordinal]
                    raw_pages.append((ordinal, ref, digest, records))
                    break
                if attempt_finished >= deadline:
                    failed = True
                    break
                retry_after = response.retry_after or timedelta(0)
                if not self._wait_until(attempt_finished + retry_after, deadline):
                    failed = True
                    break
                if retry_after == timedelta(0):
                    time.sleep(0)
            if response is None or not response.success:
                failed = True
                break
            if failed or self.clock().astimezone(UTC) > deadline:
                failed = True
                break
            page = run.pages[(ordinal, cursor)]
            next_cursor = page.next_cursor
            terminal = page.is_terminal
            if terminal:
                break
            if next_cursor is None:
                failed = True
                break
            cursor = next_cursor
            ordinal += 1
            pending = None

        ended = self.clock().astimezone(UTC)
        recorded_attempts = {item.attempt_no for item in run.attempts}
        unresolved_reservation = any(int(item["attempt_no"]) not in recorded_attempts
            for item in reservations)
        status = "partial" if failed or unresolved_reservation else "success"
        row_ordinal = 1
        run.observations = []
        for _, ref, digest, records in raw_pages:
            for record in records:
                run.observations.append(_observation(
                    run=run, ordinal=row_ordinal, record=record, page_ref=ref,
                    digest=digest, collected_at=ended, status=status,
                ))
                row_ordinal += 1
        run.ended_at = None if unresolved_reservation else ended
        run.state = RUN_RUNNING if unresolved_reservation else (RUN_PARTIAL if failed else RUN_COMPLETED)
        self._checkpoint(run, evidence, at=ended, advance=False)
        return run


__all__ = [
    "ConfiguredFixtureClient", "FileFixtureEvidenceSink", "FixtureEvidenceSink",
    "FixtureResponse", "MemoryFixtureEvidenceSink", "QualysFixtureClient",
    "ScheduledCollector", "SourceClient", "SysdigFixtureClient",
]
