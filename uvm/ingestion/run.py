"""Versioned, source-neutral collection-run accounting.

This module deliberately has no HTTP, scheduler-worker, database, CE or
scanner-specific behaviour.  Adapters retain facts here; this contract only
accounts for bounded attempts/pages and derives honest run quality.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Iterable, Optional

from uvm.identity.observations import SourceObservationV1

SCHEMA_VERSION = 1
RETRIEVAL_COMPLETE, RETRIEVAL_PARTIAL, RETRIEVAL_FAILED = "complete", "partial", "failed"
COVERAGE_COMPLETE, COVERAGE_PARTIAL, COVERAGE_UNKNOWN = "complete", "partial", "unknown"
FRESHNESS_FRESH, FRESHNESS_STALE, FRESHNESS_UNKNOWN = "fresh", "stale", "unknown"
RUN_EXPECTED, RUN_RUNNING, RUN_COMPLETED = "expected", "running", "completed"
RUN_PARTIAL, RUN_FAILED, RUN_MISSED = "partial", "failed", "missed"
UTC = timezone.utc


def _utc(value: datetime, name: str) -> None:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{name} must be timezone-aware")


def _positive(value: int, name: str) -> None:
    if not isinstance(value, int) or value < 1:
        raise ValueError(f"{name} must be a positive integer")


@dataclass(frozen=True)
class CollectionScheduleV1:
    schedule_id: str
    revision: int
    source_family: str
    source_account_id: str
    scope_key: str
    enabled: bool = True
    timezone_name: str = "UTC"
    cadence: str = "daily"
    expected_run_grace: timedelta = timedelta(hours=1)
    max_attempts: int = 3
    max_page_attempts: int = 3
    total_deadline: timedelta = timedelta(hours=2)
    freshness_rule_ref: str = "unconfigured"

    def __post_init__(self) -> None:
        _positive(self.revision, "revision")
        _positive(self.max_attempts, "max_attempts")
        _positive(self.max_page_attempts, "max_page_attempts")
        if self.expected_run_grace < timedelta(0) or self.total_deadline <= timedelta(0):
            raise ValueError("grace/deadline have invalid duration")
        if not self.source_family or not self.source_account_id or not self.scope_key:
            raise ValueError("source family, account and scope are required")


@dataclass(frozen=True)
class ExpectedRunV1:
    expected_run_id: str
    schedule_id: str
    schedule_revision: int
    scope_key: str
    due_at: datetime
    grace_deadline: datetime
    state: str = "due"
    run_id: Optional[str] = None

    def __post_init__(self) -> None:
        _utc(self.due_at, "due_at")
        _utc(self.grace_deadline, "grace_deadline")
        if self.grace_deadline < self.due_at:
            raise ValueError("grace deadline precedes due time")


@dataclass(frozen=True)
class AttemptFact:
    attempt_no: int
    started_at: datetime
    finished_at: Optional[datetime]
    response_class: str
    success: bool
    retry_after: Optional[timedelta] = None
    error_code: Optional[str] = None

    def __post_init__(self) -> None:
        _positive(self.attempt_no, "attempt_no")
        _utc(self.started_at, "started_at")
        if self.finished_at is not None:
            _utc(self.finished_at, "finished_at")
            if self.finished_at < self.started_at:
                raise ValueError("finished_at precedes started_at")
        if self.retry_after is not None and self.retry_after < timedelta(0):
            raise ValueError("retry_after cannot be negative")


@dataclass(frozen=True)
class PageFact:
    ordinal: int
    cursor: Optional[str]
    page_ref: str
    attempt_no: int
    response_class: str
    record_count: int
    evidence_digest: str
    next_cursor: Optional[str] = None
    is_terminal: bool = False
    failed: bool = False
    request_identity: str = ""
    report_id: Optional[str] = None
    query_scope: Optional[str] = None

    def __post_init__(self) -> None:
        _positive(self.ordinal, "ordinal")
        _positive(self.attempt_no, "attempt_no")
        if self.record_count < 0:
            raise ValueError("record_count cannot be negative")
        if not self.page_ref or not self.evidence_digest:
            raise ValueError("page reference and digest are required")


@dataclass(frozen=True)
class ExpectedRowV1:
    source_record_ordinal: int
    raw_evidence_ref: str
    raw_evidence_sha256: str

    def __post_init__(self) -> None:
        _positive(self.source_record_ordinal, "source_record_ordinal")
        if not self.raw_evidence_ref or not self.raw_evidence_sha256:
            raise ValueError("expected row evidence is required")


@dataclass(frozen=True)
class SyntheticExpectedCohortV1:
    run_id: str
    schedule_revision: int
    source_family: str
    source_account_id: str
    scope_key: str
    report_id: Optional[str]
    query_scope: Optional[str]
    pages: tuple[PageFact, ...]
    rows: tuple[ExpectedRowV1, ...] = ()
    rule_ref: str = "synthetic-v1"
    attempts: tuple[AttemptFact, ...] = ()

    def __post_init__(self) -> None:
        if self.source_family != "synthetic" or not self.run_id or self.schedule_revision < 1:
            raise ValueError("synthetic cohort identity is required")
        if not self.rule_ref:
            raise ValueError("synthetic cohort rule is required")


@dataclass(frozen=True)
class SyntheticFreshnessRuleV1:
    rule_ref: str
    schedule_revision: int
    max_age: timedelta

    def __post_init__(self) -> None:
        if not self.rule_ref or self.schedule_revision < 1 or self.max_age <= timedelta(0):
            raise ValueError("invalid synthetic freshness rule")


@dataclass(frozen=True)
class QualityResult:
    status: str
    reason_codes: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.status not in {
            RETRIEVAL_COMPLETE, RETRIEVAL_PARTIAL, RETRIEVAL_FAILED,
            COVERAGE_COMPLETE, COVERAGE_PARTIAL, COVERAGE_UNKNOWN,
            FRESHNESS_FRESH, FRESHNESS_STALE, FRESHNESS_UNKNOWN,
        }:
            raise ValueError(f"invalid quality status: {self.status!r}")
        if any(not isinstance(reason, str) or not reason for reason in self.reason_codes):
            raise ValueError("quality reason codes must be non-empty strings")


@dataclass(frozen=True)
class QualityEvaluation:
    """Evidence-bound result supplied by a source/fixture evaluator."""

    dimension: str
    status: str
    run_id: str
    schedule_revision: int
    source_family: str
    source_account_id: str
    scope_key: str
    page_keys: tuple[tuple[int, Optional[str]], ...] = ()
    page_facts: tuple[PageFact, ...] = ()
    observation_ids: tuple[str, ...] = ()
    rule_ref: Optional[str] = None
    evaluated_at: Optional[datetime] = None
    observed_at_values: tuple[datetime, ...] = ()
    evidence_version: str = "1"

    def __post_init__(self) -> None:
        if self.dimension not in ("coverage", "freshness"):
            raise ValueError("invalid evaluation dimension")
        allowed = ((COVERAGE_COMPLETE, COVERAGE_PARTIAL, COVERAGE_UNKNOWN)
                   if self.dimension == "coverage" else
                   (FRESHNESS_FRESH, FRESHNESS_STALE, FRESHNESS_UNKNOWN))
        if self.status not in allowed:
            raise ValueError("invalid evaluation status")
        if not self.run_id or self.schedule_revision < 1:
            raise ValueError("evaluation identity is required")
        if not self.source_family or not self.source_account_id or not self.scope_key:
            raise ValueError("evaluation source binding is required")
        if self.evaluated_at is not None:
            _utc(self.evaluated_at, "evaluated_at")
        if any(value.tzinfo is None or value.utcoffset() is None for value in self.observed_at_values):
            raise ValueError("evaluation observation times must be timezone-aware")


@dataclass(frozen=True)
class PageReplayResult:
    status: str  # created, duplicate, conflict
    page: PageFact
    conflict_with: Optional[PageFact] = None


@dataclass
class CollectionRunV1:
    run_id: str
    revision: int
    source_family: str
    source_account_id: str
    scope_key: str
    schedule: CollectionScheduleV1
    expected_run_id: Optional[str] = None
    manual_origin: Optional[str] = None
    source_report_id: Optional[str] = None
    expected_at: Optional[datetime] = None
    started_at: Optional[datetime] = None
    ended_at: Optional[datetime] = None
    state: str = RUN_EXPECTED
    attempts: list[AttemptFact] = field(default_factory=list)
    pages: dict[tuple[int, Optional[str]], PageFact] = field(default_factory=dict)
    observations: list[SourceObservationV1] = field(default_factory=list)
    scope_coverage: QualityResult | QualityEvaluation = field(default_factory=lambda: QualityResult(COVERAGE_UNKNOWN))
    freshness: QualityResult | QualityEvaluation = field(default_factory=lambda: QualityResult(FRESHNESS_UNKNOWN))
    conflicts: list[str] = field(default_factory=list)
    expected_cohort: Optional[SyntheticExpectedCohortV1] = None
    freshness_rule: Optional[SyntheticFreshnessRuleV1] = None

    def __post_init__(self) -> None:
        _positive(self.revision, "revision")
        if not self.expected_run_id and not self.manual_origin:
            raise ValueError("a run needs expected_run_id or manual_origin")
        if (self.source_family, self.source_account_id, self.scope_key) != (
            self.schedule.source_family, self.schedule.source_account_id, self.schedule.scope_key
        ):
            raise ValueError("one run must have one schedule source family/account/scope")
        for value, name in ((self.expected_at, "expected_at"), (self.started_at, "started_at"), (self.ended_at, "ended_at")):
            if value is not None:
                _utc(value, name)
        if self.started_at is not None and self.ended_at is not None and self.ended_at < self.started_at:
            raise ValueError("ended_at precedes started_at")
        self._validate_dimension(self.scope_coverage, "coverage")
        self._validate_dimension(self.freshness, "freshness")
        if self.expected_cohort is not None and self.expected_cohort.source_family != "synthetic":
            raise ValueError("only synthetic expected cohorts are supported")

    @staticmethod
    def _validate_dimension(value: QualityResult | QualityEvaluation, dimension: str) -> None:
        allowed = ((COVERAGE_COMPLETE, COVERAGE_PARTIAL, COVERAGE_UNKNOWN)
                   if dimension == "coverage" else
                   (FRESHNESS_FRESH, FRESHNESS_STALE, FRESHNESS_UNKNOWN))
        if isinstance(value, QualityEvaluation):
            if value.dimension != dimension:
                raise ValueError(f"quality evaluation is not for {dimension}")
        elif value.status not in allowed:
            raise ValueError(f"invalid {dimension} quality status")

    @classmethod
    def from_facts(
        cls, *, schedule: CollectionScheduleV1, run_id: str, revision: int,
        expected_run_id: Optional[str] = None, manual_origin: Optional[str] = None,
        attempts: Iterable[AttemptFact] = (), pages: Iterable[PageFact] = (),
        observations: Iterable[SourceObservationV1] = (),
        scope_coverage: QualityResult | QualityEvaluation | str = COVERAGE_UNKNOWN,
        freshness: QualityResult | QualityEvaluation | str = FRESHNESS_UNKNOWN,
        expected_cohort: Optional[SyntheticExpectedCohortV1] = None,
        freshness_rule: Optional[SyntheticFreshnessRuleV1] = None,
        **kwargs,
    ) -> "CollectionRunV1":
        run = cls(run_id=run_id, revision=revision, source_family=schedule.source_family,
                  source_account_id=schedule.source_account_id, scope_key=schedule.scope_key,
                  schedule=schedule, expected_run_id=expected_run_id, manual_origin=manual_origin,
                  expected_cohort=expected_cohort, freshness_rule=freshness_rule,
                  **kwargs)
        for attempt in attempts:
            run.record_attempt(attempt)
        for page in pages:
            run.replay_page(page)
        run.observations.extend(observations)
        run.scope_coverage = scope_coverage if isinstance(scope_coverage, (QualityResult, QualityEvaluation)) else QualityResult(scope_coverage)
        run.freshness = freshness if isinstance(freshness, (QualityResult, QualityEvaluation)) else QualityResult(freshness)
        run._validate_dimension(run.scope_coverage, "coverage")
        run._validate_dimension(run.freshness, "freshness")
        return run

    def record_attempt(self, attempt: AttemptFact) -> None:
        if attempt.attempt_no > self.schedule.max_attempts:
            raise ValueError("attempt budget exceeded")
        if any(a.attempt_no == attempt.attempt_no for a in self.attempts):
            if attempt not in self.attempts:
                self.conflicts.append(f"attempt:{attempt.attempt_no}")
            return
        if self.started_at is not None and attempt.started_at < self.started_at:
            self.conflicts.append(f"attempt_before_run_start:{attempt.attempt_no}")
        self.attempts.append(attempt)
        self.attempts.sort(key=lambda item: item.attempt_no)

    def replay_page(self, page: PageFact) -> PageReplayResult:
        key = (page.ordinal, page.cursor)
        prior = self.pages.get(key)
        if prior is not None:
            if prior == page:
                return PageReplayResult("duplicate", prior)
            self.conflicts.append(f"page:{page.ordinal}:{page.cursor or '<none>'}")
            return PageReplayResult("conflict", prior, prior)
        if page.cursor is not None:
            prior = next((item for item in self.pages.values() if item.cursor == page.cursor), None)
            if prior is not None:
                self.conflicts.append(f"duplicate_cursor:{page.cursor}")
                return PageReplayResult("conflict", page, prior)
        self.pages[key] = page
        return PageReplayResult("created", page)

    def set_scope_coverage(self, status: str, *reasons: str) -> None:
        if status not in (COVERAGE_COMPLETE, COVERAGE_PARTIAL, COVERAGE_UNKNOWN):
            raise ValueError("invalid scope coverage")
        self.scope_coverage = QualityResult(status, tuple(reasons))

    def set_freshness(self, status: str, *reasons: str) -> None:
        if status not in (FRESHNESS_FRESH, FRESHNESS_STALE, FRESHNESS_UNKNOWN):
            raise ValueError("invalid freshness")
        self.freshness = QualityResult(status, tuple(reasons))

    def bind_scope_coverage(self, evaluation: QualityEvaluation) -> None:
        self._validate_dimension(evaluation, "coverage")
        self.scope_coverage = evaluation

    def evaluate_scope_coverage(self, *, evidence_version: str = "synthetic-v1") -> QualityEvaluation:
        """Report the current synthetic proof, never a caller-selected label."""
        coverage = (self.derive_quality()[1] if evidence_version == "synthetic-v1" else
                    QualityResult(COVERAGE_UNKNOWN, ("unknown_coverage_rule",)))
        return QualityEvaluation("coverage", coverage.status, self.run_id,
                                 self.schedule.revision, self.source_family,
                                 self.source_account_id, self.scope_key,
                                 page_keys=tuple(sorted(self.pages)),
                                 page_facts=tuple(self.pages[key] for key in sorted(self.pages)),
                                 evidence_version=evidence_version)

    def bind_freshness(self, evaluation: QualityEvaluation) -> None:
        self._validate_dimension(evaluation, "freshness")
        self.freshness = evaluation

    def evaluate_freshness(self, *, now: datetime, max_age: timedelta) -> QualityEvaluation:
        """Synthetic versioned evaluator; source-specific rules remain external."""
        _utc(now, "now")
        if max_age <= timedelta(0) or self.schedule.freshness_rule_ref == "unconfigured":
            raise ValueError("a positive configured freshness rule is required")
        status = (self._derive_freshness(now).status if self.freshness_rule is not None
                  and max_age == self.freshness_rule.max_age else FRESHNESS_UNKNOWN)
        values = tuple(observation.observed_at for observation in self.observations
                       if observation.observed_at is not None
                       and observation.observed_at.tzinfo is not None
                       and observation.observed_at.utcoffset() is not None)
        return QualityEvaluation("freshness", status, self.run_id, self.schedule.revision,
                                 self.source_family, self.source_account_id, self.scope_key,
                                 observation_ids=tuple(o.observation_id for o in self.observations),
                                 rule_ref=self.schedule.freshness_rule_ref,
                                 evaluated_at=now, observed_at_values=values)

    def derive_quality(self, *, now: Optional[datetime] = None,
                       as_of: Optional[datetime] = None) -> tuple[QualityResult, QualityResult, QualityResult]:
        if now is not None and as_of is not None and now != as_of:
            raise ValueError("now and as_of disagree")
        if as_of is not None:
            now = as_of
        if now is not None:
            _utc(now, "now")
        reasons: list[str] = []
        pages = sorted(self.pages.values(), key=lambda page: page.ordinal)
        malformed_page_keys = any(
            key != (page.ordinal, page.cursor) for key, page in self.pages.items()
        )
        duplicate_attempt_numbers = len({attempt.attempt_no for attempt in self.attempts}) != len(self.attempts)
        terminal = [page for page in pages if page.is_terminal]
        contiguous = bool(pages) and [page.ordinal for page in pages] == list(range(1, max(p.ordinal for p in pages) + 1))
        attempt_by_no = {attempt.attempt_no: attempt for attempt in self.attempts}
        unknown_attempt = any(page.attempt_no not in attempt_by_no for page in pages)
        linked_attempts = [attempt_by_no[page.attempt_no] for page in pages if page.attempt_no in attempt_by_no]
        attempt_budget_exceeded = any(
            attempt.attempt_no > self.schedule.max_attempts for attempt in self.attempts
        ) or any(page.attempt_no > self.schedule.max_attempts for page in pages)
        unfinished_attempt = any(attempt.finished_at is None for attempt in self.attempts)
        chronology = (
            self.started_at is not None
            and all(attempt.started_at >= self.started_at for attempt in self.attempts)
            and all(attempt.finished_at is not None and attempt.finished_at >= attempt.started_at
                    for attempt in linked_attempts)
            and all(linked_attempts[index].attempt_no <= linked_attempts[index + 1].attempt_no
                    for index in range(len(linked_attempts) - 1))
        )
        failed_page = any(page.failed for page in pages)
        linked_failed = any(not attempt.success for attempt in linked_attempts)
        linked_response_class_conflict = any(
            page.response_class != attempt_by_no[page.attempt_no].response_class
            for page in pages if page.attempt_no in attempt_by_no
        )
        page_chain = (
            bool(pages)
            and pages[0].cursor is None
            and all(
                page.next_cursor == pages[index + 1].cursor
                for index, page in enumerate(pages[:-1])
            )
            and all(page.next_cursor for page in pages[:-1])
            and pages[-1].is_terminal
            and pages[-1].next_cursor is None
            and len(terminal) == 1
        )
        timestamps = [value for attempt in self.attempts for value in (attempt.started_at, attempt.finished_at) if value is not None]
        if self.ended_at is not None:
            timestamps.append(self.ended_at)
        deadline_exceeded = (
            self.started_at is not None
            and timestamps
            and max(timestamps) > self.started_at + self.schedule.total_deadline
        )
        unresolved_cursor = bool(pages) and not page_chain
        if self.conflicts or malformed_page_keys or duplicate_attempt_numbers:
            retrieval = QualityResult(RETRIEVAL_PARTIAL, ("page_or_attempt_conflict",))
        elif attempt_budget_exceeded:
            retrieval = QualityResult(RETRIEVAL_PARTIAL, ("attempt_budget_exceeded",))
        elif deadline_exceeded:
            retrieval = QualityResult(RETRIEVAL_PARTIAL, ("total_deadline_exceeded",))
        elif self.started_at is None:
            retrieval = QualityResult(RETRIEVAL_PARTIAL, ("missing_run_start",))
        elif unknown_attempt:
            retrieval = QualityResult(RETRIEVAL_PARTIAL, ("page_references_unknown_attempt",))
        elif unfinished_attempt:
            retrieval = QualityResult(RETRIEVAL_PARTIAL, ("unresolved_attempt",))
        elif not chronology:
            retrieval = QualityResult(RETRIEVAL_PARTIAL, ("invalid_attempt_chronology",))
        elif linked_response_class_conflict:
            retrieval = QualityResult(RETRIEVAL_PARTIAL, ("linked_response_class_conflict",))
        elif failed_page or linked_failed:
            retrieval = QualityResult(RETRIEVAL_PARTIAL, ("failed_page",))
        elif terminal and contiguous and not unresolved_cursor:
            retrieval = QualityResult(RETRIEVAL_COMPLETE)
        else:
            retrieval = QualityResult(RETRIEVAL_PARTIAL, ("unresolved_cursor_or_missing_page",))
        observation_binding = any(
            (observation.run_id != self.run_id or
             observation.source_family != self.source_family or
             observation.source_account_id != self.source_account_id)
            for observation in self.observations
        )
        coverage = self._derive_coverage(pages, retrieval, observation_binding)
        if self.observations and not any(page.record_count for page in pages):
            coverage = QualityResult(
                COVERAGE_PARTIAL,
                (*coverage.reason_codes, "positive_observations_conflict_empty_pages"),
            )
        freshness = self._derive_freshness(now)
        return retrieval, coverage, freshness

    def _derive_coverage(self, pages: list[PageFact], retrieval: QualityResult,
                         observation_binding: bool) -> QualityResult:
        cohort = self.expected_cohort
        if cohort is None:
            return QualityResult(COVERAGE_UNKNOWN, ("expected_cohort_required",))
        if (cohort.run_id, cohort.schedule_revision, cohort.source_family,
            cohort.source_account_id, cohort.scope_key) != (
                self.run_id, self.schedule.revision, self.source_family,
                self.source_account_id, self.scope_key):
            return QualityResult(COVERAGE_UNKNOWN, ("expected_cohort_identity_mismatch",))
        if cohort.report_id != self.source_report_id:
            return QualityResult(COVERAGE_UNKNOWN, ("report_identity_mismatch",))
        if cohort.rule_ref != "synthetic-v1":
            return QualityResult(COVERAGE_UNKNOWN, ("unknown_coverage_rule",))
        if observation_binding or retrieval.status != RETRIEVAL_COMPLETE:
            return QualityResult(COVERAGE_PARTIAL, ("retrieval_not_complete",))
        actual_pages = tuple(pages)
        expected_pages = tuple(sorted(cohort.pages, key=lambda p: p.ordinal))
        if actual_pages != expected_pages:
            return QualityResult(COVERAGE_UNKNOWN, ("expected_page_facts_mismatch",))
        if tuple(self.attempts) != tuple(sorted(cohort.attempts, key=lambda a: a.attempt_no)):
            return QualityResult(COVERAGE_UNKNOWN, ("expected_attempt_facts_mismatch",))
        actual_rows = tuple(sorted(
            (ExpectedRowV1(o.source_record_ordinal, o.raw_evidence_ref, o.raw_evidence_sha256)
             for o in self.observations),
            key=lambda row: row.source_record_ordinal))
        if actual_rows != tuple(sorted(cohort.rows, key=lambda row: row.source_record_ordinal)):
            return QualityResult(COVERAGE_UNKNOWN, ("expected_row_facts_mismatch",))
        if any((page.report_id, page.query_scope) != (cohort.report_id, cohort.query_scope)
               for page in pages):
            return QualityResult(COVERAGE_UNKNOWN, ("report_or_query_identity_mismatch",))
        # The synthetic fixture uses the retained page reference as its explicit
        # row-to-page binding. Row digests identify raw rows, not whole pages.
        page_refs = [page.page_ref for page in pages]
        if len(page_refs) != len(set(page_refs)):
            return QualityResult(COVERAGE_UNKNOWN, ("ambiguous_page_reference",))
        expected_positions = [row.source_record_ordinal for row in cohort.rows]
        actual_positions = [row.source_record_ordinal for row in self.observations]
        if (len(expected_positions) != len(set(expected_positions)) or
                len(actual_positions) != len(set(actual_positions))):
            return QualityResult(COVERAGE_UNKNOWN, ("duplicate_row_position",))
        counts = {page_ref: 0 for page_ref in page_refs}
        for observation in self.observations:
            if observation.collection_status != "success":
                return QualityResult(COVERAGE_PARTIAL, ("observation_not_successful",))
            if ((self.started_at is not None and observation.collected_at < self.started_at)
                    or (self.ended_at is not None and observation.collected_at > self.ended_at)
                    or (observation.observed_at is not None and
                        observation.observed_at > observation.collected_at)):
                return QualityResult(COVERAGE_UNKNOWN, ("observation_chronology_mismatch",))
            if (observation.coverage_scope is not None and
                    observation.coverage_scope != cohort.scope_key):
                return QualityResult(COVERAGE_UNKNOWN, ("observation_scope_mismatch",))
            if observation.report_id is not None and observation.report_id != cohort.report_id:
                return QualityResult(COVERAGE_UNKNOWN, ("observation_report_mismatch",))
            if observation.raw_evidence_ref not in counts:
                return QualityResult(COVERAGE_UNKNOWN, ("row_page_membership_unproved",))
            counts[observation.raw_evidence_ref] += 1
        if any(counts[page.page_ref] != page.record_count for page in pages):
            return QualityResult(COVERAGE_UNKNOWN, ("page_record_count_mismatch",))
        return QualityResult(COVERAGE_COMPLETE)

    def _derive_freshness(self, now: Optional[datetime]) -> QualityResult:
        if now is None:
            return QualityResult(FRESHNESS_UNKNOWN, ("as_of_required",))
        if self.source_family != "synthetic":
            return QualityResult(FRESHNESS_UNKNOWN, ("source_freshness_rule_unverified",))
        rule = self.freshness_rule
        if rule is None or rule.rule_ref != self.schedule.freshness_rule_ref \
                or rule.schedule_revision != self.schedule.revision:
            return QualityResult(FRESHNESS_UNKNOWN, ("unknown_freshness_rule",))
        if not self.observations:
            return QualityResult(FRESHNESS_UNKNOWN, ("empty_cohort_time_unavailable",))
        values = []
        for observation in self.observations:
            if (observation.run_id != self.run_id
                    or observation.source_family != self.source_family
                    or observation.source_account_id != self.source_account_id
                    or (observation.coverage_scope is not None and observation.coverage_scope != self.scope_key)
                    or (observation.report_id is not None and observation.report_id != self.source_report_id)):
                return QualityResult(FRESHNESS_UNKNOWN, ("observation_outside_run_scope",))
            if observation.collection_status == "failed":
                return QualityResult(FRESHNESS_UNKNOWN, ("failed_observation_provenance",))
            value = observation.observed_at
            if value is None or value.tzinfo is None or value.utcoffset() is None:
                return QualityResult(FRESHNESS_UNKNOWN, ("missing_source_observation_time",))
            if ((self.started_at is not None and observation.collected_at < self.started_at)
                    or (self.ended_at is not None and observation.collected_at > self.ended_at)
                    or value > observation.collected_at or observation.collected_at > now):
                return QualityResult(FRESHNESS_UNKNOWN, ("observation_chronology_mismatch",))
            if value > now:
                return QualityResult(FRESHNESS_UNKNOWN, ("future_source_time",))
            values.append(value)
        return QualityResult(
            FRESHNESS_FRESH if all(now - rule.max_age <= value <= now for value in values)
            else FRESHNESS_STALE,
            ("synthetic_rule_replayed",),
        )

    def _bound_result(self, value, dimension: str, pages: list[PageFact]) -> QualityResult:
        if not isinstance(value, QualityEvaluation):
            if value.status == (COVERAGE_COMPLETE if dimension == "coverage" else FRESHNESS_FRESH):
                return QualityResult(COVERAGE_UNKNOWN if dimension == "coverage" else FRESHNESS_UNKNOWN,
                                     (f"unbound_{dimension}_evaluation",))
            return value
        if (value.run_id, value.schedule_revision,
            value.source_family, value.source_account_id, value.scope_key) != (
                self.run_id, self.schedule.revision, self.source_family,
                self.source_account_id, self.scope_key):
            return QualityResult(COVERAGE_UNKNOWN if dimension == "coverage" else FRESHNESS_UNKNOWN,
                                 (f"unbound_{dimension}_evaluation",))
        if dimension == "coverage":
            current = tuple(sorted(self.pages))
            if tuple(value.page_keys) != current:
                return QualityResult(COVERAGE_UNKNOWN, ("stale_coverage_evaluation",))
        else:
            current = tuple(o.observation_id for o in self.observations)
            if (tuple(value.observation_ids) != current or
                tuple(o.observed_at for o in self.observations if o.observed_at is not None) != value.observed_at_values or
                value.rule_ref != self.schedule.freshness_rule_ref or
                (value.evaluated_at is not None and any(t > value.evaluated_at for t in value.observed_at_values))):
                return QualityResult(FRESHNESS_UNKNOWN, ("stale_freshness_evaluation",))
            if value.status in (FRESHNESS_FRESH, FRESHNESS_STALE) and not value.observed_at_values:
                return QualityResult(FRESHNESS_UNKNOWN, ("missing_freshness_evidence",))
        return QualityResult(value.status)

    @property
    def quality(self) -> tuple[QualityResult, QualityResult, QualityResult]:
        return self.derive_quality()

    @property
    def is_proved_empty(self) -> bool:
        retrieval, coverage, _ = self.quality
        return retrieval.status == RETRIEVAL_COMPLETE and coverage.status == COVERAGE_COMPLETE and not any(
            page.record_count for page in self.pages.values()
        ) and not self.observations and self.expected_cohort is not None \
            and not self.expected_cohort.rows

    @property
    def positive_observations(self) -> tuple[SourceObservationV1, ...]:
        """Retain positives from partial runs, with run limits still visible."""
        return tuple(self.observations)

    @property
    def observation_limitations(self) -> tuple[str, ...]:
        retrieval, coverage, freshness = self.quality
        return tuple(dict.fromkeys((*retrieval.reason_codes, *coverage.reason_codes, *freshness.reason_codes)))

    def can_claim_remediation(self) -> bool:
        return False
