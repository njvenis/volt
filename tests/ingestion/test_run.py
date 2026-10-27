import unittest
from dataclasses import replace
from datetime import datetime, timedelta, timezone

from uvm.identity import MissingField, MISSING_NOT_SUPPLIED, SourceObservationV1
from uvm.ingestion import (
    AttemptFact, CollectionRunV1, CollectionScheduleV1, PageFact, QualityResult,
    QualityEvaluation,
    ExpectedRowV1, SyntheticExpectedCohortV1, SyntheticFreshnessRuleV1,
    COVERAGE_COMPLETE, COVERAGE_UNKNOWN, FRESHNESS_FRESH, FRESHNESS_UNKNOWN,
    RETRIEVAL_COMPLETE, RETRIEVAL_PARTIAL, FRESHNESS_STALE,
)

UTC = timezone.utc
T0 = datetime(2026, 9, 29, 8, 0, tzinfo=UTC)


def schedule(**changes):
    values = dict(schedule_id="sch-1", revision=1, source_family="synthetic",
                  source_account_id="account-1", scope_key="scope-1",
                  max_attempts=2, max_page_attempts=2,
                  total_deadline=timedelta(minutes=10))
    values.update(changes)
    return CollectionScheduleV1(**values)


def observation(observed_at=T0):
    optional = (
        "native_id_scheme", "native_id_authority", "native_id_value",
        "asset_locator", "component_locator", "source_record_locator",
        "source_rating", "vulnerability_refs", "source_first_seen_at",
        "report_id", "coverage_scope",
    )
    missing = tuple(MissingField(name, MISSING_NOT_SUPPLIED) for name in optional if name != "observed_at")
    if observed_at is None:
        missing += (MissingField("observed_at", MISSING_NOT_SUPPLIED),)
    return SourceObservationV1(
        schema_version=1, observation_id="00000000-0000-0000-0000-000000000001",
        revision=1, source_family="synthetic", source_account_id="account-1",
        run_id="run-1", source_record_ordinal=1, collection_status="partial",
        collected_at=T0 + timedelta(minutes=1), raw_evidence_ref="page/1",
        raw_evidence_sha256="digest-1", missing_fields=missing, observed_at=observed_at,
    )


def attempt(number=1, started=T0, finished=None, success=True):
    return AttemptFact(number, started, finished or started + timedelta(minutes=1),
                       "200", success)
class CollectionRunTest(unittest.TestCase):
    def test_quality_requires_exact_evidence_and_rule_replay(self):
        from uvm.ingestion import COVERAGE_PARTIAL
        pages = (PageFact(1, None, "page/1", 1, "200", 0, "d1", next_cursor="c1"),
                 PageFact(2, "c1", "page/2", 2, "200", 0, "d2", is_terminal=True))
        cohort = SyntheticExpectedCohortV1(
            "run-1", 1, "synthetic", "account-1", "scope-1", None, None, pages,
            attempts=(attempt(1), attempt(2, T0 + timedelta(minutes=2))))
        kwargs = dict(schedule=schedule(freshness_rule_ref="rule-1"), run_id="run-1",
            revision=1, manual_origin="test", started_at=T0,
            attempts=[attempt(1), attempt(2, T0 + timedelta(minutes=2))], pages=pages,
            expected_cohort=cohort,
            freshness_rule=SyntheticFreshnessRuleV1("rule-1", 1, timedelta(hours=1)))
        run = CollectionRunV1.from_facts(**kwargs)
        self.assertTrue(run.is_proved_empty)
        self.assertTrue(run.replay_page(pages[0]).status == "duplicate")
        self.assertEqual(run.derive_quality(as_of=T0)[2].status, FRESHNESS_UNKNOWN)

        conflict = PageFact(1, None, "page/1", 1, "200", 1, "changed", next_cursor="c1")
        self.assertEqual(run.replay_page(conflict).status, "conflict")
        self.assertFalse(run.is_proved_empty)
        self.assertEqual(run.quality[1].status, COVERAGE_PARTIAL)

        positive = observation(T0)
        observed = CollectionRunV1.from_facts(**{**kwargs, "pages": [
            PageFact(1, None, "page/1", 1, "200", 1, "d1", next_cursor="c1"),
            pages[1]], "observations": [positive], "expected_cohort":
            SyntheticExpectedCohortV1("run-1", 1, "synthetic", "account-1", "scope-1",
                                       None, None, (PageFact(1, None, "page/1", 1,
                                       "200", 1, "d1", next_cursor="c1"), pages[1]),
                                       (ExpectedRowV1(1, "page/1", "digest-1"),))})
        self.assertEqual(observed.derive_quality(as_of=T0 + timedelta(minutes=2))[2].status,
                         FRESHNESS_FRESH)
        self.assertEqual(observed.derive_quality(as_of=T0 + timedelta(days=2))[2].status,
                         FRESHNESS_STALE)

        # A retained row cannot make a cohort complete when the page advertises
        # more rows, or when its provenance contradicts the enclosing run.
        base_page = PageFact(1, None, "page/1", 1, "200", 1, "page-digest",
                             is_terminal=True)
        base_row = replace(observation(), collection_status="success")
        base_cohort = SyntheticExpectedCohortV1(
            "run-1", 1, "synthetic", "account-1", "scope-1", None, None,
            (base_page,), (ExpectedRowV1(1, "page/1", "digest-1"),),
            attempts=(attempt(),))
        base = dict(schedule=schedule(freshness_rule_ref="rule-1"), run_id="run-1",
                    revision=1, manual_origin="test", started_at=T0,
                    attempts=[attempt()], pages=[base_page], observations=[base_row],
                    expected_cohort=base_cohort,
                    freshness_rule=SyntheticFreshnessRuleV1("rule-1", 1, timedelta(hours=1)))
        self.assertEqual(CollectionRunV1.from_facts(**base).quality[1].status,
                         COVERAGE_COMPLETE)
        for changed_row in (
            replace(base_row, coverage_scope="other-scope", missing_fields=tuple(
                field for field in base_row.missing_fields if field.field != "coverage_scope")),
            replace(base_row, report_id="other-report", missing_fields=tuple(
                field for field in base_row.missing_fields if field.field != "report_id")),
            replace(base_row, collection_status="failed"),
        ):
            candidate = CollectionRunV1.from_facts(**{**base, "observations": [changed_row]})
            self.assertNotEqual(candidate.quality[1].status, COVERAGE_COMPLETE)
        wrong_count = replace(base_page, record_count=2)
        candidate = CollectionRunV1.from_facts(**{**base, "pages": [wrong_count],
            "expected_cohort": replace(base_cohort, pages=(wrong_count,))})
        self.assertNotEqual(candidate.quality[1].status, COVERAGE_COMPLETE)
        self.assertNotEqual(candidate.evaluate_scope_coverage().status, COVERAGE_COMPLETE)

        second_page = PageFact(2, "c1", "page/2", 2, "200", 1,
                               "page-2-digest", is_terminal=True)
        first_page = replace(base_page, is_terminal=False, next_cursor="c1")
        second_row = replace(base_row,
            observation_id="00000000-0000-0000-0000-000000000002",
            source_record_ordinal=2, raw_evidence_sha256="digest-2")
        two_page_cohort = replace(base_cohort, pages=(first_page, second_page),
            rows=(ExpectedRowV1(1, "page/1", "digest-1"),
                  ExpectedRowV1(2, "page/1", "digest-2")),
            attempts=(attempt(), attempt(2, T0 + timedelta(minutes=2))))
        balanced_wrong_page = CollectionRunV1.from_facts(**{**base,
            "attempts": list(two_page_cohort.attempts),
            "pages": list(two_page_cohort.pages),
            "observations": [base_row, second_row],
            "expected_cohort": two_page_cohort})
        self.assertEqual(balanced_wrong_page.quality[0].status, RETRIEVAL_COMPLETE)
        self.assertNotEqual(balanced_wrong_page.quality[1].status, COVERAGE_COMPLETE)
        self.assertNotEqual(balanced_wrong_page.evaluate_scope_coverage().status,
                            COVERAGE_COMPLETE)
        self.assertEqual(len(balanced_wrong_page.positive_observations), 2)
        self.assertFalse(balanced_wrong_page.can_claim_remediation())

        missing_page_row = replace(second_row, raw_evidence_ref="unretained-page")
        missing_cohort = replace(two_page_cohort,
            rows=(two_page_cohort.rows[0], ExpectedRowV1(2, "unretained-page", "digest-2")))
        candidate = CollectionRunV1.from_facts(**{**base,
            "attempts": list(two_page_cohort.attempts), "pages": list(two_page_cohort.pages),
            "observations": [base_row, missing_page_row], "expected_cohort": missing_cohort})
        self.assertNotEqual(candidate.quality[1].status, COVERAGE_COMPLETE)
        duplicate_position = replace(second_row, source_record_ordinal=1)
        duplicate_cohort = replace(two_page_cohort,
            rows=(two_page_cohort.rows[0], ExpectedRowV1(1, "page/1", "digest-2")))
        candidate = CollectionRunV1.from_facts(**{**base,
            "attempts": list(two_page_cohort.attempts), "pages": list(two_page_cohort.pages),
            "observations": [base_row, duplicate_position], "expected_cohort": duplicate_cohort})
        self.assertNotEqual(candidate.quality[1].status, COVERAGE_COMPLETE)

        self.assertEqual(CollectionRunV1.from_facts(**base).evaluate_scope_coverage().status,
                         COVERAGE_COMPLETE)
        self.assertEqual(CollectionRunV1.from_facts(**base).evaluate_scope_coverage(
            evidence_version="unreviewed").status, COVERAGE_UNKNOWN)
        direct = CollectionRunV1(run_id="run-1", revision=1, source_family="synthetic",
            source_account_id="account-1", scope_key="scope-1", schedule=base["schedule"],
            manual_origin="test", started_at=T0, attempts=[attempt()],
            pages={(1, None): base_page}, observations=[base_row],
            expected_cohort=base_cohort, freshness_rule=base["freshness_rule"],
            scope_coverage=QualityResult(COVERAGE_UNKNOWN))
        self.assertEqual(direct.quality[1].status, COVERAGE_COMPLETE)
        self.assertFalse(direct.is_proved_empty)
        direct.set_scope_coverage(COVERAGE_COMPLETE)
        self.assertEqual(direct.quality[1].status, COVERAGE_COMPLETE)
        self.assertEqual(direct.replay_page(base_page).status, "duplicate")
        self.assertEqual(direct.quality[1].status, COVERAGE_COMPLETE)
        direct.pages = {(99, None): base_page}
        self.assertNotEqual(direct.quality[1].status, COVERAGE_COMPLETE)
        self.assertEqual(CollectionRunV1.from_facts(**{**base,
            "expected_cohort": None}).evaluate_scope_coverage().status, COVERAGE_UNKNOWN)
        valid_second_row = replace(second_row, raw_evidence_ref="page/2")
        valid_two_page = CollectionRunV1.from_facts(**{**base,
            "attempts": list(two_page_cohort.attempts), "pages": list(two_page_cohort.pages),
            "observations": [base_row, valid_second_row],
            "expected_cohort": replace(two_page_cohort, rows=(two_page_cohort.rows[0],
                ExpectedRowV1(2, "page/2", "digest-2")))})
        self.assertEqual(valid_two_page.quality[1].status, COVERAGE_COMPLETE)
        ambiguous_page = replace(second_page, page_ref="page/1")
        ambiguous = CollectionRunV1.from_facts(**{**base,
            "attempts": list(two_page_cohort.attempts),
            "pages": [first_page, ambiguous_page],
            "observations": [base_row, second_row],
            "expected_cohort": replace(two_page_cohort, pages=(first_page, ambiguous_page))})
        self.assertNotEqual(ambiguous.quality[1].status, COVERAGE_COMPLETE)
        partial_row = replace(base_row, collection_status="partial")
        partial = CollectionRunV1.from_facts(**{**base, "observations": [partial_row]})
        self.assertNotEqual(partial.quality[1].status, COVERAGE_COMPLETE)
        self.assertEqual(partial.derive_quality(as_of=T0 + timedelta(minutes=2))[2].status,
                         FRESHNESS_FRESH)
        self.assertEqual(partial.evaluate_freshness(now=T0 + timedelta(minutes=2),
            max_age=timedelta(hours=1)).status, FRESHNESS_FRESH)
        failed = CollectionRunV1.from_facts(**{**base,
            "observations": [replace(base_row, collection_status="failed")]})
        self.assertEqual(failed.derive_quality(as_of=T0 + timedelta(minutes=2))[2].status,
                         FRESHNESS_UNKNOWN)
        self.assertEqual(failed.evaluate_freshness(now=T0 + timedelta(minutes=2),
            max_age=timedelta(hours=1)).status, FRESHNESS_UNKNOWN)
        self.assertEqual(partial.evaluate_freshness(now=T0 + timedelta(minutes=2),
            max_age=timedelta(days=1)).status, FRESHNESS_UNKNOWN)
        contradictory = CollectionRunV1.from_facts(**{**base,
            "observations": [replace(base_row, observed_at=T0 + timedelta(minutes=2))]})
        self.assertNotEqual(contradictory.quality[1].status, COVERAGE_COMPLETE)
        self.assertEqual(contradictory.derive_quality(
            as_of=T0 + timedelta(minutes=3))[2].status, FRESHNESS_UNKNOWN)
        naive = CollectionRunV1.from_facts(**{**base,
            "observations": [replace(base_row, observed_at=T0.replace(tzinfo=None))]})
        self.assertEqual(naive.evaluate_freshness(now=T0 + timedelta(minutes=2),
            max_age=timedelta(hours=1)).status, FRESHNESS_UNKNOWN)

    def test_unbound_labels_and_direct_wrong_dimension_fail_closed(self):
        run = CollectionRunV1.from_facts(schedule=schedule(), run_id="run-1", revision=1,
            manual_origin="test", started_at=T0, attempts=[attempt()],
            pages=[PageFact(1, None, "page/1", 1, "200", 0, "d", is_terminal=True)],
            scope_coverage=QualityResult(COVERAGE_COMPLETE))
        self.assertFalse(run.is_proved_empty)
        with self.assertRaises(ValueError):
            CollectionRunV1(run_id="run-2", revision=1, source_family="synthetic",
                source_account_id="account-1", scope_key="scope-1", schedule=schedule(),
                manual_origin="test", scope_coverage=QualityResult(FRESHNESS_FRESH))

    def test_bound_empty_and_synthetic_freshness_are_evidence_checked(self):
        run = CollectionRunV1.from_facts(schedule=schedule(freshness_rule_ref="synthetic-v1"),
            run_id="run-1", revision=1, manual_origin="test", started_at=T0,
            attempts=[attempt()], pages=[PageFact(1, None, "page/1", 1, "200", 0, "d", is_terminal=True)],
            scope_coverage=QualityResult(COVERAGE_UNKNOWN))
        run.bind_scope_coverage(run.evaluate_scope_coverage())
        self.assertFalse(run.is_proved_empty)  # caller-supplied evaluation is not proof
        fresh = CollectionRunV1.from_facts(schedule=schedule(freshness_rule_ref="synthetic-v1"),
            run_id="run-2", revision=1, manual_origin="test", started_at=T0,
            attempts=[attempt()], pages=[PageFact(1, None, "page/1", 1, "200", 1, "d", is_terminal=True)],
            observations=[observation()])
        fresh.bind_freshness(fresh.evaluate_freshness(now=T0 + timedelta(minutes=2), max_age=timedelta(hours=1)))
        self.assertEqual(fresh.quality[2].status, FRESHNESS_UNKNOWN)
        fresh.bind_freshness(fresh.evaluate_freshness(now=T0 + timedelta(days=2), max_age=timedelta(hours=1)))
        self.assertEqual(fresh.quality[2].status, FRESHNESS_UNKNOWN)

    def test_schedule_occurrence_and_single_scope(self):
        run = CollectionRunV1.from_facts(
            schedule=schedule(), run_id="run-1", revision=1,
            expected_run_id="expected-1", started_at=T0,
        )
        self.assertEqual(run.schedule.revision, 1)
        self.assertEqual((run.source_family, run.source_account_id, run.scope_key),
                         ("synthetic", "account-1", "scope-1"))
        with self.assertRaises(ValueError):
            CollectionRunV1(run_id="run-2", revision=1, source_family="synthetic",
                            source_account_id="account-1", scope_key="other",
                            schedule=schedule(), manual_origin="manual")

    def test_retry_budget_and_total_deadline_are_bounded(self):
        run = CollectionRunV1.from_facts(schedule=schedule(), run_id="run-1", revision=1,
                                         manual_origin="test", started_at=T0)
        for number in (1, 2):
            run.record_attempt(AttemptFact(number, T0 + timedelta(minutes=number),
                                           T0 + timedelta(minutes=number), "429", False,
                                           retry_after=timedelta(minutes=1), error_code="rate_limit"))
        with self.assertRaises(ValueError):
            run.record_attempt(AttemptFact(3, T0 + timedelta(minutes=3), None, "429", False))
        late = CollectionRunV1.from_facts(schedule=schedule(total_deadline=timedelta(minutes=2)),
                                          run_id="run-2", revision=1, manual_origin="test",
                                          started_at=T0, ended_at=T0 + timedelta(minutes=3))
        late.replay_page(PageFact(1, None, "page/1", 1, "200", 0, "d", is_terminal=True))
        self.assertIn("total_deadline_exceeded", late.quality[0].reason_codes)

    def test_global_attempt_budget_blocks_direct_factory_and_mutated_facts(self):
        page = PageFact(1, None, "page/1", 3, "200", 0, "d3", is_terminal=True)
        over_budget = attempt(3)
        cohort = SyntheticExpectedCohortV1(
            "run-budget", 1, "synthetic", "account-1", "scope-1", None, None,
            (page,), attempts=(over_budget,))
        common = dict(schedule=schedule(max_attempts=2), run_id="run-budget", revision=1,
                      source_family="synthetic", source_account_id="account-1",
                      scope_key="scope-1", manual_origin="test", started_at=T0,
                      expected_cohort=cohort)

        direct = CollectionRunV1(
            **common, attempts=[over_budget], pages={(1, None): page})
        for run in (direct,):
            self.assertNotEqual(run.quality[0].status, RETRIEVAL_COMPLETE)
            self.assertNotEqual(run.quality[1].status, COVERAGE_COMPLETE)
            self.assertNotEqual(run.evaluate_scope_coverage().status, COVERAGE_COMPLETE)
            self.assertFalse(run.is_proved_empty)
            self.assertIn("attempt_budget_exceeded", run.observation_limitations)
            self.assertFalse(run.can_claim_remediation())

        with self.assertRaises(ValueError):
            CollectionRunV1.from_facts(
                schedule=schedule(max_attempts=2), run_id="run-budget", revision=1,
                manual_origin="test", started_at=T0, expected_cohort=cohort,
                attempts=[over_budget], pages=[page])

        incremental = CollectionRunV1(**common)
        with self.assertRaises(ValueError):
            incremental.record_attempt(over_budget)

        mutated = CollectionRunV1.from_facts(
            schedule=schedule(max_attempts=2), run_id="run-mutated", revision=1,
            manual_origin="test", started_at=T0)
        mutated.attempts.append(over_budget)
        mutated.pages[(1, None)] = page
        mutated.expected_cohort = replace(cohort, run_id="run-mutated")
        self.assertNotEqual(mutated.derive_quality()[0].status, RETRIEVAL_COMPLETE)
        self.assertNotEqual(mutated.quality[1].status, COVERAGE_COMPLETE)
        self.assertNotEqual(mutated.evaluate_scope_coverage().status, COVERAGE_COMPLETE)
        self.assertFalse(mutated.is_proved_empty)
        self.assertIn("attempt_budget_exceeded", mutated.observation_limitations)

    def test_page_replay_is_idempotent_and_conflicts_are_visible(self):
        run = CollectionRunV1.from_facts(schedule=schedule(), run_id="run-1", revision=1,
                                         manual_origin="test")
        page = PageFact(1, None, "page/1", 1, "200", 1, "digest")
        self.assertEqual(run.replay_page(page).status, "created")
        self.assertEqual(run.replay_page(page).status, "duplicate")
        conflict = PageFact(1, None, "page/1", 1, "200", 2, "other")
        self.assertEqual(run.replay_page(conflict).status, "conflict")
        self.assertEqual(run.quality[0].status, RETRIEVAL_PARTIAL)

    def test_quality_dimensions_do_not_collapse(self):
        run = CollectionRunV1.from_facts(schedule=schedule(), run_id="run-1", revision=1,
            manual_origin="test", started_at=T0,
            pages=[PageFact(1, None, "page/1", 1, "200", 0, "d", is_terminal=True)],
            attempts=[attempt()],
            scope_coverage=QualityResult(COVERAGE_UNKNOWN, ("scope_not_proven",)),
            freshness=QualityResult(FRESHNESS_FRESH))
        retrieval, coverage, freshness = run.quality
        self.assertEqual(retrieval.status, RETRIEVAL_COMPLETE)
        self.assertEqual(coverage.status, COVERAGE_UNKNOWN)
        self.assertEqual(freshness.status, FRESHNESS_UNKNOWN)  # no observations: time is unproved
        self.assertFalse(run.is_proved_empty)

    def test_missing_source_time_and_partial_positive_are_retained(self):
        run = CollectionRunV1.from_facts(schedule=schedule(), run_id="run-1", revision=1,
            manual_origin="test", observations=[observation(None)],
            pages=[PageFact(1, None, "page/1", 1, "200", 1, "d", is_terminal=False)],
            scope_coverage=QualityResult(COVERAGE_COMPLETE))
        self.assertEqual(len(run.positive_observations), 1)
        self.assertEqual(run.quality[2].status, FRESHNESS_UNKNOWN)
        self.assertIn("as_of_required", run.observation_limitations)
        self.assertFalse(run.can_claim_remediation())

    def test_valid_two_page_chain_is_complete_and_replay_is_idempotent(self):
        run = CollectionRunV1.from_facts(
            schedule=schedule(freshness_rule_ref="rule-1"), run_id="run-1", revision=1,
            manual_origin="test", started_at=T0,
            attempts=[attempt(1), attempt(2, T0 + timedelta(minutes=2))],
            pages=[
                PageFact(1, None, "page/1", 1, "200", 1, "d1", next_cursor="c1"),
                PageFact(2, "c1", "page/2", 2, "200", 1, "d2", is_terminal=True),
            ], observations=[observation()], scope_coverage=QualityResult(COVERAGE_COMPLETE),
        )
        self.assertEqual(run.quality[0].status, RETRIEVAL_COMPLETE)
        self.assertEqual(run.replay_page(run.pages[(1, None)]).status, "duplicate")

    def test_page_limit_does_not_reject_later_page_with_global_attempt_number(self):
        run = CollectionRunV1.from_facts(
            schedule=schedule(max_page_attempts=1, max_attempts=2),
            run_id="run-global-attempts", revision=1, manual_origin="test",
            started_at=T0,
            attempts=[attempt(1), attempt(2, T0 + timedelta(minutes=2))],
            pages=[
                PageFact(1, None, "page/1", 1, "200", 0, "d1", next_cursor="c1"),
                PageFact(2, "c1", "page/2", 2, "200", 0, "d2", is_terminal=True),
            ],
        )
        self.assertEqual(run.quality[0].status, RETRIEVAL_COMPLETE)

    def test_missing_middle_page_and_multiple_terminals_are_not_complete(self):
        missing = CollectionRunV1.from_facts(
            schedule=schedule(), run_id="run-1", revision=1, manual_origin="test", started_at=T0,
            attempts=[attempt()], pages=[
                PageFact(1, None, "page/1", 1, "200", 0, "d1", next_cursor="c1"),
                PageFact(3, "c2", "page/3", 1, "200", 0, "d3", is_terminal=True),
            ])
        self.assertNotEqual(missing.quality[0].status, RETRIEVAL_COMPLETE)
        terminals = CollectionRunV1.from_facts(
            schedule=schedule(), run_id="run-2", revision=1, manual_origin="test", started_at=T0,
            attempts=[attempt()], pages=[
                PageFact(1, None, "page/1", 1, "200", 0, "d1", is_terminal=True),
                PageFact(2, None, "page/2", 1, "200", 0, "d2", is_terminal=True),
            ])
        self.assertNotEqual(terminals.quality[0].status, RETRIEVAL_COMPLETE)

    def test_unknown_attempt_and_unfinished_attempt_are_not_complete(self):
        unknown = CollectionRunV1.from_facts(
            schedule=schedule(), run_id="run-1", revision=1, manual_origin="test", started_at=T0,
            attempts=[attempt()], pages=[PageFact(1, None, "page/1", 2, "200", 0, "d", is_terminal=True)])
        self.assertIn("page_references_unknown_attempt", unknown.quality[0].reason_codes)
        unfinished = CollectionRunV1.from_facts(
            schedule=schedule(), run_id="run-2", revision=1, manual_origin="test", started_at=T0,
            attempts=[AttemptFact(1, T0, None, "200", True)],
            pages=[PageFact(1, None, "page/1", 1, "200", 0, "d", is_terminal=True)])
        self.assertIn("unresolved_attempt", unfinished.quality[0].reason_codes)

    def test_deadline_uses_attempt_finish_and_reversed_timestamps_are_invalid(self):
        late = CollectionRunV1.from_facts(
            schedule=schedule(total_deadline=timedelta(minutes=2)), run_id="run-1", revision=1,
            manual_origin="test", started_at=T0, ended_at=T0 + timedelta(minutes=1),
            attempts=[AttemptFact(1, T0, T0 + timedelta(minutes=3), "200", True)],
            pages=[PageFact(1, None, "page/1", 1, "200", 0, "d", is_terminal=True)])
        self.assertIn("total_deadline_exceeded", late.quality[0].reason_codes)
        with self.assertRaises(ValueError):
            AttemptFact(1, T0 + timedelta(minutes=1), T0, "200", True)

    def test_invalid_quality_and_unverified_freshness_do_not_pass(self):
        with self.assertRaises(ValueError):
            QualityResult("made-up")
        run = CollectionRunV1.from_facts(
            schedule=schedule(), run_id="run-1", revision=1, manual_origin="test",
            attempts=[attempt()], pages=[PageFact(1, None, "page/1", 1, "200", 1, "d", is_terminal=True)],
            observations=[observation(None)], scope_coverage=QualityResult(COVERAGE_COMPLETE),
            freshness=QualityResult(FRESHNESS_FRESH))
        self.assertEqual(run.quality[2].status, FRESHNESS_UNKNOWN)
        timed_but_unverified = CollectionRunV1.from_facts(
            schedule=schedule(), run_id="run-2", revision=1, manual_origin="test",
            attempts=[attempt()], pages=[PageFact(1, None, "page/1", 1, "200", 1, "d", is_terminal=True)],
            observations=[observation()], freshness=QualityResult(FRESHNESS_FRESH))
        self.assertEqual(timed_but_unverified.quality[2].status, FRESHNESS_UNKNOWN)

    def test_positive_observation_vetoes_empty_proof_with_visible_conflict(self):
        run = CollectionRunV1.from_facts(
            schedule=schedule(), run_id="run-1", revision=1, manual_origin="test",
            attempts=[attempt()], pages=[PageFact(1, None, "page/1", 1, "200", 0, "d", is_terminal=True)],
            observations=[observation()], scope_coverage=QualityResult(COVERAGE_COMPLETE))
        self.assertFalse(run.is_proved_empty)
        self.assertIn("positive_observations_conflict_empty_pages", run.observation_limitations)

    def test_linked_response_class_conflict_blocks_empty_proof_on_public_paths(self):
        from uvm.ingestion import COVERAGE_PARTIAL

        unequal_attempt = AttemptFact(1, T0, T0 + timedelta(minutes=1), "opaque-attempt", True)
        unequal_page = PageFact(1, None, "page/1", 1, "opaque-page", 0, "digest", is_terminal=True)
        cohort = SyntheticExpectedCohortV1(
            "run-1", 1, "synthetic", "account-1", "scope-1", None, None,
            (unequal_page,), attempts=(unequal_attempt,))
        common = dict(schedule=schedule(), run_id="run-1", revision=1,
                      manual_origin="test", started_at=T0,
                      expected_cohort=cohort)

        from_facts = CollectionRunV1.from_facts(
            **common, attempts=[unequal_attempt], pages=[unequal_page])
        direct = CollectionRunV1(
            **common, source_family="synthetic", source_account_id="account-1",
            scope_key="scope-1", attempts=[unequal_attempt],
            pages={(1, None): unequal_page})
        incremental = CollectionRunV1(
            **common, source_family="synthetic", source_account_id="account-1",
            scope_key="scope-1")
        incremental.record_attempt(unequal_attempt)
        incremental.replay_page(unequal_page)

        for run in (from_facts, direct, incremental):
            retrieval, coverage, _ = run.derive_quality()
            self.assertEqual(retrieval.status, RETRIEVAL_PARTIAL)
            self.assertIn("linked_response_class_conflict", retrieval.reason_codes)
            self.assertEqual(coverage.status, COVERAGE_PARTIAL)
            self.assertEqual(run.evaluate_scope_coverage().status, COVERAGE_PARTIAL)
            self.assertIn("linked_response_class_conflict", run.observation_limitations)
            self.assertFalse(run.is_proved_empty)

        matching_attempt = replace(unequal_attempt, response_class="same-opaque-token")
        matching_page = replace(unequal_page, response_class="same-opaque-token")
        matching = CollectionRunV1.from_facts(
            **{**common, "expected_cohort": replace(cohort, pages=(matching_page,),
                                                      attempts=(matching_attempt,))},
            attempts=[matching_attempt], pages=[matching_page])
        self.assertEqual(matching.quality[0].status, RETRIEVAL_COMPLETE)
        self.assertTrue(matching.is_proved_empty)


if __name__ == "__main__":
    unittest.main()
