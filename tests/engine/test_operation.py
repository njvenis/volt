"""Focused behavioural tests for the EngineImportOperationV1 state machine.

Synthetic fixtures only: no HTTP, no persistence, no live engine. Covers
each status transition (pending -> settled/failed/quarantined, reuse
conflict), duplicate/lost responses, 0/false completion, mismatched
read-back, single-POST/reconciliation semantics, per-context
serialisation and prior-mapping retention.
"""

from __future__ import annotations

import unittest
import uuid
from dataclasses import replace
from datetime import datetime, timedelta, timezone

from uvm.engine import (
    SCHEMA_VERSION,
    REQUEST_IMPORT,
    REQUEST_REIMPORT,
    STATUS_CONFLICT,
    STATUS_FAILED,
    STATUS_PENDING,
    STATUS_QUARANTINED,
    STATUS_SETTLED,
    EngineImportOperationV1,
    OperationStore,
)
from uvm.engine.operation import (
    FirstImportBaselineV1,
    FindingReadbackV1,
    ReconciliationEventV1,
    ReconciliationReadbackV1,
)

T0 = datetime(2026, 7, 3, 9, 0, 0, tzinfo=timezone.utc)
CTX = "prod:acct-1/eng-prod/test-main"
PAYLOAD = "a" * 64


def _op(
    operation_id: str | None = None,
    context_key: str = CTX,
    payload: str = PAYLOAD,
    request_kind: str = REQUEST_REIMPORT,
    test_id: str = "test-1",
    status: str = STATUS_PENDING,
    **kwargs,
) -> EngineImportOperationV1:
    return EngineImportOperationV1(
        schema_version=SCHEMA_VERSION,
        operation_id=operation_id or str(uuid.uuid4()),
        revision=1,
        context_key=context_key,
        source_run_id="run-42",
        scan_type="qualys",
        payload_sha256=payload,
        parser_config_version="qualys-3.3.100-v1",
        engine_release="3.3.100",
        request_kind=request_kind,
        requested_at=T0,
        close_old_findings=False,
        status=status,
        test_id=test_id,
        **kwargs,
    )


def _rb(
    ref: str = "rb-1",
    verified: bool = True,
    findings=(),
    endpoints=(),
    test_id: str = "test-1",
    context_key: str = CTX,
) -> FindingReadbackV1:
    """A complete verified Test/Finding read-back event, bound to one
    Test and one context."""
    return FindingReadbackV1(
        readback_ref=ref,
        verified=verified,
        test_id=test_id,
        context_key=context_key,
        finding_ids=tuple(findings),
        endpoint_ids=tuple(endpoints),
    )


def _rec(
    ref: str = "rec-1", context_key: str = CTX, candidates=()
) -> ReconciliationEventV1:
    """A versioned verified supported-API reconciliation result for one
    context (scope + candidate/absence result + evidence ref)."""
    return ReconciliationEventV1(
        schema_version=SCHEMA_VERSION,
        reconciliation_ref=ref,
        context_key=context_key,
        candidate_test_ids=tuple(candidates),
    )


def _rrb(
    ref: str = "rb-1",
    verified: bool = True,
    candidates=("test-1",),
    dedup: bool = True,
    findings=(),
    endpoints=(),
    context_key: str = CTX,
) -> ReconciliationReadbackV1:
    """A versioned verified reconciliation read-back event. No write
    correlation: the CE supported API supplies no independently verifiable
    write-provenance field, so none is carried."""
    return ReconciliationReadbackV1(
        schema_version=SCHEMA_VERSION,
        readback_ref=ref,
        verified=verified,
        context_key=context_key,
        candidate_test_ids=tuple(candidates),
        deduplication_complete=dedup,
        finding_ids=tuple(findings),
        endpoint_ids=tuple(endpoints),
    )


class RegistrationTest(unittest.TestCase):
    def test_import_rejects_registered_test_and_settled_context(self):
        store = OperationStore()
        with_test = store.register(_op(request_kind=REQUEST_IMPORT))
        self.assertEqual(with_test.outcome, "rejected")
        self.assertIsNone(store.get(with_test.operation.operation_id))
        first = _op()
        store.register(first)
        store.issue_post(first.operation_id)
        store.record_response(first.operation_id, "resp", "test-1", True)
        store.settle(first.operation_id, "test-1", _rb(), 1)
        second = store.register(_op(request_kind=REQUEST_IMPORT, test_id=None))
        self.assertEqual(second.outcome, "rejected")
        self.assertEqual(store.active_mapping_revision(CTX), 1)

    def test_register_new_operation_stays_pending_and_retains_prior_mapping(self):
        store = OperationStore()
        result = store.register(_op(operation_id="11111111-1111-4111-8111-111111111111"))
        self.assertEqual(result.outcome, "registered")
        self.assertEqual(result.operation.status, STATUS_PENDING)
        self.assertIsNone(result.operation.prior_mapping_revision)
        self.assertIsNotNone(store.get(result.operation.operation_id))

    def test_register_import_starts_with_null_test_id(self):
        op = _op(request_kind=REQUEST_IMPORT, test_id=None)
        result = OperationStore().register(op)
        self.assertEqual(result.outcome, "registered")
        self.assertIsNone(result.operation.test_id)

    def test_register_reimport_requires_test_id(self):
        with self.assertRaises(ValueError):
            _op(request_kind=REQUEST_REIMPORT, test_id=None)

    def test_register_duplicate_same_operation_and_payload_is_idempotent(self):
        store = OperationStore()
        op = _op(operation_id=str(uuid.uuid4()))
        first = store.register(op)
        second = store.register(op)
        self.assertEqual(first.outcome, "registered")
        self.assertEqual(second.outcome, "duplicate")
        self.assertIs(first.operation, second.operation)
        self.assertEqual(len(store.for_context(CTX)), 1)

    def test_register_duplicate_after_mutation_still_idempotent(self):
        # Re-sending a stored operation after its revision advanced (e.g.
        # response recorded) is still a duplicate, not a context change.
        store = OperationStore()
        op = _op(operation_id=str(uuid.uuid4()))
        op_id = op.operation_id
        store.register(op)
        store.issue_post(op_id)
        store.record_response(op_id, "resp-1", "test-1", True)
        second = store.register(op)
        self.assertEqual(second.outcome, "duplicate")

    def test_register_reuse_with_different_payload_is_conflict(self):
        store = OperationStore()
        op = _op(operation_id=str(uuid.uuid4()))
        op_id = op.operation_id
        store.register(op)
        result = store.register(replace(op, payload_sha256="b" * 64))
        self.assertEqual(result.outcome, "conflict")
        self.assertEqual(result.conflict_with, op_id)
        retained = store.get(op_id)
        self.assertEqual(retained.status, STATUS_CONFLICT)
        self.assertIsNotNone(store.active_operation(CTX))

    def test_register_reuse_with_different_context_is_conflict(self):
        store = OperationStore()
        op = _op(operation_id=str(uuid.uuid4()))
        op_id = op.operation_id
        store.register(op)
        result = store.register(replace(op, context_key="prod:acct-1/other"))
        self.assertEqual(result.outcome, "conflict")
        self.assertEqual(result.conflict_with, op_id)
        self.assertEqual(store.get(op_id).status, STATUS_CONFLICT)

    def test_register_second_operation_for_active_context_is_conflict(self):
        # Per-context serialisation: one active write at a time.
        store = OperationStore()
        first = _op(operation_id=str(uuid.uuid4()))
        store.register(first)
        result = store.register(_op(operation_id=str(uuid.uuid4())))
        self.assertEqual(result.outcome, "conflict")
        self.assertEqual(result.conflict_with, first.operation_id)
        self.assertIsNone(store.get(result.operation.operation_id))

    def test_register_second_operation_for_same_registered_test_is_conflict(self):
        # Test-level serialisation: a different context_key targeting the
        # same registered Test may not run a second active write on it.
        store = OperationStore()
        first = _op(operation_id=str(uuid.uuid4()), context_key=CTX)
        store.register(first)
        result = store.register(
            _op(
                operation_id=str(uuid.uuid4()),
                context_key="prod:acct-1/eng-prod/test-other",
                test_id="test-1",
            )
        )
        self.assertEqual(result.outcome, "conflict")
        self.assertEqual(result.conflict_with, first.operation_id)
        self.assertIn("registered Test", result.reason)
        # an import (Test not yet known) is not Test-serialised
        store2 = OperationStore()
        store2.register(_op(operation_id=str(uuid.uuid4())))
        imp = store2.register(
            _op(
                operation_id=str(uuid.uuid4()),
                context_key="prod:acct-1/eng-prod/test-other",
                request_kind=REQUEST_IMPORT,
                test_id=None,
            )
        )
        self.assertEqual(imp.outcome, "registered")

    def test_register_reuse_with_different_test_id_is_conflict(self):
        # The registered Test is pre-POST context: reusing the operation ID
        # with a changed Test is a conflict, not an idempotent duplicate.
        store = OperationStore()
        op = _op(operation_id=str(uuid.uuid4()), test_id="test-1")
        op_id = op.operation_id
        store.register(op)
        result = store.register(replace(op, test_id="test-2"))
        self.assertEqual(result.outcome, "conflict")
        self.assertEqual(result.conflict_with, op_id)
        self.assertEqual(store.get(op_id).status, STATUS_CONFLICT)
        self.assertEqual(store.get(op_id).test_id, "test-1")

    def test_register_after_settled_or_failed_is_allowed(self):
        store = OperationStore()
        first = _op(operation_id=str(uuid.uuid4()))
        op_id = first.operation_id
        store.register(first)
        store.issue_post(op_id)
        store.record_response(op_id, "resp-1", "test-1", True)
        settled = store.settle(op_id, "test-1", _rb(findings=("f-1",), endpoints=()), 1)
        self.assertEqual(settled.outcome, "settled")
        again = store.register(_op(operation_id=str(uuid.uuid4())))
        self.assertEqual(again.outcome, "registered")
        # prior active mapping is retained on the new operation
        self.assertEqual(again.operation.prior_mapping_revision, 1)
        # a definitively rejected (failed) request does not block the context
        second = again.operation
        store.mark_failed(second.operation_id, "400", "error/missing-field")
        third = store.register(_op(operation_id=str(uuid.uuid4())))
        self.assertEqual(third.outcome, "registered")

    def test_re_register_unchanged_import_after_settle_is_duplicate(self):
        # Reviewer 718c282f finding: the Test binding is a settle result, not
        # a request mutation — re-registering the unchanged pre-POST import
        # must reconcile (duplicate), never conflict.
        store = OperationStore()
        op = _op(
            operation_id=str(uuid.uuid4()),
            request_kind=REQUEST_IMPORT,
            test_id=None,
        )
        op_id = op.operation_id
        store.register(op)
        store.record_first_import_baseline(
            op_id, FirstImportBaselineV1(SCHEMA_VERSION, "baseline-empty", True, CTX, ())
        )
        store.issue_post(op_id)
        store.record_response(op_id, "resp-1", None, True)
        settled = store.settle(
            op_id, "auto-test-7", _rb(test_id="auto-test-7", findings=("f-1",)), 1
        )
        self.assertEqual(settled.outcome, "settled")
        stored = store.get(op_id)
        self.assertIsNone(stored.test_id)
        self.assertEqual(stored.bound_test_id, "auto-test-7")
        again = store.register(op)
        self.assertEqual(again.outcome, "duplicate")
        self.assertEqual(again.operation, stored)

    def test_register_reuse_with_changed_requested_at_is_conflict(self):
        # requested_at is part of the request: a changed timestamp is a
        # conflict, not an idempotent duplicate.
        store = OperationStore()
        op = _op(operation_id=str(uuid.uuid4()))
        op_id = op.operation_id
        store.register(op)
        result = store.register(replace(op, requested_at=T0 + timedelta(seconds=1)))
        self.assertEqual(result.outcome, "conflict")
        self.assertEqual(result.conflict_with, op_id)
        self.assertEqual(store.get(op_id).status, STATUS_CONFLICT)
        # the request instant is untouched by the conflict
        self.assertEqual(store.get(op_id).requested_at, T0)


class PostAndResponseTest(unittest.TestCase):
    def test_same_operation_payload_never_triggers_a_second_post(self):
        store = OperationStore()
        op = _op(operation_id=str(uuid.uuid4()))
        op_id = op.operation_id
        store.register(op)
        first = store.issue_post(op_id)
        second = store.issue_post(op_id)
        self.assertEqual(first.outcome, "post_allowed")
        self.assertTrue(first.operation.post_issued)
        self.assertEqual(second.outcome, "post_blocked")
        self.assertIn("no second POST", second.reason)

    def test_recorded_response_stays_pending(self):
        store = OperationStore()
        op = _op(operation_id=str(uuid.uuid4()))
        op_id = op.operation_id
        store.register(op)
        store.issue_post(op_id)
        result = store.record_response(op_id, "resp-1", "test-1", True)
        self.assertEqual(result.outcome, "recorded")
        self.assertEqual(result.operation.status, STATUS_PENDING)

    def test_duplicate_response_is_idempotent_conflicting_response_is_conflict(self):
        store = OperationStore()
        op = _op(operation_id=str(uuid.uuid4()))
        op_id = op.operation_id
        store.register(op)
        store.issue_post(op_id)
        store.record_response(op_id, "resp-1", "test-1", False)
        dup = store.record_response(op_id, "resp-1", "test-1", False)
        self.assertEqual(dup.outcome, "duplicate")
        clash = store.record_response(op_id, "resp-1", "test-999", True)
        self.assertEqual(clash.outcome, "quarantined")
        self.assertEqual(store.get(op_id).response_ref, "resp-1")

    def test_conflicting_second_response_quarantines_and_blocks_settle(self):
        # A second, inconsistent HTTP response quarantines the operation
        # (design: zero/multiple/inconsistent candidates) and blocks settle
        # until reconciliation; the first response evidence is retained.
        store = OperationStore()
        op = _op(operation_id=str(uuid.uuid4()))
        op_id = op.operation_id
        store.register(op)
        store.issue_post(op_id)
        store.record_response(op_id, "resp-1", "test-1", True)
        result = store.record_response(op_id, "resp-2", "test-999", False)
        self.assertEqual(result.outcome, "quarantined")
        stored = store.get(op_id)
        self.assertEqual(stored.status, STATUS_QUARANTINED)
        self.assertEqual(stored.response_ref, "resp-1")
        self.assertEqual(stored.response_test_id, "test-1")
        # settle and retry are blocked while quarantined
        lost_settle = store.settle(op_id, "test-1", _rb(findings=(), endpoints=()), 1)
        self.assertEqual(lost_settle.outcome, "not_settled")
        self.assertEqual(store.issue_post(op_id).outcome, "post_blocked")
        # a later, identical-to-second response is not silently accepted
        self.assertEqual(
            store.record_response(op_id, "resp-2", "test-999", False).outcome,
            "not_recorded",
        )

    def test_replay_original_response_after_dedup_readback_is_not_quarantined(
        self,
    ):
        # Reviewer 718c282f finding: the replay is compared against the
        # original captured response, not against the later deduplication
        # completion state; an unchanged replay after a verified read-back
        # advanced the flag is idempotent, while a genuinely inconsistent
        # second response still quarantines.
        store = OperationStore()
        op = _op(operation_id=str(uuid.uuid4()))
        op_id = op.operation_id
        store.register(op)
        store.issue_post(op_id)
        store.record_response(op_id, "resp-1", "test-1", False)
        advanced = store.record_dedup_readback(op_id, "readback-dedup-1", True)
        self.assertEqual(advanced.outcome, "recorded")
        self.assertTrue(store.get(op_id).deduplication_complete)
        # the original captured flag is retained separately
        self.assertFalse(store.get(op_id).response_deduplication_complete)
        replay = store.record_response(op_id, "resp-1", "test-1", False)
        self.assertEqual(replay.outcome, "duplicate")
        stored = store.get(op_id)
        self.assertEqual(stored.status, STATUS_PENDING)
        self.assertTrue(stored.deduplication_complete)
        # an inconsistent second response still quarantines
        clash = store.record_response(op_id, "resp-2", "test-999", False)
        self.assertEqual(clash.outcome, "quarantined")
        # same ref and Test, different captured completion flag: inconsistent
        store2 = OperationStore()
        op2 = _op(operation_id=str(uuid.uuid4()))
        op2_id = op2.operation_id
        store2.register(op2)
        store2.issue_post(op2_id)
        store2.record_response(op2_id, "resp-1", "test-1", False)
        second = store2.record_response(op2_id, "resp-1", "test-1", True)
        self.assertEqual(second.outcome, "quarantined")
        self.assertEqual(store2.get(op2_id).status, STATUS_QUARANTINED)

    def test_lost_response_quarantines_and_empty_search_never_retries(self):
        store = OperationStore()
        op = _op(operation_id=str(uuid.uuid4()), request_kind=REQUEST_IMPORT, test_id=None)
        op_id = op.operation_id
        store.register(op)
        store.record_first_import_baseline(
            op_id, FirstImportBaselineV1(SCHEMA_VERSION, "baseline-empty", True, CTX, ())
        )
        store.issue_post(op_id)
        q = store.mark_uncertain(op_id, "lost-response:timeout")
        self.assertEqual(q.outcome, "quarantined")
        self.assertEqual(q.operation.status, STATUS_QUARANTINED)
        # retry blocked while quarantined
        self.assertEqual(store.issue_post(op_id).outcome, "post_blocked")
        # settle blocked: lost/uncertain response
        lost_settle = store.settle(op_id, "test-1", _rb(findings=(), endpoints=()), 1)
        self.assertEqual(lost_settle.outcome, "not_settled")
        # a bare Boolean is never reconciliation evidence
        bad = store.reconcile(op_id, False)
        self.assertEqual(bad.outcome, "not_reconciled")
        self.assertEqual(store.get(op_id).status, STATUS_QUARANTINED)
        # a read taken against a different context refuses
        bad_ctx = store.reconcile(op_id, _rec(context_key="other"))
        self.assertEqual(bad_ctx.outcome, "not_reconciled")
        self.assertEqual(store.get(op_id).status, STATUS_QUARANTINED)
        # A found first-import Test refuses retry and can be settled from
        # a fresh, scoped reconciliation read-back.
        found = store.reconcile(op_id, _rec(candidates=("test-1",)))
        self.assertEqual(found.outcome, "not_reconciled")
        self.assertEqual(store.get(op_id).status, STATUS_QUARANTINED)
        # An empty result after the empty pre-POST baseline cannot prove
        # that the first POST did not write or is not still in flight.
        ok = store.reconcile(op_id, _rec(ref="rec-absence-1"))
        self.assertEqual(ok.outcome, "not_reconciled")
        self.assertEqual(ok.operation.status, STATUS_QUARANTINED)
        self.assertIsNone(ok.operation.reconciliation_evidence_ref)
        retry = store.issue_post(op_id)
        self.assertEqual(retry.outcome, "post_blocked")
        self.assertFalse(retry.operation.reconciled)
        self.assertEqual(store.issue_post(op_id).outcome, "post_blocked")

    def test_pending_retains_prior_mapping_across_quarantine(self):
        store = OperationStore()
        first = _op(operation_id=str(uuid.uuid4()))
        op_id = first.operation_id
        store.register(first)
        store.issue_post(op_id)
        store.record_response(op_id, "resp-1", "test-1", True)
        store.settle(op_id, "test-1", _rb(findings=("f-1",), endpoints=("e-1",)), 1)
        self.assertEqual(store.active_mapping_revision(CTX), 1)
        # a later pending/quarantined operation holds the prior mapping
        # and never advances or erases it
        second = store.register(_op(operation_id=str(uuid.uuid4())))
        self.assertEqual(second.operation.prior_mapping_revision, 1)
        second_id = second.operation.operation_id
        store.mark_uncertain(second_id, "lost-response")
        self.assertEqual(store.get(second_id).prior_mapping_revision, 1)
        self.assertEqual(store.active_mapping_revision(CTX), 1)
        self.assertEqual(store.get(second_id).mapping_revision, None)


class PrePostStateTest(unittest.TestCase):
    """The clean pre-POST state: no response evidence before issue_post."""

    def test_record_response_rejected_before_post(self):
        # CR-01: a response recorded before the POST is not evidence about
        # this write and is rejected; the operation stays clean pre-POST.
        store = OperationStore()
        op = _op(operation_id=str(uuid.uuid4()))
        op_id = op.operation_id
        store.register(op)
        early = store.record_response(op_id, "resp-early", "test-1", True)
        self.assertEqual(early.outcome, "not_recorded")
        self.assertIn("before issue_post", early.reason)
        stored = store.get(op_id)
        self.assertIsNone(stored.response_ref)
        self.assertEqual(stored.status, STATUS_PENDING)
        # the legitimate flow still works once the POST has been issued
        self.assertEqual(store.issue_post(op_id).outcome, "post_allowed")
        self.assertEqual(store.record_response(op_id, "resp-1", "test-1", True).outcome, "recorded")

    def test_pending_dto_cannot_carry_pre_post_response_evidence(self):
        # CR-01: a pre-POST pending DTO carrying recorded response evidence
        # is evidence about a write that never happened; the dataclass
        # rejects it.
        with self.assertRaises(ValueError):
            _op(
                status=STATUS_PENDING,
                response_ref="resp-forged",
                response_test_id="test-1",
                response_deduplication_complete=True,
            )
        with self.assertRaises(ValueError):
            _op(status=STATUS_PENDING, response_test_id="test-1")
        with self.assertRaises(ValueError):
            _op(status=STATUS_PENDING, response_deduplication_complete=True)
        # post-POST response evidence on a pending operation is legitimate
        # as store-created state (issue_post + record_response)
        post = _op(
            status=STATUS_PENDING,
            post_issued=True,
            response_ref="resp-1",
            response_test_id="test-1",
            response_deduplication_complete=True,
        )
        self.assertEqual(post.response_ref, "resp-1")

    def test_register_rejects_externally_pre_issued_dto(self):
        # CR-01: a caller-supplied pending DTO carrying an externally
        # pre-issued flag plus response evidence must not be registrable;
        # it would let the caller settle a write the store never issued.
        store = OperationStore()
        forged = _op(
            status=STATUS_PENDING,
            post_issued=True,
            response_ref="resp-forged",
            response_test_id="test-1",
            response_deduplication_complete=True,
        )
        result = store.register(forged)
        self.assertEqual(result.outcome, "rejected")
        self.assertIn("issue_post", result.reason)
        self.assertIsNone(store.get(forged.operation_id))
        # and even if it were stored, settle and quarantine would refuse:
        # the store only marks writes it issued
        self.assertEqual(
            store.mark_uncertain(forged.operation_id, "lost").outcome,
            "not_found",
        )

    def test_mark_uncertain_requires_issued_post(self):
        # A lost/uncertain response presumes an issued POST: quarantining a
        # never-issued write would manufacture a lost-response state that a
        # reconciliation read-back could then settle.
        store = OperationStore()
        op = _op(operation_id=str(uuid.uuid4()))
        store.register(op)
        result = store.mark_uncertain(op.operation_id, "lost-response")
        self.assertEqual(result.outcome, "not_quarantined")
        self.assertIn("issued", result.reason)
        stored = store.get(op.operation_id)
        self.assertEqual(stored.status, STATUS_PENDING)
        # the legitimate flow: issue first, then a lost response quarantines
        self.assertEqual(store.issue_post(op.operation_id).outcome, "post_allowed")
        self.assertEqual(
            store.mark_uncertain(op.operation_id, "lost-response:timeout").outcome,
            "quarantined",
        )

    def test_settle_requires_issued_post(self):
        # Settling requires the issued write plus a post-write read-back; a
        # POST-less operation has no write to settle.
        store = OperationStore()
        op = _op(operation_id=str(uuid.uuid4()))
        store.register(op)
        result = store.settle(
            op.operation_id, "test-1", _rb(findings=("f-1",), endpoints=()), 1
        )
        self.assertEqual(result.outcome, "not_settled")
        self.assertIn("issued", result.reason)
        self.assertEqual(store.get(op.operation_id).status, STATUS_PENDING)
        self.assertIsNone(store.get(op.operation_id).mapping_revision)
        self.assertIsNone(store.active_mapping_revision(CTX))


class SettleTest(unittest.TestCase):
    def _settled_store(self, dedup: bool | None = True, response_test_id="test-1"):
        store = OperationStore()
        op = _op(operation_id=str(uuid.uuid4()))
        op_id = op.operation_id
        store.register(op)
        store.issue_post(op_id)
        store.record_response(op_id, "resp-1", response_test_id, dedup)
        return store, op_id

    def test_zero_false_completion_cannot_settle(self):
        for dedup in (False, None):
            store, op_id = self._settled_store(dedup=dedup)
            result = store.settle(op_id, "test-1", _rb(findings=(), endpoints=()), 1)
            self.assertEqual(result.outcome, "not_settled")
            self.assertIn("0/false completion", result.reason)
            self.assertEqual(store.get(op_id).status, STATUS_PENDING)

    def test_mismatched_read_back_cannot_settle(self):
        store, op_id = self._settled_store(dedup=True, response_test_id="test-1")
        result = store.settle(op_id, "test-999", _rb(findings=(), endpoints=()), 1)
        self.assertEqual(result.outcome, "not_settled")
        self.assertIn("inconsistent", result.reason)
        self.assertEqual(store.get(op_id).status, STATUS_PENDING)
        self.assertIsNone(store.get(op_id).mapping_revision)

    def test_missing_read_back_cannot_settle(self):
        store, op_id = self._settled_store(dedup=True)
        result = store.settle(op_id, "", _rb(findings=(), endpoints=()), 1)
        self.assertEqual(result.outcome, "not_settled")
        self.assertEqual(store.get(op_id).status, STATUS_PENDING)

    def test_settle_rejects_naked_caller_finding_ids(self):
        # A bare tuple of caller-supplied Finding IDs is never settle
        # evidence; only a complete FindingReadbackV1 read-back event is.
        store, op_id = self._settled_store(dedup=True)
        result = store.settle(op_id, "test-1", ("f-1",), 1)
        self.assertEqual(result.outcome, "not_settled")
        self.assertIn("naked", result.reason)
        self.assertEqual(store.get(op_id).status, STATUS_PENDING)
        self.assertIsNone(store.get(op_id).mapping_revision)

    def test_settle_rejects_unverified_and_refless_readback(self):
        store, op_id = self._settled_store(dedup=True)
        unverified = store.settle(
            op_id, "test-1", _rb(ref="rb-uv", verified=False, findings=("f-1",)), 1
        )
        self.assertEqual(unverified.outcome, "not_settled")
        self.assertIn("verified", unverified.reason)
        no_ref = store.settle(op_id, "test-1", _rb(ref=""), 1)
        self.assertEqual(no_ref.outcome, "not_settled")
        self.assertIn("evidence ref", no_ref.reason)
        self.assertEqual(store.get(op_id).status, STATUS_PENDING)
        self.assertIsNone(store.get(op_id).settle_readback_ref)

    def test_settle_allows_verified_empty_readback_and_stores_evidence(self):
        # A verified empty set is honest (the Test genuinely has no
        # findings); it settles and stores the read-back evidence.
        store, op_id = self._settled_store(dedup=True)
        result = store.settle(op_id, "test-1", _rb(ref="rb-empty"), 1)
        self.assertEqual(result.outcome, "settled")
        stored = store.get(op_id)
        self.assertEqual(stored.finding_ids, ())
        self.assertEqual(stored.endpoint_ids, ())
        self.assertEqual(stored.settle_readback_ref, "rb-empty")
        self.assertEqual(store.active_mapping_revision(CTX), 1)

    def test_settle_stores_measured_findings_from_readback(self):
        store, op_id = self._settled_store(dedup=True)
        result = store.settle(
            op_id,
            "test-1",
            _rb(ref="rb-s", findings=("f-1", "f-2"), endpoints=("e-1",)),
            1,
        )
        self.assertEqual(result.outcome, "settled")
        self.assertEqual(result.operation.finding_ids, ("f-1", "f-2"))
        self.assertEqual(result.operation.endpoint_ids, ("e-1",))
        self.assertEqual(result.operation.settle_readback_ref, "rb-s")

    def test_settle_requires_strictly_advancing_mapping_revision(self):
        store, op_id = self._settled_store(dedup=True)
        result = store.settle(op_id, "test-1", _rb(findings=("f-1",), endpoints=("e-1",)), 1)
        self.assertEqual(result.outcome, "settled")
        self.assertEqual(result.operation.status, STATUS_SETTLED)
        self.assertEqual(result.operation.test_id, "test-1")
        self.assertEqual(result.operation.finding_ids, ("f-1",))
        self.assertEqual(result.operation.mapping_revision, 1)
        self.assertEqual(result.operation.revision, 4)
        self.assertEqual(store.active_mapping_revision(CTX), 1)
        # a second settle attempt is terminal-blocked
        again = store.settle(op_id, "test-1", _rb(findings=(), endpoints=()), 2)
        self.assertEqual(again.outcome, "not_settled")

    def test_mapping_revision_must_exceed_prior_active_mapping(self):
        store, op_id = self._settled_store(dedup=True)
        store.settle(op_id, "test-1", _rb(findings=(), endpoints=()), 1)
        second = store.register(_op(operation_id=str(uuid.uuid4())))
        second_id = second.operation.operation_id
        store.issue_post(second_id)
        store.record_response(second_id, "resp-2", "test-1", True)
        same = store.settle(second_id, "test-1", _rb(findings=(), endpoints=()), 1)
        self.assertEqual(same.outcome, "not_settled")
        advanced = store.settle(second_id, "test-1", _rb(findings=(), endpoints=()), 2)
        self.assertEqual(advanced.outcome, "settled")
        self.assertEqual(store.active_mapping_revision(CTX), 2)

    def test_settle_binds_test_id_from_read_back(self):
        store = OperationStore()
        op = _op(
            operation_id=str(uuid.uuid4()),
            request_kind=REQUEST_IMPORT,
            test_id=None,
        )
        op_id = op.operation_id
        store.register(op)
        store.record_first_import_baseline(
            op_id, FirstImportBaselineV1(SCHEMA_VERSION, "baseline-empty", True, CTX, ())
        )
        # async response may not name the Test ID; the read-back binds it
        store.issue_post(op_id)
        store.record_response(op_id, "resp-1", None, True)
        result = store.settle(op_id, "auto-test-7", _rb(test_id="auto-test-7", findings=("f-1",), endpoints=()), 1)
        self.assertEqual(result.outcome, "settled")
        # the binding is a settle result; the request test_id stays null
        self.assertEqual(result.operation.bound_test_id, "auto-test-7")
        self.assertIsNone(result.operation.test_id)

    def test_import_response_without_test_id_needs_freshness_proof(self):
        store = OperationStore()
        op = _op(request_kind=REQUEST_IMPORT, test_id=None)
        store.register(op)
        store.issue_post(op.operation_id)
        store.record_response(op.operation_id, "response", None, True)
        result = store.settle(
            op.operation_id, "possibly-old-test", _rb(test_id="possibly-old-test"), 1
        )
        self.assertEqual(result.outcome, "not_settled")
        self.assertEqual(store.active_mapping_revision(CTX), None)

    def test_import_response_with_test_id_still_needs_freshness_proof(self):
        # A response naming an old Test does not prove that this first
        # import created it. The context must have been verified empty
        # before the POST, regardless of what the response contains.
        store = OperationStore()
        op = _op(request_kind=REQUEST_IMPORT, test_id=None)
        store.register(op)
        store.issue_post(op.operation_id)
        store.record_response(op.operation_id, "response", "preexisting-test", True)
        result = store.settle(
            op.operation_id,
            "preexisting-test",
            _rb(test_id="preexisting-test", findings=("old-finding",)),
            1,
        )
        self.assertEqual(result.outcome, "not_settled")
        self.assertIn("pre-POST baseline", result.reason)
        self.assertEqual(store.get(op.operation_id).status, STATUS_PENDING)
        self.assertIsNone(store.get(op.operation_id).bound_test_id)
        self.assertIsNone(store.active_mapping_revision(CTX))

    def test_import_response_with_test_id_and_empty_baseline_settles(self):
        store = OperationStore()
        op = _op(request_kind=REQUEST_IMPORT, test_id=None)
        store.register(op)
        baseline = FirstImportBaselineV1(SCHEMA_VERSION, "baseline-empty", True, CTX, ())
        self.assertEqual(
            store.record_first_import_baseline(op.operation_id, baseline).outcome,
            "recorded",
        )
        store.issue_post(op.operation_id)
        store.record_response(op.operation_id, "response", "new-test", True)
        result = store.settle(
            op.operation_id, "new-test", _rb(test_id="new-test"), 1
        )
        self.assertEqual(result.outcome, "settled")
        self.assertEqual(result.operation.bound_test_id, "new-test")
        self.assertEqual(store.active_mapping_revision(CTX), 1)

    def test_settle_rejects_readback_bound_to_different_test_or_context(self):
        # The read-back event is bound to one Test and one context; a
        # binding that disagrees with the settled Test or the operation
        # context is inconsistent settle evidence.
        store, op_id = self._settled_store(dedup=True)
        other_test = store.settle(op_id, "test-1", _rb(test_id="test-9"), 1)
        self.assertEqual(other_test.outcome, "not_settled")
        self.assertIn("inconsistent", other_test.reason)
        other_ctx = store.settle(op_id, "test-1", _rb(context_key="other"), 1)
        self.assertEqual(other_ctx.outcome, "not_settled")
        self.assertEqual(store.get(op_id).status, STATUS_PENDING)

    def test_reimport_read_back_must_match_registered_test_when_response_omitted(self):
        # The response omitted the Test ID: that never waives the registered
        # reimport Test, so a different read-back Test cannot settle.
        store, op_id = self._settled_store(dedup=True, response_test_id=None)
        result = store.settle(op_id, "test-2", _rb(test_id="test-2", findings=(), endpoints=()), 1)
        self.assertEqual(result.outcome, "not_settled")
        self.assertIn("registered reimport Test ID", result.reason)
        self.assertEqual(store.get(op_id).status, STATUS_PENDING)
        self.assertIsNone(store.get(op_id).mapping_revision)

    def test_reimport_settles_when_read_back_matches_registered_test(self):
        store, op_id = self._settled_store(dedup=True, response_test_id=None)
        result = store.settle(op_id, "test-1", _rb(findings=("f-1"), endpoints=()), 1)
        self.assertEqual(result.outcome, "settled")
        self.assertEqual(result.operation.test_id, "test-1")


class ReadbackScopeValidationTest(unittest.TestCase):
    def test_finding_readback_requires_test_and_context_scope(self):
        with self.assertRaises(ValueError):
            FindingReadbackV1(
                readback_ref="r", verified=True, test_id="", context_key=CTX
            )
        with self.assertRaises(ValueError):
            FindingReadbackV1(
                readback_ref="r", verified=True, test_id="t", context_key=""
            )

    def test_reconciliation_event_requires_scope_and_clean_candidates(self):
        with self.assertRaises(ValueError):
            ReconciliationEventV1(
                schema_version=SCHEMA_VERSION, reconciliation_ref="r", context_key=""
            )
        with self.assertRaises(ValueError):
            ReconciliationEventV1(
                schema_version=SCHEMA_VERSION,
                reconciliation_ref="r",
                context_key=CTX,
                candidate_test_ids=("test-1", "", "test-2"),
            )
        with self.assertRaises(ValueError):
            ReconciliationReadbackV1(
                schema_version=SCHEMA_VERSION,
                readback_ref="r",
                verified=True,
                context_key="",
                candidate_test_ids=("test-1",),
                deduplication_complete=True,
            )


class ReconciliationReadbackTest(unittest.TestCase):
    """A completed engine write discovered through the supported API after a
    lost HTTP response settles a quarantined operation from a unique
    context/Test/Finding read-back, with no new POST."""

    def _quarantined_lost(self):
        store = OperationStore()
        op = _op(operation_id=str(uuid.uuid4()))
        op_id = op.operation_id
        store.register(op)
        store.issue_post(op_id)
        store.mark_uncertain(op_id, "lost-response:timeout")
        self.assertEqual(store.get(op_id).status, STATUS_QUARANTINED)
        return store, op_id

    def test_settle_reconciliation_rejects_naked_tuples(self):
        # Bare caller-supplied Finding IDs (no event, no evidence ref, no
        # settle_readback_ref) are never lost-response settle evidence.
        store, op_id = self._quarantined_lost()
        result = store.settle_reconciliation_readback(op_id, ("f-1",), 1)
        self.assertEqual(result.outcome, "not_settled")
        self.assertIn("naked", result.reason)
        self.assertEqual(store.get(op_id).status, STATUS_QUARANTINED)
        self.assertIsNone(store.get(op_id).settle_readback_ref)

    def test_lost_reimport_stays_quarantined_even_with_full_readback(self):
        # CR-01/03/04: a complete, verified, in-scope read-back of the
        # registered Test's Findings cannot settle a lost reimport — the CE
        # supported API carries no independently verifiable write-provenance
        # field, so a caller-supplied source-run correlation is not proof
        # and stale preexisting data must never advance the revision.
        store, op_id = self._quarantined_lost()
        result = store.settle_reconciliation_readback(
            op_id,
            _rrb(ref="rb-1", findings=("f-1", "f-2"), endpoints=("e-1",)),
            1,
        )
        self.assertEqual(result.outcome, "not_settled")
        self.assertIn("quarantined", result.reason)
        stored = store.get(op_id)
        self.assertEqual(stored.status, STATUS_QUARANTINED)
        self.assertIsNone(stored.mapping_revision)
        self.assertEqual(store.active_mapping_revision(CTX), None)
        # An empty Test list cannot prove this preexisting Test was not reimported.
        self.assertEqual(store.reconcile(op_id, _rec(ref="rec-again")).outcome, "not_reconciled")
        self.assertEqual(store.issue_post(op_id).outcome, "post_blocked")

    def test_lost_reimport_empty_test_search_preserves_prior_mapping(self):
        store = OperationStore()
        first = _op()
        store.register(first)
        store.issue_post(first.operation_id)
        store.record_response(first.operation_id, "resp-1", "test-1", True)
        store.settle(first.operation_id, "test-1", _rb(findings=("old-finding",)), 1)
        second = _op()
        store.register(second)
        store.issue_post(second.operation_id)
        store.mark_uncertain(second.operation_id, "lost response")
        result = store.reconcile(second.operation_id, _rec(ref="empty-test-search"))
        self.assertEqual(result.outcome, "not_reconciled")
        self.assertEqual(store.get(second.operation_id).status, STATUS_QUARANTINED)
        self.assertEqual(store.issue_post(second.operation_id).outcome, "post_blocked")
        self.assertEqual(store.active_mapping_revision(CTX), 1)
        self.assertEqual(store.get(first.operation_id).finding_ids, ("old-finding",))

    def test_lost_first_import_needs_pre_post_absence_proof(self):
        store = OperationStore()
        op = _op(request_kind=REQUEST_IMPORT, test_id=None)
        store.register(op)
        store.issue_post(op.operation_id)
        store.mark_uncertain(op.operation_id, "lost response")
        result = store.settle_reconciliation_readback(
            op.operation_id, _rrb(candidates=("new-test",)), 1
        )
        self.assertEqual(result.outcome, "not_settled")
        self.assertEqual(store.get(op.operation_id).status, STATUS_QUARANTINED)
        self.assertEqual(
            store.reconcile(op.operation_id, _rec(ref="empty-after-post")).outcome,
            "not_reconciled",
        )
        self.assertEqual(store.issue_post(op.operation_id).outcome, "post_blocked")

    def test_pre_post_baseline_must_be_empty_verified_and_in_scope(self):
        store = OperationStore()
        op = _op(request_kind=REQUEST_IMPORT, test_id=None)
        store.register(op)
        for event in (
            FirstImportBaselineV1(SCHEMA_VERSION, "baseline", False, CTX, ()),
            FirstImportBaselineV1(SCHEMA_VERSION, "baseline", True, "other", ()),
            FirstImportBaselineV1(SCHEMA_VERSION, "baseline", True, CTX, ("old-test",)),
        ):
            self.assertEqual(store.record_first_import_baseline(op.operation_id, event).outcome, "not_recorded")
        good = FirstImportBaselineV1(SCHEMA_VERSION, "baseline", True, CTX, ())
        with self.assertRaises(ValueError):
            FirstImportBaselineV1(999, "baseline", True, CTX, ())
        self.assertEqual(store.record_first_import_baseline(op.operation_id, good).outcome, "recorded")
        store.issue_post(op.operation_id)
        self.assertEqual(store.record_first_import_baseline(op.operation_id, good).outcome, "not_recorded")

    def test_first_import_unique_test_readback_settles_without_new_post(self):
        # The unique Test read-back remains the settle path for a lost first
        # import: the verified empty pre-POST context and a unique fresh
        # candidate in that context identify the write.
        store = OperationStore()
        op = _op(
            operation_id=str(uuid.uuid4()),
            request_kind=REQUEST_IMPORT,
            test_id=None,
        )
        op_id = op.operation_id
        store.register(op)
        store.record_first_import_baseline(
            op_id, FirstImportBaselineV1(SCHEMA_VERSION, "baseline-empty", True, CTX, ())
        )
        store.issue_post(op_id)
        store.mark_uncertain(op_id, "lost-response:timeout")
        result = store.settle_reconciliation_readback(
            op_id,
            _rrb(
                ref="rb-1",
                candidates=("auto-test-7",),
                findings=("f-1", "f-2"),
                endpoints=("e-1",),
            ),
            1,
        )
        self.assertEqual(result.outcome, "settled")
        stored = store.get(op_id)
        self.assertEqual(stored.status, STATUS_SETTLED)
        self.assertEqual(stored.bound_test_id, "auto-test-7")
        self.assertEqual(stored.finding_ids, ("f-1", "f-2"))
        self.assertEqual(stored.endpoint_ids, ("e-1",))
        self.assertEqual(stored.mapping_revision, 1)
        self.assertTrue(stored.deduplication_complete)
        self.assertEqual(stored.deduplication_evidence_ref, "rb-1")
        # the read-back evidence ref is stored, never a fabricated response
        self.assertEqual(stored.settle_readback_ref, "rb-1")
        # the lost response is not fabricated; no new POST is possible
        self.assertIsNone(stored.response_ref)
        self.assertEqual(store.active_mapping_revision(CTX), 1)
        self.assertEqual(store.issue_post(op_id).outcome, "post_blocked")

    def test_zero_candidates_do_not_retry_reimport(self):
        store, op_id = self._quarantined_lost()
        result = store.settle_reconciliation_readback(op_id, _rrb(ref="rb-z", candidates=()), 1)
        self.assertEqual(result.outcome, "not_settled")
        self.assertEqual(store.get(op_id).status, STATUS_QUARANTINED)
        # A reimport targets a preexisting Test, so an empty Test search does
        # not prove that its write failed to execute.
        ok = store.reconcile(op_id, _rec(ref="rec-z"))
        self.assertEqual(ok.outcome, "not_reconciled")
        self.assertEqual(ok.operation.status, STATUS_QUARANTINED)
        self.assertEqual(store.issue_post(op_id).outcome, "post_blocked")

    def test_first_import_readback_rejects_test_bound_elsewhere(self):
        store = OperationStore()
        first = _op(context_key="other-context", test_id="old-test")
        store.register(first)
        store.issue_post(first.operation_id)
        store.record_response(first.operation_id, "resp", "old-test", True)
        store.settle(
            first.operation_id, "old-test",
            _rb(test_id="old-test", context_key="other-context"), 1,
        )
        op = _op(request_kind=REQUEST_IMPORT, test_id=None)
        store.register(op)
        store.record_first_import_baseline(
            op.operation_id, FirstImportBaselineV1(SCHEMA_VERSION, "baseline", True, CTX, ())
        )
        store.issue_post(op.operation_id)
        store.mark_uncertain(op.operation_id, "lost response")
        result = store.settle_reconciliation_readback(
            op.operation_id, _rrb(candidates=("old-test",)), 1
        )
        self.assertEqual(result.outcome, "not_settled")
        self.assertEqual(store.get(op.operation_id).status, STATUS_QUARANTINED)

    def test_multiple_candidates_stay_quarantined(self):
        store, op_id = self._quarantined_lost()
        result = store.settle_reconciliation_readback(
            op_id, _rrb(ref="rb-m", candidates=("test-1", "test-2")), 1
        )
        self.assertEqual(result.outcome, "not_settled")
        self.assertIn("multiple", result.reason)
        self.assertEqual(store.get(op_id).status, STATUS_QUARANTINED)

    def test_candidate_must_match_registered_reimport_test(self):
        store, op_id = self._quarantined_lost()  # registered Test is test-1
        result = store.settle_reconciliation_readback(op_id, _rrb(candidates=("test-2",)), 1)
        self.assertEqual(result.outcome, "not_settled")
        self.assertIn("registered reimport Test", result.reason)
        self.assertEqual(store.get(op_id).status, STATUS_QUARANTINED)

    def test_readback_must_be_verified_and_in_scope(self):
        store, op_id = self._quarantined_lost()
        unverified = store.settle_reconciliation_readback(op_id, _rrb(verified=False), 1)
        self.assertEqual(unverified.outcome, "not_settled")
        self.assertIn("verified", unverified.reason)
        other_ctx = store.settle_reconciliation_readback(
            op_id, _rrb(ref="rb-c", context_key="other"), 1
        )
        self.assertEqual(other_ctx.outcome, "not_settled")
        no_ref = store.settle_reconciliation_readback(op_id, _rrb(ref=""), 1)
        self.assertEqual(no_ref.outcome, "not_settled")
        self.assertEqual(store.get(op_id).status, STATUS_QUARANTINED)

    def test_conflicting_response_quarantine_needs_unique_matching_readback(self):
        store = OperationStore()
        op = _op(operation_id=str(uuid.uuid4()))
        op_id = op.operation_id
        store.register(op)
        store.issue_post(op_id)
        store.record_response(op_id, "resp-1", "test-1", False)
        # an inconsistent second response quarantines the operation
        store.record_response(op_id, "resp-2", "test-999", False)
        self.assertEqual(store.get(op_id).status, STATUS_QUARANTINED)
        # a read-back candidate that disagrees with the first recorded
        # response Test ID stays quarantined
        bad = store.settle_reconciliation_readback(
            op_id, _rrb(ref="rb-mismatch", candidates=("test-999",)), 1
        )
        self.assertEqual(bad.outcome, "not_settled")
        self.assertEqual(store.get(op_id).status, STATUS_QUARANTINED)
        # a matching unique read-back still cannot settle a lost reimport:
        # stale preexisting data is not write provenance
        ok = store.settle_reconciliation_readback(
            op_id, _rrb(ref="rb-match", findings=("f-1",)), 1
        )
        self.assertEqual(ok.outcome, "not_settled")
        self.assertIn("quarantined", ok.reason)
        self.assertEqual(store.get(op_id).status, STATUS_QUARANTINED)
        self.assertIsNone(store.get(op_id).mapping_revision)

    def test_unverified_dedup_completion_stays_quarantined(self):
        store, op_id = self._quarantined_lost()
        result = store.settle_reconciliation_readback(op_id, _rrb(ref="rb-d", dedup=False), 1)
        self.assertEqual(result.outcome, "not_settled")
        self.assertEqual(store.get(op_id).status, STATUS_QUARANTINED)

    def test_only_quarantined_operations_settle_from_readback(self):
        store = OperationStore()
        op = _op(operation_id=str(uuid.uuid4()))
        op_id = op.operation_id
        store.register(op)
        result = store.settle_reconciliation_readback(op_id, _rrb(), 1)
        self.assertEqual(result.outcome, "not_settled")
        self.assertEqual(store.get(op_id).status, STATUS_PENDING)

    def test_second_import_cannot_advance_prior_mapping(self):
        store = OperationStore()
        first = _op(operation_id=str(uuid.uuid4()))
        first_id = first.operation_id
        store.register(first)
        store.issue_post(first_id)
        store.record_response(first_id, "resp-1", "test-1", True)
        store.settle(first_id, "test-1", _rb(findings=("f-1",), endpoints=()), 1)
        self.assertEqual(store.active_mapping_revision(CTX), 1)
        second = store.register(
            _op(
                operation_id=str(uuid.uuid4()),
                request_kind=REQUEST_IMPORT,
                test_id=None,
            )
        )
        self.assertEqual(second.outcome, "rejected")
        self.assertEqual(store.active_mapping_revision(CTX), 1)

    def test_stale_reimport_data_cannot_advance_revision(self):
        # CR-03/04: a lost reimport response must not settle from the
        # preexisting Test/Finding set alone. The CE supported API has no
        # verifiable write-provenance field, so the operation stays
        # quarantined and safely unresolved; no mapping revision advances
        # without proof of this write. Empty Test search is not independent
        # proof of reimport non-execution and cannot authorise another POST.
        store, op_id = self._quarantined_lost()
        result = store.settle_reconciliation_readback(
            op_id, _rrb(ref="rb-stale", findings=("f-1", "f-2")), 1
        )
        self.assertEqual(result.outcome, "not_settled")
        self.assertIn("quarantined", result.reason)
        stored = store.get(op_id)
        self.assertEqual(stored.status, STATUS_QUARANTINED)
        self.assertIsNone(stored.mapping_revision)
        self.assertEqual(store.active_mapping_revision(CTX), None)
        # An empty Test search is not independent proof of non-execution.
        self.assertEqual(store.reconcile(op_id, _rec(ref="rec-again")).outcome, "not_reconciled")
        self.assertEqual(store.issue_post(op_id).outcome, "post_blocked")


class DedupReadbackTest(unittest.TestCase):
    def test_verified_async_dedup_advances_false_to_true_and_settles(self):
        store = OperationStore()
        op = _op(operation_id=str(uuid.uuid4()))
        op_id = op.operation_id
        store.register(op)
        # async response dispatched deduplication; completion was false
        store.issue_post(op_id)
        store.record_response(op_id, "resp-1", "test-1", False)
        self.assertEqual(store.settle(op_id, "test-1", _rb(findings=(), endpoints=()), 1).outcome, "not_settled")
        # an explicit verified read-back advances completion to true; a
        # second HTTP response is never the success evidence
        result = store.record_dedup_readback(op_id, "readback-dedup-1", True)
        self.assertEqual(result.outcome, "recorded")
        stored = store.get(op_id)
        self.assertTrue(stored.deduplication_complete)
        self.assertEqual(stored.deduplication_evidence_ref, "readback-dedup-1")
        self.assertEqual(stored.status, STATUS_PENDING)
        settled = store.settle(op_id, "test-1", _rb(findings=("f-1",), endpoints=()), 1)
        self.assertEqual(settled.outcome, "settled")

    def test_verified_async_dedup_advances_absent_to_true(self):
        store = OperationStore()
        op = _op(operation_id=str(uuid.uuid4()))
        op_id = op.operation_id
        store.register(op)
        store.issue_post(op_id)
        store.record_response(op_id, "resp-1", "test-1", None)
        self.assertEqual(store.settle(op_id, "test-1", _rb(findings=(), endpoints=()), 1).outcome, "not_settled")
        result = store.record_dedup_readback(op_id, "readback-dedup-2", True)
        self.assertEqual(result.outcome, "recorded")
        self.assertEqual(store.settle(op_id, "test-1", _rb(findings=(), endpoints=()), 1).outcome, "settled")

    def test_dedup_readback_requires_explicit_verified_evidence(self):
        store = OperationStore()
        op = _op(operation_id=str(uuid.uuid4()))
        op_id = op.operation_id
        store.register(op)
        store.issue_post(op_id)
        store.record_response(op_id, "resp-1", "test-1", False)
        no_evidence = store.record_dedup_readback(op_id, "", True)
        self.assertEqual(no_evidence.outcome, "not_recorded")
        self.assertFalse(store.get(op_id).deduplication_complete)
        # a quarantined operation cannot be advanced via read-back; it must
        # be reconciled first
        store.mark_uncertain(op_id, "lost-response")
        blocked = store.record_dedup_readback(op_id, "readback-x", True)
        self.assertEqual(blocked.outcome, "not_recorded")
        self.assertEqual(store.get(op_id).status, STATUS_QUARANTINED)

    def test_dedup_readback_completion_is_monotonic(self):
        store = OperationStore()
        op = _op(operation_id=str(uuid.uuid4()))
        op_id = op.operation_id
        store.register(op)
        store.issue_post(op_id)
        store.record_response(op_id, "resp-1", "test-1", True)
        # true is terminal: re-recording false is refused, true is duplicate
        regression = store.record_dedup_readback(op_id, "readback-bad", False)
        self.assertEqual(regression.outcome, "not_recorded")
        self.assertTrue(store.get(op_id).deduplication_complete)
        again = store.record_dedup_readback(op_id, "readback-ok", True)
        self.assertEqual(again.outcome, "duplicate")

    def test_false_readback_never_sets_true_completion(self):
        # CR-04: a verified read-back of an explicit False completion must
        # record False, never True — only an explicit True completion event
        # sets True, and False/absent completion can never settle.
        store = OperationStore()
        op = _op(operation_id=str(uuid.uuid4()))
        op_id = op.operation_id
        store.register(op)
        store.issue_post(op_id)
        store.record_response(op_id, "resp-1", "test-1", None)
        false_read = store.record_dedup_readback(op_id, "readback-false-1", False)
        self.assertEqual(false_read.outcome, "recorded")
        stored = store.get(op_id)
        self.assertFalse(stored.deduplication_complete)
        self.assertEqual(stored.deduplication_evidence_ref, "readback-false-1")
        # a False completion cannot settle
        self.assertEqual(
            store.settle(op_id, "test-1", _rb(findings=("f-1",), endpoints=()), 1).outcome,
            "not_settled",
        )
        # only an explicit True completion event sets True and settles
        true_read = store.record_dedup_readback(op_id, "readback-true-1", True)
        self.assertEqual(true_read.outcome, "recorded")
        self.assertTrue(store.get(op_id).deduplication_complete)
        self.assertEqual(
            store.settle(op_id, "test-1", _rb(findings=("f-1",), endpoints=()), 1).outcome,
            "settled",
        )


class FailureAndConflictTerminalTest(unittest.TestCase):
    def test_definitive_rejection_fails_and_blocks_later_settle(self):
        store = OperationStore()
        op = _op(operation_id=str(uuid.uuid4()))
        op_id = op.operation_id
        store.register(op)
        result = store.mark_failed(op_id, "400", "error/missing-parser")
        self.assertEqual(result.outcome, "failed")
        self.assertEqual(result.operation.status, STATUS_FAILED)
        self.assertEqual(store.get(op_id).error_code, "400")
        self.assertEqual(store.settle(op_id, "test-1", _rb(findings=(), endpoints=()), 1).outcome, "not_settled")
        self.assertEqual(store.mark_uncertain(op_id, "x").outcome, "not_quarantined")
        # a failed request did not accept the write: the context is not
        # blocked for a new operation
        self.assertIsNone(store.active_operation(CTX))

    def test_conflict_status_blocks_context_until_review(self):
        store = OperationStore()
        op = _op(operation_id=str(uuid.uuid4()))
        store.register(op)
        store.register(replace(op, payload_sha256="c" * 64))
        new = store.register(_op(operation_id=str(uuid.uuid4())))
        self.assertEqual(new.outcome, "conflict")


class TestBindingAndLostImportSafetyTest(unittest.TestCase):
    def _first_import(self, store, test_id="created-test"):
        op = _op(request_kind=REQUEST_IMPORT, test_id=None)
        self.assertEqual(store.register(op).outcome, "registered")
        self.assertEqual(
            store.record_first_import_baseline(
                op.operation_id,
                FirstImportBaselineV1(SCHEMA_VERSION, "empty-before-post", True, CTX, ()),
            ).outcome,
            "recorded",
        )
        self.assertEqual(store.issue_post(op.operation_id).outcome, "post_allowed")
        self.assertEqual(
            store.record_response(op.operation_id, "response", test_id, True).outcome,
            "recorded",
        )
        return op

    def test_response_test_serialises_foreign_context_before_settle(self):
        store = OperationStore()
        self._first_import(store)
        foreign = _op(context_key="another-context", test_id="created-test")
        result = store.register(foreign)
        self.assertEqual(result.outcome, "conflict")
        self.assertIsNone(store.get(foreign.operation_id))

    def test_settled_test_cannot_be_reimported_from_foreign_context(self):
        store = OperationStore()
        first = self._first_import(store)
        self.assertEqual(
            store.settle(first.operation_id, "created-test", _rb(test_id="created-test"), 1).outcome,
            "settled",
        )
        foreign = _op(context_key="another-context", test_id="created-test")
        self.assertEqual(store.register(foreign).outcome, "conflict")
        self.assertIsNone(store.get(foreign.operation_id))

    def test_reimport_must_use_contexts_active_mapped_test(self):
        store = OperationStore()
        first = self._first_import(store)
        self.assertEqual(
            store.settle(first.operation_id, "created-test", _rb(test_id="created-test"), 1).outcome,
            "settled",
        )
        wrong = _op(test_id="different-test")
        self.assertEqual(store.register(wrong).outcome, "rejected")
        self.assertIsNone(store.get(wrong.operation_id))
        self.assertEqual(store.active_mapping_revision(CTX), 1)
        right = _op(test_id="created-test")
        self.assertEqual(store.register(right).outcome, "registered")

    def test_preexisting_foreign_reimport_blocks_first_import_binding(self):
        store = OperationStore()
        first = _op(request_kind=REQUEST_IMPORT, test_id=None)
        store.register(first)
        store.record_first_import_baseline(
            first.operation_id,
            FirstImportBaselineV1(SCHEMA_VERSION, "empty-before-post", True, CTX, ()),
        )
        store.issue_post(first.operation_id)
        foreign = _op(context_key="another-context", test_id="created-test")
        self.assertEqual(store.register(foreign).outcome, "registered")
        store.record_response(first.operation_id, "response", "created-test", True)
        settled = store.settle(
            first.operation_id, "created-test", _rb(test_id="created-test"), 1
        )
        self.assertEqual(settled.outcome, "not_settled")
        self.assertIsNone(store.active_mapping_revision(CTX))

    def test_foreign_reimport_cannot_settle_after_import_claims_its_test(self):
        store = OperationStore()
        first = _op(request_kind=REQUEST_IMPORT, test_id=None)
        store.register(first)
        store.record_first_import_baseline(
            first.operation_id,
            FirstImportBaselineV1(SCHEMA_VERSION, "empty-before-post", True, CTX, ()),
        )
        store.issue_post(first.operation_id)
        foreign = _op(context_key="another-context", test_id="created-test")
        store.register(foreign)
        store.issue_post(foreign.operation_id)
        store.record_response(
            foreign.operation_id, "foreign-response", "created-test", True
        )
        self.assertEqual(
            store.record_response(
                first.operation_id, "first-response", "created-test", True
            ).outcome,
            "quarantined",
        )
        result = store.settle(
            foreign.operation_id,
            "created-test",
            _rb(test_id="created-test", context_key="another-context"),
            1,
        )
        self.assertEqual(result.outcome, "not_settled")
        self.assertIsNone(store.active_mapping_revision("another-context"))

    def test_empty_search_after_lost_first_import_never_allows_second_post(self):
        store = OperationStore()
        first = _op(request_kind=REQUEST_IMPORT, test_id=None)
        store.register(first)
        store.record_first_import_baseline(
            first.operation_id,
            FirstImportBaselineV1(SCHEMA_VERSION, "empty-before-post", True, CTX, ()),
        )
        store.issue_post(first.operation_id)
        store.mark_uncertain(first.operation_id, "lost response")
        result = store.reconcile(first.operation_id, _rec(ref="empty-after-post"))
        self.assertEqual(result.outcome, "not_reconciled")
        self.assertEqual(store.get(first.operation_id).status, STATUS_QUARANTINED)
        self.assertEqual(store.issue_post(first.operation_id).outcome, "post_blocked")
        self.assertIsNone(store.active_mapping_revision(CTX))


class ValidationTest(unittest.TestCase):
    def test_operation_id_must_be_uuid(self):
        with self.assertRaises(ValueError):
            _op(operation_id="not-a-uuid")

    def test_close_old_findings_must_be_explicitly_false(self):
        with self.assertRaises(ValueError):
            replace(_op(), close_old_findings=True)

    def test_status_must_be_known(self):
        with self.assertRaises(ValueError):
            _op(status="done")

    def test_requested_at_must_be_aware(self):
        with self.assertRaises(ValueError):
            replace(_op(), requested_at=datetime(2026, 7, 3, 9, 0, 0))


if __name__ == "__main__":
    unittest.main()
