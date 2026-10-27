"""Focused behavioural tests for the EngineOccurrenceLinkV1 contract.

Synthetic fixtures only: no HTTP, no persistence, no live engine. Modelled
on the CE 3.3.100/3.3.200 synthetic readbacks (6 Qualys Findings / 3
host-only Endpoints, port-only rows sharing one hash; Sysdig components
without Endpoints). Covers CR-04 proof failure on ambiguous shared
Findings, host-only Endpoint sharing, untrusted component locators,
many-to-many cardinality, non-settled-operation protection of the prior
active link, and correction supersession with retained history.

The flat Finding and Endpoint read-back cannot prove a particular pair or a
caller-supplied component locator. Record derives operation status from the
authoritative OperationStore, and supersession requires the current settled
mapping plus an active replacement. Exhaustive proof stays pending without
a trusted actionable-occurrence manifest.
"""

from __future__ import annotations

import hashlib
import json
import unittest
import uuid
from datetime import datetime, timedelta, timezone

from uvm.engine import link as links
from uvm.engine.association import (
    FindingDetailAssociationV1,
    parse_finding_detail,
)
from uvm.engine.link import (
    PROOF_FAILED,
    PROOF_PENDING,
    Cr04ProofResult,
    EngineOccurrenceLinkV1,
    LinkStore,
)
from uvm.engine.operation import (
    REQUEST_IMPORT,
    REQUEST_REIMPORT,
    STATUS_FAILED,
    STATUS_PENDING,
    STATUS_QUARANTINED,
    STATUS_SETTLED,
    EngineImportOperationV1,
    FirstImportBaselineV1,
    FindingReadbackV1,
    OperationStore,
)

T0 = datetime(2026, 9, 20, 9, 0, 0, tzinfo=timezone.utc)
OP_SETTLED = str(uuid.uuid4())
OP_PENDING = str(uuid.uuid4())
OP_QUARANTINED = str(uuid.uuid4())
OP_FAILED = str(uuid.uuid4())
OP_REIMPORT = str(uuid.uuid4())
OP_A_SETTLED = str(uuid.uuid4())
OP_A_NONCANON_TEST = str(uuid.uuid4())
OP_A_PENDING = str(uuid.uuid4())
OP_STALE = str(uuid.uuid4())
OP_FRESH = str(uuid.uuid4())
CTX_A = "ctx-pair-observed"

_COUNTER = 0


def _occ() -> str:
    return str(uuid.uuid4())


def _link(
    operation_id: str = OP_SETTLED,
    occurrence_id: str | None = None,
    finding_id: str = "f1",
    status: str = links.LINK_ACTIVE,
    link_id: str | None = None,
    endpoint_id: str | None = None,
    component_locator: str | None = None,
    effective_from: datetime | None = None,
    effective_until: datetime | None = None,
    supersedes_link_id: str | None = None,
    revision: int = 1,
) -> EngineOccurrenceLinkV1:
    global _COUNTER
    _COUNTER += 1
    return EngineOccurrenceLinkV1(
        schema_version=links.SCHEMA_VERSION,
        link_id=link_id or str(uuid.uuid4()),
        revision=revision,
        operation_id=operation_id,
        occurrence_id=occurrence_id or _occ(),
        finding_id=finding_id,
        evidence_sha256=f"sha256:evidence-{_COUNTER}",
        effective_from=effective_from or (T0 + timedelta(minutes=_COUNTER)),
        mapping_status=status,
        endpoint_id=endpoint_id,
        component_locator=component_locator,
        effective_until=effective_until,
        supersedes_link_id=supersedes_link_id,
    )


def _op_store(
    operation_id: str,
    findings=(),
    endpoints=(),
    status: str = STATUS_SETTLED,
    request_kind: str = REQUEST_IMPORT,
    test_id: str | None = None,
    operations: OperationStore | None = None,
    context_key: str | None = None,
    mapping_revision: int = 1,
    readback_test_id: str = "test-1",
) -> OperationStore:
    """An authoritative OperationStore carrying the named operation in the
    requested stored status, taken through the real transition path. A
    ``settled`` operation is read back with the given measured Finding and
    Endpoint scopes (both verified read-back outputs)."""
    ops = operations if operations is not None else OperationStore()
    op = EngineImportOperationV1(
        schema_version=links.SCHEMA_VERSION,
        operation_id=operation_id,
        revision=1,
        context_key=context_key or f"ctx-{operation_id[:8]}",
        source_run_id="run-42",
        scan_type="qualys",
        payload_sha256="a" * 64,
        parser_config_version="qualys-3.3.100-v1",
        engine_release="3.3.100",
        request_kind=request_kind,
        requested_at=T0,
        close_old_findings=False,
        status=STATUS_PENDING,
        test_id=test_id,
    )
    assert ops.register(op).outcome == "registered"
    if status == STATUS_PENDING:
        return ops
    if request_kind == REQUEST_IMPORT:
        # Fresh first import: verified empty pre-POST Test inventory, before
        # any POST.
        baseline = FirstImportBaselineV1(
            schema_version=links.SCHEMA_VERSION,
            baseline_ref="baseline-1",
            verified=True,
            context_key=op.context_key,
        )
        assert (
            ops.record_first_import_baseline(operation_id, baseline).outcome
            == "recorded"
        )
    assert ops.issue_post(operation_id).outcome == "post_allowed"
    if status == STATUS_FAILED:
        assert ops.mark_failed(operation_id, "400", "err-ref").outcome == "failed"
        return ops
    if status == STATUS_QUARANTINED:
        # The response names no Test: this helper must not depend on the
        # response-Test serialisation path (owned by the operation slice).
        assert ops.record_response(operation_id, "resp-q", None, True).outcome == "recorded"
        assert ops.mark_uncertain(operation_id, "lost-response").outcome == "quarantined"
        return ops
    # settled: the real transition path with a complete verified read-back
    # covering the given measured Finding/Endpoint scopes. The response
    # names no Test; the Test binding is proven by the verified read-back.
    assert ops.record_response(operation_id, "resp-1", None, True).outcome == "recorded"
    readback = FindingReadbackV1(
        readback_ref="rb-1",
        verified=True,
        test_id=readback_test_id,
        context_key=op.context_key,
        finding_ids=tuple(findings),
        endpoint_ids=tuple(endpoints),
    )
    assert ops.settle(operation_id, readback_test_id, readback, mapping_revision).outcome == "settled"
    return ops


def _proof(
    store: LinkStore, ops: OperationStore, operation_id: str, occs: list[str]
) -> Cr04ProofResult:
    """CR-04 proof bound to the authoritative stored operation and its
    verified Finding/Endpoint read-back scopes — the caller no longer
    supplies the operation status or scope."""
    return store.cr04_proof(ops, operation_id, tuple(occs))


def _association(
    test_id: int,
    finding_id: int,
    endpoints,
    ce_release: str = "3.3.100",
) -> FindingDetailAssociationV1:
    """A parsed FindingDetailAssociationV1 over caller-supplied synthetic
    bytes: the digest and every field derive from the same retained
    bytes, so the DTO is the only shape cr04_proof accepts."""
    body = json.dumps(
        {
            "id": finding_id,
            "test": test_id,
            "endpoints": list(endpoints),
            "verified": False,
        }
    ).encode("utf-8")
    return parse_finding_detail(
        body,
        ce_release=ce_release,
        requested_finding_id=finding_id,
        requested_test_id=test_id,
        evidence_ref=f"assoc-{finding_id}",
        evidence_sha256=hashlib.sha256(body).hexdigest(),
        source_kind="synthetic-fixture",
    )


class QualysHostsX2ComponentsTest(unittest.TestCase):
    """CE 3.3.100 readback shape: one native finding on three instances and
    two port-distinct portions each → 6 Findings but only 3 host-only
    Endpoints (port appears only in the description). All six occurrences
    must remain distinct and CR-04 proof must stay pending, never verified
    and never silently merged."""

    def setUp(self) -> None:
        self.store = LinkStore()
        self.ops = _op_store(
            OP_SETTLED,
            findings=("f1", "f2", "f3", "f4", "f5", "f6"),
            endpoints=("ep-host-1", "ep-host-2", "ep-host-3"),
        )
        self.occurrences: list[str] = []
        self.links_by_occ: list[dict[str, str]] = []
        for host in range(1, 4):
            endpoint = f"ep-host-{host}"
            for port in (443, 8443):
                occ = _occ()
                self.occurrences.append(occ)
                self.links_by_occ.append(
                    {
                        "occ": occ,
                        "finding": f"f{len(self.occurrences)}",
                        "endpoint": endpoint,
                    }
                )

    def _record_all(self) -> None:
        for row in self.links_by_occ:
            result = self.store.record(
                _link(occurrence_id=row["occ"], finding_id=row["finding"], endpoint_id=row["endpoint"]),
                self.ops,
            )
            self.assertEqual(result.outcome, "recorded")

    def test_six_distinct_occurrences_and_six_findings(self) -> None:
        self._record_all()
        # 3 hosts x 2 components: six occurrences retained, never merged to 3.
        for row in self.links_by_occ:
            effective = [
                l
                for l in self.store.for_occurrence(row["occ"])
                if l.mapping_status != links.LINK_SUPERSEDED
            ]
            self.assertEqual(len(effective), 1)
        all_links = self.store.for_operation(OP_SETTLED)
        self.assertEqual(len(all_links), 6)
        self.assertEqual(len({l.finding_id for l in all_links}), 6)
        self.assertEqual(len({l.endpoint_id for l in all_links}), 3)

    def test_shared_host_only_endpoint_yields_pending_proof_not_pass(self) -> None:
        self._record_all()
        proof = _proof(self.store, self.ops, OP_SETTLED, self.occurrences)
        for occ in self.occurrences:
            self.assertEqual(proof[occ], PROOF_PENDING, occ)

    def test_proof_is_order_independent(self) -> None:
        # Even a lone measured Endpoint lacks a trusted Finding/Endpoint pair.
        first = self.links_by_occ[0]
        result = self.store.record(
            _link(occurrence_id=first["occ"], finding_id=first["finding"], endpoint_id=first["endpoint"]),
            self.ops,
        )
        self.assertEqual(result.outcome, "recorded")
        self.assertEqual(
            _proof(self.store, self.ops, OP_SETTLED, [first["occ"]])[first["occ"]],
            PROOF_PENDING,
        )
        # A sibling port-distinct portion remains separately represented.
        sibling = self.links_by_occ[1]
        self.assertEqual(
            self.store.record(
                _link(occurrence_id=sibling["occ"], finding_id=sibling["finding"], endpoint_id=sibling["endpoint"]),
                self.ops,
            ).outcome,
            "recorded",
        )
        proof = _proof(
            self.store,
            self.ops,
            OP_SETTLED,
            [first["occ"], sibling["occ"]],
        )
        self.assertEqual(proof[first["occ"]], PROOF_PENDING)
        self.assertEqual(proof[sibling["occ"]], PROOF_PENDING)


class SysdigComponentOnlyTest(unittest.TestCase):
    """Sysdig CLI shape: components without Endpoints. The supported-API
    read-back measures Findings and Endpoints, never component locators: a
    component-only association is unmeasured and stays pending, verified or
    not; a null component identity does not pass either."""

    def setUp(self) -> None:
        self.ops = _op_store(OP_SETTLED, findings=("f-cve-2024-0002", "f1"))

    def test_component_only_association_stays_pending(self) -> None:
        # cb8ed6f0 (1): distinct component locators distinguish nothing the
        # read-back can verify — without a measured Endpoint the
        # association is never independently verified.
        store = LinkStore()
        occ_open = _occ()
        occ_lib = _occ()
        for occ, component in ((occ_open, "openssl"), (occ_lib, "libssl3")):
            result = store.record(
                _link(occurrence_id=occ, finding_id="f-cve-2024-0002", component_locator=component),
                self.ops,
            )
            self.assertEqual(result.outcome, "recorded")
        proof = _proof(store, self.ops, OP_SETTLED, [occ_open, occ_lib])
        self.assertEqual(proof[occ_open], PROOF_PENDING)
        self.assertEqual(proof[occ_lib], PROOF_PENDING)

    def test_null_component_identity_does_not_pass(self) -> None:
        store = LinkStore()
        occ = _occ()
        active = store.record(
            _link(occurrence_id=occ, finding_id="f-cve-2024-0002"),
            self.ops,
        )
        self.assertEqual(active.outcome, "rejected")
        self.assertIn("Finding ID alone", active.reason or "")
        pending = store.record(
            _link(occurrence_id=occ, finding_id="f-cve-2024-0002", status=links.LINK_PENDING),
            self.ops,
        )
        self.assertEqual(pending.outcome, "recorded")
        self.assertEqual(_proof(store, self.ops, OP_SETTLED, [occ])[occ], PROOF_PENDING)

    def test_shared_component_locator_across_occurrences_stays_pending(self) -> None:
        store = LinkStore()
        occ_a, occ_b = _occ(), _occ()
        for occ in (occ_a, occ_b):
            store.record(
                _link(occurrence_id=occ, finding_id="f1", component_locator="openssl"),
                self.ops,
            )
        proof = _proof(store, self.ops, OP_SETTLED, [occ_a, occ_b])
        self.assertEqual(proof[occ_a], PROOF_PENDING)
        self.assertEqual(proof[occ_b], PROOF_PENDING)


class SharedFindingAmbiguityTest(unittest.TestCase):
    """A shared Finding ID alone must yield pending/failed CR-04 proof,
    never a pass."""

    def setUp(self) -> None:
        self.ops = _op_store(
            OP_SETTLED,
            findings=("f-shared", "f1", "f2"),
            endpoints=("ep-1", "ep-2"),
        )

    def test_shared_finding_alone_is_pending(self) -> None:
        store = LinkStore()
        occ_a, occ_b = _occ(), _occ()
        for occ in (occ_a, occ_b):
            active = store.record(_link(occurrence_id=occ, finding_id="f-shared"), self.ops)
            self.assertEqual(active.outcome, "rejected", active.reason)
            self.assertEqual(
                store.record(_link(occurrence_id=occ, finding_id="f-shared", status=links.LINK_PENDING), self.ops).outcome,
                "recorded",
            )
        proof = _proof(store, self.ops, OP_SETTLED, [occ_a, occ_b])
        self.assertEqual(proof[occ_a], PROOF_PENDING)
        self.assertEqual(proof[occ_b], PROOF_PENDING)

    def test_one_occurrence_may_map_to_multiple_findings(self) -> None:
        store = LinkStore()
        occ = _occ()
        store.record(_link(occurrence_id=occ, finding_id="f1", endpoint_id="ep-1"), self.ops)
        store.record(_link(occurrence_id=occ, finding_id="f2", endpoint_id="ep-2"), self.ops)
        self.assertEqual(len(store.for_occurrence(occ)), 2)
        self.assertEqual(_proof(store, self.ops, OP_SETTLED, [occ])[occ], PROOF_PENDING)

    def test_settled_operation_without_links_fails_proof(self) -> None:
        store = LinkStore()
        occ = _occ()
        self.assertEqual(_proof(store, self.ops, OP_SETTLED, [occ])[occ], PROOF_FAILED)

    def test_non_settled_operation_never_proves(self) -> None:
        store = LinkStore()
        occ = _occ()
        # The authoritative store holds OP_PENDING as pending; record
        # derives that status, and only a pending link can be recorded.
        pending_ops = _op_store(OP_PENDING, findings=("f1",), status=STATUS_PENDING)
        store.record(
            _link(operation_id=OP_PENDING, occurrence_id=occ, status=links.LINK_PENDING),
            pending_ops,
        )
        self.assertEqual(_proof(store, pending_ops, OP_PENDING, [occ])[occ], PROOF_PENDING)


class OperationStatusProtectionTest(unittest.TestCase):
    """Pending/quarantined operations cannot delete or supersede the prior
    active link; a failed operation records nothing. cb8ed6f0 (2): the
    status is derived from the authoritative OperationStore, so a caller
    can no longer claim ``settled`` for a stored non-settled operation."""

    def setUp(self) -> None:
        self.store = LinkStore()
        self.ops = _op_store(OP_SETTLED, findings=("f1", "f9"), endpoints=("ep-1",))
        self.occ = _occ()
        self.prior = _link(occurrence_id=self.occ, finding_id="f1", endpoint_id="ep-1")
        self.assertEqual(
            self.store.record(self.prior, self.ops).outcome, "recorded"
        )

    def test_pending_operation_cannot_supersede(self) -> None:
        pending_ops = _op_store(OP_PENDING, findings=("f9",), status=STATUS_PENDING)
        result = self.store.record(
            _link(
                operation_id=OP_PENDING,
                occurrence_id=self.occ,
                finding_id="f9",
                endpoint_id="ep-9",
                supersedes_link_id=self.prior.link_id,
            ),
            pending_ops,
        )
        self.assertEqual(result.outcome, "rejected")
        self.assertIn("cannot supersede", result.reason or "")
        self.assertEqual(self.store.get(self.prior.link_id).mapping_status, links.LINK_ACTIVE)

    def test_stored_pending_operation_cannot_record_active_link(self) -> None:
        # The caller's intent is irrelevant: the store says pending.
        pending_ops = _op_store(OP_PENDING, findings=("f9",), status=STATUS_PENDING)
        result = self.store.record(
            _link(
                operation_id=OP_PENDING,
                occurrence_id=self.occ,
                finding_id="f9",
                endpoint_id="ep-9",
            ),
            pending_ops,
        )
        self.assertEqual(result.outcome, "rejected")
        self.assertIn("cannot produce an active candidate link", result.reason or "")

    def test_quarantined_operation_cannot_supersede_or_verify(self) -> None:
        quarantined_ops = _op_store(
            OP_QUARANTINED, findings=("f9",), status=STATUS_QUARANTINED
        )
        result = self.store.record(
            _link(
                operation_id=OP_QUARANTINED,
                occurrence_id=self.occ,
                finding_id="f9",
                endpoint_id="ep-9",
                supersedes_link_id=self.prior.link_id,
            ),
            quarantined_ops,
        )
        self.assertEqual(result.outcome, "rejected")
        # A non-settled operation also cannot create a fresh active candidate.
        fresh = self.store.record(
            _link(
                operation_id=OP_QUARANTINED,
                occurrence_id=self.occ,
                finding_id="f9",
                endpoint_id="ep-9",
            ),
            quarantined_ops,
        )
        self.assertEqual(fresh.outcome, "rejected")
        self.assertEqual(self.store.get(self.prior.link_id).mapping_status, links.LINK_ACTIVE)
        self.assertEqual(
            _proof(self.store, self.ops, OP_SETTLED, [self.occ])[self.occ],
            PROOF_PENDING,
        )

    def test_failed_operation_records_nothing(self) -> None:
        failed_ops = _op_store(OP_FAILED, status=STATUS_FAILED)
        result = self.store.record(
            _link(operation_id=OP_FAILED, occurrence_id=self.occ, status=links.LINK_PENDING),
            failed_ops,
        )
        self.assertEqual(result.outcome, "rejected")
        self.assertIn("no engine records", result.reason or "")

    def test_unknown_operation_is_not_found(self) -> None:
        ops = _op_store(str(uuid.uuid4()), findings=("f1",))
        result = self.store.record(
            _link(occurrence_id=self.occ, finding_id="f1", endpoint_id="ep-1"),
            ops,
        )
        self.assertEqual(result.outcome, "not_found")
        self.assertIn("unknown to the authoritative OperationStore", result.reason or "")


class CorrectionSupersessionTest(unittest.TestCase):
    """A correction supersedes with append-only history: the prior active
    link is retained, its revision bumps, and only the effective link can be
    superseded."""

    def setUp(self) -> None:
        self.store = LinkStore()
        self.ops = _op_store(
            OP_SETTLED, findings=("f1", "f2", "f3"), endpoints=("ep-1",)
        )
        self.occ = _occ()
        self.prior = _link(occurrence_id=self.occ, finding_id="f1", endpoint_id="ep-1")
        self.store.record(self.prior, self.ops)

    def test_supersede_retains_history_and_bumps_revision(self) -> None:
        correction = _link(
            occurrence_id=self.occ,
            finding_id="f2",  # engine Finding ID changed on correction
            endpoint_id="ep-1",
            supersedes_link_id=self.prior.link_id,
        )
        result = self.store.record(correction, self.ops)
        self.assertEqual(result.outcome, "recorded")

        old = self.store.get(self.prior.link_id)
        self.assertEqual(old.mapping_status, links.LINK_SUPERSEDED)
        self.assertEqual(old.revision, 2)
        self.assertEqual(old.effective_until, correction.effective_from)

        history = self.store.history(self.prior.link_id)
        self.assertEqual([l.link_id for l in history], [self.prior.link_id, correction.link_id])
        self.assertEqual(self.store.history(correction.link_id), history)

        # The correction is effective, but flat read-back cannot prove its pair.
        self.assertEqual(
            _proof(self.store, self.ops, OP_SETTLED, [self.occ])[self.occ],
            PROOF_PENDING,
        )

    def test_cannot_supersede_an_already_superseded_link(self) -> None:
        correction = _link(
            occurrence_id=self.occ,
            finding_id="f2",
            endpoint_id="ep-1",
            supersedes_link_id=self.prior.link_id,
        )
        self.store.record(correction, self.ops)
        third = _link(
            occurrence_id=self.occ,
            finding_id="f3",
            endpoint_id="ep-1",
            supersedes_link_id=self.prior.link_id,
        )
        result = self.store.record(third, self.ops)
        self.assertEqual(result.outcome, "rejected")
        self.assertIn("already superseded", result.reason or "")

    def test_supersede_must_target_the_same_occurrence(self) -> None:
        other = _link(
            occurrence_id=_occ(),
            finding_id="f2",
            endpoint_id="ep-1",
            supersedes_link_id=self.prior.link_id,
        )
        result = self.store.record(other, self.ops)
        self.assertEqual(result.outcome, "rejected")
        self.assertIn("same occurrence", result.reason or "")

    def test_supersede_of_unknown_link_is_not_found(self) -> None:
        result = self.store.record(
            _link(occurrence_id=self.occ, finding_id="f2", endpoint_id="ep-1", supersedes_link_id=str(uuid.uuid4())),
            self.ops,
        )
        self.assertEqual(result.outcome, "not_found")


class RecordIdempotencyTest(unittest.TestCase):
    def setUp(self) -> None:
        self.ops = _op_store(OP_SETTLED, findings=("f1", "f-different"), endpoints=("ep-1",))

    def test_identical_replay_is_duplicate(self) -> None:
        store = LinkStore()
        link = _link(endpoint_id="ep-1")
        self.assertEqual(store.record(link, self.ops).outcome, "recorded")
        self.assertEqual(store.record(link, self.ops).outcome, "duplicate")

    def test_link_id_reuse_with_different_body_is_conflict(self) -> None:
        store = LinkStore()
        link = _link(endpoint_id="ep-1")
        store.record(link, self.ops)
        clone = EngineOccurrenceLinkV1(
            schema_version=links.SCHEMA_VERSION,
            link_id=link.link_id,
            revision=link.revision,
            operation_id=link.operation_id,
            occurrence_id=link.occurrence_id,
            finding_id="f-different",
            evidence_sha256=link.evidence_sha256,
            effective_from=link.effective_from,
            mapping_status=link.mapping_status,
            endpoint_id=link.endpoint_id,
            component_locator=link.component_locator,
        )
        result = store.record(clone, self.ops)
        self.assertEqual(result.outcome, "conflict")
        self.assertEqual(store.get(link.link_id).finding_id, "f1")


class DtoValidationTest(unittest.TestCase):
    def test_invalid_mapping_status_rejected(self) -> None:
        with self.assertRaises(ValueError):
            _link(status="bogus")

    def test_naive_effective_from_rejected(self) -> None:
        with self.assertRaises(ValueError):
            _link(effective_from=datetime(2026, 9, 20, 9, 0, 0))

    def test_superseded_link_requires_effective_until(self) -> None:
        with self.assertRaises(ValueError):
            _link(status=links.LINK_SUPERSEDED)

    def test_non_uuid_link_id_rejected(self) -> None:
        with self.assertRaises(ValueError):
            _link(link_id="not-a-uuid")

    def test_effective_until_before_effective_from_rejected(self) -> None:
        with self.assertRaises(ValueError):
            _link(
                effective_from=T0,
                effective_until=T0 - timedelta(seconds=1),
                status=links.LINK_SUPERSEDED,
            )


class Cr04ProofBindingTest(unittest.TestCase):
    """Reviewer c6d48384 + cb8ed6f0 findings: ``cr04_proof`` must bind to
    the authoritative stored settled operation and its verified scoped
    Finding *and Endpoint* read-backs; a fabricated operation ID or a
    Finding/Endpoint outside the stored scope must never yield verified.
    Evidence unavailable yields pending, never verified."""

    def test_unknown_operation_cannot_verify(self) -> None:
        store = LinkStore()
        occ = _occ()
        recording_ops = _op_store(OP_SETTLED, findings=("f1",), endpoints=("ep-1",))
        store.record(
            _link(occurrence_id=occ, finding_id="f1", endpoint_id="ep-1"),
            recording_ops,
        )
        # The link names OP_SETTLED, but the authoritative store consulted
        # for proof knows no such operation: no evidence, no pass.
        ops = _op_store(str(uuid.uuid4()), findings=("f1",), endpoints=("ep-1",))
        self.assertEqual(
            store.cr04_proof(ops, OP_SETTLED, [occ])[occ], PROOF_PENDING
        )

    def test_stored_non_settled_operation_cannot_verify(self) -> None:
        store = LinkStore()
        occ = _occ()
        ops = _op_store(
            OP_SETTLED, findings=("f1",), endpoints=("ep-1",), status=STATUS_PENDING
        )
        store.record(
            _link(occurrence_id=occ, finding_id="f1", endpoint_id="ep-1", status=links.LINK_PENDING),
            ops,
        )
        self.assertEqual(
            store.cr04_proof(ops, OP_SETTLED, [occ])[occ], PROOF_PENDING
        )

    def test_finding_outside_verified_readback_scope_cannot_verify(self) -> None:
        store = LinkStore()
        occ = _occ()
        ops = _op_store(OP_SETTLED, findings=("f1",), endpoints=("ep-1",))
        store.record(
            _link(occurrence_id=occ, finding_id="f9", endpoint_id="ep-1"),
            ops,
        )
        # The settled operation's verified read-back scope does not include
        # the link's Finding: the association is unproven, not verified.
        self.assertEqual(
            store.cr04_proof(ops, OP_SETTLED, [occ])[occ], PROOF_PENDING
        )

    def test_endpoint_outside_verified_readback_scope_cannot_verify(self) -> None:
        # cb8ed6f0 (1): the Finding is measured, but the link's Endpoint is
        # not in the stored Endpoint read-back scope — unmeasured pairing.
        store = LinkStore()
        occ = _occ()
        ops = _op_store(OP_SETTLED, findings=("f1",), endpoints=("ep-1",))
        store.record(
            _link(occurrence_id=occ, finding_id="f1", endpoint_id="ep-9"),
            ops,
        )
        self.assertEqual(
            store.cr04_proof(ops, OP_SETTLED, [occ])[occ], PROOF_PENDING
        )

    def test_flat_readback_cannot_bind_finding_to_another_findings_endpoint(self) -> None:
        store = LinkStore()
        occ = _occ()
        # The read-back has f1 and f2 plus f2's Endpoint, but exposes no
        # trusted Finding/Endpoint pair. f1 + ep-f2 must not pass.
        ops = _op_store(OP_SETTLED, findings=("f1", "f2"), endpoints=("ep-f2",))
        self.assertEqual(
            store.record(_link(occurrence_id=occ, finding_id="f1", endpoint_id="ep-f2"), ops).outcome,
            "recorded",
        )
        self.assertEqual(store.cr04_proof(ops, OP_SETTLED, [occ])[occ], PROOF_PENDING)

    def test_in_scope_flat_sets_still_cannot_prove_pair(self) -> None:
        store = LinkStore()
        occ = _occ()
        ops = _op_store(OP_SETTLED, findings=("f1", "f2"), endpoints=("ep-1", "ep-2"))
        store.record(
            _link(occurrence_id=occ, finding_id="f1", endpoint_id="ep-1"),
            ops,
        )
        self.assertEqual(
            store.cr04_proof(ops, OP_SETTLED, [occ])[occ], PROOF_PENDING
        )

    def test_settled_operation_without_links_fails(self) -> None:
        store = LinkStore()
        occ = _occ()
        ops = _op_store(OP_SETTLED, findings=("f1",), endpoints=("ep-1",))
        self.assertEqual(
            store.cr04_proof(ops, OP_SETTLED, [occ])[occ], PROOF_FAILED
        )


class DistinctComponentLocatorTest(unittest.TestCase):
    """Flat Finding/Endpoint sets never attest a component locator or its
    binding. Component-bearing links stay pending even where their locator
    strings differ or their endpoints are separately measured."""

    def setUp(self) -> None:
        self.ops = _op_store(
            OP_SETTLED, findings=("f1", "f2", "f3"), endpoints=("ep-host-1",)
        )

    def test_invented_package_on_real_finding_and_endpoint_is_pending(self) -> None:
        store = LinkStore()
        real = _occ()
        invented = _occ()
        store.record(
            _link(occurrence_id=real, finding_id="f1", endpoint_id="ep-host-1",
                  component_locator="real-package"), self.ops,
        )
        store.record(
            _link(occurrence_id=invented, finding_id="f1", endpoint_id="ep-host-1",
                  component_locator="invented-package"), self.ops,
        )
        proof = store.cr04_proof(self.ops, OP_SETTLED, [real, invented])
        self.assertEqual(proof[invented], PROOF_PENDING)
        self.assertEqual(proof[real], PROOF_PENDING)

    def test_omitted_actionable_occurrence_cannot_yield_exhaustive_proof(self) -> None:
        store = LinkStore()
        occ = _occ()
        store.record(_link(occurrence_id=occ, endpoint_id="ep-host-1"), self.ops)
        proof = store.cr04_proof(self.ops, OP_SETTLED, [occ])
        self.assertEqual(proof[occ], PROOF_PENDING)
        self.assertEqual(proof.scope, "requested_occurrences")
        self.assertEqual(proof.exhaustive_status, PROOF_PENDING)
        self.assertEqual(proof.occurrence_ids, (occ,))

    def test_distinct_locators_on_shared_host_endpoint_stay_pending(self) -> None:
        store = LinkStore()
        occ_a, occ_b = _occ(), _occ()
        for occ, finding, component in (
            (occ_a, "f1", "nginx"),
            (occ_b, "f2", "apache"),
        ):
            result = store.record(
                _link(
                    occurrence_id=occ,
                    finding_id=finding,
                    endpoint_id="ep-host-1",
                    component_locator=component,
                ),
                self.ops,
            )
            self.assertEqual(result.outcome, "recorded")
        proof = store.cr04_proof(self.ops, OP_SETTLED, [occ_a, occ_b])
        self.assertEqual(proof[occ_a], PROOF_PENDING)
        self.assertEqual(proof[occ_b], PROOF_PENDING)

    def test_host_only_port_description_without_locator_stays_pending(self) -> None:
        # The port appears only in the host-only Endpoint description: no
        # component locator, so the shared endpoint cannot be distinguished.
        store = LinkStore()
        occ_a, occ_b = _occ(), _occ()
        for occ, finding in ((occ_a, "f1"), (occ_b, "f2")):
            store.record(
                _link(occurrence_id=occ, finding_id=finding, endpoint_id="ep-host-1"),
                self.ops,
            )
        proof = store.cr04_proof(self.ops, OP_SETTLED, [occ_a, occ_b])
        self.assertEqual(proof[occ_a], PROOF_PENDING)
        self.assertEqual(proof[occ_b], PROOF_PENDING)

    def test_identical_component_locator_on_shared_endpoint_stays_pending(self) -> None:
        store = LinkStore()
        occ_a, occ_b = _occ(), _occ()
        for occ, finding in ((occ_a, "f1"), (occ_b, "f2")):
            store.record(
                _link(
                    occurrence_id=occ,
                    finding_id=finding,
                    endpoint_id="ep-host-1",
                    component_locator="openssl",
                ),
                self.ops,
            )
        proof = store.cr04_proof(self.ops, OP_SETTLED, [occ_a, occ_b])
        self.assertEqual(proof[occ_a], PROOF_PENDING)
        self.assertEqual(proof[occ_b], PROOF_PENDING)

    def test_same_component_on_distinct_measured_endpoints_stays_pending(self) -> None:
        # Both endpoints are measured, but neither component binding is.
        store = LinkStore()
        occ_a, occ_b = _occ(), _occ()
        ops = _op_store(
            OP_SETTLED,
            findings=("f1", "f2"),
            endpoints=("ep-1", "ep-2"),
        )
        for occ, finding, endpoint in (
            (occ_a, "f1", "ep-1"),
            (occ_b, "f2", "ep-2"),
        ):
            store.record(
                _link(
                    occurrence_id=occ,
                    finding_id=finding,
                    endpoint_id=endpoint,
                    component_locator="openssl",
                ),
                ops,
            )
        proof = store.cr04_proof(ops, OP_SETTLED, [occ_a, occ_b])
        self.assertEqual(proof[occ_a], PROOF_PENDING)
        self.assertEqual(proof[occ_b], PROOF_PENDING)

    def test_same_component_on_distinct_unmeasured_endpoints_stays_pending(self) -> None:
        # Neither component is attested; ep-2 is also outside read-back.
        store = LinkStore()
        occ_a, occ_b = _occ(), _occ()
        ops = _op_store(
            OP_SETTLED, findings=("f1", "f2"), endpoints=("ep-1",)
        )
        for occ, finding, endpoint in (
            (occ_a, "f1", "ep-1"),
            (occ_b, "f2", "ep-2"),
        ):
            store.record(
                _link(
                    occurrence_id=occ,
                    finding_id=finding,
                    endpoint_id=endpoint,
                    component_locator="openssl",
                ),
                ops,
            )
        proof = store.cr04_proof(ops, OP_SETTLED, [occ_a, occ_b])
        self.assertEqual(proof[occ_a], PROOF_PENDING)
        self.assertEqual(proof[occ_b], PROOF_PENDING)


class ReimportSupersessionTest(unittest.TestCase):
    """Reviewer c6d48384 finding: a settled reimport (a new operation)
    supersedes the previous operation's link in append-only history; a
    pending/quarantined operation (as the store holds it) must retain the
    prior active link."""

    def setUp(self) -> None:
        self.store = LinkStore()
        self.ops = _op_store(
            OP_SETTLED, findings=("f1", "f9"), endpoints=("ep-1",)
        )
        self.occ = _occ()
        self.prior = _link(occurrence_id=self.occ, finding_id="f1", endpoint_id="ep-1")
        self.store.record(self.prior, self.ops)

    def test_settled_reimport_supersedes_prior_operation_link(self) -> None:
        reimport = _op_store(
            OP_REIMPORT,
            findings=("f2",),
            endpoints=("ep-2",),
            request_kind=REQUEST_REIMPORT,
            test_id="test-1",
            operations=self.ops,
            context_key=self.ops.get(OP_SETTLED).context_key,
            mapping_revision=2,
        )
        correction = _link(
            operation_id=OP_REIMPORT,
            occurrence_id=self.occ,
            finding_id="f2",
            endpoint_id="ep-2",
            supersedes_link_id=self.prior.link_id,
        )
        result = self.store.record(correction, reimport)
        self.assertEqual(result.outcome, "recorded")

        old = self.store.get(self.prior.link_id)
        self.assertEqual(old.mapping_status, links.LINK_SUPERSEDED)
        self.assertEqual(old.revision, 2)
        self.assertEqual(old.effective_until, correction.effective_from)

        history = self.store.history(self.prior.link_id)
        self.assertEqual(
            [l.link_id for l in history], [self.prior.link_id, correction.link_id]
        )

        # Only the reimport's link is effective; pair proof remains pending.
        self.assertEqual(
            self.store.cr04_proof(reimport, OP_REIMPORT, [self.occ])[self.occ],
            PROOF_PENDING,
        )
        self.assertEqual(
            self.store.cr04_proof(reimport, OP_SETTLED, [self.occ])[self.occ],
            PROOF_FAILED,
        )

    def test_foreign_context_cannot_supersede_active_link(self) -> None:
        foreign = _op_store(
            OP_REIMPORT, findings=("f2",), endpoints=("ep-2"),
            operations=self.ops,
            readback_test_id="test-foreign",
        )
        result = self.store.record(
            _link(operation_id=OP_REIMPORT, occurrence_id=self.occ,
                  finding_id="f2", endpoint_id="ep-2",
                  supersedes_link_id=self.prior.link_id), foreign,
        )
        self.assertEqual(result.outcome, "rejected")
        self.assertIn("same registered context", result.reason or "")
        self.assertEqual(self.store.get(self.prior.link_id).mapping_status, links.LINK_ACTIVE)

    def test_older_settled_mapping_cannot_supersede_newer_link(self) -> None:
        _op_store(
            OP_REIMPORT, findings=("f2",), endpoints=("ep-2",),
            request_kind=REQUEST_REIMPORT, test_id="test-1",
            operations=self.ops,
            context_key=self.ops.get(OP_SETTLED).context_key,
            mapping_revision=2,
        )
        current = _link(operation_id=OP_REIMPORT, occurrence_id=self.occ,
                        finding_id="f2", endpoint_id="ep-2",
                        supersedes_link_id=self.prior.link_id)
        self.assertEqual(self.store.record(current, self.ops).outcome, "recorded")
        stale = _link(operation_id=OP_SETTLED, occurrence_id=self.occ,
                      finding_id="f1", endpoint_id="ep-1",
                      supersedes_link_id=current.link_id)
        result = self.store.record(stale, self.ops)
        self.assertEqual(result.outcome, "rejected")
        self.assertIn("active settled mapping revision", result.reason or "")
        self.assertEqual(self.store.get(current.link_id).mapping_status, links.LINK_ACTIVE)

    def test_superseding_operation_must_still_be_active_mapping(self) -> None:
        context = self.ops.get(OP_SETTLED).context_key
        _op_store(
            OP_REIMPORT, findings=("f2",), endpoints=("ep-2",),
            request_kind=REQUEST_REIMPORT, test_id="test-1",
            operations=self.ops, context_key=context, mapping_revision=2,
        )
        _op_store(
            str(uuid.uuid4()), findings=("f3",), endpoints=("ep-3",),
            request_kind=REQUEST_REIMPORT, test_id="test-1",
            operations=self.ops, context_key=context, mapping_revision=3,
        )
        stale = _link(
            operation_id=OP_REIMPORT, occurrence_id=self.occ,
            finding_id="f2", endpoint_id="ep-2",
            supersedes_link_id=self.prior.link_id,
        )
        result = self.store.record(stale, self.ops)
        self.assertEqual(result.outcome, "rejected")
        self.assertIn("active settled mapping revision", result.reason or "")
        self.assertEqual(self.store.get(self.prior.link_id).mapping_status, links.LINK_ACTIVE)

    def test_same_operation_correction_cannot_use_stale_mapping(self) -> None:
        context = self.ops.get(OP_SETTLED).context_key
        _op_store(
            OP_REIMPORT, findings=("f2",), endpoints=("ep-2",),
            request_kind=REQUEST_REIMPORT, test_id="test-1",
            operations=self.ops, context_key=context, mapping_revision=2,
        )
        stale = _link(
            occurrence_id=self.occ, finding_id="f9", endpoint_id="ep-1",
            supersedes_link_id=self.prior.link_id,
        )
        result = self.store.record(stale, self.ops)
        self.assertEqual(result.outcome, "rejected")
        self.assertIn("active settled mapping revision", result.reason or "")
        self.assertEqual(self.store.history(self.prior.link_id), [self.prior])

    def test_settled_pending_correction_retains_prior_active_link(self) -> None:
        pending = _link(
            occurrence_id=self.occ, finding_id="f9", status=links.LINK_PENDING,
            supersedes_link_id=self.prior.link_id,
        )
        result = self.store.record(pending, self.ops)
        self.assertEqual(result.outcome, "rejected")
        self.assertIn("pending link cannot supersede", result.reason or "")
        self.assertEqual(self.store.history(self.prior.link_id), [self.prior])
        self.assertEqual(self.store.get(self.prior.link_id).mapping_status, links.LINK_ACTIVE)

    def test_settled_reimport_pending_link_cannot_supersede(self) -> None:
        _op_store(
            OP_REIMPORT, findings=("f2",), endpoints=("ep-2",),
            request_kind=REQUEST_REIMPORT, test_id="test-1",
            operations=self.ops, context_key=self.ops.get(OP_SETTLED).context_key,
            mapping_revision=2,
        )
        pending = _link(
            operation_id=OP_REIMPORT, occurrence_id=self.occ,
            finding_id="f2", status=links.LINK_PENDING,
            supersedes_link_id=self.prior.link_id,
        )
        result = self.store.record(pending, self.ops)
        self.assertEqual(result.outcome, "rejected")
        self.assertIn("pending link cannot supersede", result.reason or "")
        self.assertEqual(self.store.history(self.prior.link_id), [self.prior])
        self.assertEqual(self.store.get(self.prior.link_id).mapping_status, links.LINK_ACTIVE)

    def test_pending_reimport_retains_prior_active_link(self) -> None:
        pending_ops = _op_store(
            OP_PENDING, findings=("f9",), status=STATUS_PENDING
        )
        result = self.store.record(
            _link(
                operation_id=OP_PENDING,
                occurrence_id=self.occ,
                finding_id="f9",
                endpoint_id="ep-9",
                supersedes_link_id=self.prior.link_id,
            ),
            pending_ops,
        )
        self.assertEqual(result.outcome, "rejected")
        self.assertIn("cannot supersede", result.reason or "")
        self.assertEqual(self.store.get(self.prior.link_id).mapping_status, links.LINK_ACTIVE)
        self.assertEqual(
            self.store.cr04_proof(self.ops, OP_SETTLED, [self.occ])[self.occ],
            PROOF_PENDING,
        )

    def test_quarantined_reimport_retains_prior_active_link(self) -> None:
        quarantined_ops = _op_store(
            OP_QUARANTINED, findings=("f9",), status=STATUS_QUARANTINED
        )
        result = self.store.record(
            _link(
                operation_id=OP_QUARANTINED,
                occurrence_id=self.occ,
                finding_id="f9",
                endpoint_id="ep-9",
                supersedes_link_id=self.prior.link_id,
            ),
            quarantined_ops,
        )
        self.assertEqual(result.outcome, "rejected")
        self.assertIn("cannot supersede", result.reason or "")
        self.assertEqual(self.store.get(self.prior.link_id).mapping_status, links.LINK_ACTIVE)



class PairObservedDiagnosticTest(unittest.TestCase):
    """Bounded pair observation is a diagnostic only, never CR-04 proof.

    Caller-supplied parsed ``FindingDetailAssociationV1`` objects are
    synthetic/retained evidence bytes — never a live CE proof — so
    ``cr04_proof`` keeps every effective link ``pending`` and
    ``exhaustive_status`` ``pending`` until a separately trusted
    actionable-occurrence manifest and live API provenance exist. The
    ``pair_observed`` diagnostic reports only whether the supplied parsed
    bytes show a distinct per-occurrence Finding↔Endpoint pair: a stored
    settled CURRENT mapping (not a stale mapping revision), an ``active``
    effective link, exact canonical decimal string forms of the bound
    Test and the link Finding/Endpoint, per-Finding Endpoint membership in
    the parsed ``endpoint_ids``, and no indistinguishably shared pair
    (host-only sharing or a fabricated component distinction never
    observes).
    """

    def setUp(self) -> None:
        self.store = LinkStore()
        # Integer IDs end-to-end: the stored bound Test is the canonical
        # decimal string of the association's Test ID.
        self.ops = _op_store(
            OP_A_SETTLED,
            findings=(1, 2),
            endpoints=(10, 11),
            readback_test_id="42",
        )

    def _record(self, finding: str, endpoint: str | None = "10", **kw) -> EngineOccurrenceLinkV1:
        occ = _occ()
        link = _link(
            operation_id=OP_A_SETTLED,
            occurrence_id=occ,
            finding_id=finding,
            endpoint_id=endpoint,
            **kw,
        )
        assert self.store.record(link, self.ops).outcome == "recorded"
        return link

    def _observed(self, occ: str, *assocs) -> bool:
        return self.store.pair_observed(
            self.ops, OP_A_SETTLED, occ, list(assocs)
        )

    def test_positive_distinct_pair_is_observed(self) -> None:
        # A second occurrence on a distinct measured Endpoint (with a
        # different caller locator) never hides the distinct pair: the
        # measured Endpoint carries the distinction, so the pair is still
        # observed.
        link = self._record("1", "10", component_locator="comp-b")
        self._record("2", "11", component_locator="comp-a")
        self.assertTrue(
            self._observed(
                link.occurrence_id, _association(42, 1, (10, 11), ce_release="3.3.100")
            )
        )

    def test_positive_distinct_pair_keeps_cr04_pending(self) -> None:
        # Observed is not verified: with or without associations the
        # caller-supplied parsed bytes never flip CR-04 proof.
        link = self._record("1", "10")
        proof = self.store.cr04_proof(self.ops, OP_A_SETTLED, [link.occurrence_id])
        self.assertEqual(proof[link.occurrence_id], PROOF_PENDING)
        self.assertEqual(proof.exhaustive_status, PROOF_PENDING)
        self.assertEqual(proof.scope, "requested_occurrences")

    def test_synthetic_bytes_are_diagnostic_only(self) -> None:
        # The observation rides on synthetic-fixture bytes (a bounded inert
        # origin label, never a live read-back) and never yields verified.
        link = self._record("1", "10")
        assoc = _association(42, 1, (10, 11))
        self.assertEqual(assoc.source_kind, "synthetic-fixture")
        self.assertTrue(self._observed(link.occurrence_id, assoc))
        proof = self.store.cr04_proof(self.ops, OP_A_SETTLED, [link.occurrence_id])
        self.assertEqual(proof[link.occurrence_id], PROOF_PENDING)
        self.assertEqual(proof.exhaustive_status, PROOF_PENDING)

    def test_pending_link_is_not_observed(self) -> None:
        # A recorded-but-pending link is not an active effective link: the
        # diagnostic never observes it, even with a matching association.
        link = self._record("1", "10", status=links.LINK_PENDING)
        self.assertFalse(self._observed(link.occurrence_id, _association(42, 1, (10,))))
        proof = self.store.cr04_proof(self.ops, OP_A_SETTLED, [link.occurrence_id])
        self.assertEqual(proof[link.occurrence_id], PROOF_PENDING)

    def test_stale_operation_is_not_observed(self) -> None:
        # OP_A_SETTLED stays settled but is no longer the CURRENT mapping of
        # its context once a newer settled reimport takes the mapping: the
        # diagnostic requires the stored operation to be the current
        # active mapping revision.
        ops = _op_store(
            OP_STALE,
            findings=(1,),
            endpoints=(10,),
            readback_test_id="42",
            mapping_revision=1,
            context_key=CTX_A,
        )
        ops = _op_store(
            OP_FRESH,
            findings=(1,),
            endpoints=(10,),
            readback_test_id="42",
            mapping_revision=2,
            context_key=CTX_A,
            request_kind=REQUEST_REIMPORT,
            test_id="42",
            operations=ops,
        )
        self.assertNotEqual(
            ops.active_mapping_revision(CTX_A),
            ops.get(OP_STALE).mapping_revision,
        )
        occ = _occ()
        stale = _link(
            operation_id=OP_STALE,
            occurrence_id=occ,
            finding_id="1",
            endpoint_id="10",
        )
        assert self.store.record(stale, ops).outcome == "recorded"
        self.assertFalse(
            self.store.pair_observed(
                ops, OP_STALE, occ, [_association(42, 1, (10,))]
            )
        )
        proof = self.store.cr04_proof(ops, OP_STALE, [occ])
        self.assertEqual(proof[occ], PROOF_PENDING)

    def test_fabricated_component_distinction_is_not_observed(self) -> None:
        # Two occurrences on distinct Findings claim a component
        # distinction, but the measured pair is the same Endpoint with the
        # same locator: indistinguishably shared, so neither is observed.
        link_a = self._record("1", "10", component_locator="comp-1")
        link_b = self._record("2", "10", component_locator="comp-1")
        self.assertFalse(
            self._observed(
                link_a.occurrence_id, _association(42, 1, (10,))
            )
        )
        self.assertFalse(
            self._observed(
                link_b.occurrence_id, _association(42, 2, (10,))
            )
        )

    def test_distinct_invented_locators_on_same_endpoint_are_not_observed(self) -> None:
        # Two occurrences on distinct Findings claim DIFFERENT component
        # locators, but the measured pair is the same Endpoint: the flat
        # read-back never independently binds a component locator, so the
        # invented locators must not distinguish the shared pair — neither
        # occurrence is observed.
        link_a = self._record("1", "10", component_locator="comp-a")
        link_b = self._record("2", "10", component_locator="comp-b")
        self.assertFalse(
            self._observed(
                link_a.occurrence_id, _association(42, 1, (10,), ce_release="3.3.100")
            )
        )
        self.assertFalse(
            self._observed(
                link_b.occurrence_id, _association(42, 2, (10,), ce_release="3.3.100")
            )
        )

    def test_locator_vs_none_on_same_endpoint_is_not_observed(self) -> None:
        # One occurrence claims a component locator on a measured Endpoint,
        # the other rests on that same Endpoint with no locator: the
        # locator is caller-supplied and unbound, so the locator-vs-none
        # asymmetry cannot distinguish the shared pair.
        link_a = self._record("1", "10", component_locator="comp-a")
        link_b = self._record("2", "10")
        self.assertFalse(
            self._observed(
                link_a.occurrence_id, _association(42, 1, (10,), ce_release="3.3.100")
            )
        )
        self.assertFalse(
            self._observed(
                link_b.occurrence_id, _association(42, 2, (10,), ce_release="3.3.100")
            )
        )

    def test_association_from_other_release_is_not_observed(self) -> None:
        # The association bytes were parsed from a CE release that does not
        # exactly match the stored operation's engine_release: those bytes
        # cannot show this operation's pair. The exact-match release is
        # observed (positive control).
        link = self._record("1", "10")
        self.assertFalse(
            self._observed(
                link.occurrence_id, _association(42, 1, (10, 11), ce_release="3.3.200")
            )
        )
        self.assertTrue(
            self._observed(
                link.occurrence_id, _association(42, 1, (10, 11), ce_release="3.3.100")
            )
        )

    def test_shared_host_only_pair_is_not_observed(self) -> None:
        # Two occurrences on distinct Findings sharing one host-only
        # Endpoint: the pair is indistinguishable, so the parsed bytes
        # show the pair for neither occurrence.
        link_a = self._record("1", "10")
        link_b = self._record("2", "10")
        self.assertFalse(
            self._observed(
                link_a.occurrence_id, _association(42, 1, (10,))
            )
        )
        self.assertFalse(
            self._observed(
                link_b.occurrence_id, _association(42, 2, (10,))
            )
        )

    def test_endpoint_less_component_link_is_not_observed(self) -> None:
        # A component locator with no Endpoint never establishes a pair,
        # even with an association for that Finding.
        link = self._record("1", None, component_locator="comp-1")
        self.assertFalse(self._observed(link.occurrence_id, _association(42, 1, (10,))))
        proof = self.store.cr04_proof(self.ops, OP_A_SETTLED, [link.occurrence_id])
        self.assertEqual(proof[link.occurrence_id], PROOF_PENDING)

    def test_wrong_test_is_not_observed(self) -> None:
        link = self._record("1", "10")
        self.assertFalse(self._observed(link.occurrence_id, _association(43, 1, (10, 11))))

    def test_noncanonical_bound_test_is_not_observed(self) -> None:
        # Stored bound Test is the padded "042": not the exact canonical
        # decimal string form of the association's Test ID 42.
        ops = _op_store(
            OP_A_NONCANON_TEST,
            findings=(1,),
            endpoints=(10,),
            readback_test_id="042",
        )
        occ = _occ()
        link = _link(
            operation_id=OP_A_NONCANON_TEST,
            occurrence_id=occ,
            finding_id="1",
            endpoint_id="10",
        )
        assert self.store.record(link, ops).outcome == "recorded"
        self.assertFalse(
            self.store.pair_observed(
                ops, OP_A_NONCANON_TEST, occ, [_association(42, 1, (10,))]
            )
        )

    def test_noncanonical_link_finding_id_is_not_observed(self) -> None:
        # "01" is not the canonical decimal string form of the
        # association's Finding ID 1, nor is it in the stored scope {1, 2}.
        link = self._record("01", "10")
        self.assertFalse(
            self._observed(link.occurrence_id, _association(42, 1, (10, 11)))
        )

    def test_wrong_finding_is_not_observed(self) -> None:
        # The association shows Finding 1's endpoints; it cannot show
        # this link's Finding 2.
        link = self._record("2", "10")
        self.assertFalse(
            self._observed(link.occurrence_id, _association(42, 1, (10,)))
        )

    def test_invented_endpoint_is_not_observed(self) -> None:
        # Endpoint 11 is in the stored scope, but the association for this
        # Finding binds only Endpoint 10: the pair is unshown.
        link = self._record("1", "11")
        self.assertFalse(
            self._observed(link.occurrence_id, _association(42, 1, (10,)))
        )

    def test_fabricated_endpoint_outside_scope_is_not_observed(self) -> None:
        # Endpoint 99 appears nowhere in the stored read-back scope: an
        # association cannot show the link against an unmeasured Endpoint.
        link = self._record("1", "99")
        self.assertFalse(
            self._observed(link.occurrence_id, _association(42, 1, (99,)))
        )

    def test_rejects_non_dto_associations(self) -> None:
        link = self._record("1", "10")
        with self.assertRaises(ValueError):
            self.store.pair_observed(
                self.ops, OP_A_SETTLED, link.occurrence_id, ["not-a-dto"]
            )
        with self.assertRaises(ValueError):
            self.store.pair_observed(
                self.ops, OP_A_SETTLED, link.occurrence_id, [object()]
            )


if __name__ == "__main__":
    unittest.main()
