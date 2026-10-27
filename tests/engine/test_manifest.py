"""Focused synthetic tests for the source-neutral manifest contract
(uvm.engine.manifest, G1 CR-03/CR-04, FR-ID-02).

Synthetic fixtures only: no HTTP, no persistence, no live engine. The
supplied snapshot mirrors the shape of
``uvm.persistence.observation_store.RetainedRun`` / ``RetainedObservation``
without importing the persistence layer. Covers: the happy path, the
unapproved ``excluded_reviewed`` rejection (no trusted rule/permissions
service in this slice), conflict holders forced ``blocked``, omitted rows,
duplicate rows, cross-account/run rows, stale/superseded resolutions,
empty/unsealed/concurrently extended inventories, unknown row kinds,
payload record mapping rules (unknown payload observations raise
ManifestError, never StopIteration), operation/run binding without
operation-account claims, dual/conflicting manifest binding, partial-run
positives without run-coverage claims, and the explicit pending
payload-membership / unverified completeness-and-currency boundary (no
``verified``, no ``cr04_proof``).
"""

from __future__ import annotations

import unittest
import uuid
import weakref
from dataclasses import dataclass, fields, replace
from datetime import datetime, timezone

from uvm.engine.manifest import (
    DISPOSITION_BLOCKED,
    DISPOSITION_EXCLUDED_REVIEWED,
    DISPOSITION_INCLUDED,
    ManifestBindingRegistry,
    ManifestConflictError,
    ManifestError,
    OccurrenceManifestV1,
    PAYLOAD_MEMBERSHIP_PENDING,
    PayloadRecordV1,
    ROW_KIND_CANDIDATE_POSITIVE,
    ROW_KIND_CONTROL_METADATA,
    RUN_COVERAGE_NONE,
    RowDispositionV1,
    InventorySealV1,
    build_occurrence_manifest,
)
from uvm.engine.operation import EngineImportOperationV1
from uvm.identity.model import IdentityResolutionV1
from uvm.identity.observations import (
    COLLECTION_PARTIAL,
    COLLECTION_SUCCESS,
    MissingField,
    SourceObservationV1,
)

T0 = datetime(2026, 9, 28, 8, 0, 0, tzinfo=timezone.utc)
FAMILY = "defectdojo-ce"
ACCOUNT = "acct-1"
RUN = "run-7"
DIGEST = "ab" * 32
MISSING_FIELDS = tuple(
    MissingField(field, "not_supplied")
    for field in (
        "observed_at", "native_id_scheme", "native_id_authority",
        "native_id_value", "asset_locator", "component_locator",
        "source_record_locator", "source_rating", "vulnerability_refs",
        "source_first_seen_at", "report_id", "coverage_scope",
    )
)


@dataclass(frozen=True)
class RetainedRow:
    """Mirrors uvm.persistence.observation_store.RetainedObservation."""

    observation: SourceObservationV1
    retention_order: int
    ingest_outcome: str


@dataclass(frozen=True)
class RetainedRun:
    """Mirrors uvm.persistence.observation_store.RetainedRun."""

    source_account_id: str
    run_id: str
    rows: tuple
    quarantine: tuple = ()


def make_obs(
    ordinal: int,
    *,
    account: str = ACCOUNT,
    run: str = RUN,
    family: str = FAMILY,
    status: str = COLLECTION_SUCCESS,
    observation_id=None,
    outcome: str = "created",
) -> SourceObservationV1:
    return SourceObservationV1(
        schema_version=1,
        observation_id=str(uuid.uuid4()) if observation_id is None
        else observation_id,
        revision=1,
        source_family=family,
        source_account_id=account,
        run_id=run,
        source_record_ordinal=ordinal,
        collection_status=status,
        collected_at=T0,
        raw_evidence_ref=f"ev-{ordinal}",
        raw_evidence_sha256=DIGEST,
        missing_fields=MISSING_FIELDS,
        occurrence_id=None,
    )


def make_row(obs: SourceObservationV1, order: int,
             outcome: str = "created") -> RetainedRow:
    return RetainedRow(obs, order, outcome)


def make_resolution(
    obs_id: str, revision: int = 1, outcome: str = "matched",
    supersedes=None, occurrence_id=None,
) -> IdentityResolutionV1:
    return IdentityResolutionV1(
        schema_version=1,
        resolution_id=str(uuid.uuid4()),
        revision=revision,
        observation_id=obs_id,
        rule_id="rule-match-1",
        rule_version=1,
        matching_inputs={"native_id": "value"},
        candidate_workload_ids=(),
        outcome=outcome,
        evaluated_at=T0,
        group_id=str(uuid.uuid4()) if outcome in ("matched", "new") else None,
        workload_id=str(uuid.uuid4()) if outcome in ("matched", "new") else None,
        incarnation_id=str(uuid.uuid4()) if outcome in ("matched", "new") else None,
        exposure_id=str(uuid.uuid4()) if outcome in ("matched", "new") else None,
        occurrence_id=(str(uuid.uuid4()) if occurrence_id is None
                       and outcome in ("matched", "new")
                       else occurrence_id),
        supersedes_resolution_id=supersedes,
    )


def make_operation(
    *, run: str = RUN, payload: str = DIGEST, bound_test_id=None,
    context_key: str = "prod:acct-1/eng-prod/test-main",
) -> EngineImportOperationV1:
    return EngineImportOperationV1(
        schema_version=1,
        operation_id=str(uuid.uuid4()),
        revision=1,
        context_key=context_key,
        source_run_id=run,
        scan_type="zap",
        payload_sha256=payload,
        parser_config_version="pc-1",
        engine_release="3.3.100",
        request_kind="import",
        requested_at=T0,
        close_old_findings=False,
        status="pending",
        bound_test_id=bound_test_id,
    )


def make_seal(**overrides) -> InventorySealV1:
    kwargs = dict(
        source_family=FAMILY,
        source_account_id=ACCOUNT,
        run_id=RUN,
        retention_high_watermark=3,
        retained_row_count=3,
        conflict_holder_count=0,
        seal_ref="seal-ref-1",
    )
    kwargs.update(overrides)
    return InventorySealV1(schema_version=1, **kwargs)


def included_disposition(row: RetainedRow, resolution) -> RowDispositionV1:
    return RowDispositionV1(
        schema_version=1,
        observation_id=row.observation.observation_id,
        source_record_ordinal=row.observation.source_record_ordinal,
        raw_evidence_sha256=DIGEST,
        disposition=DISPOSITION_INCLUDED,
        occurrence_id=resolution.occurrence_id,
        resolution_id=resolution.resolution_id,
        resolution_revision=resolution.revision,
    )


def excluded_disposition(row: RetainedRow) -> RowDispositionV1:
    return RowDispositionV1(
        schema_version=1,
        observation_id=row.observation.observation_id,
        source_record_ordinal=row.observation.source_record_ordinal,
        raw_evidence_sha256=DIGEST,
        disposition=DISPOSITION_EXCLUDED_REVIEWED,
        exclusion_rule_id="rule-control-9",
        exclusion_rule_version=2,
        exclusion_evidence_ref="ev-control-1",
        exclusion_reason="scanner banner row proven control metadata",
        exclusion_actor="reviewer-actor-1",
    )


def blocked_disposition(row: RetainedRow, reason: str = "unresolved identity") -> RowDispositionV1:
    return RowDispositionV1(
        schema_version=1,
        observation_id=row.observation.observation_id,
        source_record_ordinal=row.observation.source_record_ordinal,
        raw_evidence_sha256=DIGEST,
        disposition=DISPOSITION_BLOCKED,
        blocked_reason=reason,
    )


class ManifestContractTests(unittest.TestCase):
    """The approved V1 manifest rule, boundary by boundary."""

    # -- fixtures ------------------------------------------------------------

    def three_row_snapshot(self):
        """r1 candidate positive (included), r2 control metadata (blocked
        - exclusion review unapproved in this slice), r3 unknown kind
        (blocked)."""
        r1 = make_row(make_obs(1), 1)
        r2 = make_row(make_obs(2), 2)
        r3 = make_row(make_obs(3), 3)
        retained = RetainedRun(ACCOUNT, RUN, (r1, r2, r3))
        resolution = make_resolution(r1.observation.observation_id)
        operation = make_operation()
        return retained, (r1, r2, r3), resolution, operation

    def build(self, retained, seal, resolutions, dispositions,
              payload_records, row_kinds, operation):
        return build_occurrence_manifest(
            operation=operation,
            retained=retained,
            seal=seal,
            resolutions=resolutions,
            dispositions=dispositions,
            payload_records=payload_records,
            row_kinds=row_kinds,
        )

    def good_arguments(self):
        retained, (r1, r2, r3), resolution, operation = \
            self.three_row_snapshot()
        dispositions = (
            included_disposition(r1, resolution),
            blocked_disposition(r2,
                                "control metadata; exclusion review "
                                "unapproved in this slice"),
            blocked_disposition(r3),
        )
        payload_records = (PayloadRecordV1(1, "rec-1",
                                           (r1.observation.observation_id,)),)
        row_kinds = {
            r1.observation.observation_id: ROW_KIND_CANDIDATE_POSITIVE,
            r2.observation.observation_id: ROW_KIND_CONTROL_METADATA,
        }  # r3 absent -> unknown
        return (retained, make_seal(), {r1.observation.observation_id:
                                        (resolution,)},
                dispositions, payload_records, row_kinds, operation)

    # -- happy path ----------------------------------------------------------

    def test_happy_path_manifest_binds_all_fields(self):
        (retained, seal, resolutions, dispositions, payload_records,
         row_kinds, operation) = self.good_arguments()
        manifest = self.build(retained, seal, resolutions, dispositions,
                              payload_records, row_kinds, operation)
        self.assertEqual(manifest.operation_id, operation.operation_id)
        self.assertEqual(manifest.context_key, operation.context_key)
        self.assertEqual(manifest.source_family, FAMILY)
        self.assertEqual(manifest.source_account_id, ACCOUNT)
        self.assertEqual(manifest.run_id, RUN)
        self.assertEqual(manifest.payload_sha256, operation.payload_sha256)
        self.assertIsNone(manifest.bound_test_id)
        self.assertEqual(len(manifest.dispositions), 3)
        # Completeness and currency are explicit unverified constants: no
        # caller-created seal or truncated snapshot proves them.
        self.assertNotIn("run_complete", manifest.__dataclass_fields__)
        self.assertEqual(manifest.run_completeness_status, "unverified")
        self.assertEqual(manifest.run_currency_status, "unverified")
        # Deterministic identity: same content, same ID and digest.
        again = self.build(retained, seal, resolutions, dispositions,
                           payload_records, row_kinds, operation)
        self.assertEqual(again.manifest_id, manifest.manifest_id)
        self.assertEqual(again.manifest_sha256, manifest.manifest_sha256)
        self.assertEqual(len(manifest.manifest_sha256), 64)
        uuid.UUID(manifest.manifest_id)

    def test_reimport_manifest_binds_requested_test_not_post_result(self):
        args = self.good_arguments()
        operation = replace(args[-1], request_kind="reimport",
                            test_id="test-requested")
        manifest = self.build(*args[:-1], operation)
        self.assertEqual(manifest.bound_test_id, "test-requested")
        self.assertIsNone(operation.bound_test_id)

    def test_registry_bind_idempotent(self):
        (retained, seal, resolutions, dispositions, payload_records,
         row_kinds, operation) = self.good_arguments()
        manifest = self.build(retained, seal, resolutions, dispositions,
                              payload_records, row_kinds, operation)
        registry = ManifestBindingRegistry()
        self.assertEqual(registry.bind(manifest).outcome, "bound")
        self.assertEqual(registry.bind(manifest).outcome, "duplicate")
        self.assertIs(registry.for_operation(operation.operation_id),
                      manifest)
        self.assertIs(registry.for_manifest(manifest.manifest_id), manifest)

    def test_registry_rejects_second_conflicting_binding(self):
        (retained, seal, resolutions, _, _, row_kinds, operation) = \
            self.good_arguments()
        r1 = retained.rows[0]
        r2, r3 = retained.rows[1], retained.rows[2]
        first = self.build(
            retained, seal, resolutions,
            (included_disposition(r1, next(iter(resolutions.values()))[0]),
             blocked_disposition(r2, "control metadata; exclusion "
                                    "unapproved"),
             blocked_disposition(r3, "unresolved identity")),
            (PayloadRecordV1(1, "rec-1",
                             (r1.observation.observation_id,)),),
            row_kinds, operation)
        second = self.build(
            retained, seal, resolutions,
            (included_disposition(r1, next(iter(resolutions.values()))[0]),
             blocked_disposition(r2, "control metadata; exclusion "
                                    "unapproved"),
             blocked_disposition(r3, "different blocked reason")),
            (PayloadRecordV1(1, "rec-1",
                             (r1.observation.observation_id,)),),
            row_kinds, operation)
        self.assertNotEqual(first.manifest_id, second.manifest_id)
        registry = ManifestBindingRegistry()
        registry.bind(first)
        with self.assertRaises(ManifestConflictError):
            registry.bind(second)
        # The first binding is retained unchanged.
        self.assertIs(registry.for_operation(operation.operation_id), first)

    # -- omissions and duplicates --------------------------------------------

    def test_omitted_row_rejected(self):
        (retained, seal, resolutions, _, _, row_kinds, operation) = \
            self.good_arguments()
        r1, r2, r3 = retained.rows
        with self.assertRaises(ManifestError) as ctx:
            self.build(retained, seal, resolutions,
                       (included_disposition(r1,
                                             next(iter(resolutions.values()))
                                             [0]),
                        blocked_disposition(r2, "control metadata; "
                                               "exclusion unapproved")),
                       (PayloadRecordV1(1, "rec-1",
                                        (r1.observation.observation_id,)),),
                       row_kinds, operation)
        self.assertIn("no disposition", str(ctx.exception))

    def test_disposition_for_row_outside_run_rejected(self):
        (retained, seal, resolutions, dispositions, payload_records,
         row_kinds, operation) = self.good_arguments()
        foreign = blocked_disposition(
            RetainedRow(make_obs(9, account="acct-9"), 4, "created"))
        with self.assertRaises(ManifestError) as ctx:
            self.build(retained, seal, resolutions,
                       (*dispositions, foreign), payload_records, row_kinds,
                       operation)
        self.assertIn("outside the sealed run", str(ctx.exception))

    def test_duplicate_row_rejected(self):
        r1 = make_row(make_obs(1), 1)
        r2 = make_row(make_obs(2), 2)
        r3 = make_row(make_obs(3), 3)
        retained = RetainedRun(ACCOUNT, RUN, (r1, r2, r3, r2))
        resolution = make_resolution(r1.observation.observation_id)
        with self.assertRaises(ManifestError) as ctx:
            self.build(
                retained, make_seal(),
                {r1.observation.observation_id: (resolution,)},
                (included_disposition(r1, resolution),
                 blocked_disposition(r2, "control metadata; exclusion "
                                         "unapproved"),
                 blocked_disposition(r3),
                 blocked_disposition(r2)),
                (PayloadRecordV1(1, "rec-1",
                                 (r1.observation.observation_id,)),),
                {}, make_operation())
        self.assertIn("appears twice", str(ctx.exception))

    def test_two_dispositions_for_one_row_rejected(self):
        (retained, seal, resolutions, dispositions, payload_records,
         row_kinds, operation) = self.good_arguments()
        extra = blocked_disposition(retained.rows[2], "also blocked")
        with self.assertRaises(ManifestError):
            self.build(retained, seal, resolutions, (*dispositions, extra),
                       payload_records, row_kinds, operation)

    # -- cross-account/run scope ----------------------------------------------

    def test_cross_account_row_rejected(self):
        r1 = make_row(make_obs(1), 1)
        r2 = make_row(make_obs(2, account="acct-2"), 2)
        r3 = make_row(make_obs(3), 3)
        retained = RetainedRun(ACCOUNT, RUN, (r1, r2, r3))
        resolution = make_resolution(r1.observation.observation_id)
        with self.assertRaises(ManifestError) as ctx:
            self.build(
                retained, make_seal(),
                {r1.observation.observation_id: (resolution,)},
                (included_disposition(r1, resolution),
                 blocked_disposition(r2, "control metadata; exclusion "
                                         "unapproved"),
                 blocked_disposition(r3)),
                (PayloadRecordV1(1, "rec-1",
                                 (r1.observation.observation_id,)),),
                {}, make_operation())
        self.assertIn("cross-account", str(ctx.exception))

    def test_cross_run_row_rejected(self):
        r1 = make_row(make_obs(1), 1)
        r2 = make_row(make_obs(2, run="run-8"), 2)
        r3 = make_row(make_obs(3), 3)
        retained = RetainedRun(ACCOUNT, RUN, (r1, r2, r3))
        resolution = make_resolution(r1.observation.observation_id)
        with self.assertRaises(ManifestError) as ctx:
            self.build(
                retained, make_seal(),
                {r1.observation.observation_id: (resolution,)},
                (included_disposition(r1, resolution),
                 blocked_disposition(r2, "control metadata; exclusion "
                                         "unapproved"),
                 blocked_disposition(r3)),
                (PayloadRecordV1(1, "rec-1",
                                 (r1.observation.observation_id,)),),
                {}, make_operation())
        self.assertIn("cross-account", str(ctx.exception))

    def test_cross_family_row_rejected(self):
        r1 = make_row(make_obs(1), 1)
        r2 = make_row(make_obs(2, family="other-scanner"), 2)
        r3 = make_row(make_obs(3), 3)
        retained = RetainedRun(ACCOUNT, RUN, (r1, r2, r3))
        resolution = make_resolution(r1.observation.observation_id)
        with self.assertRaises(ManifestError) as ctx:
            self.build(
                retained, make_seal(),
                {r1.observation.observation_id: (resolution,)},
                (included_disposition(r1, resolution),
                 blocked_disposition(r2, "control metadata; exclusion "
                                         "unapproved"),
                 blocked_disposition(r3)),
                (PayloadRecordV1(1, "rec-1",
                                 (r1.observation.observation_id,)),),
                {}, make_operation())
        self.assertIn("families", str(ctx.exception))

    def test_seal_scope_mismatch_rejected(self):
        (retained, _, resolutions, dispositions, payload_records,
         row_kinds, operation) = self.good_arguments()
        foreign_seal = make_seal(source_account_id="acct-9")
        with self.assertRaises(ManifestError) as ctx:
            self.build(retained, foreign_seal, resolutions, dispositions,
                       payload_records, row_kinds, operation)
        self.assertIn("seal scope", str(ctx.exception))

    def test_operation_run_mismatch_rejected(self):
        (retained, seal, resolutions, dispositions, payload_records,
         row_kinds, _) = self.good_arguments()
        foreign_op = make_operation(run="run-8")
        with self.assertRaises(ManifestError) as ctx:
            self.build(retained, seal, resolutions, dispositions,
                       payload_records, row_kinds, foreign_op)
        self.assertIn("source_run_id", str(ctx.exception))
        self.assertIn("unverified", str(ctx.exception))

    # -- stale / superseded resolutions ---------------------------------------

    def test_stale_resolution_revision_rejected(self):
        (retained, seal, resolutions, _, _, row_kinds, operation) = \
            self.good_arguments()
        r1, r2, r3 = retained.rows
        first = make_resolution(r1.observation.observation_id)
        later = make_resolution(r1.observation.observation_id,
                                revision=2, supersedes=first.resolution_id)
        resolutions = {r1.observation.observation_id: (first, later)}
        stale = RowDispositionV1(
            schema_version=1,
            observation_id=r1.observation.observation_id,
            source_record_ordinal=1,
            raw_evidence_sha256=DIGEST,
            disposition=DISPOSITION_INCLUDED,
            occurrence_id=first.occurrence_id,
            resolution_id=first.resolution_id,
            resolution_revision=1,
        )
        with self.assertRaises(ManifestError) as ctx:
            self.build(retained, seal, resolutions,
                       (stale, blocked_disposition(r2, "control metadata; "
                                                      "exclusion "
                                                      "unapproved"),
                        blocked_disposition(r3)),
                       (PayloadRecordV1(1, "rec-1",
                                        (r1.observation.observation_id,)),),
                       row_kinds, operation)
        self.assertIn("stale/superseded", str(ctx.exception))

    def test_broken_supersession_chain_rejected(self):
        (retained, seal, _, _, _, row_kinds, operation) = \
            self.good_arguments()
        r1, r2, r3 = retained.rows
        first = make_resolution(r1.observation.observation_id)
        orphan = make_resolution(r1.observation.observation_id,
                                 revision=2, supersedes=None)
        resolutions = {r1.observation.observation_id: (first, orphan)}
        with self.assertRaises(ManifestError) as ctx:
            self.build(retained, seal, resolutions,
                       (included_disposition(r1, orphan),
                        blocked_disposition(r2, "control metadata; "
                                               "exclusion unapproved"),
                        blocked_disposition(r3)),
                       (PayloadRecordV1(1, "rec-1",
                                        (r1.observation.observation_id,)),),
                       row_kinds, operation)
        self.assertIn("supersede", str(ctx.exception))

    def test_ambiguous_head_cannot_be_included(self):
        (retained, seal, _, _, _, row_kinds, operation) = \
            self.good_arguments()
        r1, r2, r3 = retained.rows
        ambiguous = make_resolution(
            r1.observation.observation_id, outcome="ambiguous",
            occurrence_id=None)
        resolutions = {r1.observation.observation_id: (ambiguous,)}
        attempt = RowDispositionV1(
            schema_version=1,
            observation_id=r1.observation.observation_id,
            source_record_ordinal=1,
            raw_evidence_sha256=DIGEST,
            disposition=DISPOSITION_INCLUDED,
            occurrence_id=str(uuid.uuid4()),
            resolution_id=ambiguous.resolution_id,
            resolution_revision=ambiguous.revision,
        )
        with self.assertRaises(ManifestError) as ctx:
            self.build(retained, seal, resolutions,
                       (attempt, blocked_disposition(r2, "control "
                                                        "metadata; "
                                                        "exclusion "
                                                        "unapproved"),
                        blocked_disposition(r3)),
                       (PayloadRecordV1(1, "rec-1",
                                        (r1.observation.observation_id,)),),
                       row_kinds, operation)
        self.assertIn("cannot be included", str(ctx.exception))

    def test_included_row_without_resolution_rejected(self):
        (retained, seal, resolutions, dispositions, payload_records,
         row_kinds, operation) = self.good_arguments()
        with self.assertRaises(ManifestError) as ctx:
            self.build(retained, seal, {}, dispositions, payload_records,
                       row_kinds, operation)
        self.assertIn("no resolution", str(ctx.exception))

    def test_wrong_occurrence_rejected(self):
        (retained, seal, resolutions, dispositions, payload_records,
         row_kinds, operation) = self.good_arguments()
        resolution = next(iter(resolutions.values()))[0]
        r1 = retained.rows[0]
        wrong = RowDispositionV1(
            schema_version=1,
            observation_id=r1.observation.observation_id,
            source_record_ordinal=1,
            raw_evidence_sha256=DIGEST,
            disposition=DISPOSITION_INCLUDED,
            occurrence_id=str(uuid.uuid4()),
            resolution_id=resolution.resolution_id,
            resolution_revision=resolution.revision,
        )
        with self.assertRaises(ManifestError) as ctx:
            self.build(retained, seal, resolutions,
                       (wrong, *dispositions[1:]), payload_records,
                       row_kinds, operation)
        self.assertIn("names occurrence", str(ctx.exception))

    def test_resolution_outside_sealed_run_rejected(self):
        (retained, seal, resolutions, dispositions, payload_records,
         row_kinds, operation) = self.good_arguments()
        foreign = make_resolution(str(uuid.uuid4()))
        resolutions["foreign"] = (foreign,)
        with self.assertRaises(ManifestError) as ctx:
            self.build(retained, seal, resolutions, dispositions,
                       payload_records, row_kinds, operation)
        self.assertIn("outside the sealed run", str(ctx.exception))

    # -- empty / unsealed / extended inventory --------------------------------

    def test_empty_inventory_rejected(self):
        retained = RetainedRun(ACCOUNT, RUN, ())
        with self.assertRaises(ManifestError) as ctx:
            self.build(retained, make_seal(retained_row_count=0,
                                           retention_high_watermark=0),
                       {}, (), (), {}, make_operation())
        self.assertIn("empty inventory", str(ctx.exception))

    def test_missing_seal_ref_rejected(self):
        with self.assertRaises(ManifestError):
            make_seal(seal_ref="")

    def test_stale_low_high_watermark_rejected(self):
        """The snapshot was extended after the seal was taken: a newly
        retained row raises the true watermark above the sealed one."""
        r1 = make_row(make_obs(1), 1)
        r2 = make_row(make_obs(2), 2)
        r3 = make_row(make_obs(3), 3)
        r4 = make_row(make_obs(4), 4)
        retained = RetainedRun(ACCOUNT, RUN, (r1, r2, r3, r4))
        resolution = make_resolution(r1.observation.observation_id)
        stale_seal = make_seal(retained_row_count=4)  # watermark still 3
        with self.assertRaises(ManifestError) as ctx:
            self.build(
                retained, stale_seal,
                {r1.observation.observation_id: (resolution,)},
                (included_disposition(r1, resolution),
                 blocked_disposition(r2, "control metadata; exclusion "
                                         "unapproved"),
                 blocked_disposition(r3),
                 blocked_disposition(r4)),
                (PayloadRecordV1(1, "rec-1",
                                 (r1.observation.observation_id,)),),
                {}, make_operation())
        self.assertIn("high watermark", str(ctx.exception))

    def test_seal_omitting_conflict_holders_rejected(self):
        r1 = make_row(make_obs(1), 1)
        r2 = make_row(make_obs(2), 2, outcome="conflict")
        r3 = make_row(make_obs(3), 3)
        retained = RetainedRun(ACCOUNT, RUN, (r1, r2, r3))
        resolution = make_resolution(r1.observation.observation_id)
        seal = make_seal(conflict_holder_count=0)  # omits r2's conflict
        with self.assertRaises(ManifestError) as ctx:
            self.build(
                retained, seal,
                {r1.observation.observation_id: (resolution,)},
                (included_disposition(r1, resolution),
                 blocked_disposition(r2, "conflicting bytes at this "
                                         "position"),
                 blocked_disposition(r3)),
                (PayloadRecordV1(1, "rec-1",
                                 (r1.observation.observation_id,)),),
                {}, make_operation())
        self.assertIn("conflict holders", str(ctx.exception))

    def test_conflict_holders_are_disposed(self):
        """The seal includes all conflict holders: every conflict row still
        needs exactly one disposition."""
        r1 = make_row(make_obs(1), 1)
        r2 = make_row(make_obs(2), 2, outcome="conflict")
        r3 = make_row(make_obs(3), 3)
        retained = RetainedRun(ACCOUNT, RUN, (r1, r2, r3))
        seal = make_seal(conflict_holder_count=1)
        resolution = make_resolution(r1.observation.observation_id)
        with self.assertRaises(ManifestError) as ctx:
            self.build(
                retained, seal,
                {r1.observation.observation_id: (resolution,)},
                (included_disposition(r1, resolution),
                 blocked_disposition(r3, "control metadata; exclusion "
                                         "unapproved")),
                (PayloadRecordV1(1, "rec-1",
                                 (r1.observation.observation_id,)),),
                {r1.observation.observation_id: ROW_KIND_CANDIDATE_POSITIVE},
                make_operation())
        self.assertIn("no disposition", str(ctx.exception))
        manifest = self.build(
            retained, seal,
            {r1.observation.observation_id: (resolution,)},
            (included_disposition(r1, resolution),
             blocked_disposition(r2, "conflicting bytes at this position"),
             blocked_disposition(r3, "control metadata; exclusion "
                                     "unapproved")),
            (PayloadRecordV1(1, "rec-1",
                             (r1.observation.observation_id,)),),
            {r1.observation.observation_id: ROW_KIND_CANDIDATE_POSITIVE,
             r3.observation.observation_id: ROW_KIND_CONTROL_METADATA},
            make_operation())
        # completeness/currency stay unverified even with a conflict holder

    # -- candidate-positive / unknown-kind exclusion ---------------------------

    def test_candidate_positive_exclusion_rejected(self):
        (retained, seal, resolutions, dispositions, payload_records,
         row_kinds, operation) = self.good_arguments()
        r1 = retained.rows[0]
        candidate_excluded = RowDispositionV1(
            schema_version=1,
            observation_id=r1.observation.observation_id,
            source_record_ordinal=1,
            raw_evidence_sha256=DIGEST,
            disposition=DISPOSITION_EXCLUDED_REVIEWED,
            exclusion_rule_id="rule-1",
            exclusion_rule_version=1,
            exclusion_evidence_ref="ev-1",
            exclusion_reason="attempted positive-row exclusion",
            exclusion_actor="reviewer-actor-1",
        )
        with self.assertRaises(ManifestError) as ctx:
            self.build(retained, seal, {},
                       (candidate_excluded, *dispositions[1:]),
                       (), row_kinds, operation)
        # No trusted rule/permissions service in this slice: every
        # excluded_reviewed attempt is rejected as unapproved.
        self.assertIn("unapproved", str(ctx.exception))

    def test_unknown_kind_may_only_be_blocked(self):
        (retained, seal, resolutions, dispositions, payload_records,
         row_kinds, operation) = self.good_arguments()
        r3 = retained.rows[2]
        unknown_included = RowDispositionV1(
            schema_version=1,
            observation_id=r3.observation.observation_id,
            source_record_ordinal=3,
            raw_evidence_sha256=DIGEST,
            disposition=DISPOSITION_INCLUDED,
            occurrence_id=str(uuid.uuid4()),
            resolution_id=str(uuid.uuid4()),
            resolution_revision=1,
        )
        with self.assertRaises(ManifestError) as ctx:
            self.build(retained, seal, {},
                       (dispositions[0], dispositions[1], unknown_included),
                       payload_records, row_kinds, operation)
        self.assertIn("unknown row kind", str(ctx.exception))

    def test_exclusion_requires_reviewed_actor_fields(self):
        r1 = make_row(make_obs(1), 1)
        with self.assertRaises(ManifestError):
            RowDispositionV1(
                schema_version=1,
                observation_id=r1.observation.observation_id,
                source_record_ordinal=1,
                raw_evidence_sha256=DIGEST,
                disposition=DISPOSITION_EXCLUDED_REVIEWED,
                exclusion_rule_id="rule-1",
                exclusion_rule_version=1,
                exclusion_evidence_ref=None,  # missing evidence
                exclusion_reason="r",
                exclusion_actor="a",
            )

    # -- payload record mapping ------------------------------------------------

    def test_payload_record_to_excluded_row_rejected(self):
        (retained, seal, resolutions, _, payload_records, row_kinds,
         operation) = self.good_arguments()
        r1, r2, r3 = retained.rows
        resolutions = {r1.observation.observation_id:
                       (next(iter(resolutions.values()))[0],)}
        with self.assertRaises(ManifestError) as ctx:
            self.build(
                retained, seal, resolutions,
                (included_disposition(
                    r1, next(iter(resolutions.values()))[0]),
                 blocked_disposition(r2, "control metadata; exclusion "
                                         "unapproved"),
                 blocked_disposition(r3)),
                (PayloadRecordV1(1, "rec-1",
                                 (r2.observation.observation_id,)),),
                row_kinds, operation)
        self.assertIn("included rows only", str(ctx.exception))

    def test_included_row_without_payload_record_rejected(self):
        (retained, seal, resolutions, dispositions, _, row_kinds,
         operation) = self.good_arguments()
        with self.assertRaises(ManifestError) as ctx:
            self.build(retained, seal, resolutions, dispositions, (),
                       row_kinds, operation)
        self.assertIn("no payload record", str(ctx.exception))

    def test_row_mapped_by_two_payload_records_rejected(self):
        (retained, seal, resolutions, dispositions, payload_records,
         row_kinds, operation) = self.good_arguments()
        r1 = retained.rows[0]
        duplicate = (
            *payload_records,
            PayloadRecordV1(1, "rec-2",
                            (r1.observation.observation_id,)),
        )
        with self.assertRaises(ManifestError) as ctx:
            self.build(retained, seal, resolutions, dispositions, duplicate,
                       row_kinds, operation)
        self.assertIn("exactly one", str(ctx.exception))

    def test_versioned_transformation_records_all_source_rows(self):
        """A two-row versioned transformation is allowed when every named
        source row is included and each row maps to exactly one record."""
        r1 = make_row(make_obs(1), 1)
        r2 = make_row(make_obs(2), 2)
        r3 = make_row(make_obs(3), 3)
        retained = RetainedRun(ACCOUNT, RUN, (r1, r2, r3))
        seal = make_seal()
        res1 = make_resolution(r1.observation.observation_id)
        res2 = make_resolution(r2.observation.observation_id)
        resolutions = {
            r1.observation.observation_id: (res1,),
            r2.observation.observation_id: (res2,),
        }
        manifest = self.build(
            retained, seal, resolutions,
            (included_disposition(r1, res1), included_disposition(r2, res2),
             blocked_disposition(r3)),
            (PayloadRecordV1(1, "rec-merged",
                             (r1.observation.observation_id,
                              r2.observation.observation_id),
                             transformation_version=2),),
            {
                r1.observation.observation_id: ROW_KIND_CANDIDATE_POSITIVE,
                r2.observation.observation_id: ROW_KIND_CANDIDATE_POSITIVE,
            },
            make_operation())
        self.assertEqual(len(manifest.payload_records), 1)
        self.assertEqual(
            set(manifest.payload_records[0].source_observation_ids),
            {r1.observation.observation_id, r2.observation.observation_id})

    # -- partial run / coverage boundary ----------------------------------------

    def test_partial_run_positives_import_without_coverage_claim(self):
        """Candidate positives from a partial collection are importable,
        but the manifest never claims run coverage or remediation."""
        r1 = make_row(make_obs(1, status=COLLECTION_PARTIAL), 1)
        r2 = make_row(make_obs(2), 2)
        retained = RetainedRun(ACCOUNT, RUN, (r1, r2))
        seal = make_seal(retained_row_count=2, retention_high_watermark=2)
        res1 = make_resolution(r1.observation.observation_id)
        manifest = self.build(
            retained, seal,
            {r1.observation.observation_id: (res1,)},
            (included_disposition(r1, res1),
             blocked_disposition(r2, "unresolved identity")),
            (PayloadRecordV1(1, "rec-1",
                             (r1.observation.observation_id,)),),
            {r1.observation.observation_id: ROW_KIND_CANDIDATE_POSITIVE},
            make_operation())
        self.assertEqual(manifest.run_completeness_status, "unverified")
        self.assertEqual(manifest.run_currency_status, "unverified")
        self.assertEqual(manifest.run_coverage_status, RUN_COVERAGE_NONE)
        self.assertEqual(manifest.payload_membership_status,
                         PAYLOAD_MEMBERSHIP_PENDING)

    def test_contract_never_verified(self):
        """This is a contract only: no verified outcome, no cr04_proof."""
        import uvm.engine.manifest as manifest_module
        self.assertFalse(
            hasattr(manifest_module, "cr04_proof"),
            "the contract must not provide cr04_proof")
        (retained, seal, resolutions, dispositions, payload_records,
         row_kinds, operation) = self.good_arguments()
        manifest = self.build(retained, seal, resolutions, dispositions,
                              payload_records, row_kinds, operation)
        self.assertFalse(
            any(f.lower().startswith("verified")
                for f in manifest.__dataclass_fields__),
            "the manifest carries no verified flag")
        self.assertEqual(manifest.payload_membership_status,
                         PAYLOAD_MEMBERSHIP_PENDING)

    def test_tampered_manifest_content_rejected(self):
        from dataclasses import replace
        (retained, seal, resolutions, dispositions, payload_records,
         row_kinds, operation) = self.good_arguments()
        manifest = self.build(retained, seal, resolutions, dispositions,
                              payload_records, row_kinds, operation)
        with self.assertRaises(ManifestError):
            replace(
                manifest,
                dispositions=(blocked_disposition(
                    retained.rows[0], "rewritten"),
                              *manifest.dispositions[1:]),
            )

    def test_registry_rejects_resigned_builder_manifest_after_mutation(self):
        """Re-signing a mutated builder object must not renew its issuance."""
        import uvm.engine.manifest as manifest_module

        (retained, seal, resolutions, dispositions, payload_records,
         row_kinds, operation) = self.good_arguments()
        manifest = self.build(retained, seal, resolutions, dispositions,
                              payload_records, row_kinds, operation)
        mutated_dispositions = (blocked_disposition(
            retained.rows[0], "rewritten after issuance"),)
        mutated_payload_records = ()
        digest, manifest_id = manifest_module._content_digest(
            manifest.operation_id, manifest.context_key,
            manifest.bound_test_id, manifest.source_family,
            manifest.source_account_id, manifest.run_id,
            manifest.payload_sha256, manifest.inventory_seal,
            mutated_dispositions, mutated_payload_records)
        object.__setattr__(manifest, "dispositions", mutated_dispositions)
        object.__setattr__(manifest, "payload_records", mutated_payload_records)
        object.__setattr__(manifest, "manifest_sha256", digest)
        object.__setattr__(manifest, "manifest_id", manifest_id)

        registry = ManifestBindingRegistry()
        with self.assertRaises(ManifestError):
            registry.bind(manifest)
        self.assertIsNone(registry.for_operation(manifest.operation_id))
        self.assertIsNone(registry.for_manifest(manifest.manifest_id))

    def test_registry_rejects_every_omitted_version_and_status_mutation(self):
        """The public content digest omits these fields, but issuance does not."""
        cases = (
            ("seal version", lambda m: m.inventory_seal,
             "schema_version", 2),
            ("manifest version", lambda m: m, "schema_version", 2),
            ("disposition version", lambda m: m.dispositions[0],
             "schema_version", 2),
            ("payload version", lambda m: m.payload_records[0],
             "schema_version", 2),
            ("completeness", lambda m: m,
             "run_completeness_status", "verified"),
            ("currency", lambda m: m,
             "run_currency_status", "verified"),
            ("coverage", lambda m: m, "run_coverage_status", "complete"),
            ("membership", lambda m: m,
             "payload_membership_status", "verified"),
        )
        for name, target, field, value in cases:
            with self.subTest(name=name):
                args = self.good_arguments()
                manifest = self.build(*args)
                object.__setattr__(target(manifest), field, value)
                registry = ManifestBindingRegistry()
                with self.assertRaises(ManifestError):
                    registry.bind(manifest)
                self.assertIsNone(registry.for_operation(manifest.operation_id))

    def test_registry_rejects_nested_payload_and_disposition_mutation(self):
        """Nested values and tuple shape cannot change after issuance."""
        cases = (
            ("blocked reason", lambda m: m.dispositions[1],
             "blocked_reason", "changed after issuance"),
            ("transformation version", lambda m: m.payload_records[0],
             "transformation_version", 2),
            ("payload membership shape", lambda m: m.payload_records[0],
             "source_observation_ids", []),
        )
        for name, target, field, value in cases:
            with self.subTest(name=name):
                manifest = self.build(*self.good_arguments())
                object.__setattr__(target(manifest), field, value)
                registry = ManifestBindingRegistry()
                with self.assertRaises(ManifestError):
                    registry.bind(manifest)
                self.assertIsNone(registry.for_operation(manifest.operation_id))

    def test_registry_snapshot_covers_all_declared_dto_fields(self):
        """A new DTO field cannot silently escape the issuance comparison."""
        paths = (
            ("manifest", lambda m: m),
            ("seal", lambda m: m.inventory_seal),
            ("disposition", lambda m: m.dispositions[0]),
            ("payload", lambda m: m.payload_records[0]),
        )
        for path, target in paths:
            baseline = self.build(*self.good_arguments())
            for field in fields(target(baseline)):
                with self.subTest(path=path, field=field.name):
                    manifest = self.build(*self.good_arguments())
                    object.__setattr__(target(manifest), field.name,
                                       "changed after issuance")
                    registry = ManifestBindingRegistry()
                    with self.assertRaises(ManifestError):
                        registry.bind(manifest)
                    self.assertIsNone(
                        registry.for_operation(manifest.operation_id))

    def test_issuance_snapshot_does_not_retain_manifest(self):
        import gc
        import uvm.engine.manifest as manifest_module

        manifest = self.build(*self.good_arguments())
        key = id(manifest)
        reference = weakref.ref(manifest)
        self.assertIn(key, manifest_module._BUILT_MANIFEST_PROVENANCE)
        del manifest
        gc.collect()
        self.assertIsNone(reference())
        self.assertNotIn(key, manifest_module._BUILT_MANIFEST_PROVENANCE)

    def test_registry_rejects_mutated_duplicate_bind(self):
        manifest = self.build(*self.good_arguments())
        registry = ManifestBindingRegistry()
        self.assertEqual(registry.bind(manifest).outcome, "bound")
        object.__setattr__(manifest.inventory_seal, "schema_version", 2)
        with self.assertRaises(ManifestError):
            registry.bind(manifest)

    def test_registry_rejects_added_dto_attribute(self):
        manifest = self.build(*self.good_arguments())
        object.__setattr__(manifest.payload_records[0], "extra", "value")
        registry = ManifestBindingRegistry()
        with self.assertRaises(ManifestError):
            registry.bind(manifest)
        self.assertIsNone(registry.for_operation(manifest.operation_id))


class Reviewer676b37dfRepairTests(unittest.TestCase):
    """Failing-first regressions for Reviewer 676b37df's five findings.

    (1) conflict holders MUST be blocked; (2) caller-supplied
    control_metadata / rule / actor text cannot authorise exclusion;
    (3) no trusted completeness/currency claim (``run_complete`` removed);
    (4) operation carries only source_run_id, no account binding;
    (5) unknown payload observation raises ManifestError, not
    StopIteration.
    """

    def conflict_holder_args(self):
        """r1 created / candidate positive (included), r2 retained CONFLICT
        holder with a supplied matched resolution, r3 created / unknown."""
        r1 = make_row(make_obs(1), 1)
        r2 = make_row(make_obs(2), 2, outcome="conflict")
        r3 = make_row(make_obs(3), 3)
        retained = RetainedRun(ACCOUNT, RUN, (r1, r2, r3))
        seal = make_seal(conflict_holder_count=1)
        res1 = make_resolution(r1.observation.observation_id)
        res2 = make_resolution(r2.observation.observation_id)
        return retained, seal, res1, res2, (r1, r2, r3)

    def good_build(self, *, dispositions=None, payload_records=None,
                   row_kinds=None, resolutions=None, operation=None,
                   retained=None, seal=None):
        (retained_g, seal_g, resolutions_g, dispositions_g,
         payload_records_g, row_kinds_g, operation_g) = \
            ManifestContractTests().good_arguments()
        return build_occurrence_manifest(
            operation=operation or operation_g,
            retained=retained or retained_g,
            seal=seal or seal_g,
            resolutions=resolutions if resolutions is not None
            else resolutions_g,
            dispositions=dispositions or dispositions_g,
            payload_records=payload_records or payload_records_g,
            row_kinds=row_kinds if row_kinds is not None else row_kinds_g,
        )

    # -- (1) conflict holders must be blocked -------------------------------

    def test_conflict_holder_included_even_with_matched_resolution_rejected(self):
        retained, seal, res1, res2, (r1, r2, r3) = \
            self.conflict_holder_args()
        with self.assertRaises(ManifestError) as ctx:
            build_occurrence_manifest(
                operation=make_operation(),
                retained=retained,
                seal=seal,
                resolutions={r1.observation.observation_id: (res1,),
                             r2.observation.observation_id: (res2,)},
                dispositions=(included_disposition(r1, res1),
                              included_disposition(r2, res2),
                              blocked_disposition(r3)),
                payload_records=(PayloadRecordV1(
                    1, "rec-1", (r1.observation.observation_id,)),
                    PayloadRecordV1(
                        1, "rec-2", (r2.observation.observation_id,))),
                row_kinds={r1.observation.observation_id:
                          ROW_KIND_CANDIDATE_POSITIVE,
                          r2.observation.observation_id:
                          ROW_KIND_CANDIDATE_POSITIVE},
            )
        self.assertIn("conflict", str(ctx.exception))

    def test_conflict_holder_excluded_rejected(self):
        retained, seal, res1, res2, (r1, r2, r3) = \
            self.conflict_holder_args()
        with self.assertRaises(ManifestError) as ctx:
            build_occurrence_manifest(
                operation=make_operation(),
                retained=retained,
                seal=seal,
                resolutions={r1.observation.observation_id: (res1,)},
                dispositions=(included_disposition(r1, res1),
                              excluded_disposition(r2),
                              blocked_disposition(r3)),
                payload_records=(PayloadRecordV1(
                    1, "rec-1", (r1.observation.observation_id,)),),
                row_kinds={r1.observation.observation_id:
                          ROW_KIND_CANDIDATE_POSITIVE,
                          r2.observation.observation_id:
                          ROW_KIND_CONTROL_METADATA},
            )
        self.assertIn("blocked", str(ctx.exception))

    # -- (2) exclusion unapproved without a trusted service -----------------

    def test_excluded_reviewed_unapproved_without_trusted_service(self):
        """Caller-supplied control_metadata kind, rule ID/evidence and actor
        text cannot authorise an exclusion: rejected, row stays blocked."""
        (retained, seal, resolutions, _, payload_records, row_kinds,
         operation) = ManifestContractTests().good_arguments()
        r2 = retained.rows[1]
        with self.assertRaises(ManifestError) as ctx:
            build_occurrence_manifest(
                operation=operation,
                retained=retained,
                seal=seal,
                resolutions=resolutions,
                dispositions=(included_disposition(
                    retained.rows[0],
                    next(iter(resolutions.values()))[0]),
                    excluded_disposition(r2),
                    blocked_disposition(retained.rows[2])),
                payload_records=payload_records,
                row_kinds=row_kinds,
            )
        message = str(ctx.exception)
        self.assertIn("unapproved", message)
        self.assertIn("trusted", message)

    # -- (3) no trusted completeness/currency claim --------------------------

    def test_manifest_carries_no_completeness_or_currency_claim(self):
        """The caller-created seal and supplied (possibly truncated)
        RetainedRun cannot prove full inventory or the current head:
        ``run_complete`` is gone and both statuses are explicit
        ``unverified``."""
        manifest = self.good_build()
        self.assertNotIn("run_complete", manifest.__dataclass_fields__)
        self.assertEqual(manifest.run_completeness_status, "unverified")
        self.assertEqual(manifest.run_currency_status, "unverified")

    # -- (4) operation carries only source_run_id ----------------------------

    def test_operation_run_mismatch_names_unverified_account_binding(self):
        """The mismatch refusal names source_run_id and marks the
        operation-account binding unverified (never claimed)."""
        (retained, seal, resolutions, dispositions, payload_records,
         row_kinds, _) = ManifestContractTests().good_arguments()
        with self.assertRaises(ManifestError) as ctx:
            build_occurrence_manifest(
                operation=make_operation(run="run-8"),
                retained=retained, seal=seal, resolutions=resolutions,
                dispositions=dispositions,
                payload_records=payload_records, row_kinds=row_kinds,
            )
        message = str(ctx.exception)
        self.assertIn("source_run_id", message)
        self.assertIn("unverified", message)

    def test_operation_context_key_not_parsed_as_account_evidence(self):
        """A foreign account label inside the free-form context_key is not
        parsed as account proof: the manifest records the seal/account scope
        of the supplied snapshot and carries the context key verbatim."""
        (retained, seal, resolutions, dispositions, payload_records,
         row_kinds, _) = ManifestContractTests().good_arguments()
        foreign_op = make_operation(context_key="prod:acct-9/eng-prod/test-x")
        manifest = build_occurrence_manifest(
            operation=foreign_op,
            retained=retained, seal=seal, resolutions=resolutions,
            dispositions=dispositions,
            payload_records=payload_records, row_kinds=row_kinds,
        )
        self.assertEqual(manifest.source_account_id, ACCOUNT)
        self.assertEqual(manifest.context_key, foreign_op.context_key)
        self.assertEqual(manifest.run_completeness_status, "unverified")
        self.assertEqual(manifest.run_currency_status, "unverified")

    # -- (5) unknown payload observation -------------------------------------

    def test_unknown_payload_observation_raises_manifest_error(self):
        (retained, seal, resolutions, dispositions, payload_records,
         row_kinds, operation) = ManifestContractTests().good_arguments()
        foreign = PayloadRecordV1(1, "rec-1", (str(uuid.uuid4()),))
        with self.assertRaises(ManifestError) as ctx:
            build_occurrence_manifest(
                operation=operation,
                retained=retained, seal=seal, resolutions=resolutions,
                dispositions=dispositions, payload_records=(foreign,),
                row_kinds=row_kinds,
            )
        self.assertIn("not a retained row", str(ctx.exception))

    # -- retained boundaries --------------------------------------------------

    def test_payload_membership_pending_and_run_coverage_none(self):
        manifest = self.good_build()
        self.assertEqual(manifest.payload_membership_status,
                         PAYLOAD_MEMBERSHIP_PENDING)
        self.assertEqual(manifest.run_coverage_status, RUN_COVERAGE_NONE)


class Reviewer425c829dRepairTests(unittest.TestCase):
    """Failing-first regressions for Reviewer 425c829d's two bypasses.

    (1) The payload_records iterable is materialised exactly once before
    the type check and mapping validation: generator and tuple input
    containing a blocked/unknown-row mapping or an unknown payload
    observation ID are rejected identically; (2) the binding registry
    accepts only builder-issued manifests, so a directly constructed
    ``OccurrenceManifestV1`` that bypasses the builder row checks (e.g.
    an unapproved ``excluded_reviewed`` exclusion) cannot be bound.
    """

    def all_blocked_args(self):
        """Three retained rows, all dispositions blocked; the supplied
        payload record maps to a blocked row."""
        r1 = make_row(make_obs(1), 1)
        r2 = make_row(make_obs(2), 2)
        r3 = make_row(make_obs(3), 3)
        retained = RetainedRun(ACCOUNT, RUN, (r1, r2, r3))
        seal = make_seal()
        dispositions = (
            blocked_disposition(r1, "unresolved identity"),
            blocked_disposition(r2, "control metadata; exclusion "
                                    "unapproved in this slice"),
            blocked_disposition(r3),
        )
        row_kinds = {
            r1.observation.observation_id: ROW_KIND_CANDIDATE_POSITIVE,
            r2.observation.observation_id: ROW_KIND_CONTROL_METADATA,
        }
        record = PayloadRecordV1(1, "rec-1",
                                 (r1.observation.observation_id,))
        return retained, seal, dispositions, row_kinds, record

    # -- (1) payload_records materialised exactly once ---------------------

    def test_payload_record_generator_rejected_like_tuple(self):
        """A generator whose record maps to a blocked row must hit the
        same 'included rows only' rejection as tuple input, not silently
        collapse to an empty (consumed) payload mapping."""
        retained, seal, dispositions, row_kinds, record = \
            self.all_blocked_args()
        with self.assertRaises(ManifestError) as ctx:
            build_occurrence_manifest(
                operation=make_operation(), retained=retained, seal=seal,
                resolutions={}, dispositions=dispositions,
                payload_records=(record,), row_kinds=row_kinds)
        self.assertIn("included rows only", str(ctx.exception))
        with self.assertRaises(ManifestError) as ctx:
            build_occurrence_manifest(
                operation=make_operation(), retained=retained, seal=seal,
                resolutions={}, dispositions=dispositions,
                payload_records=iter((record,)), row_kinds=row_kinds)
        self.assertIn("included rows only", str(ctx.exception))

    def test_unknown_payload_observation_generator_rejected_like_tuple(self):
        """A generator of payload records naming an observation outside
        the sealed run raises ManifestError, identically to tuple input."""
        (retained, seal, resolutions, dispositions, payload_records,
         row_kinds, operation) = ManifestContractTests().good_arguments()
        foreign = PayloadRecordV1(1, "rec-1", (str(uuid.uuid4()),))
        with self.assertRaises(ManifestError) as ctx:
            build_occurrence_manifest(
                operation=operation, retained=retained, seal=seal,
                resolutions=resolutions, dispositions=dispositions,
                payload_records=iter((foreign,)), row_kinds=row_kinds)
        self.assertIn("not a retained row", str(ctx.exception))

    def test_payload_record_generator_accepted_identically(self):
        """Exactly-once materialisation: generator input of valid records
        builds the same immutable manifest as tuple input."""
        (retained, seal, resolutions, dispositions, payload_records,
         row_kinds, operation) = ManifestContractTests().good_arguments()
        manifest = build_occurrence_manifest(
            operation=operation, retained=retained, seal=seal,
            resolutions=resolutions, dispositions=dispositions,
            payload_records=payload_records, row_kinds=row_kinds)
        again = build_occurrence_manifest(
            operation=operation, retained=retained, seal=seal,
            resolutions=resolutions, dispositions=dispositions,
            payload_records=iter(payload_records), row_kinds=row_kinds)
        self.assertEqual(again.manifest_id, manifest.manifest_id)
        self.assertEqual(again.manifest_sha256, manifest.manifest_sha256)
        self.assertEqual(again.payload_records, payload_records)

    # -- (2) registry binds only builder-issued manifests -------------------

    def test_registry_rejects_directly_constructed_manifest(self):
        """A field-identical ``replace()`` copy passes the post-init
        content digest check but was not built by the approved builder:
        it bypasses the builder row checks and cannot be bound."""
        from dataclasses import replace
        (retained, seal, resolutions, dispositions, payload_records,
         row_kinds, operation) = ManifestContractTests().good_arguments()
        manifest = build_occurrence_manifest(
            operation=operation, retained=retained, seal=seal,
            resolutions=resolutions, dispositions=dispositions,
            payload_records=payload_records, row_kinds=row_kinds)
        forged = replace(manifest)
        self.assertIsNot(forged, manifest)
        registry = ManifestBindingRegistry()
        with self.assertRaises(ManifestError) as ctx:
            registry.bind(forged)
        self.assertIn("build_occurrence_manifest", str(ctx.exception))
        # The builder-issued original still binds normally.
        self.assertEqual(registry.bind(manifest).outcome, "bound")

    def test_registry_rejects_direct_manifest_with_unapproved_exclusion(self):
        """A directly constructed manifest carrying a validly-shaped but
        unapproved excluded_reviewed disposition (builder row checks
        bypassed) passes its content digest check yet cannot be bound."""
        import uvm.engine.manifest as manifest_module
        r2 = make_row(make_obs(2), 2)
        seal = make_seal(retained_row_count=1, retention_high_watermark=1)
        operation = make_operation()
        unapproved = (excluded_disposition(r2),)
        digest, manifest_id = manifest_module._content_digest(
            operation.operation_id, operation.context_key,
            operation.bound_test_id, FAMILY, ACCOUNT, RUN,
            operation.payload_sha256, seal, unapproved, ())
        forged = OccurrenceManifestV1(
            1, manifest_id, digest, operation.operation_id,
            operation.context_key, operation.bound_test_id, FAMILY,
            ACCOUNT, RUN, operation.payload_sha256, seal, unapproved, ())
        registry = ManifestBindingRegistry()
        with self.assertRaises(ManifestError) as ctx:
            registry.bind(forged)
        self.assertIn("build_occurrence_manifest", str(ctx.exception))


class Reviewer90195466RepairTests(unittest.TestCase):
    """Failing-first regressions for Reviewer 90195466: the module-private
    issuance ledger must track builder-issued manifests by object identity,
    so two independently built, equal-but-distinct manifests both bind,
    while direct construction / copy / pickle of a manifest are still
    refused by the registry.
    """

    def _good_args(self):
        return ManifestContractTests().good_arguments()

    def _build(self, args):
        (retained, seal, resolutions, dispositions, payload_records,
         row_kinds, operation) = args
        return build_occurrence_manifest(
            operation=operation, retained=retained, seal=seal,
            resolutions=resolutions, dispositions=dispositions,
            payload_records=payload_records, row_kinds=row_kinds)

    def test_two_independent_equal_builder_manifests_both_bind(self):
        """Two independent builder calls over identical content produce
        two distinct objects that compare equal (field-based __eq__).
        Both are legitimate builder-issued manifests and both must bind:
        the old field-hash WeakSet collapsed the second into the first's
        identity and the registry rejected it."""
        args = self._good_args()
        m1 = self._build(args)
        m2 = self._build(args)
        self.assertIsNot(m1, m2)
        self.assertEqual(m1, m2)
        self.assertEqual(m1.manifest_id, m2.manifest_id)
        # Bind each to its own registry (a single registry would treat the
        # second as a harmless identical duplicate under one operation ID).
        self.assertEqual(ManifestBindingRegistry().bind(m1).outcome, "bound")
        self.assertEqual(ManifestBindingRegistry().bind(m2).outcome, "bound")

    def test_repeated_build_each_distinct_and_bindable(self):
        """Repeated builder calls keep tracking every distinct issued
        object; none are lost to identity collapse."""
        import uvm.engine.manifest as manifest_module
        args = self._good_args()
        built = [self._build(args) for _ in range(4)]
        self.assertEqual(len({id(m) for m in built}), 4)
        self.assertEqual(len({id(m) for m in built}),
                         len({id(m) for m in built
                              if any(b is m
                                     for b in manifest_module
                                     ._BUILT_MANIFESTS.values())}))
        for m in built:
            self.assertEqual(ManifestBindingRegistry().bind(m).outcome,
                             "bound")

    def test_gc_collects_dropped_ledger_entry(self):
        """The ledger is weakly tracked: dropping the only strong reference
        to a builder-issued manifest and collecting removes its entry, so
        a later (fresh) equal object is not mistaken for a still-live
        issued one and the ledger does not leak."""
        import gc
        import uvm.engine.manifest as manifest_module
        args = self._good_args()
        m1 = self._build(args)
        self.assertTrue(any(b is m1
                            for b in manifest_module
                            ._BUILT_MANIFESTS.values()))
        del m1
        gc.collect()
        # A fresh build must still be recognised as builder-issued.
        m2 = self._build(args)
        self.assertTrue(any(b is m2
                            for b in manifest_module
                            ._BUILT_MANIFESTS.values()))
        self.assertEqual(ManifestBindingRegistry().bind(m2).outcome, "bound")

    def test_direct_construction_copy_and_pickle_still_rejected(self):
        """The identity-keyed ledger must not widen the bypass: a
        field-identical copy or an unpickled manifest that was not built
        by build_occurrence_manifest still cannot be bound."""
        import pickle
        from dataclasses import replace
        args = self._good_args()
        original = self._build(args)
        registry = ManifestBindingRegistry()
        # replace() copy: distinct object, passes the digest check.
        with self.assertRaises(ManifestError):
            registry.bind(replace(original))
        # pickle round-trip: a new object, not the builder-issued one.
        revived = pickle.loads(pickle.dumps(original))
        self.assertIsNot(revived, original)
        self.assertEqual(revived, original)
        with self.assertRaises(ManifestError):
            registry.bind(revived)
        # The builder-issued original still binds.
        self.assertEqual(registry.bind(original).outcome, "bound")


if __name__ == "__main__":
    unittest.main()
