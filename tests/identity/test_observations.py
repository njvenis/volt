"""Retained source observations: explicit nulls, idempotency, conflict,
cohort semantics (CR-02/CR-06 inputs). Synthetic fixtures only.
"""

import unittest
from datetime import datetime, timezone

from uvm.identity import (
    MissingField,
    MISSING_NOT_SUPPLIED,
    ObservationStore,
    SourceObservationV1,
)

from fixtures import T1, make_observation, synthetic_id

UTC = timezone.utc


class ObservationValidationTest(unittest.TestCase):
    def test_null_optional_without_reason_rejected(self):
        with self.assertRaises(ValueError):
            SourceObservationV1(
                schema_version=1,
                observation_id=synthetic_id("obs-x"),
                revision=1,
                source_family="qualys",
                source_account_id="acc-1",
                run_id="run-1",
                source_record_ordinal=1,
                collection_status="success",
                collected_at=T1,
                raw_evidence_ref="ref/1",
                raw_evidence_sha256="ab",
                observed_at=None,  # null without a missing_fields entry
            )

    def test_null_observed_at_with_reason_is_explicit(self):
        obs = make_observation(observed_at=None)
        self.assertIsNone(obs.observed_at)
        self.assertIn(MissingField("observed_at", MISSING_NOT_SUPPLIED), obs.missing_fields)

    def test_collection_time_is_not_observation_time(self):
        observed = datetime(2026, 9, 1, 8, 0, tzinfo=UTC)
        obs = make_observation(observed_at=observed, collected_at=T1)
        self.assertIsNot(obs.observed_at, obs.collected_at)
        self.assertLess(obs.observed_at, obs.collected_at)
        # No field silently substitutes one for the other.
        self.assertEqual(obs.observed_at, observed)

    def test_naive_timestamp_rejected(self):
        with self.assertRaises(ValueError):
            SourceObservationV1(
                schema_version=1,
                observation_id=synthetic_id("obs-x"),
                revision=1,
                source_family="qualys",
                source_account_id="acc-1",
                run_id="run-1",
                source_record_ordinal=1,
                collection_status="success",
                collected_at=datetime(2026, 9, 8, 8, 0),  # naive
                raw_evidence_ref="ref/1",
                raw_evidence_sha256="ab",
                missing_fields=(
                    MissingField("observed_at", MISSING_NOT_SUPPLIED),
                    MissingField("vulnerability_refs", MISSING_NOT_SUPPLIED),
                ),
                observed_at=None,
            )


class ObservationStoreTest(unittest.TestCase):
    def test_duplicate_row_is_idempotent(self):
        store = ObservationStore()
        obs = make_observation()
        self.assertEqual(store.ingest(obs).status, "created")
        result = store.ingest(obs)  # same (account, run, ordinal, sha)
        self.assertEqual(result.status, "duplicate")
        self.assertEqual(len(store.observations), 1)

    def test_conflicting_bytes_at_same_position_retained(self):
        store = ObservationStore()
        first = make_observation(raw_bytes="v1")
        changed = make_observation(source_rating="High", raw_bytes="v2")
        store.ingest(first)
        result = store.ingest(changed)
        self.assertEqual(result.status, "conflict")
        self.assertEqual(result.conflict_with, first.observation_id)
        # Both retained; never silently deduplicated.
        self.assertEqual(len(store.observations), 2)
        self.assertEqual(
            {o.raw_evidence_sha256 for o in store.observations},
            {first.raw_evidence_sha256, changed.raw_evidence_sha256},
        )

    def test_failed_or_partial_row_is_not_successful_cohort(self):
        store = ObservationStore()
        store.ingest(make_observation(collection_status="success"))
        self.assertTrue(store.successful_cohort("acc-1", "run-1"))
        store.ingest(
            make_observation(source_record_ordinal=2, collection_status="partial")
        )
        self.assertFalse(store.successful_cohort("acc-1", "run-1"))
        store.ingest(
            make_observation(run_id="run-x", collection_status="failed")
        )
        self.assertFalse(store.successful_cohort("acc-1", "run-x"))

    def test_empty_run_is_not_successful_cohort(self):
        store = ObservationStore()
        self.assertFalse(store.successful_cohort("acc-1", "run-none"))


if __name__ == "__main__":
    unittest.main()
