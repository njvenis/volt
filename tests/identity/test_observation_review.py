"""Regression tests for G1 identity-review finding #5 (CR-04) and
independent re-review findings (CR-04 observation identity correctness).

- Duplicate ingest returns the stored observation ID, not the incoming one.
- Same (account, run, ordinal, raw digest) with a changed parsed source row
  is retained as ``conflict``, never silently deduplicated.
- A conflict (changed row or conflicting bytes) blocks
  ``successful_cohort`` for the run.
- A genuine duplicate stays idempotent and does not affect the cohort.
- A different incoming observation UUID alone is NOT a parsed-row change.
- A reused observation_id at a different source position is an explicit
  conflict; the second holder is retained under a distinct surrogate
  identity so every retained ID resolves unambiguously, and the reuse is
  quarantined with the attempted ID and both source positions.
- Retrying a retained changed-row conflict under a new incoming ID returns
  the actually stored conflict ID, never an unstored one.
Synthetic fixtures only; every synthetic ID is a UVM UUID per the approved
G1 Version 1 shared contracts.
"""

import dataclasses
import unittest
import uuid

from uvm.identity import ObservationStore
from uvm.identity.observations import QuarantinedIdReuse

from fixtures import make_observation, synthetic_id

SHARED = synthetic_id("obs-shared")
STORED = synthetic_id("obs-stored")
RESENT = synthetic_id("obs-resent")
CONFLICT_1 = synthetic_id("obs-conflict-1")
CONFLICT_2 = synthetic_id("obs-conflict-2")
RETRY_Z = synthetic_id("obs-retry-z")


class DuplicateStoredIdentityTest(unittest.TestCase):
    def test_duplicate_ingest_returns_stored_observation_id(self):
        store = ObservationStore()
        first = make_observation(observation_id=STORED)
        self.assertEqual(store.ingest(first).status, "created")
        # Same account/run/ordinal and raw digest, only the incoming UUID
        # differs: this is a genuine duplicate, not a parsed-row change.
        resent = dataclasses.replace(first, observation_id=RESENT)
        result = store.ingest(resent)
        self.assertEqual(result.status, "duplicate")
        self.assertEqual(result.observation_id, STORED)
        self.assertEqual(len(store.observations), 1)

    def test_genuine_duplicate_is_idempotent_and_keeps_cohort(self):
        store = ObservationStore()
        first = make_observation()
        store.ingest(first)
        for _ in range(3):
            result = store.ingest(first)  # identical row, identical digest
            self.assertEqual(result.status, "duplicate")
            self.assertEqual(result.observation_id, first.observation_id)
        self.assertEqual(len(store.observations), 1)
        self.assertTrue(store.successful_cohort("acc-1", "run-1"))


class ChangedRowConflictTest(unittest.TestCase):
    def test_same_digest_changed_parsed_row_is_conflict(self):
        store = ObservationStore()
        first = make_observation(raw_bytes="payload")
        # Identical position and identical raw digest, but the parsed
        # source_rating field changed.
        store.ingest(first)
        changed = dataclasses.replace(first, source_rating="High")
        self.assertEqual(changed.raw_evidence_sha256, first.raw_evidence_sha256)
        result = store.ingest(changed)
        self.assertEqual(result.status, "conflict")
        self.assertEqual(result.conflict_with, first.observation_id)
        # Both retained; never silently deduplicated.
        self.assertEqual(len(store.observations), 2)
        self.assertEqual(
            {o.source_rating for o in store.observations},
            {None, "High"},
        )

    def test_changed_row_conflict_blocks_successful_cohort(self):
        store = ObservationStore()
        first = make_observation(raw_bytes="payload")
        store.ingest(first)
        self.assertTrue(store.successful_cohort("acc-1", "run-1"))
        store.ingest(dataclasses.replace(first, source_rating="High"))
        self.assertFalse(store.successful_cohort("acc-1", "run-1"))

    def test_conflicting_bytes_also_blocks_successful_cohort(self):
        store = ObservationStore()
        first = make_observation(raw_bytes="v1")
        changed = make_observation(raw_bytes="v2")
        store.ingest(first)
        result = store.ingest(changed)
        self.assertEqual(result.status, "conflict")
        self.assertFalse(store.successful_cohort("acc-1", "run-1"))

    def test_conflict_in_one_run_does_not_block_another_run(self):
        store = ObservationStore()
        first = make_observation(raw_bytes="payload")
        store.ingest(first)
        store.ingest(dataclasses.replace(first, source_rating="High"))
        other = make_observation(run_id="run-2", raw_bytes="other")
        store.ingest(other)
        self.assertFalse(store.successful_cohort("acc-1", "run-1"))
        self.assertTrue(store.successful_cohort("acc-1", "run-2"))


class ReusedObservationIdTest(unittest.TestCase):
    def test_same_id_at_different_position_is_explicit_conflict(self):
        store = ObservationStore()
        first = make_observation(observation_id=SHARED)
        self.assertEqual(store.ingest(first).status, "created")
        # Same observation_id, different source position (ordinal 2):
        # identity reuse must be an explicit conflict, both retained.
        second = make_observation(
            observation_id=SHARED, source_record_ordinal=2
        )
        result = store.ingest(second)
        self.assertEqual(result.status, "conflict")
        self.assertEqual(result.conflict_with, SHARED)
        # Nothing lost: both rows retained, cohort blocked; the second
        # holder is retained under a distinct surrogate identity.
        self.assertEqual(len(store.observations), 2)
        self.assertNotEqual(result.observation_id, SHARED)
        self.assertFalse(store.successful_cohort("acc-1", "run-1"))
        # get() resolves each retained identity unambiguously.
        self.assertIs(store.get(SHARED), first)
        self.assertIsNotNone(store.get(result.observation_id))

    def test_reused_id_conflict_does_not_block_other_run(self):
        store = ObservationStore()
        first = make_observation(observation_id=SHARED)
        store.ingest(first)
        store.ingest(make_observation(observation_id=SHARED,
                                      source_record_ordinal=2))
        other = make_observation(run_id="run-2", raw_bytes="other")
        store.ingest(other)
        self.assertFalse(store.successful_cohort("acc-1", "run-1"))
        self.assertTrue(store.successful_cohort("acc-1", "run-2"))


class RepeatedConflictRetryTest(unittest.TestCase):
    def test_changed_row_conflict_retry_returns_stored_conflict_id(self):
        store = ObservationStore()
        first = make_observation(raw_bytes="payload")
        store.ingest(first)
        changed = dataclasses.replace(
            first, source_rating="High", observation_id=CONFLICT_1
        )
        result = store.ingest(changed)
        self.assertEqual(result.status, "conflict")
        self.assertEqual(result.observation_id, CONFLICT_1)
        self.assertEqual(result.conflict_with, first.observation_id)
        # Retry of the already retained conflict under a new incoming ID:
        # must return the actually stored ID, not the unstored one.
        retry = dataclasses.replace(changed, observation_id=CONFLICT_2)
        result2 = store.ingest(retry)
        self.assertEqual(result2.status, "conflict")
        self.assertEqual(result2.observation_id, CONFLICT_1)
        self.assertEqual(result2.conflict_with, first.observation_id)
        self.assertIsNotNone(store.get(CONFLICT_1))
        self.assertIsNone(store.get(CONFLICT_2))
        # No duplicate retention of the same conflict row.
        self.assertEqual(len(store.observations), 2)

    def test_changed_row_conflict_retry_same_id_is_stable(self):
        store = ObservationStore()
        first = make_observation(raw_bytes="payload")
        store.ingest(first)
        changed = dataclasses.replace(
            first, source_rating="High", observation_id=CONFLICT_1
        )
        for _ in range(2):
            result = store.ingest(changed)
            self.assertEqual(result.status, "conflict")
            self.assertEqual(result.observation_id, CONFLICT_1)
            self.assertEqual(result.conflict_with, first.observation_id)
        self.assertEqual(len(store.observations), 2)


class UniqueRetainedIdRegressionTest(unittest.TestCase):
    """CR-04 regression: a reused observation_id must never be retained
    twice. The second holder is retained under a distinct retained identity
    (surrogate) so every retained ID resolves unambiguously; the attempted
    reused ID and both source positions stay durably linked in the
    quarantine record; the conflict holder stays non-actionable; and
    retries at the same position+digest+parsed row are stable.
    """

    def test_reused_id_retained_under_distinct_id(self):
        store = ObservationStore()
        first = make_observation(observation_id=SHARED)
        self.assertEqual(store.ingest(first).status, "created")
        second = make_observation(
            observation_id=SHARED, source_record_ordinal=2
        )
        result = store.ingest(second)
        self.assertEqual(result.status, "conflict")
        # Retained IDs are unique: exactly one row keeps the reused ID.
        holders = [o for o in store.observations if o.observation_id == SHARED]
        self.assertIs(holders[0], first)
        self.assertEqual(len(holders), 1)
        self.assertEqual(
            len({o.observation_id for o in store.observations}),
            len(store.observations),
        )
        surrogate = result.observation_id
        self.assertNotEqual(surrogate, SHARED)
        # The second holder's evidence is retained intact; only its
        # identity is substituted.
        self.assertEqual(
            store.get(surrogate),
            dataclasses.replace(second, observation_id=surrogate),
        )
        # get() resolves each distinct retained identity unambiguously.
        self.assertIs(store.get(SHARED), first)
        self.assertIsNotNone(store.get(surrogate))
        # Durable quarantine link: attempted ID and both source positions.
        self.assertEqual(len(store.quarantine), 1)
        record = store.quarantine[0]
        self.assertIsInstance(record, QuarantinedIdReuse)
        self.assertEqual(record.attempted_id, SHARED)
        self.assertEqual(
            record.positions,
            (("acc-1", "run-1", 1), ("acc-1", "run-1", 2)),
        )
        self.assertEqual(record.retained_ids, (SHARED, surrogate))
        # Non-actionable until corrected: the run is not a successful cohort.
        self.assertFalse(store.successful_cohort("acc-1", "run-1"))

    def test_reused_id_retry_under_any_incoming_id_is_stable(self):
        store = ObservationStore()
        first = make_observation(observation_id=SHARED)
        store.ingest(first)
        second = make_observation(
            observation_id=SHARED, source_record_ordinal=2
        )
        surrogate = store.ingest(second).observation_id
        for incoming_id in (
            synthetic_id("obs-retry-a"),
            synthetic_id("obs-retry-b"),
            SHARED,
        ):
            result = store.ingest(
                dataclasses.replace(second, observation_id=incoming_id)
            )
            self.assertEqual(result.status, "conflict")
            self.assertEqual(result.observation_id, surrogate)
            self.assertEqual(len(store.observations), 2)
            self.assertEqual(len(store.quarantine), 1)
        self.assertIs(store.get(SHARED), first)
        self.assertIsNotNone(store.get(surrogate))


class ReusedIdFreshIdRetryTest(unittest.TestCase):
    """CR-04: a retained reused-ID conflict must be indexed by
    position+digest so an identical retry under a fresh incoming ID is an
    idempotent conflict, never a ``created`` third row. The reuse itself is
    recorded as an explicit quarantine so one observation_id never silently
    identifies two retained rows.
    """

    def test_reused_id_retry_under_fresh_id_is_conflict_not_created(self):
        store = ObservationStore()
        first = make_observation(observation_id=SHARED)
        self.assertEqual(store.ingest(first).status, "created")
        second = make_observation(
            observation_id=SHARED, source_record_ordinal=2
        )
        result = store.ingest(second)
        self.assertEqual(result.status, "conflict")
        self.assertEqual(result.conflict_with, SHARED)
        self.assertEqual(len(store.observations), 2)
        surrogate = result.observation_id
        self.assertNotEqual(surrogate, SHARED)
        # Identical retry of the retained conflict under a fresh incoming
        # ID: idempotent conflict returning the stored surrogate identity,
        # no third row, fresh ID never resolves.
        retry = dataclasses.replace(second, observation_id=synthetic_id("obs-retry"))
        result2 = store.ingest(retry)
        self.assertEqual(result2.status, "conflict")
        self.assertEqual(result2.observation_id, surrogate)
        self.assertEqual(len(store.observations), 2)
        self.assertIs(store.get(SHARED), first)
        self.assertIsNotNone(store.get(surrogate))
        self.assertIsNone(store.get(retry.observation_id))
        self.assertFalse(store.successful_cohort("acc-1", "run-1"))
        # Explicit quarantine record for the reused ID: the attempted ID
        # and both positions are honestly linked to the distinct identity
        # each holder is retained under (first holder keeps the ID).
        self.assertEqual(len(store.quarantine), 1)
        record = store.quarantine[0]
        self.assertIsInstance(record, QuarantinedIdReuse)
        self.assertEqual(record.attempted_id, SHARED)
        self.assertEqual(
            record.positions,
            (("acc-1", "run-1", 1), ("acc-1", "run-1", 2)),
        )
        self.assertEqual(record.retained_ids, (SHARED, surrogate))

    def test_reused_id_retry_is_stable_across_repeats(self):
        store = ObservationStore()
        first = make_observation(observation_id=SHARED)
        store.ingest(first)
        second = make_observation(
            observation_id=SHARED, source_record_ordinal=2
        )
        surrogate = store.ingest(second).observation_id
        for incoming_id in (
            synthetic_id("obs-retry-1"),
            synthetic_id("obs-retry-2"),
            SHARED,
        ):
            result = store.ingest(
                dataclasses.replace(second, observation_id=incoming_id)
            )
            self.assertEqual(result.status, "conflict")
            self.assertEqual(result.observation_id, surrogate)
            self.assertEqual(len(store.observations), 2)
            self.assertEqual(len(store.quarantine), 1)
        self.assertIs(store.get(SHARED), first)
        self.assertIsNotNone(store.get(surrogate))


class ReusedIdFreshRetryConflictPeerTest(unittest.TestCase):
    """CR-04 (reviewer 667e863f): a genuine reused-ID conflict resent under
    a fresh incoming ID returns the stored surrogate as ``observation_id``;
    ``conflict_with`` must name the original ID holder, not the surrogate
    itself. Unique rows, deterministic surrogate, quarantine and cohort
    behavior are preserved.
    """

    def test_fresh_retry_conflict_with_names_original_id_holder(self):
        store = ObservationStore()
        first = make_observation(observation_id=SHARED)
        self.assertEqual(store.ingest(first).status, "created")
        second = make_observation(
            observation_id=SHARED, source_record_ordinal=2
        )
        surrogate = store.ingest(second).observation_id
        self.assertNotEqual(surrogate, SHARED)
        retry = dataclasses.replace(
            second, observation_id=synthetic_id("obs-fresh-peer")
        )
        result = store.ingest(retry)
        self.assertEqual(result.status, "conflict")
        self.assertEqual(result.observation_id, surrogate)
        # The conflict peer is the original ID holder, not the surrogate
        # the holder is retained under.
        self.assertEqual(result.conflict_with, SHARED)
        # Preserved behavior: unique rows, no added quarantine, blocked
        # cohort, deterministic identities still resolve.
        self.assertEqual(len(store.observations), 2)
        self.assertEqual(len(store.quarantine), 1)
        self.assertIs(store.get(SHARED), first)
        self.assertIsNotNone(store.get(surrogate))
        self.assertIsNone(store.get(retry.observation_id))
        self.assertFalse(store.successful_cohort("acc-1", "run-1"))


class QuarantinedRetainedIdUuidTest(unittest.TestCase):
    """CR-04 contract correction: the approved G1 Version 1 shared
    contracts state every UVM ID is an immutable UUID. The quarantined
    second holder's retained ID must therefore be a deterministic UUID
    (v5 over the full source-position/digest/attempted-ID key), not a
    prefix-tagged digest; retries stay idempotent; retained IDs stay
    unique; and a candidate that collides with an existing retained ID
    is disambiguated explicitly before storing, never asserted
    collision-proof by its prefix.
    """

    def test_retained_surrogate_is_deterministic_uuid5(self):
        store = ObservationStore()
        first = make_observation(observation_id=SHARED)
        store.ingest(first)
        second = make_observation(
            observation_id=SHARED, source_record_ordinal=2
        )
        result = store.ingest(second)
        self.assertEqual(result.status, "conflict")
        surrogate = result.observation_id
        # The generated retained ID must satisfy uuid.UUID parsing and be
        # version 5 (the prefix-tagged surrogate no longer qualifies).
        parsed = uuid.UUID(surrogate)
        self.assertEqual(parsed.version, 5)
        self.assertNotEqual(surrogate, SHARED)
        self.assertIsNotNone(store.get(surrogate))
        self.assertIs(store.get(SHARED), first)

    def test_surrogate_is_deterministic_across_replay(self):
        def run() -> str:
            store = ObservationStore()
            store.ingest(make_observation(observation_id=SHARED))
            second = make_observation(
                observation_id=SHARED, source_record_ordinal=2
            )
            return store.ingest(second).observation_id

        self.assertEqual(run(), run())

    def test_surrogate_retry_idempotent_and_retained_ids_unique(self):
        store = ObservationStore()
        first = make_observation(observation_id=SHARED)
        store.ingest(first)
        second = make_observation(
            observation_id=SHARED, source_record_ordinal=2
        )
        surrogate = store.ingest(second).observation_id
        for incoming_id in (
            synthetic_id("obs-retry-x"),
            synthetic_id("obs-retry-y"),
            SHARED,
        ):
            result = store.ingest(
                dataclasses.replace(second, observation_id=incoming_id)
            )
            self.assertEqual(result.status, "conflict")
            self.assertEqual(result.observation_id, surrogate)
            self.assertEqual(len(store.observations), 2)
            self.assertEqual(len(store.quarantine), 1)
            self.assertEqual(
                len({o.observation_id for o in store.observations}),
                len(store.observations),
            )

    def test_existing_id_collision_disambiguated_before_storing(self):
        store = ObservationStore()
        first = make_observation(observation_id=SHARED)
        store.ingest(first)
        second = make_observation(
            observation_id=SHARED, source_record_ordinal=2
        )
        # A genuine retained row that happens to already hold exactly the
        # un-salted UUIDv5 candidate of the second holder: collision must
        # be handled explicitly before storing, not asserted away.
        candidate = ObservationStore._quarantined_id(
            SHARED, ("acc-1", "run-1", 2), second.raw_evidence_sha256
        )
        genuine = make_observation(
            observation_id=candidate, source_account_id="acc-2"
        )
        self.assertEqual(store.ingest(genuine).status, "created")
        result = store.ingest(second)
        self.assertEqual(result.status, "conflict")
        retained = result.observation_id
        self.assertNotEqual(retained, candidate)
        self.assertNotEqual(retained, SHARED)
        self.assertEqual(uuid.UUID(retained).version, 5)
        # Every retained identity still resolves unambiguously and stays
        # unique; the genuine row keeps its ID untouched.
        self.assertEqual(
            len({o.observation_id for o in store.observations}),
            len(store.observations),
        )
        self.assertIs(store.get(candidate), genuine)
        self.assertIs(store.get(SHARED), first)
        self.assertIsNotNone(store.get(retained))
        # A retry of the retained conflict returns the stored disambiguated
        # identity, never the candidate or a fresh third row.
        retry = dataclasses.replace(second, observation_id=RETRY_Z)
        retry_result = store.ingest(retry)
        self.assertEqual(retry_result.status, "conflict")
        self.assertEqual(retry_result.observation_id, retained)
        self.assertEqual(len(store.observations), 3)


class SurrogateRowPositionIndexTest(unittest.TestCase):
    """CR-04 edge (independent review fdebeff3): a reused-ID row retained
    under a UUIDv5 surrogate must keep source-position indexing; a later
    row with different raw bytes at that same position is an explicit
    conflict, never a ``created`` row, and retries stay duplicate-free.
    """

    def test_different_bytes_at_surrogate_position_is_conflict_not_created(self):
        store = ObservationStore()
        first = make_observation(observation_id=SHARED, raw_bytes="bytes-a")
        self.assertEqual(store.ingest(first).status, "created")
        second = make_observation(
            observation_id=SHARED, source_record_ordinal=2, raw_bytes="bytes-b"
        )
        result = store.ingest(second)
        self.assertEqual(result.status, "conflict")
        surrogate = result.observation_id
        # Later row at the surrogate holder's position with different raw
        # bytes: explicit conflict against the retained row at that
        # position, never a created row.
        third = make_observation(source_record_ordinal=2, raw_bytes="bytes-c")
        result3 = store.ingest(third)
        self.assertEqual(result3.status, "conflict")
        self.assertEqual(result3.conflict_with, surrogate)
        self.assertEqual(len(store.observations), 3)
        # Retry of the retained surrogate row under a fresh incoming ID is
        # a stable conflict; no fourth row, retained IDs stay unique.
        retry = dataclasses.replace(
            second, observation_id=synthetic_id("obs-pos-retry")
        )
        retry_result = store.ingest(retry)
        self.assertEqual(retry_result.status, "conflict")
        self.assertEqual(retry_result.observation_id, surrogate)
        self.assertEqual(len(store.observations), 3)
        self.assertEqual(
            len({o.observation_id for o in store.observations}),
            len(store.observations),
        )
        # The conflict at this position keeps blocking the cohort.
        self.assertFalse(store.successful_cohort("acc-1", "run-1"))


class SurrogateIdentityRetryTest(unittest.TestCase):
    def test_exact_retry_under_returned_surrogate_does_not_self_quarantine(self):
        store = ObservationStore()
        first = make_observation(observation_id=SHARED)
        store.ingest(first)
        second = make_observation(
            observation_id=SHARED, source_record_ordinal=2
        )
        surrogate = store.ingest(second).observation_id
        original_quarantine = tuple(store.quarantine)
        retry = dataclasses.replace(second, observation_id=surrogate)

        for _ in range(2):
            result = store.ingest(retry)
            self.assertEqual(result.status, "conflict")
            self.assertEqual(result.observation_id, surrogate)
            self.assertEqual(result.conflict_with, SHARED)
            self.assertEqual(len(store.observations), 2)
            self.assertEqual(tuple(store.quarantine), original_quarantine)
            self.assertIs(store.get(surrogate), store.observations[1])
            self.assertFalse(store.successful_cohort("acc-1", "run-1"))

    def test_exact_retry_of_same_position_surrogate_preserves_quarantine(self):
        store = ObservationStore()
        first = make_observation(observation_id=SHARED, raw_bytes="bytes-a")
        store.ingest(first)
        changed = make_observation(observation_id=SHARED, raw_bytes="bytes-b")
        surrogate = store.ingest(changed).observation_id
        original_quarantine = tuple(store.quarantine)

        result = store.ingest(dataclasses.replace(changed, observation_id=surrogate))
        # This path's existing idempotency rule reports an exact resend as
        # duplicate; it must still avoid inventing a second ID reuse.
        self.assertEqual(result.status, "duplicate")
        self.assertEqual(result.observation_id, surrogate)
        self.assertIsNone(result.conflict_with)
        self.assertEqual(len(store.observations), 2)
        self.assertEqual(tuple(store.quarantine), original_quarantine)
        self.assertFalse(store.successful_cohort("acc-1", "run-1"))


if __name__ == "__main__":
    unittest.main()
