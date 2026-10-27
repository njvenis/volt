"""Reviewer fc3e96f7 defects (CR-02/03/04, FR-ID-01/02), synthetic fixtures.

1. Changed parsed-row and changed raw-byte conflict branches retain a
   duplicate observation_id when the incoming row reuses a retained ID.
2. Input observation IDs accept arbitrary strings and generated model IDs
   are prefix-tagged, contrary to the UUID contract in the approved G1
   Version 1 shared contracts.
3. Host-locator aliases were keyed without the workload, so one correction
   blocked the same locator under an unrelated workload.
"""

import dataclasses
import unittest
import uuid

from uvm.identity import (
    ObservationStore,
    IdentityState,
    RuleV1,
    resolve,
)

from fixtures import T1, T2, RULE, make_observation, synthetic_id


class UniqueConflictIdRegressionTest(unittest.TestCase):
    """Defect 1: every conflict path retains unique observation IDs."""

    def test_changed_parsed_row_same_id_retained_under_distinct_id(self):
        store = ObservationStore()
        first = make_observation(raw_bytes="payload",
                                 observation_id=synthetic_id("obs-payload"))
        self.assertEqual(store.ingest(first).status, "created")
        # Same position, same digest, changed parsed row AND the same
        # retained observation_id: both rows retained, IDs unique.
        changed = dataclasses.replace(first, source_rating="High")
        self.assertEqual(changed.observation_id, first.observation_id)
        result = store.ingest(changed)
        self.assertEqual(result.status, "conflict")
        self.assertEqual(result.conflict_with, first.observation_id)
        self.assertNotEqual(result.observation_id, first.observation_id)
        self.assertEqual(len(store.observations), 2)
        self.assertEqual(
            len({o.observation_id for o in store.observations}),
            len(store.observations),
        )
        self.assertIs(store.get(first.observation_id), first)
        self.assertIsNotNone(store.get(result.observation_id))
        # The reuse is durably linked: attempted ID and both retained IDs.
        self.assertEqual(len(store.quarantine), 1)
        self.assertEqual(store.quarantine[0].attempted_id, first.observation_id)
        self.assertIn(result.observation_id, store.quarantine[0].retained_ids)
        self.assertFalse(store.successful_cohort("acc-1", "run-1"))
        # Deterministic replay: the same collision derives the same surrogate.
        replay = ObservationStore()
        replay.ingest(first)
        self.assertEqual(
            replay.ingest(dataclasses.replace(first, source_rating="High")).observation_id,
            result.observation_id,
        )

    def test_conflicting_bytes_same_id_retained_under_distinct_id(self):
        store = ObservationStore()
        first = make_observation(raw_bytes="v1",
                                 observation_id=synthetic_id("obs-bytes"))
        self.assertEqual(store.ingest(first).status, "created")
        # Same position, different raw bytes, same retained observation_id.
        changed = make_observation(raw_bytes="v2", source_rating="High",
                                   observation_id=first.observation_id)
        result = store.ingest(changed)
        self.assertEqual(result.status, "conflict")
        self.assertEqual(result.conflict_with, first.observation_id)
        self.assertNotEqual(result.observation_id, first.observation_id)
        self.assertEqual(len(store.observations), 2)
        self.assertEqual(
            len({o.observation_id for o in store.observations}),
            len(store.observations),
        )
        self.assertIs(store.get(first.observation_id), first)
        self.assertIsNotNone(store.get(result.observation_id))
        # Retry of the retained conflict row is idempotent: the stored
        # conflict identity is reported, no third row, retained IDs stay
        # unique (same retry semantics as the fresh-ID raw-byte path).
        retry = store.ingest(changed)
        self.assertEqual(retry.status, "duplicate")
        self.assertEqual(retry.observation_id, result.observation_id)
        self.assertEqual(len(store.observations), 2)
        self.assertFalse(store.successful_cohort("acc-1", "run-1"))


class UuidIdentityContractTest(unittest.TestCase):
    """Defect 2: UVM identity records carry UUIDs, validated throughout."""

    def _obs(self, observation_id: str) -> "SourceObservationV1":
        # A fully valid record with only the observation ID substituted, so
        # any rejection can only come from the ID itself.
        return dataclasses.replace(make_observation(), observation_id=observation_id)

    def test_non_uuid_observation_id_rejected(self):
        with self.assertRaises(ValueError):
            self._obs("not-a-uuid")

    def test_non_canonical_uuid_observation_id_rejected(self):
        upper = uuid.UUID(synthetic_id("obs-upper")).__str__().upper()
        with self.assertRaises(ValueError):
            self._obs(upper)

    def test_resolution_record_rejects_non_uuid_ids(self):
        state = IdentityState()
        res = resolve(state, make_observation(), RULE, {"provisioning_key": "pk-1"}, T1)
        with self.assertRaises(ValueError):
            dataclasses.replace(res, resolution_id="not-a-uuid")
        with self.assertRaises(ValueError):
            dataclasses.replace(res, observation_id="not-a-uuid")

    def test_generated_model_ids_are_uuids(self):
        state = IdentityState()
        res = resolve(state, make_observation(), RULE, {"provisioning_key": "pk-1"}, T1)
        rec = state.record_correction("workload", res.workload_id, "pk-1", "pk-2",
                                      "actor", "renamed", "corr-uuid", (), T2)
        for value in (
            state.groups[res.group_id].group_id,
            state.workloads[res.workload_id].workload_id,
            state.incarnations[res.incarnation_id].incarnation_id,
            res.exposure_id,
            res.occurrence_id,
            res.resolution_id,
            rec.correction_id,
            make_observation().observation_id,
        ):
            self.assertEqual(str(uuid.UUID(value)), value,
                             f"{value!r} is not a canonical UVM UUID")


class HostLocatorAliasScopeTest(unittest.TestCase):
    """Defect 3: a corrected host locator is historical only for the
    workload that owned it; the same locator under an unrelated workload
    is not blocked."""

    def test_host_locator_alias_is_scoped_to_its_workload(self):
        state = IdentityState()
        first = resolve(state, make_observation(native_id_value="101",
                                                asset_locator="host-a"),
                        RULE, {"provisioning_key": "pk-1"}, T1)
        other = resolve(state, make_observation(native_id_value="202",
                                                asset_locator="host-b",
                                                source_record_ordinal=2),
                        RULE, {"provisioning_key": "pk-2"}, T1)
        self.assertNotEqual(first.workload_id, other.workload_id)
        state.record_correction("incarnation", first.incarnation_id,
                                "host-a", "host-corrected", "actor",
                                "locator repaired", "corr-scope", (), T2)
        # The alias is recorded workload-scoped.
        self.assertIn(("incarnation", "host_locator", first.workload_id, "host-a"),
                      state.mapping_aliases)
        # The owning workload still treats the corrected locator as
        # historical: no incarnation guessed.
        stale = resolve(state, make_observation(native_id_value="101", run_id="run-2"),
                        RULE, {"provisioning_key": "pk-1"}, T2)
        self.assertEqual(stale.outcome, "unresolved")
        self.assertIsNone(stale.incarnation_id)
        # The unrelated workload may still use the same locator as a fresh
        # host: distinct incarnation, matched identity.
        unrelated = resolve(state, make_observation(native_id_value="202",
                                                    asset_locator="host-a",
                                                    source_record_ordinal=3,
                                                    run_id="run-3"),
                            RULE, {"provisioning_key": "pk-2"}, T2)
        self.assertEqual(unrelated.outcome, "matched")
        self.assertEqual(unrelated.workload_id, other.workload_id)
        self.assertNotEqual(unrelated.incarnation_id, other.incarnation_id)


if __name__ == "__main__":
    unittest.main()
