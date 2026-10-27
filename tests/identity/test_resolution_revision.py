"""FR-ID-01 versioned resolution: a re-resolution of the same observation
appends a new record with revision = prior.revision + 1 and
supersedes_resolution_id = prior.resolution_id; the prior record is
retained, so (observation_id, revision) stays unique (the in-memory
invariant of the lineage schema UNIQUE(observation_id, revision))."""

import unittest
from datetime import timedelta

from fixtures import T1, T2, RULE, make_observation
from uvm.identity import IdentityState, RuleV1, resolve

T3 = T2 + timedelta(days=7)


def _unique_revision_pairs(state: IdentityState) -> list[tuple[str, int]]:
    pairs = [(r.observation_id, r.revision) for r in state.resolutions]
    return pairs


class ResolutionRevisionTest(unittest.TestCase):
    def test_reresolution_after_correction_appends_next_revision(self):
        state = IdentityState()
        w1, _ = state.find_or_create_workload(
            {"provisioning_key": "pk-1", "service_key": "svc-1"}, T1)
        obs = make_observation()
        inputs = {"provisioning_key": "pk-1", "service_key": "svc-2"}
        first = resolve(state, obs, RULE, inputs, T1)
        # The stored service_key contradicts the supplied value: no match
        # is guessed.
        self.assertEqual(first.outcome, "unresolved")
        self.assertEqual(first.revision, 1)
        self.assertIsNone(first.occurrence_id)
        # A reviewed correction repairs the stale stable value; the retained
        # observation is re-resolved, not rewritten.
        state.record_correction(
            "workload", w1.workload_id, "svc-1", "svc-2", "actor",
            "stale stable value repaired", "corr-rev-1", (), T2)
        second = resolve(state, obs, RULE, inputs, T2)
        self.assertEqual(second.outcome, "matched")
        self.assertEqual(second.workload_id, w1.workload_id)
        self.assertEqual(second.revision, 2)
        self.assertEqual(second.supersedes_resolution_id, first.resolution_id)
        # History retained: both records remain, prior untouched.
        self.assertEqual(len(state.resolutions), 2)
        self.assertEqual(state.resolutions[0], first)
        self.assertIsNone(first.supersedes_resolution_id)
        self.assertEqual(state.resolution_for_observation(obs.observation_id), second)
        pairs = _unique_revision_pairs(state)
        self.assertEqual(len(pairs), len(set(pairs)))

    def test_reresolution_still_ambiguous_appends_next_revision(self):
        state = IdentityState()
        state.find_or_create_workload(
            {"provisioning_key": "pk-1", "service_key": "svc-1"}, T1)
        state.find_or_create_workload(
            {"provisioning_key": "pk-1", "service_key": "svc-2"}, T1)
        obs = make_observation()
        first = resolve(state, obs, RULE, {"provisioning_key": "pk-1"}, T1)
        self.assertEqual(first.outcome, "ambiguous")
        second = resolve(state, obs, RULE, {"provisioning_key": "pk-1"}, T2)
        self.assertEqual(second.outcome, "ambiguous")
        self.assertEqual(second.revision, 2)
        self.assertEqual(second.supersedes_resolution_id, first.resolution_id)
        self.assertIsNone(second.occurrence_id)
        pairs = _unique_revision_pairs(state)
        self.assertEqual(len(pairs), len(set(pairs)))

    def test_replayed_linked_observation_bumps_revision(self):
        state = IdentityState()
        rule = RuleV1(RULE.rule_id, RULE.rule_version, RULE.workload_match_fields,
                      verified_asset_locator=True)
        obs = make_observation()
        first = resolve(state, obs, rule, {"provisioning_key": "pk-1"}, T1)
        self.assertEqual(first.revision, 1)
        second = resolve(state, obs, rule, {"provisioning_key": "pk-1"}, T2)
        self.assertEqual(second.revision, 2)
        self.assertEqual(second.supersedes_resolution_id, first.resolution_id)
        third = resolve(state, obs, rule, {"provisioning_key": "pk-1"}, T3)
        self.assertEqual(third.revision, 3)
        self.assertEqual(third.supersedes_resolution_id, second.resolution_id)
        # Lineage, identity and occurrence membership are unchanged.
        self.assertEqual(len(state.resolutions), 3)
        for res in (second, third):
            self.assertEqual(res.group_id, first.group_id)
            self.assertEqual(res.workload_id, first.workload_id)
            self.assertEqual(res.incarnation_id, first.incarnation_id)
            self.assertEqual(res.exposure_id, first.exposure_id)
            self.assertEqual(res.occurrence_id, first.occurrence_id)
        self.assertEqual(state.occurrence_for_observation(obs.observation_id),
                         first.occurrence_id)
        self.assertEqual(len(state.occurrences), 1)
        pairs = _unique_revision_pairs(state)
        self.assertEqual(len(pairs), len(set(pairs)))


if __name__ == "__main__":
    unittest.main()
