"""FR-ID-01: explainable matching — matched/new/ambiguous/unresolved.

Ambiguity is queued with candidate/rule evidence; no match is ever guessed.
Ephemeral attributes can never prove workload correspondence.
"""

import unittest

from uvm.identity import IdentityState, resolve

from fixtures import T1, RULE, make_observation


def seed_workloads(state):
    """Two plausible workloads sharing a service key (ambiguous pair) plus a
    uniquely keyed workload."""
    state.find_or_create_workload({"service_key": "svc-1"}, at=T1)
    state.find_or_create_workload({"service_key": "svc-1", "provisioning_key": "pk-9"}, at=T1)
    state.find_or_create_workload({"provisioning_key": "pk-1", "host_name": "h-x"}, at=T1)
    return [w for _, w in sorted(state.workloads.items(), key=lambda kv: kv[1].workload_id)]


class ResolverOutcomesTest(unittest.TestCase):
    def test_new_group_matched_workload_is_new_identity(self):
        state = IdentityState()
        seed_workloads(state)
        obs = make_observation(native_id_value="101")
        res = resolve(state, obs, RULE, {"provisioning_key": "pk-1"}, T1)
        # New group => new identity, but the workload was matched, not invented.
        self.assertEqual(res.outcome, "new")
        self.assertEqual(len(state.workloads), 3)
        self.assertTrue(all((res.group_id, res.workload_id, res.incarnation_id, res.exposure_id, res.occurrence_id)))
        # Explainability: inputs, rule version and matching evidence recorded.
        self.assertEqual(res.rule_id, RULE.rule_id)
        self.assertEqual(res.rule_version, 1)
        self.assertEqual(res.matching_inputs, {"provisioning_key": "pk-1"})
        self.assertTrue(
            any(e.get("field") == "provisioning_key" and e.get("value") == "pk-1"
                for e in res.candidate_explanations)
        )
        # Observation linked to exactly one occurrence.
        self.assertEqual(state.occurrence_for_observation(obs.observation_id), res.occurrence_id)

    def test_existing_group_and_workload_is_matched(self):
        state = IdentityState()
        seed_workloads(state)
        o1 = make_observation(native_id_value="101")
        first = resolve(state, o1, RULE, {"provisioning_key": "pk-1"}, T1)
        o2 = make_observation(native_id_value="101", run_id="run-2",
                              asset_locator="host-b")
        res = resolve(state, o2, RULE, {"provisioning_key": "pk-1"}, T1)
        self.assertEqual(res.outcome, "matched")
        self.assertEqual(res.group_id, first.group_id)
        self.assertEqual(res.workload_id, first.workload_id)
        self.assertEqual(state.occurrence_for_observation(o2.observation_id), res.occurrence_id)

    def test_fully_new_identity_creates_all_records(self):
        state = IdentityState()
        obs = make_observation(native_id_value="101")
        res = resolve(state, obs, RULE, {"provisioning_key": "pk-new"}, T1)
        self.assertEqual(res.outcome, "new")
        self.assertEqual(len(state.groups), 1)
        self.assertEqual(len(state.workloads), 1)
        self.assertEqual(len(state.exposures), 1)
        self.assertEqual(len(state.occurrences), 1)
        self.assertEqual(state.workloads[res.workload_id].stable_attrs, {"provisioning_key": "pk-new"})

    def test_ambiguous_queues_candidates_without_guessing(self):
        state = IdentityState()
        seed_workloads(state)
        obs = make_observation(native_id_value="101")
        res = resolve(state, obs, RULE, {"service_key": "svc-1"}, T1)
        self.assertEqual(res.outcome, "ambiguous")
        self.assertEqual(len(res.candidate_workload_ids), 2)
        self.assertEqual(res.workload_id, None)
        self.assertEqual(res.exposure_id, None)
        self.assertEqual(res.occurrence_id, None)
        # Group still resolves natively (CR-02 is independent of CVE/workload).
        self.assertIsNotNone(res.group_id)
        self.assertEqual(len(state.exposures), 0)
        self.assertEqual(len(state.occurrences), 0)
        # Candidate explanations retained and queryable.
        self.assertEqual(
            {e["workload_id"] for e in res.candidate_explanations},
            set(res.candidate_workload_ids),
        )
        # The unresolved observation keeps no occurrence link.
        self.assertIsNone(state.occurrence_for_observation(obs.observation_id))

    def test_missing_native_id_is_unresolved_not_new(self):
        state = IdentityState()
        obs = make_observation(native_id_scheme=None, native_id_value=None)
        res = resolve(state, obs, RULE, {"provisioning_key": "pk-1"}, T1)
        self.assertEqual(res.outcome, "unresolved")
        self.assertIsNone(res.group_id)
        self.assertIsNone(res.workload_id)
        self.assertEqual(len(state.groups), 0)
        self.assertIsNone(state.occurrence_for_observation(obs.observation_id))

    def test_missing_stable_attributes_is_unresolved(self):
        state = IdentityState()
        seed_workloads(state)
        obs = make_observation(native_id_value="101")
        res = resolve(state, obs, RULE, {}, T1)
        self.assertEqual(res.outcome, "unresolved")
        self.assertEqual(len(state.workloads), 3, "no workload invented from nothing")

    def test_ephemeral_field_is_rejected_evidence(self):
        state = IdentityState()
        seed_workloads(state)  # includes workload with host_name h-x
        obs = make_observation(native_id_value="101")
        res = resolve(state, obs, RULE, {"host_name": "h-x"}, T1)
        # host_name matches an existing workload but is not a rule field:
        # no stable evidence -> unresolved, with the rejection explained.
        self.assertEqual(res.outcome, "unresolved")
        self.assertEqual(len(state.workloads), 3)
        self.assertTrue(
            any(
                e.get("field") == "host_name"
                and "cannot prove" in e.get("reason", "")
                for e in res.candidate_explanations
            ),
            res.candidate_explanations,
        )

    def test_resolution_record_is_append_only_and_versioned(self):
        state = IdentityState()
        obs = make_observation(native_id_value="101")
        first = resolve(state, obs, RULE, {"provisioning_key": "pk-1"}, T1)
        again = resolve(state, obs, RULE, {"provisioning_key": "pk-1"}, T1)
        # Append-only: a new record is appended; identity outcomes agree.
        self.assertEqual(len(state.resolutions), 2)
        self.assertNotEqual(first.resolution_id, again.resolution_id)
        # Same observation re-resolved: same identity, no new records.
        self.assertEqual(first.group_id, again.group_id)
        self.assertEqual(first.occurrence_id, again.occurrence_id)
        self.assertEqual(len(state.occurrences), 1)
        self.assertEqual(len(state.exposures), 1)


if __name__ == "__main__":
    unittest.main()
