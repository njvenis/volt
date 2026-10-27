"""CR-03/CR-04/FR-ID-02: verified rebuilds, occurrence portions, corrections.

A verified successor incarnation retains the exposure ID, earliest
supported detection and assessment/issue lineage (out of slice: none of
those stores exist yet), while the incarnation and occurrence identities
are distinct. Same-role replicas are distinct incarnations. One occurrence
per remediable instance/component portion; completing one never completes
another. Corrections append versioned records and keep aliases without
touching first-detection history. Synthetic fixtures only.
"""

import unittest

from uvm.identity import IdentityState, RuleV1, resolve

from fixtures import T0, T1, T2, RULE, make_observation


# Synthetic fixture contract: these tests explicitly assume the asset locator
# is unique and does not recycle within their invented source cohort. D-01
# still requires external-system proof before any live rule enables this option.
VERIFIED_LOCATOR_RULE = RuleV1(
    "rule-synthetic-verified-locator", 1,
    ("provisioning_key", "service_key"), verified_asset_locator=True,
)


class RebuildContinuityTest(unittest.TestCase):
    def test_verified_rebuild_retains_exposure_not_incarnation(self):
        state = IdentityState()
        old = make_observation(native_id_value="101", asset_locator="host-old",
                               observed_at=T0, collected_at=T1)
        first = resolve(state, old, RULE, {"provisioning_key": "pk-1"}, T1)
        new = make_observation(native_id_value="101", asset_locator="host-new",
                               observed_at=T1, collected_at=T2)
        second = resolve(state, new, RULE, {"provisioning_key": "pk-1"}, T2)

        # Stable exposure across the verified rebuild.
        self.assertEqual(second.outcome, "matched")
        self.assertEqual(second.exposure_id, first.exposure_id)
        self.assertEqual(second.group_id, first.group_id)
        self.assertEqual(second.workload_id, first.workload_id)
        # Distinct incarnation and occurrence for the successor host.
        self.assertNotEqual(second.incarnation_id, first.incarnation_id)
        self.assertNotEqual(second.occurrence_id, first.occurrence_id)
        # Original detection history retained; clocks not restarted.
        exp = state.exposures[first.exposure_id]
        self.assertEqual(exp.first_observed_at, T0)
        self.assertEqual(len(state.exposures), 1)
        occ_new = state.occurrences[second.occurrence_id]
        self.assertEqual(occ_new.first_observed_at, T1)
        self.assertEqual(occ_new.first_ingested_at, T2)
        # Explanation names the rebuild so the record is reviewable.
        self.assertTrue(
            any("incarnation" in e.get("reason", "") for e in second.candidate_explanations)
        )

    def test_same_role_replicas_are_distinct_incarnations(self):
        state = IdentityState()
        r1 = make_observation(native_id_value="101", asset_locator="host-a")
        r2 = make_observation(native_id_value="101", asset_locator="host-b",
                              source_record_ordinal=2)
        a = resolve(state, r1, RULE, {"provisioning_key": "pk-1"}, T1)
        b = resolve(state, r2, RULE, {"provisioning_key": "pk-1"}, T1)
        self.assertEqual(a.workload_id, b.workload_id)
        self.assertEqual(a.exposure_id, b.exposure_id)
        self.assertNotEqual(a.incarnation_id, b.incarnation_id)
        self.assertNotEqual(a.occurrence_id, b.occurrence_id)
        self.assertEqual(len(state.incarnations), 2)

    def test_component_portions_are_distinct_occurrences(self):
        # CR-04: one native finding on three instances and two independently
        # remediable components -> every instance/component association kept.
        state = IdentityState()
        seen = set()
        for i, host in enumerate(("host-a", "host-b", "host-c")):
            for j, comp in enumerate(("comp-x", "comp-y")):
                obs = make_observation(
                    native_id_value="101",
                    asset_locator=host,
                    component_locator=comp,
                    source_record_ordinal=10 + i * 2 + j,
                )
                res = resolve(state, obs, VERIFIED_LOCATOR_RULE,
                              {"provisioning_key": "pk-1"}, T1)
                seen.add(res.occurrence_id)
        self.assertEqual(len(seen), 6, "each instance/component portion needs its own occurrence")
        self.assertEqual(len(state.occurrences), 6)
        # All six are portions of one exposure on one group.
        self.assertEqual(len(state.exposures), 1)
        self.assertEqual(len(state.groups), 1)
        # No shared state couples the portions: a portion-level write could
        # never be mistaken for another portion by identity.
        occ = list(state.occurrences.values())
        self.assertEqual({o.occurrence_id for o in occ}, seen)
        self.assertEqual(len({(o.incarnation_id, o.component_locator) for o in occ}), 6)

    def test_unknown_observation_time_never_becomes_collection_time(self):
        state = IdentityState()
        obs = make_observation(native_id_value="101", observed_at=None)
        res = resolve(state, obs, RULE, {"provisioning_key": "pk-1"}, T2)
        exp = state.exposures[res.exposure_id]
        occ = state.occurrences[res.occurrence_id]
        self.assertIsNone(exp.first_observed_at)
        self.assertIsNone(occ.first_observed_at)
        # Ingestion time is recorded separately and is not a detection claim.
        self.assertEqual(occ.first_ingested_at, T2)
        self.assertIsNotNone(occ.first_ingested_at)

    def test_repeated_report_adds_observation_not_new_occurrence(self):
        state = IdentityState()
        o1 = make_observation(native_id_value="101")
        o2 = make_observation(native_id_value="101", run_id="run-2",
                              observed_at=T1, collected_at=T2)
        a = resolve(state, o1, VERIFIED_LOCATOR_RULE,
                    {"provisioning_key": "pk-1"}, T1)
        b = resolve(state, o2, VERIFIED_LOCATOR_RULE,
                    {"provisioning_key": "pk-1"}, T2)
        self.assertEqual(b.occurrence_id, a.occurrence_id)
        self.assertEqual(len(state.occurrences), 1)
        # The occurrence keeps the earliest detection; reports never replace it.
        self.assertEqual(state.occurrences[a.occurrence_id].first_observed_at, T0)
        self.assertEqual(state.occurrences[a.occurrence_id].first_ingested_at, T1)


class CorrectionLineageTest(unittest.TestCase):
    def test_versioned_rule_change_preserves_lineage(self):
        # FR-ID-02: a corrected workload attribute under a newer rule version
        # appends a versioned record, keeps the old value as an alias and
        # increments the record revision without resetting first detection.
        state = IdentityState()
        obs = make_observation(native_id_value="101", observed_at=T0)
        first = resolve(state, obs, RULE, {"provisioning_key": "pk-1"}, T1)
        workload = state.workloads[first.workload_id]
        old_key = workload.stable_attrs["provisioning_key"]

        state.record_correction(
            record_type="workload",
            record_id=workload.workload_id,
            old_value=old_key,
            new_value="pk-1-renamed",
            actor="svc:identity-admin",
            reason="rule v2 renames the stable provisioning key",
            correlation_id="corr-1",
            affected_record_ids=(first.exposure_id, first.occurrence_id),
            at=T2,
        )

        self.assertEqual(len(state.corrections), 1)
        rec = state.corrections[0]
        self.assertEqual((rec.actor, rec.old_value, rec.new_value),
                         ("svc:identity-admin", "pk-1", "pk-1-renamed"))
        self.assertTrue({first.exposure_id, first.occurrence_id, first.incarnation_id}
                        <= set(rec.affected_record_ids))
        self.assertEqual(workload.revision, 2)
        # Former value remains a resolvable historical alias.
        self.assertEqual(state.resolve_alias("pk-1"), workload.workload_id)
        # First detection and history are untouched.
        self.assertEqual(state.exposures[first.exposure_id].first_observed_at, T0)
        self.assertEqual(first.occurrence_id, state.occurrence_for_observation(obs.observation_id))
        # Historical resolution records keep their rule version.
        self.assertEqual(first.rule_version, 1)
        self.assertEqual(len(state.resolutions), 1)

    def test_alias_chain_resolves_to_current_record(self):
        state = IdentityState()
        w, _ = state.find_or_create_workload({"provisioning_key": "pk-1"}, at=T1)
        state.record_correction("workload", w.workload_id, "pk-1", "pk-2",
                                "a", "rename", "c1", (), T2)
        self.assertEqual(state.resolve_alias("pk-1"), w.workload_id)
        self.assertEqual(state.resolve_alias(w.workload_id), w.workload_id)


if __name__ == "__main__":
    unittest.main()
