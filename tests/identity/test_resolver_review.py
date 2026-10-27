"""Regressions for the independent G1 identity review (synthetic evidence)."""

import unittest

from fixtures import T0, T1, T2, RULE, make_observation, synthetic_id
from uvm.identity import (CorrectionRecord, IdentityResolutionV1, IdentityState,
                          MISSING_UNVERIFIED, MissingField, NativeGroupKey, RuleV1,
                          resolve)


class ReviewedIdentityTest(unittest.TestCase):
    def test_ephemeral_rule_field_is_rejected(self):
        with self.assertRaises(ValueError):
            RuleV1("rule-host-name", 1, ("host_name",))

    def test_locator_trust_change_requires_new_rule_version(self):
        state = IdentityState()
        obs = make_observation()
        resolve(state, obs, RULE, {"provisioning_key": "pk-1"}, T1)
        changed = RuleV1(RULE.rule_id, RULE.rule_version,
                         RULE.workload_match_fields, verified_asset_locator=True)
        before = len(state.resolutions)
        with self.assertRaises(ValueError):
            resolve(state, make_observation(run_id="run-2"), changed,
                    {"provisioning_key": "pk-1"}, T2)
        self.assertEqual(len(state.resolutions), before)

    def test_conflicting_stable_field_cannot_match_one_agreeing_field(self):
        state = IdentityState()
        old, _ = state.find_or_create_workload(
            {"provisioning_key": "pk-1", "service_key": "svc-1"}, T0
        )
        obs = make_observation(asset_locator="host-conflict")
        result = resolve(state, obs, RULE, {
            "provisioning_key": "pk-1", "service_key": "svc-other"
        }, T1)
        self.assertEqual(result.outcome, "unresolved")
        self.assertIsNone(result.workload_id)
        self.assertIsNone(result.exposure_id)
        self.assertEqual(len(state.workloads), 1)
        self.assertEqual(old.workload_id, next(iter(state.workloads)))

    def test_blank_stable_value_does_not_create_workload(self):
        state = IdentityState()
        result = resolve(state, make_observation(), RULE,
                         {"provisioning_key": "   "}, T1)
        self.assertEqual(result.outcome, "unresolved")
        self.assertFalse(state.workloads)

    def test_missing_asset_locator_does_not_create_an_incarnation(self):
        state = IdentityState()
        obs = make_observation(asset_locator=None)
        result = resolve(state, obs, RULE, {"provisioning_key": "pk-1"}, T1)
        self.assertEqual(result.outcome, "unresolved")
        self.assertFalse(state.incarnations)
        self.assertFalse(state.occurrences)

    def test_reused_unverified_locator_does_not_collapse_observations(self):
        state = IdentityState()
        unverified = RuleV1("rule-unverified", 1, ("provisioning_key",))
        first = resolve(state, make_observation(asset_locator="host-a"),
                        unverified, {"provisioning_key": "pk-1"}, T1)
        second = resolve(state, make_observation(asset_locator="host-a", run_id="run-2",
                                                 observed_at=T2),
                         unverified, {"provisioning_key": "pk-1"}, T2)
        self.assertEqual(first.outcome, "new")
        self.assertEqual(second.outcome, "unresolved")
        self.assertIsNone(second.occurrence_id)
        self.assertEqual(len(state.incarnations), 1)
        self.assertEqual(len(state.occurrences), 1)

    def test_workload_correction_updates_match_and_records_impact(self):
        state = IdentityState()
        observed = make_observation()
        first = resolve(state, observed, RULE,
                        {"provisioning_key": "pk-1"}, T1)
        rec = state.record_correction(
            "workload", first.workload_id, "pk-1", "pk-2", "actor", "renamed",
            "correlation-1", (first.exposure_id, first.occurrence_id), T2,
        )
        self.assertEqual(state.workloads[first.workload_id].stable_attrs["provisioning_key"], "pk-2")
        self.assertEqual(rec.field_name, "provisioning_key")
        self.assertEqual(rec.previous_revision, 1)
        self.assertEqual(rec.new_revision, 2)
        self.assertIn(first.exposure_id, rec.affected_record_ids)
        self.assertIn(observed.observation_id, rec.affected_record_ids)
        self.assertEqual(rec.assessment_impact, "unverified")
        self.assertEqual(state.resolve_alias("pk-1"), first.workload_id)
        again = resolve(state, make_observation(run_id="run-2", asset_locator="host-b"),
                        RULE, {"provisioning_key": "pk-2"}, T2)
        self.assertEqual(again.workload_id, first.workload_id)
        self.assertEqual(again.exposure_id, first.exposure_id)
        old = resolve(state, make_observation(run_id="run-3", asset_locator="host-c"),
                      RULE, {"provisioning_key": "pk-1"}, T2)
        self.assertEqual(old.outcome, "unresolved")
        self.assertEqual(len(state.workloads), 1)

    def test_corrected_native_group_key_reindexes_without_reusing_old_key(self):
        state = IdentityState()
        first = resolve(state, make_observation(native_id_value="101"), RULE,
                        {"provisioning_key": "pk-1"}, T1)
        state.record_correction("group", first.group_id, "101", "202", "actor",
                                "native ID corrected", "correlation-2",
                                (first.exposure_id,), T2)
        self.assertEqual(state.groups[first.group_id].key.native_id_value, "202")
        current = resolve(state, make_observation(native_id_value="202", asset_locator="host-b"),
                          RULE, {"provisioning_key": "pk-1"}, T2)
        self.assertEqual(current.group_id, first.group_id)
        former = resolve(state, make_observation(native_id_value="101", asset_locator="host-c"),
                         RULE, {"provisioning_key": "pk-1"}, T2)
        self.assertEqual(former.outcome, "unresolved")
        self.assertEqual(len(state.groups), 1)

    def test_group_alias_is_scoped_to_complete_native_key(self):
        state = IdentityState()
        original = resolve(state, make_observation(native_id_value="101"), RULE,
                           {"provisioning_key": "pk-1"}, T1)
        state.record_correction("group", original.group_id, "101", "202", "actor",
                                "native ID corrected", "correlation-a", (), T2)
        self.assertEqual(state.resolve_group_alias(NativeGroupKey(
            "qualys", "qualys-qid", "global", "101")), original.group_id)
        unrelated = resolve(state, make_observation(
            source_family="sysdig", native_id_scheme="scanner-id",
            native_id_authority="account-a", native_id_value="101",
            asset_locator="sysdig-host"), RULE, {"provisioning_key": "pk-2"}, T2)
        self.assertEqual(unrelated.outcome, "new")
        self.assertNotEqual(unrelated.group_id, original.group_id)
        state.record_correction("group", unrelated.group_id, "101", "303", "actor",
                                "independent native ID correction", "correlation-b", (), T2)
        self.assertEqual(state.groups[unrelated.group_id].key.native_id_value, "303")
        self.assertEqual(len(state.groups), 2)

    def test_unverified_component_does_not_collapse_distinct_source_rows(self):
        state = IdentityState()
        rule = RuleV1("rule-component-unverified", 1, ("provisioning_key",),
                      verified_asset_locator=True)
        first = resolve(state, make_observation(
            component_locator=None, source_record_locator="row-a"), rule,
            {"provisioning_key": "pk-1"}, T1)
        second = resolve(state, make_observation(
            component_locator=None, source_record_locator="row-b", run_id="run-2"),
            rule, {"provisioning_key": "pk-1"}, T2)
        self.assertFalse(first.occurrence_id and first.occurrence_id == second.occurrence_id)
        self.assertEqual(second.outcome, "unresolved")
        self.assertIsNone(second.occurrence_id)
        self.assertFalse(state.occurrences)

    def test_explicitly_unverified_component_locator_is_unresolved(self):
        state = IdentityState()
        obs = make_observation(
            component_locator="reported-component",
            source_record_locator="row-a",
            missing=(MissingField("component_locator", MISSING_UNVERIFIED),),
        )
        result = resolve(state, obs, RULE, {"provisioning_key": "pk-1"}, T1)
        self.assertEqual(result.outcome, "unresolved")
        self.assertIsNone(result.occurrence_id)
        self.assertFalse(state.occurrences)

    def test_reresolution_after_exposure_group_correction_rejects_stale_membership(self):
        state = IdentityState()
        obs = make_observation()
        first = resolve(state, obs, RULE, {"provisioning_key": "pk-1"}, T1)
        second_group, _ = state.find_or_create_group(
            NativeGroupKey("qualys", "qualys-qid", "global", "202"), T2)
        state.record_correction("exposure", first.exposure_id, first.group_id,
                                second_group.group_id, "actor", "mapping repaired",
                                "correlation-c", (), T2)
        before = len(state.resolutions)
        with self.assertRaises(ValueError):
            resolve(state, obs, RULE, {"provisioning_key": "pk-1"}, T2)
        self.assertEqual(len(state.resolutions), before)
        self.assertEqual(state.exposures[first.exposure_id].group_id, second_group.group_id)

    def test_incarnation_correction_reindexes_and_preserves_observation(self):
        state = IdentityState()
        obs = make_observation()
        first = resolve(state, obs, RULE, {"provisioning_key": "pk-1"}, T1)
        rec = state.record_correction("incarnation", first.incarnation_id,
                                      "host-a", "host-corrected", "actor",
                                      "locator repaired", "correlation-3", (), T2)
        self.assertIn(first.occurrence_id, rec.affected_record_ids)
        self.assertEqual(state.occurrence_for_observation(obs.observation_id), first.occurrence_id)
        self.assertNotIn((first.workload_id, "host-a"), state._incarnation_index)
        self.assertEqual(state._incarnation_index[(first.workload_id, "host-corrected")],
                         first.incarnation_id)

    def test_exposure_and_occurrence_corrections_keep_indexes_and_scoped_aliases(self):
        state = IdentityState()
        obs = make_observation()
        first = resolve(state, obs, RULE, {"provisioning_key": "pk-1"}, T1)
        second_group, _ = state.find_or_create_group(
            NativeGroupKey("qualys", "qualys-qid", "global", "202"), T2)
        state.record_correction("exposure", first.exposure_id,
                                first.group_id, second_group.group_id,
                                "actor", "group mapping repaired", "correlation-5", (), T2)
        self.assertNotIn((first.group_id, first.workload_id), state._exposure_index)
        self.assertEqual(state._exposure_index[(second_group.group_id, first.workload_id)],
                         first.exposure_id)
        self.assertEqual(state.resolve_alias(first.group_id), first.group_id)
        self.assertEqual(state.resolve_alias(first.group_id, record_type="exposure",
                                             field_name="group_id",
                                            scope=first.workload_id), first.exposure_id)
        rec = state.record_correction("occurrence", first.occurrence_id,
                                      "comp-a", "comp-b", "actor", "component repaired",
                                      "correlation-6", (), T2)
        self.assertNotIn((first.exposure_id, first.incarnation_id, "comp-a"),
                         state._occurrence_index)
        self.assertEqual(state._occurrence_index[(first.exposure_id,
                                                   first.incarnation_id, "comp-b")],
                         first.occurrence_id)
        self.assertIn(obs.observation_id, rec.affected_record_ids)

    def test_colliding_correction_is_rejected_before_any_mutation(self):
        state = IdentityState()
        a = resolve(state, make_observation(asset_locator="host-a"), RULE,
                    {"provisioning_key": "pk-1"}, T1)
        b = resolve(state, make_observation(asset_locator="host-b"), RULE,
                    {"provisioning_key": "pk-1"}, T1)
        before = (len(state.corrections), state.incarnations[a.incarnation_id].revision)
        with self.assertRaises(ValueError):
            state.record_correction("incarnation", a.incarnation_id,
                                    "host-a", "host-b", "actor", "collision",
                                    "correlation-4", (), T2)
        self.assertEqual(before, (len(state.corrections), state.incarnations[a.incarnation_id].revision))
        self.assertEqual(state._incarnation_index[(a.workload_id, "host-a")], a.incarnation_id)
        self.assertEqual(state._incarnation_index[(a.workload_id, "host-b")], b.incarnation_id)

    def test_rejected_reresolution_leaves_no_orphan_records(self):
        state = IdentityState()
        obs = make_observation()
        first = resolve(state, obs, RULE, {"provisioning_key": "pk-1"}, T1)
        before = tuple(len(getattr(state, name)) for name in
                       ("groups", "workloads", "incarnations", "exposures", "occurrences", "resolutions"))
        with self.assertRaises(ValueError):
            resolve(state, obs, RULE, {"provisioning_key": "pk-2"}, T2)
        self.assertEqual(before, tuple(len(getattr(state, name)) for name in
                                       ("groups", "workloads", "incarnations", "exposures", "occurrences", "resolutions")))
        self.assertEqual(state.occurrence_for_observation(obs.observation_id), first.occurrence_id)


class AliasReversalReviewedIdentityTest(unittest.TestCase):
    def test_host_locator_reversal_reactivates_and_retires_alias(self):
        state = IdentityState()
        rule = RuleV1("rule-verified", 1, ("provisioning_key",),
                      verified_asset_locator=True)
        first = resolve(state, make_observation(asset_locator="host-a"),
                        rule, {"provisioning_key": "pk-1"}, T1)
        state.record_correction("incarnation", first.incarnation_id, "host-a",
                                "host-corrected", "actor", "locator repaired",
                                "correlation-r1", (), T2)
        state.record_correction("incarnation", first.incarnation_id,
                                "host-corrected", "host-a", "actor",
                                "locator reversal", "correlation-r2", (), T2)
        self.assertEqual(state._incarnation_index[(first.workload_id, "host-a")],
                         first.incarnation_id)
        self.assertNotIn(("incarnation", "host_locator", first.workload_id, "host-a"),
                         state.mapping_aliases)
        back = resolve(state, make_observation(run_id="run-2", asset_locator="host-a"),
                       rule, {"provisioning_key": "pk-1"}, T2)
        self.assertEqual(back.outcome, "matched")
        self.assertEqual(back.incarnation_id, first.incarnation_id)
        stale = resolve(state, make_observation(run_id="run-3",
                                                asset_locator="host-corrected"),
                        rule, {"provisioning_key": "pk-1"}, T2)
        self.assertEqual(stale.outcome, "unresolved")
        self.assertIsNone(stale.occurrence_id)

    def test_host_locator_reversal_to_foreign_alias_is_rejected(self):
        state = IdentityState()
        a = resolve(state, make_observation(asset_locator="host-a"), RULE,
                    {"provisioning_key": "pk-1"}, T1)
        b = resolve(state, make_observation(asset_locator="host-b", run_id="run-2"),
                    RULE, {"provisioning_key": "pk-1"}, T1)
        state.record_correction("incarnation", a.incarnation_id, "host-a",
                                "host-x", "actor", "repaired",
                                "correlation-f1", (), T2)
        before = (len(state.corrections),
                  state._incarnation_index[(b.workload_id, "host-b")])
        with self.assertRaises(ValueError):
            state.record_correction("incarnation", b.incarnation_id, "host-b",
                                    "host-x", "actor", "stale locator",
                                    "correlation-f2", (), T2)
        self.assertEqual(before, (len(state.corrections),
                                  state._incarnation_index[(b.workload_id, "host-b")]))

    def test_group_key_reversal_reactivates_and_retires_alias(self):
        state = IdentityState()
        first = resolve(state, make_observation(native_id_value="101"), RULE,
                        {"provisioning_key": "pk-1"}, T1)
        state.record_correction("group", first.group_id, "101", "202", "actor",
                                "native ID corrected", "correlation-g1", (), T2)
        state.record_correction("group", first.group_id, "202", "101", "actor",
                                "native ID reversal", "correlation-g2", (), T2)
        self.assertEqual(state.groups[first.group_id].key.native_id_value, "101")
        self.assertIsNone(state.resolve_group_alias(NativeGroupKey(
            "qualys", "qualys-qid", "global", "101")))
        back = resolve(state, make_observation(native_id_value="101",
                                               asset_locator="host-b"),
                       RULE, {"provisioning_key": "pk-1"}, T2)
        self.assertEqual(back.outcome, "matched")
        self.assertEqual(back.group_id, first.group_id)
        stale = resolve(state, make_observation(native_id_value="202",
                                                asset_locator="host-c"),
                        RULE, {"provisioning_key": "pk-1"}, T2)
        self.assertEqual(stale.outcome, "unresolved")
        self.assertEqual(len(state.groups), 1)

    def test_rejected_correction_leaves_no_mutation(self):
        state = IdentityState()
        first = resolve(state, make_observation(), RULE, {"provisioning_key": "pk-1"}, T1)
        before = (len(state.corrections),
                  state.workloads[first.workload_id].revision,
                  state.workloads[first.workload_id].stable_attrs["provisioning_key"])
        with self.assertRaises(ValueError):
            state.record_correction("workload", first.workload_id, "pk-1", "pk-2",
                                    "actor", "renamed", "correlation-atomic",
                                    ("not-a-uuid",), T2)
        self.assertEqual(before, (len(state.corrections),
                                  state.workloads[first.workload_id].revision,
                                  state.workloads[first.workload_id].stable_attrs["provisioning_key"]))
        self.assertFalse(state.mapping_aliases)
        self.assertFalse(state.aliases)

    def test_independent_exposures_may_retire_the_same_former_value(self):
        state = IdentityState()
        first = resolve(state, make_observation(native_id_value="101"), RULE,
                        {"provisioning_key": "pk-1"}, T1)
        second = resolve(state, make_observation(native_id_value="101",
                                                 run_id="run-2"), RULE,
                         {"provisioning_key": "pk-2"}, T1)
        self.assertEqual(first.group_id, second.group_id)
        self.assertNotEqual(first.workload_id, second.workload_id)
        g_a, _ = state.find_or_create_group(
            NativeGroupKey("qualys", "qualys-qid", "global", "201"), T2)
        g_b, _ = state.find_or_create_group(
            NativeGroupKey("qualys", "qualys-qid", "global", "202"), T2)
        state.record_correction("exposure", first.exposure_id, first.group_id,
                                g_a.group_id, "actor", "mapping repaired",
                                "correlation-e1", (), T2)
        state.record_correction("exposure", second.exposure_id, second.group_id,
                                g_b.group_id, "actor", "mapping repaired",
                                "correlation-e2", (), T2)
        self.assertEqual(state.exposures[first.exposure_id].group_id, g_a.group_id)
        self.assertEqual(state.exposures[second.exposure_id].group_id, g_b.group_id)
        self.assertEqual(state.resolve_alias(first.group_id, record_type="exposure",
                                            field_name="group_id",
                                            scope=first.workload_id),
                         first.exposure_id)
        self.assertEqual(state.resolve_alias(second.group_id, record_type="exposure",
                                             field_name="group_id",
                                             scope=second.workload_id),
                         second.exposure_id)

    def test_exposure_alias_reversal_still_reactivates(self):
        state = IdentityState()
        first = resolve(state, make_observation(native_id_value="101"), RULE,
                        {"provisioning_key": "pk-1"}, T1)
        g_b, _ = state.find_or_create_group(
            NativeGroupKey("qualys", "qualys-qid", "global", "202"), T2)
        state.record_correction("exposure", first.exposure_id, first.group_id,
                                g_b.group_id, "actor", "mapping repaired",
                                "correlation-e3", (), T2)
        state.record_correction("exposure", first.exposure_id, g_b.group_id,
                                first.group_id, "actor", "mapping reversal",
                                "correlation-e4", (), T2)
        self.assertEqual(state._exposure_index[(first.group_id, first.workload_id)],
                         first.exposure_id)
        self.assertNotIn(("exposure", "group_id", first.workload_id, first.group_id),
                         state.mapping_aliases)
        self.assertEqual(state.exposures[first.exposure_id].group_id, first.group_id)


class UuidRuleReviewedIdentityTest(unittest.TestCase):
    def test_resolution_rejects_non_uuid_candidate_workload_ids(self):
        with self.assertRaises(ValueError):
            IdentityResolutionV1(
                schema_version=1, resolution_id=synthetic_id("res-uuid-1"),
                revision=1, observation_id=synthetic_id("obs-uuid-1"),
                rule_id="rule-uuid", rule_version=1, matching_inputs={},
                candidate_workload_ids=("not-a-uuid",), outcome="ambiguous",
                evaluated_at=T1,
            )

    def test_resolution_accepts_uuid_candidate_workload_ids(self):
        res = IdentityResolutionV1(
            schema_version=1, resolution_id=synthetic_id("res-uuid-2"),
            revision=1, observation_id=synthetic_id("obs-uuid-2"),
            rule_id="rule-uuid", rule_version=1, matching_inputs={},
            candidate_workload_ids=(synthetic_id("wl-uuid-1"),),
            outcome="ambiguous", evaluated_at=T1,
        )
        self.assertEqual(res.candidate_workload_ids, (synthetic_id("wl-uuid-1"),))

    def test_correction_rejects_non_uuid_affected_record_ids(self):
        with self.assertRaises(ValueError):
            CorrectionRecord(
                correction_id=synthetic_id("cor-uuid-1"), record_type="workload",
                record_id=synthetic_id("wl-uuid-2"), old_value="a", new_value="b",
                actor="actor", reason="reason", correlation_id="corr-1",
                affected_record_ids=("not-a-uuid",), created_at=T1,
            )

    def test_correction_rejects_non_uuid_correction_id(self):
        with self.assertRaises(ValueError):
            CorrectionRecord(
                correction_id="not-a-uuid", record_type="workload",
                record_id=synthetic_id("wl-uuid-3"), old_value="a", new_value="b",
                actor="actor", reason="reason", correlation_id="corr-1",
                affected_record_ids=(), created_at=T1,
            )

    def test_correction_rejects_non_uuid_record_id(self):
        with self.assertRaises(ValueError):
            CorrectionRecord(
                correction_id=synthetic_id("cor-uuid-2"), record_type="workload",
                record_id="not-a-uuid", old_value="a", new_value="b",
                actor="actor", reason="reason", correlation_id="corr-1",
                affected_record_ids=(), created_at=T1,
            )


class LocatorNullCorrectionTest(unittest.TestCase):
    """CR-03/CR-04 locator-correction clarification (synthetic): a withdrawn
    host/component locator may be corrected to null without collapsing the
    retained record; null is never an index or match key; replay of a
    withdrawn locator stays unresolved until a reviewed correction."""

    @classmethod
    def setUpClass(cls):
        # Replays across repeated reports need a verified asset locator so
        # the host does not trip the unverified-reuse guard first.
        cls.RULE_V = RuleV1(RULE.rule_id, RULE.rule_version,
                            RULE.workload_match_fields,
                            verified_asset_locator=True)

    def test_two_incarnations_of_one_workload_can_both_be_corrected_to_null(self):
        state = IdentityState()
        obs_a = make_observation(asset_locator="host-a")
        first = resolve(state, obs_a, RULE, {"provisioning_key": "pk-1"}, T1)
        obs_b = make_observation(asset_locator="host-b", run_id="run-2",
                                 observed_at=T2)
        second = resolve(state, obs_b, RULE, {"provisioning_key": "pk-1"}, T2)
        self.assertEqual(first.workload_id, second.workload_id)
        self.assertNotEqual(first.incarnation_id, second.incarnation_id)
        state.record_correction(
            "incarnation", first.incarnation_id, "host-a", None, "actor",
            "locator withdrawn", "corr-null-a", (first.occurrence_id,), T2,
        )
        state.record_correction(
            "incarnation", second.incarnation_id, "host-b", None, "actor",
            "locator withdrawn", "corr-null-b", (second.occurrence_id,), T2,
        )
        # UUIDs, lineage and first detection are unchanged.
        self.assertIsNone(state.incarnations[first.incarnation_id].host_locator)
        self.assertIsNone(state.incarnations[second.incarnation_id].host_locator)
        self.assertEqual(
            state.incarnations[first.incarnation_id].first_observed_at, T0)
        self.assertEqual(
            state.occurrence_for_observation(obs_a.observation_id),
            first.occurrence_id)
        self.assertEqual(
            state.occurrence_for_observation(obs_b.observation_id),
            second.occurrence_id)
        # null is never an index key.
        self.assertNotIn(None, (key[1] for key in state._incarnation_index))
        self.assertNotIn(None, (key[2] for key in state._occurrence_index))

    def test_two_component_occurrences_under_one_incarnation_can_both_be_corrected_to_null(self):
        state = IdentityState()
        obs_a = make_observation(component_locator="comp-a")
        first = resolve(state, obs_a, self.RULE_V, {"provisioning_key": "pk-1"}, T1)
        obs_b = make_observation(component_locator="comp-b", run_id="run-2",
                                 observed_at=T2)
        second = resolve(state, obs_b, self.RULE_V, {"provisioning_key": "pk-1"}, T2)
        self.assertEqual(first.exposure_id, second.exposure_id)
        self.assertEqual(first.incarnation_id, second.incarnation_id)
        self.assertNotEqual(first.occurrence_id, second.occurrence_id)
        state.record_correction(
            "occurrence", first.occurrence_id, "comp-a", None, "actor",
            "locator withdrawn", "corr-null-comp-a", (), T2)
        state.record_correction(
            "occurrence", second.occurrence_id, "comp-b", None, "actor",
            "locator withdrawn", "corr-null-comp-b", (), T2)
        self.assertIsNone(state.occurrences[first.occurrence_id].component_locator)
        self.assertIsNone(state.occurrences[second.occurrence_id].component_locator)
        self.assertEqual(
            state.occurrences[first.occurrence_id].first_observed_at, T0)
        self.assertEqual(
            state.occurrence_for_observation(obs_a.observation_id),
            first.occurrence_id)
        self.assertEqual(
            state.occurrence_for_observation(obs_b.observation_id),
            second.occurrence_id)
        self.assertNotIn(None, (key[2] for key in state._occurrence_index))

    def test_component_aliases_are_scoped_by_exposure_and_incarnation(self):
        state = IdentityState()
        first = resolve(
            state, make_observation(asset_locator="host-a",
                                     component_locator="nginx"),
            RULE, {"provisioning_key": "pk-1"}, T1)
        second = resolve(
            state, make_observation(asset_locator="host-b", run_id="run-2",
                                    observed_at=T2, component_locator="nginx"),
            RULE, {"provisioning_key": "pk-1"}, T2)
        self.assertEqual(first.exposure_id, second.exposure_id)
        self.assertNotEqual(first.incarnation_id, second.incarnation_id)
        state.record_correction(
            "occurrence", first.occurrence_id, "nginx", None, "actor",
            "locator withdrawn", "corr-null-nginx-a", (), T2)
        state.record_correction(
            "occurrence", second.occurrence_id, "nginx", None, "actor",
            "locator withdrawn", "corr-null-nginx-b", (), T2)
        self.assertEqual(
            state.mapping_aliases[
                ("occurrence", "component_locator", first.exposure_id,
                 first.incarnation_id, "nginx")],
            first.occurrence_id)
        self.assertEqual(
            state.mapping_aliases[
                ("occurrence", "component_locator", second.exposure_id,
                 second.incarnation_id, "nginx")],
            second.occurrence_id)

    def test_replayed_withdrawn_component_locator_stays_unresolved(self):
        state = IdentityState()
        first = resolve(
            state, make_observation(component_locator="nginx"),
            self.RULE_V, {"provisioning_key": "pk-1"}, T1)
        state.record_correction(
            "occurrence", first.occurrence_id, "nginx", None, "actor",
            "locator withdrawn", "corr-null-replay", (), T2)
        replay = resolve(
            state, make_observation(run_id="run-2", observed_at=T2,
                                    component_locator="nginx"),
            self.RULE_V, {"provisioning_key": "pk-1"}, T2)
        self.assertEqual(replay.outcome, "unresolved")
        self.assertIsNone(replay.occurrence_id)
        self.assertEqual(len(state.occurrences), 1)

    def test_withdrawn_component_locator_is_not_blocked_in_another_incarnation(self):
        state = IdentityState()
        first = resolve(
            state, make_observation(asset_locator="host-a",
                                     component_locator="nginx"),
            self.RULE_V, {"provisioning_key": "pk-1"}, T1)
        second = resolve(
            state, make_observation(asset_locator="host-b", run_id="run-2",
                                    observed_at=T2, component_locator="nginx"),
            self.RULE_V, {"provisioning_key": "pk-1"}, T2)
        state.record_correction(
            "occurrence", first.occurrence_id, "nginx", None, "actor",
            "locator withdrawn", "corr-null-scope", (), T2)
        replay = resolve(
            state, make_observation(asset_locator="host-b", run_id="run-3",
                                    observed_at=T2, component_locator="nginx"),
            self.RULE_V, {"provisioning_key": "pk-1"}, T2)
        self.assertEqual(replay.outcome, "matched")
        self.assertEqual(replay.occurrence_id, second.occurrence_id)

    def test_reactivation_with_verified_locator_reindexes_only_the_record(self):
        state = IdentityState()
        first = resolve(
            state, make_observation(asset_locator="host-a"),
            RULE, {"provisioning_key": "pk-1"}, T1)
        second = resolve(
            state, make_observation(asset_locator="host-b", run_id="run-2",
                                    observed_at=T2),
            RULE, {"provisioning_key": "pk-1"}, T2)
        state.record_correction(
            "incarnation", first.incarnation_id, "host-a", None, "actor",
            "locator withdrawn", "corr-reindex-a", (), T2)
        state.record_correction(
            "incarnation", first.incarnation_id, None, "host-c", "actor",
            "verified non-colliding locator", "corr-reindex-b", (), T2)
        self.assertEqual(
            state._incarnation_index[(first.workload_id, "host-c")],
            first.incarnation_id)
        self.assertEqual(
            state._incarnation_index[(second.workload_id, "host-b")],
            second.incarnation_id)
        self.assertNotIn((first.workload_id, "host-a"), state._incarnation_index)
        # The withdrawn locator stays historical to the same record.
        self.assertEqual(
            state.mapping_aliases[
                ("incarnation", "host_locator", first.workload_id, "host-a")],
            first.incarnation_id)
        self.assertEqual(len(state._incarnation_index), 2)

    def test_reactivation_collision_is_rejected_atomically(self):
        state = IdentityState()
        first = resolve(
            state, make_observation(asset_locator="host-a"),
            RULE, {"provisioning_key": "pk-1"}, T1)
        second = resolve(
            state, make_observation(asset_locator="host-b", run_id="run-2",
                                    observed_at=T2),
            RULE, {"provisioning_key": "pk-1"}, T2)
        state.record_correction(
            "incarnation", first.incarnation_id, "host-a", None, "actor",
            "locator withdrawn", "corr-collide-a", (), T2)
        # Active locator owned by another incarnation: rejected, nothing moves.
        with self.assertRaises(ValueError):
            state.record_correction(
                "incarnation", first.incarnation_id, None, "host-b", "actor",
                "collision", "corr-collide-b", (), T2)
        self.assertIsNone(state.incarnations[first.incarnation_id].host_locator)
        self.assertEqual(
            state._incarnation_index[(second.workload_id, "host-b")],
            second.incarnation_id)
        # Withdrawn locator still historical to the first record: the second
        # incarnation cannot take it without a reviewed correction.
        with self.assertRaises(ValueError):
            state.record_correction(
                "incarnation", second.incarnation_id, "host-b", "host-a",
                "actor", "foreign alias", "corr-collide-c", (), T2)
        self.assertEqual(
            state.incarnations[second.incarnation_id].host_locator, "host-b")

    def test_null_component_occurrences_move_to_one_target_scope_without_collision(self):
        state = IdentityState()
        obs_a = make_observation(component_locator="comp-a")
        first = resolve(state, obs_a, self.RULE_V, {"provisioning_key": "pk-1"}, T1)
        obs_b = make_observation(native_id_value="102", asset_locator="host-b",
                                 component_locator="comp-b", run_id="run-2",
                                 observed_at=T2)
        second = resolve(state, obs_b, self.RULE_V, {"provisioning_key": "pk-1"}, T2)
        target_group, _ = state.find_or_create_group(
            NativeGroupKey("qualys", "qualys-qid", "global", "202"), T2)
        target_exposure, _ = state.find_or_create_exposure(
            target_group, state.workloads[first.workload_id], None, T2)
        target_incarnation, _ = state.find_or_create_incarnation(
            state.workloads[first.workload_id], "host-z", None, None, T2)
        # Withdraw both component locators: both occurrences now have null.
        state.record_correction("occurrence", first.occurrence_id, "comp-a", None,
                                "actor", "locator withdrawn",
                                "corr-nn-a", (), T2)
        state.record_correction("occurrence", second.occurrence_id, "comp-b", None,
                                "actor", "locator withdrawn",
                                "corr-nn-b", (), T2)
        # Both null-component occurrences must move into the same target
        # scope via exposure_id and incarnation_id corrections without
        # colliding: null is never an index key.
        state.record_correction("occurrence", first.occurrence_id,
                                first.exposure_id, target_exposure.exposure_id,
                                "actor", "reparented", "corr-nn-c", (), T2)
        state.record_correction("occurrence", second.occurrence_id,
                                second.exposure_id, target_exposure.exposure_id,
                                "actor", "reparented", "corr-nn-d", (), T2)
        state.record_correction("occurrence", first.occurrence_id,
                                first.incarnation_id,
                                target_incarnation.incarnation_id,
                                "actor", "moved", "corr-nn-e", (), T2)
        state.record_correction("occurrence", second.occurrence_id,
                                second.incarnation_id,
                                target_incarnation.incarnation_id,
                                "actor", "moved", "corr-nn-f", (), T2)
        self.assertEqual(
            state.occurrences[first.occurrence_id].exposure_id,
            target_exposure.exposure_id)
        self.assertEqual(
            state.occurrences[second.occurrence_id].exposure_id,
            target_exposure.exposure_id)
        self.assertEqual(
            state.occurrences[second.occurrence_id].incarnation_id,
            target_incarnation.incarnation_id)
        self.assertEqual(
            state.occurrences[first.occurrence_id].incarnation_id,
            target_incarnation.incarnation_id)
        # UUIDs, earliest detection and observation links remain distinct.
        self.assertNotEqual(first.occurrence_id, second.occurrence_id)
        self.assertEqual(
            state.occurrences[first.occurrence_id].first_observed_at, T0)
        self.assertEqual(
            state.occurrences[second.occurrence_id].first_observed_at, T2)
        self.assertEqual(
            state.occurrence_for_observation(obs_a.observation_id),
            first.occurrence_id)
        self.assertEqual(
            state.occurrence_for_observation(obs_b.observation_id),
            second.occurrence_id)
        self.assertNotIn(None, (key[2] for key in state._occurrence_index))

    def test_known_locator_occurrence_exposure_correction_still_rejects_collision(self):
        state = IdentityState()
        first = resolve(state, make_observation(component_locator="comp-a"),
                        self.RULE_V, {"provisioning_key": "pk-1"}, T1)
        second = resolve(state, make_observation(component_locator="comp-b",
                                                 run_id="run-2", observed_at=T2),
                         self.RULE_V, {"provisioning_key": "pk-1"}, T2)
        target_group, _ = state.find_or_create_group(
            NativeGroupKey("qualys", "qualys-qid", "global", "202"), T2)
        target_exposure, _ = state.find_or_create_exposure(
            target_group, state.workloads[first.workload_id], None, T2)
        # A known locator already occupied under the target scope.
        state.find_or_create_occurrence(
            target_exposure, state.incarnations[first.incarnation_id],
            "comp-a", T0, T2)
        before = (state.occurrences[first.occurrence_id].exposure_id,
                  state._occurrence_index[(first.exposure_id,
                                           first.incarnation_id, "comp-a")])
        with self.assertRaises(ValueError):
            state.record_correction("occurrence", first.occurrence_id,
                                    first.exposure_id, target_exposure.exposure_id,
                                    "actor", "collision", "corr-nn-f", (), T2)
        self.assertEqual(
            (state.occurrences[first.occurrence_id].exposure_id,
             state._occurrence_index[(first.exposure_id,
                                      first.incarnation_id, "comp-a")]),
            before)
        self.assertEqual(len(state.occurrences), 3)

    def test_group_aliased_out_of_exposure_does_not_create_replacement_exposure(self):
        state = IdentityState()
        first = resolve(state, make_observation(native_id_value="101"),
                        self.RULE_V, {"provisioning_key": "pk-1"}, T1)
        target_group, _ = state.find_or_create_group(
            NativeGroupKey("qualys", "qualys-qid", "global", "202"), T2)
        state.record_correction("exposure", first.exposure_id, first.group_id,
                                target_group.group_id, "actor",
                                "mapping repaired", "corr-hist-1", (), T2)
        before = (len(state.exposures), len(state.incarnations),
                  len(state.occurrences))
        # A later group-A observation under the same workload must consult
        # the scoped historical exposure alias and stay unresolved rather
        # than auto-create a replacement exposure.
        replay = resolve(state, make_observation(native_id_value="101",
                                                 run_id="run-2", observed_at=T2),
                         self.RULE_V, {"provisioning_key": "pk-1"}, T2)
        self.assertEqual(replay.outcome, "unresolved")
        self.assertIsNone(replay.exposure_id)
        self.assertIsNone(replay.occurrence_id)
        self.assertEqual(before, (len(state.exposures), len(state.incarnations),
                                  len(state.occurrences)))
        self.assertEqual(state.exposures[first.exposure_id].group_id,
                         target_group.group_id)
        self.assertNotIn((first.group_id, first.workload_id),
                         state._exposure_index)
        # An independent workload is unaffected by the scoped alias: the
        # same group under another workload still resolves and owns its
        # own exposure.
        independent = resolve(state, make_observation(native_id_value="101",
                                                      asset_locator="host-z",
                                                      run_id="run-3",
                                                      observed_at=T2),
                              self.RULE_V, {"provisioning_key": "pk-2"}, T2)
        self.assertEqual(independent.outcome, "new")
        self.assertEqual(independent.group_id, first.group_id)
        self.assertNotEqual(independent.exposure_id, first.exposure_id)

    def test_workload_aliased_out_of_exposure_does_not_recreate_old_relation(self):
        state = IdentityState()
        group, _ = state.find_or_create_group(
            NativeGroupKey("qualys", "qualys-qid", "global", "101"), T1)
        workload_a, _ = state.find_or_create_workload(
            {"provisioning_key": "pk-a"}, T1)
        workload_b, _ = state.find_or_create_workload(
            {"provisioning_key": "pk-b"}, T1)
        exposure, _ = state.find_or_create_exposure(group, workload_a, T0, T1)
        state.record_correction(
            "exposure", exposure.exposure_id, workload_a.workload_id,
            workload_b.workload_id, "actor", "workload mapping repaired",
            "corr-hist-workload", (), T2)
        before = (len(state.exposures), len(state.incarnations),
                  len(state.occurrences))
        replay = resolve(state, make_observation(run_id="run-replay"),
                         self.RULE_V, {"provisioning_key": "pk-a"}, T2)
        self.assertEqual(replay.outcome, "unresolved")
        self.assertIsNone(replay.exposure_id)
        self.assertEqual(before, (len(state.exposures), len(state.incarnations),
                                  len(state.occurrences)))
        self.assertEqual(state.exposures[exposure.exposure_id].workload_id,
                         workload_b.workload_id)
        retained = resolve(state, make_observation(
            asset_locator="host-b", run_id="run-current"), self.RULE_V,
            {"provisioning_key": "pk-b"}, T2)
        self.assertEqual(retained.outcome, "matched")
        self.assertEqual(retained.exposure_id, exposure.exposure_id)
        unrelated = resolve(state, make_observation(
            native_id_value="202", asset_locator="host-other",
            run_id="run-unrelated"), self.RULE_V,
            {"provisioning_key": "pk-a"}, T2)
        self.assertEqual(unrelated.outcome, "new")
        self.assertNotEqual(unrelated.exposure_id, exposure.exposure_id)

    def test_direct_null_component_creation_cannot_match_another_record(self):
        state = IdentityState()
        group, _ = state.find_or_create_group(
            NativeGroupKey("qualys", "qualys-qid", "global", "101"), T1)
        workload, _ = state.find_or_create_workload(
            {"provisioning_key": "pk-a"}, T1)
        exposure, _ = state.find_or_create_exposure(group, workload, T0, T1)
        incarnation, _ = state.find_or_create_incarnation(
            workload, "host-a", None, T0, T1)
        before = (len(state.occurrences), dict(state._occurrence_index))
        with self.assertRaises(ValueError):
            state.find_or_create_occurrence(exposure, incarnation, None, T0, T1)
        with self.assertRaises(ValueError):
            state.find_or_create_occurrence(exposure, incarnation, None, T2, T2)
        self.assertEqual((len(state.occurrences), state._occurrence_index), before)


if __name__ == "__main__":
    unittest.main()
