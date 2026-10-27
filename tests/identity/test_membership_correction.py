"""Atomic multi-record membership correction for a populated exposure
(FR-ID-02 / CR-03).

A populated exposure's workload cannot be changed by a scalar field
correction: the reviewed atomic correction must specify the new
incarnation/occurrence memberships, preserve IDs and detection times and
observation links, and append its correction rows sharing one correlation
ID with assessment/issue impact left unverified. Synthetic evidence only.
"""

import unittest

from fixtures import T0, T1, T2, RULE, make_observation, next_id
from uvm.identity import IdentityState, NativeGroupKey, resolve


ATTRS = {"provisioning_key": "pk-1", "service_key": "svc-1"}
NEW_ATTRS = {"provisioning_key": "pk-2", "service_key": "svc-2"}


def _populated_state():
    """One exposure with two occurrences (comp-a / comp-b on two
    incarnations), plus a verified successor workload/incarnation pair."""
    state = IdentityState()
    obs_a = make_observation(component_locator="comp-a", asset_locator="host-a")
    obs_b = make_observation(component_locator="comp-b", asset_locator="host-b",
                             run_id="run-2")
    a = resolve(state, obs_a, RULE, ATTRS, T1)
    b = resolve(state, obs_b, RULE, ATTRS, T1)
    assert a.exposure_id == b.exposure_id
    new_workload, _ = state.find_or_create_workload(NEW_ATTRS, T1)
    new_inc, _ = state.find_or_create_incarnation(new_workload, "host-n1", None, T1, T1)
    return state, (a, b), (obs_a, obs_b), new_workload, new_inc


class MembershipCorrectionTest(unittest.TestCase):
    def test_successful_populated_correction_preserves_ids_clocks_and_links(self):
        state, (a, b), (obs_a, obs_b), new_wl, new_inc = _populated_state()
        exp = state.exposures[a.exposure_id]
        old_workload_id = exp.workload_id
        state.link_observation(obs_a.observation_id, a.occurrence_id)
        state.link_observation(obs_b.observation_id, b.occurrence_id)
        before = {
            occ_id: (state.occurrences[occ_id].first_observed_at,
                     state.occurrences[occ_id].first_ingested_at,
                     state.occurrences[occ_id].created_at)
            for occ_id in (a.occurrence_id, b.occurrence_id)
        }
        records = state.apply_membership_correction(
            exp.exposure_id, new_wl.workload_id,
            {a.occurrence_id: new_inc.incarnation_id,
             b.occurrence_id: new_inc.incarnation_id},
            "reviewer", "verified successor mapping", "corr-mc-1", T2)
        self.assertEqual(state.exposures[exp.exposure_id].workload_id,
                         new_wl.workload_id)
        self.assertEqual(state.exposures[exp.exposure_id].first_observed_at,
                         exp.first_observed_at)
        self.assertNotIn((exp.group_id, old_workload_id), state._exposure_index)
        self.assertEqual(state._exposure_index[(exp.group_id, new_wl.workload_id)],
                         exp.exposure_id)
        for res in (a, b):
            occ = state.occurrences[res.occurrence_id]
            self.assertEqual(occ.incarnation_id, new_inc.incarnation_id)
            self.assertEqual(
                (occ.first_observed_at, occ.first_ingested_at, occ.created_at),
                before[res.occurrence_id])
        self.assertEqual(state.occurrence_for_observation(obs_a.observation_id),
                         a.occurrence_id)
        self.assertEqual(state.occurrence_for_observation(obs_b.observation_id),
                         b.occurrence_id)
        self.assertEqual(len(records), 3)

    def test_correction_rows_share_correlation_and_report_unverified_impact(self):
        state, (a, b), (obs_a, obs_b), new_wl, new_inc = _populated_state()
        exp = state.exposures[a.exposure_id]
        old_workload_id = exp.workload_id
        state.link_observation(obs_a.observation_id, a.occurrence_id)
        records = state.apply_membership_correction(
            exp.exposure_id, new_wl.workload_id,
            {a.occurrence_id: new_inc.incarnation_id,
             b.occurrence_id: new_inc.incarnation_id},
            "reviewer", "verified successor mapping", "corr-mc-2", T2)
        self.assertEqual(len(state.corrections), 3)
        self.assertTrue(all(r.correlation_id == "corr-mc-2" for r in records))
        for rec in records:
            self.assertEqual(rec.assessment_impact, "unverified")
            self.assertEqual(rec.issue_impact, "unverified")
        exp_rec = next(r for r in records if r.record_type == "exposure")
        self.assertEqual((exp_rec.field_name, exp_rec.old_value, exp_rec.new_value),
                         ("workload_id", old_workload_id, new_wl.workload_id))
        self.assertEqual(set(exp_rec.affected_record_ids),
                         {a.occurrence_id, b.occurrence_id,
                          obs_a.observation_id, obs_b.observation_id})
        for res in (a, b):
            occ_rec = next(r for r in records
                           if r.record_type == "occurrence"
                           and r.record_id == res.occurrence_id)
            self.assertEqual((occ_rec.field_name, occ_rec.old_value,
                              occ_rec.new_value),
                             ("incarnation_id", res.incarnation_id,
                              new_inc.incarnation_id))
            self.assertEqual(occ_rec.new_revision, occ_rec.previous_revision + 1)

    def test_incomplete_bundle_is_rejected_without_mutation(self):
        state, (a, b), _, new_wl, new_inc = _populated_state()
        exp = state.exposures[a.exposure_id]
        with self.assertRaises(ValueError):
            state.apply_membership_correction(
                exp.exposure_id, new_wl.workload_id,
                {a.occurrence_id: new_inc.incarnation_id},
                "reviewer", "partial mapping", "corr-mc-3", T2)
        self.assertEqual(state.exposures[a.exposure_id].workload_id, exp.workload_id)
        self.assertEqual(state.occurrences[a.occurrence_id].incarnation_id,
                         a.incarnation_id)
        self.assertEqual(state.occurrences[b.occurrence_id].incarnation_id,
                         b.incarnation_id)
        self.assertFalse(state.corrections)

    def test_foreign_occurrence_membership_is_rejected_without_mutation(self):
        state, (a, b), _, new_wl, new_inc = _populated_state()
        exp = state.exposures[a.exposure_id]
        other_group, _ = state.find_or_create_group(
            NativeGroupKey("qualys", "qualys-qid", "global", "999"), T1)
        other_wl, _ = state.find_or_create_workload(
            {"provisioning_key": "pk-3", "service_key": "svc-3"}, T1)
        other_exp, _ = state.find_or_create_exposure(other_group, other_wl, T0, T1)
        other_inc, _ = state.find_or_create_incarnation(other_wl, "host-z", None, T1, T1)
        other_occ, _ = state.find_or_create_occurrence(other_exp, other_inc,
                                                       "comp-z", T1, T1)
        with self.assertRaises(ValueError):
            state.apply_membership_correction(
                exp.exposure_id, new_wl.workload_id,
                {a.occurrence_id: new_inc.incarnation_id,
                 b.occurrence_id: new_inc.incarnation_id,
                 other_occ.occurrence_id: other_inc.incarnation_id},
                "reviewer", "unrelated membership", "corr-mc-4", T1)
        self.assertEqual(state.exposures[a.exposure_id].workload_id, exp.workload_id)
        self.assertFalse(state.corrections)

    def test_invalid_reference_and_wrong_workload_membership_rejected(self):
        state, (a, b), _, new_wl, new_inc = _populated_state()
        exp = state.exposures[a.exposure_id]
        foreign_wl, _ = state.find_or_create_workload(
            {"provisioning_key": "pk-3", "service_key": "svc-3"}, T1)
        foreign_inc, _ = state.find_or_create_incarnation(foreign_wl, "host-z",
                                                          None, T1, T1)
        for bad_target in (next_id("no-such-incarnation"),
                           foreign_inc.incarnation_id):
            with self.assertRaises(ValueError):
                state.apply_membership_correction(
                    exp.exposure_id, new_wl.workload_id,
                    {a.occurrence_id: bad_target,
                     b.occurrence_id: new_inc.incarnation_id},
                    "reviewer", "invalid reference", "corr-mc-5", T1)
        self.assertEqual(state.exposures[a.exposure_id].workload_id, exp.workload_id)
        self.assertEqual(state.occurrences[a.occurrence_id].incarnation_id,
                         a.incarnation_id)
        self.assertFalse(state.corrections)

    def test_exposure_index_collision_is_rejected_without_mutation(self):
        state, (a, b), _, new_wl, new_inc = _populated_state()
        exp = state.exposures[a.exposure_id]
        # Another exposure already holds the same group on the target workload.
        other_exp, _ = state.find_or_create_exposure(state.groups[exp.group_id],
                                                     new_wl, None, T1)
        self.assertNotEqual(other_exp.exposure_id, exp.exposure_id)
        with self.assertRaises(ValueError):
            state.apply_membership_correction(
                exp.exposure_id, new_wl.workload_id,
                {a.occurrence_id: new_inc.incarnation_id,
                 b.occurrence_id: new_inc.incarnation_id},
                "reviewer", "collision", "corr-mc-6", T1)
        self.assertEqual(state.exposures[a.exposure_id].workload_id, exp.workload_id)
        self.assertFalse(state.corrections)

    def test_shared_incarnation_collision_is_atomically_rejected(self):
        # Two occurrences of one exposure (same component locator on two
        # incarnations) both mapped onto a single successor incarnation would
        # collide the occurrence index: the whole bundle must be rejected.
        state = IdentityState()
        obs_a = make_observation(component_locator="comp-a")
        obs_b = make_observation(component_locator="comp-a",
                                 asset_locator="host-b", run_id="run-2")
        a = resolve(state, obs_a, RULE, ATTRS, T1)
        b = resolve(state, obs_b, RULE, ATTRS, T1)
        self.assertEqual(a.exposure_id, b.exposure_id)
        self.assertNotEqual(a.incarnation_id, b.incarnation_id)
        exp = state.exposures[a.exposure_id]
        old_workload_id = exp.workload_id
        new_wl, _ = state.find_or_create_workload(NEW_ATTRS, T1)
        new_inc, _ = state.find_or_create_incarnation(new_wl, "host-c", None, T1, T1)
        with self.assertRaises(ValueError):
            state.apply_membership_correction(
                exp.exposure_id, new_wl.workload_id,
                {a.occurrence_id: new_inc.incarnation_id,
                 b.occurrence_id: new_inc.incarnation_id},
                "reviewer", "shared incarnation", "corr-mc-7", T1)
        self.assertEqual(state.exposures[a.exposure_id].workload_id,
                         old_workload_id)
        self.assertEqual(state.occurrences[a.occurrence_id].incarnation_id,
                         a.incarnation_id)
        self.assertEqual(state.occurrences[b.occurrence_id].incarnation_id,
                         b.incarnation_id)
        self.assertFalse(state.corrections)

    def test_invalid_linked_observation_id_rejected_before_any_mutation(self):
        # A linked observation id outside the UVM UUID contract must reject
        # the correction before ANY mutation (Reviewer 39015fd finding 1,
        # FR-ID-02 append-only lineage).
        state, (a, b), _, new_wl, new_inc = _populated_state()
        exp = state.exposures[a.exposure_id]
        raw_obs_id = "qualys-obs-raw-1"  # not a canonical UVM UUID
        state.link_observation(raw_obs_id, a.occurrence_id)
        occ_a = state.occurrences[a.occurrence_id]
        old_locator = occ_a.component_locator
        with self.assertRaises(ValueError):
            state.record_correction("occurrence", occ_a.occurrence_id,
                                    old_locator, "comp-a2", "reviewer",
                                    "bad linked observation", "corr-iv-1",
                                    (), T2)
        self.assertEqual(state.occurrences[a.occurrence_id].component_locator,
                         old_locator)
        self.assertEqual(state.occurrences[a.occurrence_id].revision, 1)
        self.assertEqual(state._occurrence_index[
            (exp.exposure_id, a.incarnation_id, old_locator)], a.occurrence_id)
        self.assertFalse(state.corrections)
        # Same prevalidation on the atomic bundle path.
        with self.assertRaises(ValueError):
            state.apply_membership_correction(
                exp.exposure_id, new_wl.workload_id,
                {a.occurrence_id: new_inc.incarnation_id,
                 b.occurrence_id: new_inc.incarnation_id},
                "reviewer", "bad linked observation", "corr-iv-2", T2)
        self.assertEqual(state.exposures[a.exposure_id].workload_id,
                         exp.workload_id)
        self.assertEqual(state.occurrences[a.occurrence_id].incarnation_id,
                         a.incarnation_id)
        self.assertEqual(state.occurrences[b.occurrence_id].incarnation_id,
                         b.incarnation_id)
        self.assertFalse(state.corrections)

    def test_proposed_mapping_holding_foreign_exposure_alias_rejected(self):
        # The proposed active exposure mapping may not hold a value that is
        # historical (retired) to ANOTHER exposure: reject atomically,
        # preserving scalar-path resolver semantics (Reviewer 39015fd
        # finding 2, FR-ID-02/CR-03).
        state, (a, b), _, new_wl, new_inc = _populated_state()
        exp = state.exposures[a.exposure_id]
        old_workload_id = exp.workload_id
        # Second exposure of the same group on the proposed target workload.
        other_exp, _ = state.find_or_create_exposure(state.groups[exp.group_id],
                                                     new_wl, None, T1)
        # Move it away (empty exposure, scalar path), retiring new_wl as a
        # historical value owned by the other exposure.
        third_wl, _ = state.find_or_create_workload(
            {"provisioning_key": "pk-9", "service_key": "svc-9"}, T1)
        state.record_correction("exposure", other_exp.exposure_id,
                                new_wl.workload_id, third_wl.workload_id,
                                "reviewer", "move away", "corr-fa-1", (), T1)
        with self.assertRaises(ValueError):
            state.apply_membership_correction(
                exp.exposure_id, new_wl.workload_id,
                {a.occurrence_id: new_inc.incarnation_id,
                 b.occurrence_id: new_inc.incarnation_id},
                "reviewer", "foreign alias", "corr-fa-2", T2)
        self.assertEqual(state.exposures[a.exposure_id].workload_id,
                         old_workload_id)
        self.assertEqual(state.occurrences[a.occurrence_id].incarnation_id,
                         a.incarnation_id)
        self.assertEqual(state.occurrences[b.occurrence_id].incarnation_id,
                         b.incarnation_id)
        self.assertEqual(len(state.corrections), 1)  # only the setup move

    def test_null_component_locator_never_indexed_and_may_share_target_scope(self):
        # Distinct null-locator occurrences may move into one target scope
        # without coalescing, and a null locator is never written to
        # _occurrence_index (Reviewer 39015fd finding 3, CR-03/CR-04).
        state, (a, b), _, new_wl, new_inc = _populated_state()
        exp = state.exposures[a.exposure_id]
        for occ_id in (a.occurrence_id, b.occurrence_id):
            occ = state.occurrences[occ_id]
            state.record_correction("occurrence", occ_id,
                                    occ.component_locator, None, "reviewer",
                                    "locator withdrawn", "corr-nl-1", (), T2)
            self.assertIsNone(state.occurrences[occ_id].component_locator)
        records = state.apply_membership_correction(
            exp.exposure_id, new_wl.workload_id,
            {a.occurrence_id: new_inc.incarnation_id,
             b.occurrence_id: new_inc.incarnation_id},
            "reviewer", "verified successor mapping", "corr-nl-2", T2)
        self.assertEqual(state.occurrences[a.occurrence_id].incarnation_id,
                         new_inc.incarnation_id)
        self.assertEqual(state.occurrences[b.occurrence_id].incarnation_id,
                         new_inc.incarnation_id)
        # No coalescing: both distinct occurrences retained.
        self.assertIn(a.occurrence_id, state.occurrences)
        self.assertIn(b.occurrence_id, state.occurrences)
        self.assertNotIn((exp.exposure_id, new_inc.incarnation_id, None),
                         state._occurrence_index)
        self.assertEqual(len(records), 3)

    def test_scalar_reversal_retires_alias_only_after_full_validation(self):
        # Reviewer 37abc457: the scalar path retired the historical alias
        # BEFORE validating the linked observation IDs, so a bad raw
        # observation id rejected the correction but left the alias retired.
        # Retirement must happen after all affected-ID validation, before
        # the final commit (FR-ID-02/CR-03).
        state = IdentityState()
        obs = make_observation(component_locator="comp-a", asset_locator="host-a")
        res = resolve(state, obs, RULE, ATTRS, T1)
        occ_id = res.occurrence_id
        exp = state.exposures[res.exposure_id]
        # First correction retires "comp-a" as a historical alias of this
        # occurrence.
        state.record_correction("occurrence", occ_id, "comp-a", "comp-a1",
                                "reviewer", "rename", "corr-rev-1", (), T2)
        self.assertEqual(state.occurrences[occ_id].component_locator, "comp-a1")
        alias_key = ("occurrence", "component_locator", exp.exposure_id,
                     res.incarnation_id, "comp-a")
        self.assertEqual(state.mapping_aliases[alias_key], occ_id)
        self.assertEqual(state.aliases["comp-a"], occ_id)
        # Link a raw (non-UVM-UUID) observation id to the occurrence AFTER
        # the first correction so it only rejects the reversal.
        state.link_observation("qualys-obs-raw-1", occ_id)
        revision = state.occurrences[occ_id].revision
        index = dict(state._occurrence_index)
        aliases_snapshot = dict(state.aliases)
        mapping_snapshot = dict(state.mapping_aliases)
        corrections = list(state.corrections)
        # Reversal back to the retired value must be rejected wholesale with
        # state, index, aliases and corrections all unchanged.
        with self.assertRaises(ValueError):
            state.record_correction("occurrence", occ_id, "comp-a1", "comp-a",
                                    "reviewer", "reversal", "corr-rev-2", (), T2)
        self.assertEqual(state.occurrences[occ_id].component_locator, "comp-a1")
        self.assertEqual(state.occurrences[occ_id].revision, revision)
        self.assertEqual(state._occurrence_index, index)
        self.assertEqual(state.mapping_aliases, mapping_snapshot)
        self.assertEqual(state.aliases, aliases_snapshot)
        self.assertEqual(state.corrections, corrections)

    def test_scalar_workload_correction_still_rejects_populated_exposure(self):
        # model.py scalar path: a populated exposure's workload cannot be
        # moved by a single field correction (FR-ID-02, G1 design).
        state, (a, _), _, new_wl, _ = _populated_state()
        exp = state.exposures[a.exposure_id]
        old_workload_id = exp.workload_id
        with self.assertRaises(ValueError):
            state.record_correction("exposure", exp.exposure_id,
                                    old_workload_id, new_wl.workload_id,
                                    "reviewer", "cannot scalar", "corr-scalar",
                                    (), T2)
        self.assertEqual(state.exposures[a.exposure_id].workload_id,
                         old_workload_id)
        self.assertFalse(state.corrections)


if __name__ == "__main__":
    unittest.main()
