"""FR-ID-01/02, CR-03: IdentityResolutionV2 DTO contract (approved
revision-anchor amendment, decision recorded at d5fe24d).

Synthetic unit label only: no integration or external data, no temporal
claim beyond the DTO's own validation. V1 behaviour is nonregressed.
"""

import unittest
import json
from dataclasses import FrozenInstanceError
from datetime import datetime, timedelta, timezone
from uuid import uuid4

from uvm.identity import (
    SCHEMA_VERSION,
    IdentityResolutionV1,
    IdentityResolutionV2,
    SCHEMA_VERSION_V2,
)
from uvm.identity.model import OUTCOMES

from tests.identity.fixtures import T1


def _uuid() -> str:
    return str(uuid4())


def _base(outcome: str, **overrides) -> dict:
    exposure_id = _uuid()
    occurrence_id = _uuid()
    values = dict(
        schema_version=SCHEMA_VERSION_V2,
        resolution_id=_uuid(),
        revision=1,
        observation_id=_uuid(),
        rule_id="rule-1",
        rule_version=1,
        matching_inputs={"provisioning_key": "pk-1"},
        candidate_workload_ids=(_uuid(),),
        outcome=outcome,
        evaluated_at=T1,
        group_id=_uuid(),
        workload_id=_uuid(),
        incarnation_id=_uuid(),
        exposure_id=exposure_id,
        occurrence_id=occurrence_id,
        selected_exposure_revision=2,
        selected_occurrence_revision=1,
    )
    if outcome in ("ambiguous", "unresolved"):
        # The selected-membership/anchor fields must be null for these
        # outcomes; build from the unselected shape.
        values.update(group_id=None, workload_id=None, incarnation_id=None,
                      exposure_id=None, occurrence_id=None,
                      selected_exposure_revision=None,
                      selected_occurrence_revision=None)
    values.update(overrides)
    return values


class ResolutionV2ShapeTest(unittest.TestCase):
    def test_matched_carries_positive_anchors_tied_to_selected_ids(self):
        record = IdentityResolutionV2(**_base("matched"))
        self.assertEqual(record.outcome, "matched")
        self.assertEqual(record.selected_exposure_revision, 2)
        self.assertEqual(record.selected_occurrence_revision, 1)
        self.assertIsNotNone(record.exposure_id)
        self.assertIsNotNone(record.occurrence_id)

    def test_new_carries_positive_anchors(self):
        record = IdentityResolutionV2(**_base("new"))
        self.assertEqual(record.outcome, "new")
        self.assertGreater(record.selected_exposure_revision, 0)
        self.assertGreater(record.selected_occurrence_revision, 0)

    def test_ambiguous_selects_no_membership_or_anchor(self):
        workload_a, workload_b = _uuid(), _uuid()
        record = IdentityResolutionV2(
            **_base("ambiguous", candidate_workload_ids=(workload_a, workload_b),
                    candidate_explanations=(
                        {"workload_id": workload_a},
                        {"workload_id": workload_b})))
        self.assertIsNone(record.exposure_id)
        self.assertIsNone(record.occurrence_id)
        self.assertIsNone(record.selected_exposure_revision)
        self.assertIsNone(record.selected_occurrence_revision)
        # The not_applicable temporal-selection status is a later reader
        # derivation, not a persisted field.
        self.assertFalse(hasattr(record, "temporal_selection_status"))

    def test_unresolved_selects_no_membership_or_anchor(self):
        record = IdentityResolutionV2(
            **_base("unresolved", reason="no safe match",
                    candidate_workload_ids=()))
        self.assertIsNone(record.exposure_id)
        self.assertIsNone(record.selected_exposure_revision)
        self.assertIsNone(record.selected_occurrence_revision)

    def test_frozen_immutable(self):
        record = IdentityResolutionV2(**_base("matched"))
        with self.assertRaises(FrozenInstanceError):
            record.selected_exposure_revision = 3
        with self.assertRaises(FrozenInstanceError):
            record.outcome = OUTCOMES[0]


class ResolutionV2AnchorValidationTest(unittest.TestCase):
    def _reject(self, **kwargs):
        with self.assertRaises(ValueError):
            IdentityResolutionV2(**_base("matched", **kwargs))

    def test_zero_revision_rejected(self):
        self._reject(selected_exposure_revision=0)
        self._reject(selected_occurrence_revision=0)

    def test_negative_revision_rejected(self):
        self._reject(selected_exposure_revision=-1)

    def test_bool_revision_rejected(self):
        self._reject(selected_exposure_revision=True)
        self._reject(selected_occurrence_revision=False)

    def test_non_integer_revision_rejected(self):
        self._reject(selected_exposure_revision=1.0)
        self._reject(selected_occurrence_revision="1")
        self._reject(selected_exposure_revision=None)

    def test_anchor_without_selected_ids_rejected(self):
        self._reject(exposure_id=None)
        self._reject(occurrence_id=None)
        with self.assertRaises(ValueError):
            IdentityResolutionV2(**_base("new", exposure_id=None,
                                         occurrence_id=None))

    def test_ambiguous_or_unresolved_with_anchor_rejected(self):
        with self.assertRaises(ValueError):
            IdentityResolutionV2(**_base("ambiguous",
                                         selected_exposure_revision=1))
        with self.assertRaises(ValueError):
            IdentityResolutionV2(**_base("ambiguous", exposure_id=_uuid()))
        with self.assertRaises(ValueError):
            IdentityResolutionV2(**_base("unresolved",
                                         selected_occurrence_revision=1))
        with self.assertRaises(ValueError):
            IdentityResolutionV2(**_base("unresolved", occurrence_id=_uuid()))

    def test_unsupported_outcome_rejected(self):
        values = _base("matched")
        values["outcome"] = "verified"
        with self.assertRaises(ValueError):
            IdentityResolutionV2(**values)

    def test_wrong_schema_version_rejected(self):
        with self.assertRaises(ValueError):
            IdentityResolutionV2(**_base("matched", schema_version=1))

    def test_non_canonical_uuid_rejected(self):
        with self.assertRaises(ValueError):
            IdentityResolutionV2(**_base("matched", resolution_id="not-a-uuid"))
        with self.assertRaises(ValueError):
            IdentityResolutionV2(
                **_base("matched", candidate_workload_ids=("UPPERCASE-NOPE",)))


class ResolutionV2DefectRegressionTest(unittest.TestCase):
    """Failing-first regressions for reviewer b502a9dc reproductions."""

    # --- matched/new must reject missing group/workload/incarnation ---

    def test_matched_missing_group_id_rejected(self):
        with self.assertRaises(ValueError):
            IdentityResolutionV2(**_base("matched", group_id=None))

    def test_matched_missing_workload_id_rejected(self):
        with self.assertRaises(ValueError):
            IdentityResolutionV2(**_base("matched", workload_id=None))

    def test_matched_missing_incarnation_id_rejected(self):
        with self.assertRaises(ValueError):
            IdentityResolutionV2(**_base("matched", incarnation_id=None))

    def test_new_missing_group_id_rejected(self):
        with self.assertRaises(ValueError):
            IdentityResolutionV2(**_base("new", group_id=None))

    def test_new_missing_workload_id_rejected(self):
        with self.assertRaises(ValueError):
            IdentityResolutionV2(**_base("new", workload_id=None))

    def test_new_missing_incarnation_id_rejected(self):
        with self.assertRaises(ValueError):
            IdentityResolutionV2(**_base("new", incarnation_id=None))

    # --- ambiguous must reject selected workload ---

    def test_ambiguous_selected_workload_rejected(self):
        with self.assertRaises(ValueError):
            IdentityResolutionV2(**_base("ambiguous", workload_id=_uuid()))

    def test_ambiguous_selected_incarnation_rejected(self):
        with self.assertRaises(ValueError):
            IdentityResolutionV2(**_base("ambiguous", incarnation_id=_uuid()))

    def test_ambiguous_known_group_preserves_group_without_selecting_membership(self):
        first, second, group_id = _uuid(), _uuid(), _uuid()
        values = _base(
            "ambiguous", group_id=group_id,
            candidate_workload_ids=(first, second),
            candidate_explanations=({"workload_id": first, "why": "candidate"},
                                    {"workload_id": second, "why": "candidate"}),
        )
        record = IdentityResolutionV2(**values)
        self.assertEqual(record.group_id, group_id)
        self.assertIsNone(record.workload_id)
        self.assertIsNone(record.incarnation_id)
        self.assertIsNone(record.exposure_id)
        self.assertIsNone(record.occurrence_id)
        self.assertIsNone(record.selected_exposure_revision)
        self.assertIsNone(record.selected_occurrence_revision)
        self.assertEqual(json.loads(json.dumps(record.to_primitives()))["group_id"],
                         group_id)
        for name in ("workload_id", "incarnation_id", "exposure_id",
                     "occurrence_id"):
            with self.subTest(name=name), self.assertRaises(ValueError):
                IdentityResolutionV2(**{**values, name: _uuid()})

    # --- unresolved must reject selected group ---

    def test_unresolved_selected_group_rejected(self):
        with self.assertRaises(ValueError):
            IdentityResolutionV2(**_base("unresolved", group_id=_uuid()))

    def test_unresolved_selected_workload_rejected(self):
        with self.assertRaises(ValueError):
            IdentityResolutionV2(**_base("unresolved", workload_id=_uuid()))

    def test_unresolved_selected_incarnation_rejected(self):
        with self.assertRaises(ValueError):
            IdentityResolutionV2(**_base("unresolved", incarnation_id=_uuid()))

    # --- revision and rule_version must be positive integers ---

    def test_zero_record_revision_rejected(self):
        with self.assertRaises(ValueError):
            IdentityResolutionV2(**_base("matched", revision=0))

    def test_negative_record_revision_rejected(self):
        with self.assertRaises(ValueError):
            IdentityResolutionV2(**_base("matched", revision=-1))

    def test_bool_record_revision_rejected(self):
        with self.assertRaises(ValueError):
            IdentityResolutionV2(**_base("matched", revision=True))

    def test_zero_rule_version_rejected(self):
        with self.assertRaises(ValueError):
            IdentityResolutionV2(**_base("matched", rule_version=0))

    def test_negative_rule_version_rejected(self):
        with self.assertRaises(ValueError):
            IdentityResolutionV2(**_base("matched", rule_version=-3))

    def test_bool_rule_version_rejected(self):
        with self.assertRaises(ValueError):
            IdentityResolutionV2(**_base("matched", rule_version=True))

    def test_non_integer_rule_version_rejected(self):
        with self.assertRaises(ValueError):
            IdentityResolutionV2(**_base("matched", rule_version=1.0))

    # --- deep immutability: no caller aliasing ---

    def test_caller_mutation_of_matching_inputs_not_visible_in_dto(self):
        caller_dict = {"provisioning_key": "pk-1"}
        record = IdentityResolutionV2(
            **_base("matched", matching_inputs=caller_dict))
        caller_dict["provisioning_key"] = "CHANGED"
        self.assertEqual(record.matching_inputs["provisioning_key"], "pk-1")

    def test_caller_mutation_of_candidate_explanations_not_visible_in_dto(self):
        explanation = {"workload_id": _uuid()}
        record = IdentityResolutionV2(
            **_base("matched", candidate_explanations=(explanation,)))
        explanation["workload_id"] = "CHANGED"
        self.assertNotEqual(record.candidate_explanations[0]["workload_id"],
                            "CHANGED")

    # --- deep immutability: mutation through DTO raises ---

    def test_mutation_through_dto_matching_inputs_raises(self):
        record = IdentityResolutionV2(**_base("matched"))
        with self.assertRaises(TypeError):
            record.matching_inputs["x"] = "y"

    def test_mutation_through_dto_candidate_explanations_raises(self):
        record = IdentityResolutionV2(
            **_base("matched", candidate_explanations=({"a": "b"},)))
        with self.assertRaises(TypeError):
            record.candidate_explanations[0]["a"] = "c"

    def test_deletion_through_dto_matching_inputs_raises(self):
        record = IdentityResolutionV2(
            **_base("matched", matching_inputs={"k": "v"}))
        with self.assertRaises(TypeError):
            del record.matching_inputs["k"]

    def test_nested_caller_aliases_cannot_change_evidence(self):
        inputs = {"proof": [{"signals": ["first", {"valid": True}]}]}
        explanation = {"details": {"reasons": ["stable", {"weight": 3}]}}
        explanations = [explanation]
        record = IdentityResolutionV2(**_base(
            "matched", matching_inputs=inputs,
            candidate_explanations=explanations))

        inputs["proof"][0]["signals"][0] = "changed"
        inputs["proof"][0]["signals"][1]["valid"] = False
        explanation["details"]["reasons"][0] = "changed"
        explanation["details"]["reasons"][1]["weight"] = 99
        explanations.append({"extra": "candidate"})

        self.assertEqual(record.matching_inputs["proof"][0]["signals"],
                         ("first", {"valid": True}))
        self.assertEqual(record.candidate_explanations[0]["details"]["reasons"],
                         ("stable", {"weight": 3}))
        self.assertEqual(len(record.candidate_explanations), 1)

    def test_nested_evidence_cannot_be_mutated_through_dto(self):
        record = IdentityResolutionV2(**_base(
            "matched", matching_inputs={"proof": [{"tags": ["a"]}]},
            candidate_explanations=({"details": {"reasons": ["x"]}},)))
        with self.assertRaises(TypeError):
            record.matching_inputs["proof"][0]["tags"][0] = "changed"
        with self.assertRaises(AttributeError):
            record.matching_inputs["proof"].append("changed")
        with self.assertRaises(TypeError):
            record.candidate_explanations[0]["details"]["reasons"][0] = "changed"
        with self.assertRaises(TypeError):
            record.candidate_explanations[0]["details"]["new"] = "changed"

    def test_unsupported_nested_values_and_keys_are_rejected(self):
        for evidence in ({"proof": [{"bad": object()}]},
                         {"proof": [{"bad": {1, 2}}]},
                         {"proof": [{1: "non-string key"}]},
                         {"proof": [float("nan")]},
                         {"proof": [float("inf")]}):
            with self.subTest(evidence=evidence), self.assertRaises(ValueError):
                IdentityResolutionV2(**_base("matched", matching_inputs=evidence))
        with self.assertRaises(ValueError):
            IdentityResolutionV2(**_base(
                "matched", candidate_explanations=({"bad": [object()]},)))
        with self.assertRaises(ValueError):
            IdentityResolutionV2(**_base(
                "matched", candidate_explanations=("not an object",)))

    def test_huge_nested_integer_is_rejected_before_dto_is_returned(self):
        huge_integer = 10 ** 4999  # Exactly 5000 decimal digits.
        for evidence in ({"proof": [{"count": huge_integer}]},
                         {"proof": [{"count": -huge_integer}]}):
            with self.subTest(sign=evidence["proof"][0]["count"] < 0):
                with self.assertRaisesRegex(ValueError, "JSON.serialisable"):
                    IdentityResolutionV2(**_base(
                        "matched", matching_inputs=evidence))
        with self.assertRaisesRegex(ValueError, "JSON.serialisable"):
            IdentityResolutionV2(**_base(
                "matched", candidate_explanations=(
                    {"proof": [{"count": huge_integer}]},)))

    def test_cyclic_evidence_is_rejected_without_recursion_error(self):
        inputs = {}
        inputs["self"] = inputs
        reasons = []
        reasons.append(reasons)
        with self.assertRaisesRegex(ValueError, "cycle"):
            IdentityResolutionV2(**_base("matched", matching_inputs=inputs))
        with self.assertRaisesRegex(ValueError, "cycle"):
            IdentityResolutionV2(**_base(
                "matched", candidate_explanations=({"reasons": reasons},)))

    def test_evidence_beyond_python_recursion_limit_is_copied(self):
        nested = "leaf"
        for _ in range(1100):
            nested = [nested]
        record = IdentityResolutionV2(**_base(
            "matched", matching_inputs={"deep": nested}))
        json.dumps(record.to_primitives())
        frozen = record.matching_inputs["deep"]
        plain = record.to_primitives()["matching_inputs"]["deep"]
        for _ in range(1100):
            self.assertIs(type(frozen), tuple)
            self.assertIs(type(plain), list)
            frozen = frozen[0]
            plain = plain[0]
        self.assertEqual((frozen, plain), ("leaf", "leaf"))

    def test_candidate_id_array_is_copied_to_tuple(self):
        ids = [_uuid(), _uuid()]
        record = IdentityResolutionV2(**_base(
            "ambiguous", candidate_workload_ids=ids,
            candidate_explanations=tuple({"workload_id": candidate}
                                         for candidate in ids)))
        ids.append(_uuid())
        self.assertEqual(record.candidate_workload_ids, tuple(ids[:2]))
        self.assertIs(type(record.to_primitives()["candidate_workload_ids"]), list)

    def test_primitive_conversion_is_json_ready_and_roundtrips_shape(self):
        first, second = _uuid(), _uuid()
        record = IdentityResolutionV2(**_base(
            "ambiguous", candidate_workload_ids=(first, second),
            matching_inputs={"proof": [{"weight": 2.5, "present": None}]},
            candidate_explanations=(
                {"workload_id": first, "reasons": ["one", {"score": 1}]},
                {"workload_id": second, "reasons": ["two"]})))
        primitive = record.to_primitives()
        self.assertEqual(json.loads(json.dumps(primitive)), primitive)
        self.assertIs(type(primitive), dict)
        self.assertIs(type(primitive["matching_inputs"]["proof"]), list)
        self.assertIs(type(primitive["candidate_explanations"]), list)
        self.assertEqual(primitive["evaluated_at"], T1.isoformat())

        # The persisted timestamp is restored to datetime by the later reader.
        restored = IdentityResolutionV2(**{
            **primitive, "evaluated_at": datetime.fromisoformat(
                primitive["evaluated_at"]),
        })
        self.assertEqual(restored.to_primitives(), primitive)
        primitive["matching_inputs"]["proof"][0]["weight"] = 99
        primitive["candidate_explanations"][0]["reasons"].append("changed")
        self.assertEqual(record.matching_inputs["proof"][0]["weight"], 2.5)
        self.assertEqual(record.candidate_explanations[0]["reasons"],
                         ("one", {"score": 1}))

    # --- positive controls: full outcome shapes ---

    def test_matched_full_shape_accepted(self):
        record = IdentityResolutionV2(
            **_base("matched",
                    candidate_explanations=(
                        {"workload_id": _uuid(), "score": "0.9"},)))
        self.assertEqual(record.outcome, "matched")
        self.assertEqual(record.revision, 1)
        self.assertEqual(record.rule_version, 1)
        self.assertIsNotNone(record.group_id)
        self.assertIsNotNone(record.workload_id)
        self.assertIsNotNone(record.incarnation_id)
        self.assertIsNotNone(record.exposure_id)
        self.assertIsNotNone(record.occurrence_id)

    def test_new_full_shape_accepted(self):
        record = IdentityResolutionV2(
            **_base("new", selected_exposure_revision=1,
                    selected_occurrence_revision=1,
                    reason="new identity"))
        self.assertEqual(record.outcome, "new")
        self.assertIsNotNone(record.group_id)

    def test_ambiguous_full_shape_accepted(self):
        wa, wb = _uuid(), _uuid()
        record = IdentityResolutionV2(
            **_base("ambiguous",
                    candidate_workload_ids=(wa, wb),
                    candidate_explanations=(
                        {"workload_id": wa, "reason": "r1"},
                        {"workload_id": wb, "reason": "r2"})))
        self.assertEqual(record.outcome, "ambiguous")
        self.assertIsNone(record.group_id)
        self.assertIsNone(record.workload_id)
        self.assertIsNone(record.incarnation_id)
        self.assertIsNone(record.exposure_id)
        self.assertIsNone(record.occurrence_id)

    def test_unresolved_full_shape_accepted(self):
        record = IdentityResolutionV2(
            **_base("unresolved", reason="no candidate matched",
                    candidate_workload_ids=()))
        self.assertEqual(record.outcome, "unresolved")
        self.assertIsNone(record.group_id)
        self.assertIsNone(record.workload_id)


class ResolutionV2ScalarAndAmbiguityRegressionTest(unittest.TestCase):
    """Reviewer 68760dd9: every accepted V2 value remains serialisable."""

    def test_rule_id_must_be_a_nonempty_string(self):
        for rule_id in ({"rule": "one"}, ["rule"], "", None, 1):
            with self.subTest(rule_id=rule_id), self.assertRaises(ValueError):
                IdentityResolutionV2(**_base("matched", rule_id=rule_id))

    def test_reason_must_be_string_or_null(self):
        for reason in (["mutable"], {"mutable": True}, 3, False):
            with self.subTest(reason=reason), self.assertRaises(ValueError):
                IdentityResolutionV2(**_base("matched", reason=reason))

    def test_schema_version_must_be_exact_integer_two(self):
        for version in (2.0, True, "2", None):
            with self.subTest(version=version), self.assertRaises(ValueError):
                IdentityResolutionV2(**_base("matched", schema_version=version))

    def test_evaluated_at_must_be_timezone_aware_datetime(self):
        for evaluated_at in (datetime(2026, 1, 1), "2026-01-01T00:00:00Z",
                             None):
            with self.subTest(evaluated_at=evaluated_at), self.assertRaises(ValueError):
                IdentityResolutionV2(**_base("matched", evaluated_at=evaluated_at))

    def test_aware_evaluated_at_is_normalised_to_utc(self):
        local_time = datetime(2026, 1, 1, 13, 30,
                              tzinfo=timezone(timedelta(hours=1)))
        record = IdentityResolutionV2(**_base("matched", evaluated_at=local_time))
        self.assertEqual(record.evaluated_at, datetime(2026, 1, 1, 12, 30,
                                                       tzinfo=timezone.utc))
        self.assertEqual(record.to_primitives()["evaluated_at"],
                         "2026-01-01T12:30:00+00:00")

    def test_ambiguous_requires_two_distinct_candidates(self):
        first = _uuid()
        for candidates, explanations in (
            ((), ()),
            ((first,), ({"workload_id": first},)),
            ((first, first), ({"workload_id": first},
                              {"workload_id": first})),
        ):
            with self.subTest(candidates=candidates), self.assertRaises(ValueError):
                IdentityResolutionV2(**_base(
                    "ambiguous", candidate_workload_ids=candidates,
                    candidate_explanations=explanations))

    def test_ambiguous_requires_one_explanation_per_candidate_id(self):
        first, second, other = _uuid(), _uuid(), _uuid()
        for explanations in (
            (),
            ({"workload_id": first},),
            ({"why": "first"}, {"workload_id": second}),
            ({"workload_id": first}, {"workload_id": first}),
            ({"workload_id": first}, {"workload_id": other}),
            ({"workload_id": first}, {"workload_id": "not-a-uuid"}),
            ({"workload_id": first}, {"workload_id": second},
             {"workload_id": other}),
        ):
            with self.subTest(explanations=explanations), self.assertRaises(ValueError):
                IdentityResolutionV2(**_base(
                    "ambiguous", candidate_workload_ids=(first, second),
                    candidate_explanations=explanations))

    def test_accepted_values_are_stable_and_primitives_are_fresh(self):
        first, second = _uuid(), _uuid()
        candidates = [first, second]
        explanation = {"workload_id": first, "details": ["unchanged"]}
        record = IdentityResolutionV2(**_base(
            "ambiguous", candidate_workload_ids=candidates,
            candidate_explanations=(explanation, {"workload_id": second}),
            matching_inputs={"proof": [{"valid": True}]}, reason="review"))
        before = record.to_primitives()
        candidates[0] = _uuid()
        explanation["details"].append("changed")
        self.assertEqual(record.to_primitives(), before)
        before["candidate_workload_ids"][0] = _uuid()
        before["candidate_explanations"][0]["details"].append("changed")
        before["matching_inputs"]["proof"][0]["valid"] = False
        after = record.to_primitives()
        self.assertEqual(after["candidate_workload_ids"], [first, second])
        self.assertEqual(after["candidate_explanations"][0]["details"],
                         ["unchanged"])
        self.assertTrue(after["matching_inputs"]["proof"][0]["valid"])
        self.assertEqual(json.loads(json.dumps(after)), after)


class ResolutionV1NonregressionTest(unittest.TestCase):
    def test_v1_constructor_unchanged_and_v1_schema_preserved(self):
        # V1 still validates, still stores schema_version 1, and needs no
        # anchors.
        record = IdentityResolutionV1(
            schema_version=1,
            resolution_id=_uuid(),
            revision=1,
            observation_id=_uuid(),
            rule_id="rule-1",
            rule_version=1,
            matching_inputs={},
            candidate_workload_ids=(),
            outcome="matched",
            evaluated_at=T1,
            group_id=_uuid(),
            workload_id=_uuid(),
            incarnation_id=_uuid(),
            exposure_id=_uuid(),
            occurrence_id=_uuid(),
        )
        self.assertEqual(record.schema_version, SCHEMA_VERSION)
        self.assertFalse(hasattr(record, "selected_exposure_revision"))
        self.assertFalse(hasattr(record, "selected_occurrence_revision"))

    def test_v1_outcomes_unchanged(self):
        self.assertEqual(OUTCOMES,
                         ("matched", "new", "ambiguous", "unresolved"))
        self.assertEqual(SCHEMA_VERSION, 1)
        self.assertEqual(SCHEMA_VERSION_V2, 2)


if __name__ == "__main__":
    unittest.main()
