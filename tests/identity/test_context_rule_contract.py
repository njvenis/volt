import unittest
from datetime import datetime, timezone

from uvm.identity.resolver import RuleV1
from uvm.persistence.identity_repository import IdentityRepository


class WorkloadContextRuleContractTest(unittest.TestCase):
    def test_legacy_and_nonempty_definition_digest_golden(self):
        legacy = RuleV1("r", 1, ("provisioning_key", "service_key"),
            verified_asset_locator=True)
        contextual = RuleV1("r", 1, ("provisioning_key", "service_key"),
            verified_asset_locator=True, workload_context_fields=("environment",))
        self.assertEqual(IdentityRepository._rule_digest(legacy),
            "6ad174d7105acaa0f301671dad9bf4ff93e5b51a31dee5ebc84764959faf9bf7")
        self.assertEqual(IdentityRepository._rule_digest(contextual),
            "310bb8393829ed6763ad4816a1791eddc1823300b80f737dde73f713f43bcc58")

    def test_request_fingerprint_legacy_and_nonempty_golden(self):
        at = datetime(2026, 9, 8, 8, tzinfo=timezone.utc)
        legacy = RuleV1("r", 1, ("provisioning_key", "service_key"),
            verified_asset_locator=True)
        contextual = RuleV1("r", 1, ("provisioning_key", "service_key"),
            verified_asset_locator=True, workload_context_fields=("environment",))
        self.assertEqual(IdentityRepository._request_fingerprint(
            observation_id="obs", observation_revision=1, rule=legacy,
            matching_inputs={"provisioning_key": "pk-1"}, evaluated_at=at),
            "39c0ac355f40936972cb0a65584ffe4de4bc026af155ec3629d9ca6656b8ceb8")
        self.assertEqual(IdentityRepository._request_fingerprint(
            observation_id="obs", observation_revision=1, rule=contextual,
            matching_inputs={"environment": "local", "provisioning_key": "pk-1"},
            evaluated_at=at),
            "8be2bb49c42897f017ff1b161555cb24eb438acfa38fa2a1f1a5722d230d7ad8")

    def test_stored_context_must_be_an_exact_array_without_duplicates_or_overlap(self):
        check = IdentityRepository._stored_context_fields
        self.assertEqual(check(["environment"], ["provisioning_key"]), ("environment",))
        for malformed in ("environment", ("environment",), {"environment": True},
                          ["environment", "environment"], [" provisioning_key"]):
            with self.subTest(malformed=malformed), self.assertRaises(ValueError):
                check(malformed, ["provisioning_key"])
        with self.assertRaises(ValueError):
            check(["provisioning_key"], ["provisioning_key"])
