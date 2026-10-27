"""CR-02: native groups keyed by namespaced native IDs; CVEs as references.

Synthetic fixture baseline per the approved G1 design matrix: QID A ->
CVEs X/Y, QID B -> X, QID C -> no CVE, repeated across two accounts. A
globally meaningful QID is not split by collector account; account-local
identifiers include the account in their authority namespace.
"""

import unittest

from uvm.identity import IdentityState, resolve

from fixtures import T1, RULE, make_observation


class NativeGroupingTest(unittest.TestCase):
    def test_three_native_groups_shared_cve_does_not_merge(self):
        state = IdentityState()
        a1 = make_observation(native_id_value="101", vulnerability_refs=("CVE-X", "CVE-Y"))
        a2 = make_observation(
            source_account_id="acc-2", run_id="run-2",
            native_id_value="101", vulnerability_refs=("CVE-X", "CVE-Y"),
        )
        b = make_observation(
            source_record_ordinal=2,
            native_id_value="202", vulnerability_refs=("CVE-X",),
        )
        c = make_observation(
            source_record_ordinal=3,
            native_id_value="303", vulnerability_refs=(),
        )
        for obs in (a1, a2, b, c):
            resolve(state, obs, RULE, {"provisioning_key": f"pk-{obs.native_id_value}"}, T1)

        self.assertEqual(len(state.groups), 3, "shared CVE membership must not merge groups")
        gA = next(g for g in state.groups.values() if g.key.native_id_value == "101")
        gB = next(g for g in state.groups.values() if g.key.native_id_value == "202")
        gC = next(g for g in state.groups.values() if g.key.native_id_value == "303")
        # QID is globally meaningful: both accounts land in the same group.
        self.assertEqual(state.groups_for_cve("CVE-X"), {gA.group_id, gB.group_id})
        self.assertEqual(state.groups_for_cve("CVE-Y"), {gA.group_id})
        self.assertEqual(gA.cve_refs, {"CVE-X", "CVE-Y"})
        self.assertEqual(state.groups_for_cve("CVE-UNLINKED"), set())
        # No-CVE group remains a valid native group.
        self.assertEqual(gC.cve_refs, set())

    def test_account_local_identifier_splits_by_account(self):
        state = IdentityState()
        o1 = make_observation(
            source_account_id="acc-1", native_id_scheme="sysdig-fingerprint",
            native_id_authority="acc-1", native_id_value="fp-9",
        )
        o2 = make_observation(
            source_account_id="acc-2", native_id_scheme="sysdig-fingerprint",
            native_id_authority="acc-2", native_id_value="fp-9",
        )
        resolve(state, o1, RULE, {"provisioning_key": "pk-a"}, T1)
        resolve(state, o2, RULE, {"provisioning_key": "pk-b"}, T1)
        self.assertEqual(len(state.groups), 2, "account-local IDs must carry their account")
        # Same scheme and value, distinct authority namespaces -> distinct groups.
        keys = sorted((g.key for g in state.groups.values()), key=lambda k: (k.native_id_authority, k.native_id_value))
        self.assertEqual(
            [(k.native_id_scheme, k.native_id_value) for k in keys],
            [("sysdig-fingerprint", "fp-9")] * 2,
        )
        self.assertEqual(
            sorted(k.native_id_authority for k in keys), ["acc-1", "acc-2"]
        )


if __name__ == "__main__":
    unittest.main()
