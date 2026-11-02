"""Focused regression coverage for native access and owner separation."""
from datetime import datetime, timezone
import unittest

from uvm.auth.native_authority import effective_access, effective_team_members
from uvm.assessment.api import _candidate_permission_actions


class NativeIdentityAuthorityTest(unittest.TestCase):
    def setUp(self):
        self.now = datetime(2026, 10, 29, 12, tzinfo=timezone.utc)
        self.policy = {
            "principals": {"alice": {"enabled": True}},
            "native_authority": {
                "mode": "uvm_native_v1",
                "revision": 8,
                "access_groups": {
                    "group-a": {
                        "enabled": True,
                        "revision": 3,
                        "source_scopes": [{"source_family": "sysdig",
                            "source_account_id": "acct-a", "scope_key": "scope-a"}],
                        "permissions": [{"role_id": "role-a"}],
                        "memberships": [{"principal_id": "alice",
                            "effective_from": "2026-10-01T00:00:00Z",
                            "enabled": True, "revision": 2}],
                    },
                    "group-b": {
                        "enabled": True,
                        "revision": 2,
                        "source_scopes": [{"source_family": "qualys",
                            "source_account_id": "acct-b", "scope_key": "scope-b"}],
                        "permissions": [{"role_id": "role-b"}],
                        "memberships": [{"principal_id": "alice",
                            "effective_from": "2026-10-01T00:00:00Z",
                            "enabled": True, "revision": 1}],
                    },
                },
                "ownership_teams": {"team-a": {
                    "enabled": True,
                    "revision": 2,
                    "memberships": [{"principal_id": "alice",
                        "effective_from": "2026-10-01T00:00:00Z",
                        "effective_until": "2026-11-01T00:00:00Z",
                        "enabled": True, "revision": 4}],
                }},
            },
        }

    def test_disabling_one_group_membership_preserves_only_unrelated_current_grant(self):
        before = effective_access(self.policy, "alice", self.now)
        self.assertEqual(before[0], ("group-a", "group-b"))
        self.assertEqual(before[1], (("group-a", ("role-a",)), ("group-b", ("role-b",))))

        self.policy["native_authority"]["access_groups"]["group-a"]["memberships"].append({
            "principal_id": "alice", "effective_from": "2026-10-29T11:00:00Z",
            "enabled": False, "revision": 3,
        })
        after = effective_access(self.policy, "alice", self.now)

        self.assertEqual(after[0], ("group-b",))
        self.assertEqual(after[1], (("group-b", ("role-b",)),))
        self.assertEqual(after[2], (("group-b", (("qualys", "acct-b", "scope-b"),)),))
        self.assertGreater(after[3], 0)

    def test_ownership_membership_is_effective_dated_and_never_an_access_grant(self):
        self.assertEqual(effective_team_members(self.policy, "team-a", self.now), ("alice",))
        self.assertEqual(effective_team_members(self.policy, "team-a",
            datetime(2026, 11, 1, tzinfo=timezone.utc)), ())
        self.assertEqual(effective_access(self.policy, "alice", self.now)[0],
            ("group-a", "group-b"))

    def test_permissions_projection_includes_only_current_native_access_group_actions(self):
        groups = self.policy["native_authority"]["access_groups"]
        groups["group-a"]["permissions"] = [
            {"action": "acceptance.submit"}, {"action": "acceptance.approve"},
            {"action": "owners.directory.read"}]
        groups["group-b"]["permissions"] = [{"action": "owners.assign"}]
        groups["expired-group"] = {
            "enabled": True,
            "memberships": [{"principal_id": "alice", "effective_from": "2026-10-01T00:00:00Z",
                "effective_until": "2026-10-29T11:00:00Z", "enabled": True}],
            "permissions": [{"action": "native.secret"}],
        }
        actions = _candidate_permission_actions(self.policy, "alice")
        self.assertTrue({"acceptance.submit", "acceptance.approve", "owners.directory.read",
            "owners.assign"} <= actions)
        self.assertNotIn("native.secret", actions)
        self.assertNotIn("*", actions)

    def test_disabled_account_has_no_native_group_access_or_team_membership(self):
        self.policy["principals"]["alice"]["enabled"] = False
        self.assertEqual(effective_access(self.policy, "alice", self.now), ((), (), (), 8))
        self.assertEqual(effective_team_members(self.policy, "team-a", self.now), ())


if __name__ == "__main__":
    unittest.main()
