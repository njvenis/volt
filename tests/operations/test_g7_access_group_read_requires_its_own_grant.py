"""A team manager must not inherit access-group directory visibility."""

from datetime import datetime, timezone
import os
import unittest
from unittest.mock import patch

import sqlalchemy as sa
from fastapi import HTTPException


class AccessGroupReadBoundaryTest(unittest.TestCase):
    def test_team_manager_with_explicit_access_group_deny_gets_forbidden(self):
        from uvm.api.app import create_app
        from uvm.persistence.assessment_schema import assessment_policy

        engine = sa.create_engine("sqlite://")
        assessment_policy.create(engine)
        team_id = "00000000-0000-4000-8000-000000000081"
        team_group_id = "00000000-0000-4000-8000-000000000082"
        policy = {
            "principals": {"alice": {"enabled": True}},
            "denies": [{"deny_id": "explicit-access-group-deny",
                "principal_id": "alice", "actions": ["access_group.read"],
                "target_ids": ["*"]}],
            "native_authority": {"mode": "uvm_native_v1", "revision": 2,
                "bootstrap_admins": [], "access_groups": {team_group_id: {
                    "enabled": True, "revision": 1,
                    "memberships": [{"principal_id": "alice",
                        "effective_from": "2020-01-01T00:00:00Z", "enabled": True}],
                    "permissions": [{"permission_id": "team-manager",
                        "role_id": "team-manager-role", "action": "ownership.team.manage",
                        "target_scope": {"group_ids": [team_id],
                            "source_families": [], "environments": [],
                            "service_ids": [], "membership_mode": "explicit"}}]}},
                "ownership_teams": {team_id: {"enabled": True, "revision": 1,
                    "memberships": []}}},
        }
        with engine.begin() as connection:
            connection.execute(assessment_policy.insert().values(policy_id=1,
                revision=3, document=policy, updated_at=datetime.now(timezone.utc),
                updated_by="fixture"))
        try:
            with patch.dict(os.environ, {"UVM_AUTH_MODE": "bearer"}, clear=False):
                app = create_app(engine, principals={}, cursor_secret="access-group-test-secret")
            route = next(item for item in app.routes if getattr(item, "path", None)
                == "/api/v1/assessment/access-groups")
            with self.assertRaises(HTTPException) as denied:
                route.endpoint(principal="alice")
            self.assertEqual(denied.exception.status_code, 403)
        finally:
            engine.dispose()


if __name__ == "__main__":
    unittest.main()
