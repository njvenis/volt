from __future__ import annotations

from datetime import datetime, timedelta
import unittest
from unittest.mock import patch

import sqlalchemy as sa
from fastapi import HTTPException

from uvm.auth import service as auth_service
from uvm.auth.schema import AUTHORITY_CONTEXT
from uvm.assessment.api import _matching_grants
from uvm.persistence.assessment_schema import assessment_policy
from uvm.persistence.auth_schema import (auth_principals, oidc_sessions,
    oidc_subject_groups, oidc_subject_links, oidc_sync_state)


ISSUER = "https://identity.example.test"
SUBJECT = "stable-subject"
PRINCIPAL = "principal-one"
PROVIDER_GROUP = "okta-group-current"
NATIVE_GROUP = "native-access-group"
ROLE_BOTH = "00000000-0000-4000-8000-000000000011"
ROLE_NATIVE_ONLY = "00000000-0000-4000-8000-000000000012"
ROLE_IDP_ONLY = "00000000-0000-4000-8000-000000000013"
SCOPE_BOTH = ("qualys", "account-one", "scope-one")
SCOPE_NATIVE_ONLY = ("qualys", "account-two", "scope-two")
SCOPE_CEILING_ONLY = ("sysdig", "account-three", "scope-three")


def permission(role_id: str) -> dict:
    return {"permission_id": role_id, "role_id": role_id, "action": "access_group.read",
        "target_scope": {"group_ids": ["target-group"], "source_families": ["qualys"],
            "environments": [], "service_ids": [], "membership_mode": "explicit"},
        "limits": {}, "separation_of_duties": {}}


class NativeOidcIntersectionTests(unittest.TestCase):
    def setUp(self):
        self.engine = sa.create_engine("sqlite://")
        tables = [auth_principals, oidc_subject_links, oidc_sessions,
            oidc_subject_groups, oidc_sync_state, assessment_policy]
        for table in tables:
            table.create(self.engine, checkfirst=True)
        # SQLite's portable DateTime returns naive values; production uses aware
        # UTC values on PostgreSQL. Keep this test clock aligned with its DB rows.
        self.now = datetime(2026, 11, 17, 12)
        self.cookie = "synthetic-current-session-cookie"
        self.mapping = {PROVIDER_GROUP: {"role_ids": [ROLE_BOTH, ROLE_IDP_ONLY],
            "source_scopes": [dict(zip(("source_family", "source_account_id", "scope_key"), SCOPE_BOTH)),
                dict(zip(("source_family", "source_account_id", "scope_key"), SCOPE_CEILING_ONLY))]}}
        self.config = {"provider_id": "test-provider", "issuer": ISSUER,
            "mapping_revision": 9, "heartbeat_max_age_seconds": 120,
            "source_scope_ceilings": [dict(zip(("source_family", "source_account_id", "scope_key"), SCOPE_BOTH)),
                dict(zip(("source_family", "source_account_id", "scope_key"), SCOPE_CEILING_ONLY))],
            "group_mappings": self.mapping}
        self.service = auth_service.OIDCAuth.__new__(auth_service.OIDCAuth)
        self.service.engine = self.engine
        self.service.config = self.config
        self.policy = {"principals": {PRINCIPAL: {"enabled": True}},
            "roles": {}, "grants": [], "denies": [],
            "native_authority": {"mode": "uvm_native_v1", "revision": 4,
                "mapping_revision": 3, "bootstrap_admins": [], "access_groups": {
                    NATIVE_GROUP: {"enabled": True, "source_scopes": [
                        dict(zip(("source_family", "source_account_id", "scope_key"), SCOPE_BOTH)),
                        dict(zip(("source_family", "source_account_id", "scope_key"), SCOPE_NATIVE_ONLY))],
                        "permissions": [permission(ROLE_BOTH), permission(ROLE_NATIVE_ONLY)],
                        "memberships": [{"principal_id": PRINCIPAL,
                            "effective_from": "2026-11-01T00:00:00Z", "enabled": True,
                            "revision": 2}]}}}}
        self._insert_current_identity()

    def tearDown(self):
        self.engine.dispose()

    def _insert_current_identity(self):
        with self.engine.begin() as connection:
            connection.execute(auth_principals.insert().values(principal_id=PRINCIPAL,
                display_label="Test principal", enabled=True, revision=1,
                created_at=self.now))
            connection.execute(oidc_subject_links.insert().values(link_id="00000000-0000-4000-8000-000000000001",
                issuer=ISSUER, subject=SUBJECT, principal_id=PRINCIPAL, revision=1,
                enabled=True, actor_id="operator", rationale="test link", evidence_ref="test",
                created_at=self.now, updated_at=self.now))
            connection.execute(oidc_sessions.insert().values(session_hash=auth_service._sha(self.cookie),
                session_id="00000000-0000-4000-8000-000000000002", principal_id=PRINCIPAL,
                link_id="00000000-0000-4000-8000-000000000001", link_revision=1,
                revision=1, csrf_hash=auth_service._sha("csrf"), created_at=self.now,
                expires_at=self.now + timedelta(hours=1), revoked_at=None))
            connection.execute(oidc_subject_groups.insert().values(issuer=ISSUER, subject=SUBJECT,
                group_id=PROVIDER_GROUP, provider_revision=5, updated_at=self.now))
            connection.execute(oidc_sync_state.insert().values(provider_id="test-provider", revision=5,
                heartbeat_at=self.now, snapshot_digest="a" * 64))
            connection.execute(assessment_policy.insert().values(policy_id=1, revision=12,
                document=self.policy, updated_at=self.now, updated_by="test"))

    def resolve(self):
        with patch.object(auth_service, "_now", return_value=self.now):
            with self.engine.connect() as connection:
                return self.service.resolve_cookie(connection, self.cookie)

    def persist_policy(self):
        with self.engine.begin() as connection:
            connection.execute(assessment_policy.update().where(
                assessment_policy.c.policy_id == 1).values(document=self.policy))

    def test_native_and_current_provider_permissions_and_scopes_intersect_independently(self):
        context = self.resolve()
        self.assertEqual(context.access_groups, (NATIVE_GROUP,))
        self.assertEqual(context.roles_for_group(NATIVE_GROUP), (ROLE_BOTH,))
        self.assertEqual(context.scopes_for_group(NATIVE_GROUP), (SCOPE_BOTH,))
        self.assertEqual(context.role_ids, (ROLE_BOTH,))
        self.assertEqual(context.source_scopes, (SCOPE_BOTH,))
        self.assertEqual(context.mapping_revision, self.config["mapping_revision"])
        token = AUTHORITY_CONTEXT.set(context)
        try:
            grants = _matching_grants(self.policy, PRINCIPAL, "access_group.read", "target-group")
        finally:
            AUTHORITY_CONTEXT.reset(token)
        self.assertEqual([grant["role_id"] for grant in grants], [ROLE_BOTH])

    def test_missing_or_unmapped_provider_group_denies_native_only_and_idp_only_roles(self):
        with self.engine.begin() as connection:
            connection.execute(oidc_subject_groups.delete())
        context = self.resolve()
        self.assertEqual(context.roles_for_group(NATIVE_GROUP), ())
        self.assertEqual(context.scopes_for_group(NATIVE_GROUP), ())
        token = AUTHORITY_CONTEXT.set(context)
        try:
            self.assertEqual(_matching_grants(self.policy, PRINCIPAL,
                "access_group.read", "target-group"), [])
        finally:
            AUTHORITY_CONTEXT.reset(token)

    def test_provider_role_or_scope_removal_narrows_only_its_independent_dimension(self):
        self.config["group_mappings"][PROVIDER_GROUP] = {"role_ids": [ROLE_BOTH],
            "source_scopes": [dict(zip(("source_family", "source_account_id", "scope_key"), SCOPE_CEILING_ONLY))]}
        context = self.resolve()
        self.assertEqual(context.roles_for_group(NATIVE_GROUP), (ROLE_BOTH,))
        self.assertEqual(context.scopes_for_group(NATIVE_GROUP), ())
        self.config["group_mappings"][PROVIDER_GROUP] = {"role_ids": [],
            "source_scopes": [dict(zip(("source_family", "source_account_id", "scope_key"), SCOPE_BOTH))]}
        context = self.resolve()
        self.assertEqual(context.roles_for_group(NATIVE_GROUP), ())
        self.assertEqual(context.scopes_for_group(NATIVE_GROUP), (SCOPE_BOTH,))

    def test_native_grant_removal_and_provider_group_readdition_cannot_recreate_authority(self):
        self.policy["native_authority"]["access_groups"][NATIVE_GROUP]["permissions"] = [permission(ROLE_NATIVE_ONLY)]
        self.persist_policy()
        context = self.resolve()
        self.assertEqual(context.roles_for_group(NATIVE_GROUP), ())
        self.assertEqual(context.scopes_for_group(NATIVE_GROUP), (SCOPE_BOTH,))
        self.policy["native_authority"]["access_groups"].clear()
        self.persist_policy()
        context = self.resolve()
        self.assertEqual(context.access_groups, ())
        self.assertEqual(context.role_ids, ())

    def test_missing_or_stale_provider_state_fails_closed(self):
        with self.engine.begin() as connection:
            connection.execute(oidc_sync_state.delete())
        with self.assertRaises(HTTPException) as missing:
            self.resolve()
        self.assertEqual(missing.exception.status_code, 503)
        with self.engine.begin() as connection:
            connection.execute(oidc_sync_state.insert().values(provider_id="test-provider",
                revision=5, heartbeat_at=self.now - timedelta(seconds=121), snapshot_digest="b" * 64))
        with self.assertRaises(HTTPException) as stale:
            self.resolve()
        self.assertEqual(stale.exception.status_code, 503)


if __name__ == "__main__":
    unittest.main()
