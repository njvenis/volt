"""Shared trusted request authority context."""
from contextvars import ContextVar
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any


@dataclass(frozen=True)
class AuthorityContext:
    principal_id: str
    credential_mode: str
    issuer: str | None
    subject: str | None
    link_id: str | None
    link_revision: int | None
    session_id: str | None
    session_revision: int | None
    access_groups: tuple[str, ...]
    group_revision: int
    mapping_revision: int
    policy_revision: int
    source_scopes: tuple[tuple[str, str, str], ...]
    role_ids: tuple[str, ...]
    evaluated_at: datetime
    group_roles: tuple[tuple[str, tuple[str, ...]], ...] = ()
    group_scopes: tuple[tuple[str, tuple[tuple[str, str, str], ...]], ...] = ()

    def document(self) -> dict[str, Any]:
        data = asdict(self)
        data["evaluated_at"] = self.evaluated_at.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
        data["source_scopes"] = [list(scope) for scope in self.source_scopes]
        data["access_groups"] = list(self.access_groups)
        data["role_ids"] = list(self.role_ids)
        data["group_roles"] = {group: list(roles) for group, roles in self.group_roles}
        data["group_scopes"] = {group: [list(scope) for scope in scopes]
            for group, scopes in self.group_scopes}
        return data

    def roles_for_group(self, group_id: str) -> tuple[str, ...]:
        return dict(self.group_roles).get(group_id, ())

    def scopes_for_group(self, group_id: str) -> tuple[tuple[str, str, str], ...]:
        if self.credential_mode not in {"oidc_session", "github_link"}:
            return self.source_scopes
        return dict(self.group_scopes).get(group_id, ())

    def scopes_for_granting_groups(self, group_ids) -> frozenset[tuple[str, str, str]]:
        """Union only ceilings attached to groups that supplied a role grant."""
        if self.credential_mode not in {"oidc_session", "github_link"}:
            return frozenset(self.source_scopes)
        return frozenset(scope for group_id in set(group_ids)
            if group_id in self.access_groups for scope in self.scopes_for_group(group_id))


AUTHORITY_CONTEXT: ContextVar[AuthorityContext | None] = ContextVar(
    "uvm_auth_authority_context", default=None)
