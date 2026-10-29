"""Effective-dated native access and ownership authority stored in policy history."""
from __future__ import annotations

import copy
import uuid
from datetime import datetime, timezone


UTC = timezone.utc
NATIVE_MODE = "uvm_native_v1"
NATIVE_ACTIONS = {
    "native.authority.activate", "native.authority.rollback",
    "access_group.create", "access_group.update", "access_group.membership.set",
    "ownership.team.create", "ownership.team.update", "ownership.team.membership.set",
}
OBSERVER_TIMING_ACTIONS = {"observer.timing.read", "observer.timing.configure"}
DEPLOYMENT_AUDIT_ACTIONS = {"audit.read.deployment"}
BACKUP_SETTINGS_ACTIONS = {"backup.settings.read", "backup.settings.configure"}
DEPLOYMENT_SETTINGS_ACTIONS = OBSERVER_TIMING_ACTIONS | BACKUP_SETTINGS_ACTIONS | DEPLOYMENT_AUDIT_ACTIONS
ACCESS_ACTIONS = {"native.authority.activate", "access_group.create", "access_group.update",
    "access_group.membership.set"}
OWNERSHIP_ACTIONS = {"ownership.team.create", "ownership.team.update",
    "ownership.team.membership.set"}


def native_state(policy: dict) -> dict:
    value = policy.get("native_authority")
    if not isinstance(value, dict):
        return {"mode": "legacy", "revision": 0, "ownership_revision": 0,
            "mapping_revision": 0, "bootstrap_admins": [], "grantable_envelope": {},
            "access_groups": {}, "ownership_teams": {}, "revocations": []}
    return value


def effective_access(policy: dict, principal_id: str, at: datetime | None = None):
    """Return current native group IDs, roles and exact source scopes."""
    state = native_state(policy)
    if state.get("mode") != NATIVE_MODE:
        return None
    if policy.get("principals", {}).get(principal_id, {}).get("enabled") is False:
        return (), (), (), int(state.get("revision", 0))
    at = (at or datetime.now(UTC)).astimezone(UTC)
    memberships, roles, scopes = [], {}, {}
    for group_id, group in state.get("access_groups", {}).items():
        if not group.get("enabled", True):
            continue
        history = [entry for entry in group.get("memberships", [])
            if entry.get("principal_id") == principal_id]
        parsed = []
        for item in history:
            try:
                start = datetime.fromisoformat(item["effective_from"].replace("Z", "+00:00"))
                end = (datetime.fromisoformat(item["effective_until"].replace("Z", "+00:00"))
                    if item.get("effective_until") else None)
            except (KeyError, ValueError, TypeError, AttributeError):
                continue
            if start.tzinfo is None or (end is not None and end.tzinfo is None):
                continue
            if start <= at:
                parsed.append((start.astimezone(UTC), int(item.get("revision", 0)), item, end))
        if not parsed:
            continue
        _start, _revision, latest, end = max(parsed, key=lambda item: (item[0], item[1]))
        if not latest.get("enabled") or (end is not None and end.astimezone(UTC) <= at):
            continue
        memberships.append(group_id)
        roles[group_id] = tuple(sorted(permission["role_id"] for permission in
            group.get("permissions", []) if isinstance(permission, dict)
            and isinstance(permission.get("role_id"), str)))
        scopes[group_id] = tuple(sorted(tuple(scope[key] for key in
            ("source_family", "source_account_id", "scope_key")) for scope in
            group.get("source_scopes", []) if isinstance(scope, dict)))
    return tuple(sorted(memberships)), tuple(sorted(roles.items())), tuple(sorted(scopes.items())), int(state.get("revision", 0))


def effective_team_members(policy: dict, team_id: str, at: datetime):
    """Return members of one retained native team at a report effective time."""
    state = native_state(policy)
    team = state.get("ownership_teams", {}).get(team_id)
    if not team or not team.get("enabled", True):
        return ()
    at = at.astimezone(UTC)
    members = []
    by_principal = {}
    for entry in team.get("memberships", []):
        if not isinstance(entry, dict) or not isinstance(entry.get("principal_id"), str):
            continue
        try:
            start = datetime.fromisoformat(entry["effective_from"].replace("Z", "+00:00"))
            end = datetime.fromisoformat(entry["effective_until"].replace("Z", "+00:00")) if entry.get("effective_until") else None
        except (KeyError, ValueError, TypeError, AttributeError):
            continue
        if start.tzinfo is None or (end is not None and end.tzinfo is None):
            continue
        if start.astimezone(UTC) <= at:
            old = by_principal.get(entry["principal_id"])
            candidate = (start.astimezone(UTC), int(entry.get("revision", 0)), entry, end)
            if old is None or candidate[:2] > old[:2]:
                by_principal[entry["principal_id"]] = candidate
    for principal_id, (_start, _revision, entry, end) in by_principal.items():
        if (entry.get("enabled") is True and
                (end is None or end.astimezone(UTC) > at) and
                policy.get("principals", {}).get(principal_id, {}).get("enabled", True) is True):
            members.append(principal_id)
    return tuple(sorted(members))


def apply_command(policy: dict, action: str, payload: dict, principal_id: str,
                  now: datetime, configured_principals: dict[str, dict], *,
                  validate_permission, envelope_allows, expected_revisions=None):
    """Build the next JSON policy snapshot; caller owns locks and transaction."""
    after = copy.deepcopy(policy)
    state = after.setdefault("native_authority", {
        "mode": "legacy", "revision": 0, "ownership_revision": 0,
        "mapping_revision": 0, "bootstrap_admins": [], "grantable_envelope": {},
        "access_groups": {}, "ownership_teams": {}, "revocations": []})
    state.setdefault("access_groups", {})
    state.setdefault("ownership_teams", {})
    state.setdefault("bootstrap_admins", [])
    state.setdefault("revocations", [])
    now = now.astimezone(UTC)
    expected_revisions = expected_revisions or {}
    if action in NATIVE_ACTIONS and type(expected_revisions.get("authority")) is not int:
        raise ValueError("expected_revisions.authority is required")
    if action.startswith("ownership.team.") and type(expected_revisions.get("ownership")) is not int:
        raise ValueError("expected_revisions.ownership is required")
    if action in {"access_group.update", "access_group.membership.set"} and type(
            expected_revisions.get("access_group")) is not int:
        raise ValueError("expected_revisions.access_group is required")
    if action in {"ownership.team.update", "ownership.team.membership.set"} and type(
            expected_revisions.get("team")) is not int:
        raise ValueError("expected_revisions.team is required")
    for key, actual_key in (("authority", "revision"), ("ownership", "ownership_revision")):
        if key in expected_revisions and expected_revisions[key] != int(state.get(actual_key, 0)):
            raise RuntimeError(f"{key.title()} revision changed")

    def instant(value, label, *, required=True):
        if value is None and not required:
            return None
        if not isinstance(value, str):
            raise ValueError(f"{label} must be a UTC RFC 3339 timestamp")
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None or parsed.utcoffset() != UTC.utcoffset(parsed):
            raise ValueError(f"{label} must include a UTC offset")
        return parsed.astimezone(UTC)

    if action in ACCESS_ACTIONS and principal_id not in state["bootstrap_admins"]:
        raise PermissionError("Protected bootstrap administration is required")
    if action == "native.authority.activate":
        revision = payload.get("mapping_revision")
        if state.get("mode") != "legacy" or type(revision) is not int or revision < 1:
            raise ValueError("Native activation requires legacy mode and a positive mapping revision")
        state.update(mode=NATIVE_MODE, mapping_revision=revision,
            activated_at=now.isoformat().replace("+00:00", "Z"), activated_by=principal_id)
        state["revision"] = int(state.get("revision", 0)) + 1
        return after, "administration.authority.reconcile", "00000000-0000-4000-8000-000000000000"
    if action == "native.authority.rollback":
        raise RuntimeError("Legacy rollback is fenced until every revoked grant and session is reconciled")
    if action in {"access_group.create", "access_group.update"}:
        group_id = str(uuid.UUID(payload.get("access_group_id", "")))
        groups = state["access_groups"]
        old = groups.get(group_id)
        creating = action == "access_group.create"
        if creating and old is not None:
            raise FileExistsError("Access-group IDs are retained and never reused")
        if not creating and old is None:
            raise LookupError("Access group does not exist")
        expected_object = expected_revisions.get("access_group")
        if not creating and expected_object != old.get("revision"):
            raise RuntimeError("Access-group object revision changed")
        name = payload.get("display_name")
        description = payload.get("description", old.get("description", "") if old else "")
        enabled = payload.get("enabled", True)
        source_scopes = payload.get("source_scopes", old.get("source_scopes", []) if old else [])
        permissions = payload.get("permissions", [])
        if not isinstance(name, str) or not name.strip() or not isinstance(description, str) or type(enabled) is not bool:
            raise ValueError("Access-group display fields are invalid")
        if not isinstance(source_scopes, list) or not source_scopes:
            raise ValueError("Access group requires explicit exact source scopes")
        scope_keys = ("source_family", "source_account_id", "scope_key")
        normalized_scopes = []
        for scope in source_scopes:
            if not isinstance(scope, dict) or set(scope) != set(scope_keys) or any(
                    not isinstance(scope.get(key), str) or not scope[key] for key in scope_keys):
                raise ValueError("Access-group source scope is invalid")
            normalized_scopes.append({key: scope[key] for key in scope_keys})
        if len({tuple(item[key] for key in scope_keys) for item in normalized_scopes}) != len(normalized_scopes):
            raise ValueError("Access-group source scopes must be unique")
        if not isinstance(permissions, list) or not permissions:
            raise ValueError("Access group requires at least one permission")
        normalized_permissions = []
        seen_ids = set()
        prior_role_ids = {item.get("role_id") for item in (old or {}).get("permissions", [])}
        used_role_ids = {str(role_id) for role_id in after.get("roles", {})}
        for other_id, other_group in groups.items():
            if other_id != group_id:
                used_role_ids.update(item.get("role_id") for item in other_group.get("permissions", [])
                    if isinstance(item, dict))
        for permission in permissions:
            fields = {"permission_id", "role_id", "action", "target_scope", "limits", "separation_of_duties"}
            supplied_fields = set(permission) if isinstance(permission, dict) else set()
            observer_action = (isinstance(permission, dict)
                and permission.get("action") in DEPLOYMENT_SETTINGS_ACTIONS)
            if (not isinstance(permission, dict)
                    or supplied_fields != fields | ({"deployment_scopes"} if observer_action else set())):
                raise ValueError("Access-group permission shape is invalid")
            pid, rid, permission_action = permission["permission_id"], permission["role_id"], permission["action"]
            pid, rid = str(uuid.UUID(pid)), str(uuid.UUID(rid))
            if rid in used_role_ids and rid not in prior_role_ids:
                raise ValueError("Permission role IDs must be unique across legacy roles and native groups")
            if pid in seen_ids or permission_action in {"policy.role.create", "policy.role.assign",
                    "policy.role.update", "principal.update", "access_group.create", "access_group.update",
                    "access_group.membership.set", "native.authority.activate", "native.authority.rollback",
                    "ownership.team.create", "ownership.team.update", "ownership.team.membership.set"}:
                raise ValueError("Permission identity or selectable action is invalid")
            seen_ids.add(pid)
            role_input = {"role_id": rid, "actions": [permission_action],
                "target_scope": permission["target_scope"], "limits": permission["limits"],
                "separation_of_duties": permission["separation_of_duties"]}
            deployment_scopes = None
            if permission_action in DEPLOYMENT_SETTINGS_ACTIONS:
                deployment_scopes = permission.get("deployment_scopes")
                if (not isinstance(deployment_scopes, list) or not deployment_scopes
                        or any(not isinstance(item, str) or not item.strip()
                            or len(item) > 256 or any(ord(char) < 32 for char in item)
                            for item in deployment_scopes)
                        or len(deployment_scopes) != len(set(deployment_scopes))):
                    raise ValueError("Observer timing permission requires exact deployment scopes")
                role_input["deployment_scopes"] = list(deployment_scopes)
            role = validate_permission(role_input)
            if deployment_scopes is not None:
                role["deployment_scopes"] = list(deployment_scopes)
            if not envelope_allows(state.get("grantable_envelope", {}), role,
                    normalized_scopes, principal_id):
                raise PermissionError("Access-group permission exceeds the protected grantable envelope")
            normalized_permissions.append({"permission_id": pid, "role_id": rid,
                "action": permission_action, "target_scope": role["target_scope"],
                "limits": role["limits"], "separation_of_duties": role["separation_of_duties"],
                **({"deployment_scopes": list(deployment_scopes)}
                    if deployment_scopes is not None else {})})
        old_roles = {entry.get("role_id") for entry in (old or {}).get("permissions", [])}
        for permission in normalized_permissions:
            role_id = permission["role_id"]
        groups[group_id] = {"access_group_id": group_id, "display_name": name.strip(),
            "description": description, "enabled": enabled,
            "revision": int(old.get("revision", 0)) + 1 if old else 1,
            "source_scopes": normalized_scopes, "permissions": normalized_permissions,
            "memberships": copy.deepcopy((old or {}).get("memberships", [])),
            "created_at": (old or {}).get("created_at", now.isoformat().replace("+00:00", "Z")),
            "updated_at": now.isoformat().replace("+00:00", "Z")}
        state["revision"] = int(state.get("revision", 0)) + 1
        return after, "administration.authority.reconcile", group_id
    if action == "access_group.membership.set":
        group_id = str(uuid.UUID(payload.get("access_group_id", "")))
        group = state["access_groups"].get(group_id)
        if group is None or not group.get("enabled", True):
            raise LookupError("Enabled access group does not exist")
        if expected_revisions.get("access_group") != group["revision"]:
            raise RuntimeError("Access-group object revision changed")
        member = payload.get("principal_id")
        identity = configured_principals.get(member) if isinstance(member, str) and isinstance(configured_principals, dict) else None
        if (not isinstance(member, str) or not isinstance(identity, dict)
                or identity.get("actor_kind") != "principal" or identity.get("enabled") is not True):
            raise ValueError("Access-group member must be an enabled persisted human principal")
        start = instant(payload.get("effective_from"), "effective_from")
        end = instant(payload.get("effective_until"), "effective_until", required=False)
        enabled = payload.get("enabled")
        if type(enabled) is not bool:
            raise ValueError("Membership enabled must be boolean")
        if start < now and enabled is False:
            start = now
        if start < now or end is not None and end <= start:
            raise ValueError("New membership cannot be backdated and must have a valid half-open interval")
        state["revision"] = int(state.get("revision", 0)) + 1
        group["revision"] += 1
        group["memberships"].append({"principal_id": member,
            "effective_from": start.isoformat().replace("+00:00", "Z"),
            "effective_until": end.isoformat().replace("+00:00", "Z") if end else None,
            "enabled": enabled, "revision": state["revision"],
            "recorded_at": now.isoformat().replace("+00:00", "Z"), "recorded_by": principal_id})
        group["updated_at"] = now.isoformat().replace("+00:00", "Z")
        if not enabled:
            state["revocations"].append({"principal_id": member, "access_group_id": group_id,
                "effective_at": start.isoformat().replace("+00:00", "Z"),
                "authority_revision": state["revision"]})
        return after, "administration.authority.reconcile", group_id
    if action in {"ownership.team.create", "ownership.team.update"}:
        team_id = str(uuid.UUID(payload.get("team_id", "")))
        teams = state["ownership_teams"]
        old = teams.get(team_id)
        creating = action == "ownership.team.create"
        if creating and old is not None:
            raise FileExistsError("Ownership-team IDs are retained and never reused")
        if not creating and old is None:
            raise LookupError("Ownership team does not exist")
        if not creating and expected_revisions.get("team") != old.get("revision"):
            raise RuntimeError("Ownership-team object revision changed")
        name = payload.get("display_name")
        enabled = payload.get("enabled", True)
        if not isinstance(name, str) or not name.strip() or type(enabled) is not bool:
            raise ValueError("Ownership-team fields are invalid")
        state["ownership_revision"] = int(state.get("ownership_revision", 0)) + 1
        teams[team_id] = {"team_id": team_id, "display_name": name.strip(), "enabled": enabled,
            "revision": int(old.get("revision", 0)) + 1 if old else 1,
            "memberships": copy.deepcopy((old or {}).get("memberships", [])),
            "created_at": (old or {}).get("created_at", now.isoformat().replace("+00:00", "Z")),
            "updated_at": now.isoformat().replace("+00:00", "Z")}
        directory = after.setdefault("owner_directory", [])
        prior_entry = next((item for item in directory if item.get("owner_id") == team_id), None)
        entry = {"owner_id": team_id, "owner_type": "team", "display_name": name.strip(),
            "enabled": enabled, "revision": teams[team_id]["revision"]}
        if prior_entry is None:
            directory.append(entry)
        else:
            prior_entry.update(entry)
        return after, "administration.ownership.reconcile", team_id
    if action == "ownership.team.membership.set":
        team_id = str(uuid.UUID(payload.get("team_id", "")))
        team = state["ownership_teams"].get(team_id)
        if team is None or not team.get("enabled", True):
            raise LookupError("Enabled ownership team does not exist")
        if expected_revisions.get("team") != team["revision"]:
            raise RuntimeError("Ownership-team object revision changed")
        member = payload.get("principal_id")
        identity = configured_principals.get(member) if isinstance(member, str) and isinstance(configured_principals, dict) else None
        if (not isinstance(member, str) or not isinstance(identity, dict)
                or identity.get("actor_kind") != "principal" or identity.get("enabled") is not True):
            raise ValueError("Ownership-team member must be an enabled persisted human principal")
        start = instant(payload.get("effective_from"), "effective_from")
        end = instant(payload.get("effective_until"), "effective_until", required=False)
        enabled = payload.get("enabled")
        if type(enabled) is not bool:
            raise ValueError("Membership enabled must be boolean")
        if start < now and enabled is False:
            start = now
        if start < now or end is not None and end <= start:
            raise ValueError("New membership cannot be backdated and must have a valid half-open interval")
        state["ownership_revision"] = int(state.get("ownership_revision", 0)) + 1
        team["revision"] += 1
        team["memberships"].append({"principal_id": member,
            "effective_from": start.isoformat().replace("+00:00", "Z"),
            "effective_until": end.isoformat().replace("+00:00", "Z") if end else None,
            "enabled": enabled, "revision": state["ownership_revision"],
            "recorded_at": now.isoformat().replace("+00:00", "Z"), "recorded_by": principal_id})
        team["updated_at"] = now.isoformat().replace("+00:00", "Z")
        return after, "administration.ownership.reconcile", team_id
    raise ValueError("Native administration action is not supported")
