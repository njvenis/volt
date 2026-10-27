"""Authenticated GitHub control, signed-preview and poll routes."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

import sqlalchemy as sa
from fastapi import Depends, FastAPI, Header, HTTPException, Request

from uvm.assessment.api import (_ZERO_ID, _lock_group_membership, _matches,
                                _membership, _require_authority, _uuid)
from uvm.assessment.episodes import ensure_current_episodes
from uvm.github.client import GitHubError, GitHubOutcomeUnknown, GitHubREST, repo_path
from uvm.persistence.assessment_schema import assessment_group_state, assessment_policy
from uvm.persistence.connector_schema import connector_setup_flows
from uvm.persistence.g4_schema import (github_command_previews,
    github_group_issues, github_identity_link_events, github_identity_links,
    github_inbox_commands, github_poll_state, github_projection_intents,
    github_repositories, github_repository_events)
from uvm.persistence.schema import exposures, groups, occurrences

UTC = timezone.utc
_STATUSES = {"unlinked", "pending", "applied", "failed", "uncertain",
    "conflict", "audience_blocked", "needs_resubmission"}


def _error(status: int, code: str, message: str, details: dict | None = None):
    raise HTTPException(status, {"code": code, "message": message,
        "details": details or {}})


def _instant(value: datetime) -> str:
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
        ensure_ascii=True, allow_nan=False).encode()


def _sha(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _command_mapping(command: dict) -> tuple[str, str, dict]:
    action = command.get("action")
    scope = command.get("scope")
    payload = command.get("payload")
    if action == "confirm_remediation" and scope in {"portion", "whole_group"}:
        action_name = "remediation.confirm_portion" if scope == "portion" else "remediation.confirm_group"
        allowed = {"portion_id", "membership_ids", "rationale", "evidence_ref"}
        required = {"membership_ids", "rationale", "evidence_ref"}
        if scope == "portion":
            required.add("portion_id")
        if not isinstance(payload, dict) or set(payload) != allowed.intersection(payload.keys()) \
                or not required <= payload.keys() or payload.keys() - allowed:
            raise ValueError("confirmation payload fields are invalid")
        result = dict(payload)
        return action_name, scope, result
    if action == "set_owners" and scope in {"portion", "whole_group"}:
        if not isinstance(payload, dict):
            raise ValueError("owner payload must be an object")
        required = {"owners", "rationale"} if scope == "whole_group" else {
            "portion_id", "owner_ids", "membership_ids", "rationale"}
        if set(payload) != required:
            raise ValueError("owner payload fields are invalid")
        if scope == "portion":
            return "portion.transfer", scope, {key: payload[key] for key in required}
        return "owners.assign", scope, {"owners": payload["owners"],
            "rationale": payload["rationale"]}
    raise ValueError("command action or scope is unsupported")


def _g3_envelope(command: dict, group_id: str) -> dict:
    action_name, scope, payload = _command_mapping(command)
    top_members = command.get("membership_ids")
    if not isinstance(top_members, list) or not top_members:
        raise ValueError("membership_ids must be a non-empty array")
    if scope == "portion" and action_name in {"remediation.confirm_portion", "portion.transfer"}:
        if payload.get("membership_ids") != top_members:
            raise ValueError("payload and command membership_ids differ")
    if action_name == "remediation.confirm_group":
        payload = {key: command["payload"][key] for key in (
            "membership_ids", "rationale", "evidence_ref")}
    expected = command.get("expected_revisions")
    if not isinstance(expected, dict) or set(expected) != {
            "target", "identity_membership", "policy", "owners"}:
        raise ValueError("expected_revisions must contain the four current G3 revisions")
    result = {"command_id": _uuid(command.get("command_id"), "command_id"),
        "target_id": _uuid(group_id, "target_id"), "action": action_name,
        "membership_ids": top_members, "expected_revisions": expected,
        "payload": payload}
    if action_name in {"remediation.confirm_portion", "remediation.confirm_group"}:
        guards = command.get("expected_exposures")
        if not isinstance(guards, list):
            raise ValueError("expected_exposures is required for remediation")
        result["expected_exposures"] = guards
    return result


def _rest(engine=None, *, connector_id=None, principal=None, expected_revisions=None,
        action="connector.configure", authorization_target=None, allow_candidate=False) -> GitHubREST:
    try:
        if engine is not None:
            from uvm.connectors.runtime import connector_rest
            resolved = connector_rest(engine, connector_id=connector_id,
                principal=principal, expected_revisions=expected_revisions,
                action=action, authorization_target=authorization_target,
                allow_candidate=allow_candidate)
            if resolved is not None:
                return resolved
        return GitHubREST()
    except HTTPException:
        raise
    except (OSError, RuntimeError, ValueError):
        # Preserve the established API error while never trying the legacy
        # token when an explicit connector resolver refused the request.
        _error(503, "github_unavailable", "GitHub credentials are unavailable")


def _repo_audience(rest: GitHubREST, repo: dict) -> tuple[dict, str]:
    path = repo_path(repo["owner"], repo["name"])
    actual = rest.get(path)
    if str(actual.get("id")) != str(repo["repository_id"]) or not actual.get("private"):
        _error(409, "github_audience_unknown",
            "Repository stable identity or private audience changed")
    people = rest.get_all(path + "/collaborators?affiliation=all&per_page=100")
    teams = rest.get_all(path + "/teams?per_page=100")
    team_members = []
    for team in teams:
        team_members.extend(rest.get_all(f"/orgs/{repo['owner']}/teams/"
            f"{team['slug']}/members?per_page=100"))
    audience = {"repository_id": str(actual["id"]),
        "private": bool(actual.get("private")),
        "reader_account_ids": sorted({str(item["id"]) for item in [*people, *team_members]}),
        "team_slugs": sorted(str(item["slug"]) for item in teams)}
    return audience, _sha(audience)


def _capture_group_audience_binding(connection, group_id: str,
                                    reader_account_ids: list[str]) -> dict:
    group = connection.execute(sa.select(groups).where(
        groups.c.group_id == group_id)).mappings().first()
    policy = connection.execute(sa.select(assessment_policy).where(
        assessment_policy.c.policy_id == 1).with_for_update()).mappings().first()
    if group is None or policy is None:
        _error(409, "github_audience_unknown", "Group or current UVM policy is unavailable")
    members, membership_revision = _membership(connection, group_id)
    reader_bindings = []
    for account_id in sorted(set(reader_account_ids)):
        link = connection.execute(sa.select(github_identity_links).where(
            github_identity_links.c.github_host == "github.com",
            github_identity_links.c.account_id == account_id,
            github_identity_links.c.enabled.is_(True)).order_by(
                github_identity_links.c.updated_at.desc()).limit(1)).mappings().first()
        if link is None or not _matches(policy["document"], link["principal_id"],
                "assessment.read", group_id, group["source_family"]):
            _error(409, "github_audience_unknown",
                "Every GitHub reader must have current UVM read authority for included membership",
                {"group_id": group_id, "reader_account_id": account_id})
        reader_bindings.append({"account_id": account_id,
            "principal_id": link["principal_id"], "link_id": link["link_id"],
            "link_revision": int(link["revision"])})
    return {"group_id": group_id, "membership_revision": int(membership_revision),
        "membership_sha256": _sha(sorted(members)),
        "policy_revision": int(policy["revision"]),
        "reader_bindings": reader_bindings,
        "reader_policy_sha256": _sha({"policy_revision": int(policy["revision"]),
            "readers": reader_bindings})}


def _assert_group_audience_binding(connection, repository: dict,
                                   group_id: str) -> dict:
    saved = (repository.get("audience_document") or {}).get("included_scopes", {}).get(group_id)
    if saved is None:
        _error(409, "github_audience_unknown",
            "This native group is outside the explicitly approved disclosure scope")
    current = _capture_group_audience_binding(connection, group_id,
        [item["account_id"] for item in saved["reader_bindings"]])
    if current != saved:
        _error(409, "github_audience_unknown",
            "Included membership, UVM policy, or reader identity binding changed",
            {"group_id": group_id})
    return current


def _current_authority(connection, principal: str, action: str, group_id: str,
                       source_family: str, request: Request | None = None):
    row = connection.execute(sa.select(assessment_policy).where(
        assessment_policy.c.policy_id == 1).with_for_update()).mappings().first()
    if row is None:
        _error(503, "persistence_unavailable", "Assessment policy is unavailable")
    if request is not None:
        auth_service = getattr(request.app.state, "oidc_auth", None)
        context = auth_service.final_context(connection, request) if auth_service else None
        if context is not None and context.principal_id != principal:
            _error(403, "authority_changed", "Current identity authority changed")
    grants = _require_authority(row["document"], principal, action, group_id,
        source_family, origin="local_api", correlation_id=str(uuid.uuid4()))
    from uvm.auth.schema import AUTHORITY_CONTEXT
    from uvm.auth.service import group_scope_covered
    if not group_scope_covered(connection, AUTHORITY_CONTEXT.get(), [group_id],
            granting_identity_groups=[grant.get("principal_id") for grant in grants]):
        _error(403, "source_scope_forbidden", "Current exact source scope is required")
    return row, grants


def _require_source_covered_grants(connection, group_id: str, source_family: str,
                                   *grant_sets: list[dict]) -> None:
    """Require each action to have its own grant covered by the linked group scope."""
    from uvm.auth.schema import AUTHORITY_CONTEXT
    from uvm.auth.service import group_scope_covered
    context = AUTHORITY_CONTEXT.get()
    if context is None:
        return
    for grants in grant_sets:
        if not any(group_scope_covered(connection, context, [group_id],
                granting_identity_groups=[grant.get("principal_id")]) for grant in grants):
            _error(403, "source_scope_forbidden", "Current exact source scope is required")


def _assert_preview_revisions(connection, group_id: str, command: dict,
                              policy_revision: int, *, now: datetime):
    group = connection.execute(sa.select(groups).where(
        groups.c.group_id == group_id).with_for_update()).mappings().first()
    if group is None:
        _error(404, "invalid_command", "Target group not found")
    _lock_group_membership(connection, group_id)
    members, identity_revision = _membership(connection, group_id)
    state = connection.execute(sa.select(assessment_group_state).where(
        assessment_group_state.c.group_id == group_id).with_for_update()).mappings().first()
    policy = connection.execute(sa.select(assessment_policy).where(
        assessment_policy.c.policy_id == 1).with_for_update()).mappings().one()
    document = state["document"] if state else {}
    expected = command.get("expected_revisions")
    current = {"target": int(state["revision"]) if state else 1,
        "identity_membership": identity_revision,
        "policy": int(policy["revision"]),
        "owners": int(document.get("owner_revision", 1))}
    if expected != current:
        _error(409, "revision_conflict", "Assessment scope changed; refresh before preview",
            {"current_revisions": current})
    if set(command.get("membership_ids", [])) - set(members):
        _error(409, "revision_conflict", "Captured membership is no longer current")
    guards = command.get("expected_exposures", [])
    if command.get("action") == "confirm_remediation":
        targeted = set(connection.execute(sa.select(exposures.c.exposure_id)
            .select_from(occurrences.join(exposures,
                occurrences.c.exposure_id == exposures.c.exposure_id))
            .where(exposures.c.group_id == group_id,
                occurrences.c.occurrence_id.in_(command["membership_ids"]))).scalars())
        if not isinstance(guards, list) or len(guards) != len(targeted):
            _error(422, "invalid_command", "expected_exposures must exactly cover captured membership")
        episode_records = ensure_current_episodes(connection, group_id, now=now)
        current_guards = {item["episode"]["exposure_id"]: {
            "exposure_id": item["episode"]["exposure_id"],
            "episode_id": item["episode"]["episode_id"],
            "state_revision": int(item["episode"]["state_revision"])}
            for item in episode_records if item["episode"]["exposure_id"] in targeted}
        provided = {}
        for item in guards:
            if (not isinstance(item, dict) or set(item) != {
                    "exposure_id", "episode_id", "state_revision"}
                    or type(item.get("state_revision")) is not int):
                _error(422, "invalid_command", "expected_exposures item is invalid")
            if item["exposure_id"] in provided:
                _error(422, "invalid_command", "expected_exposures must be unique")
            provided[item["exposure_id"]] = item
        if provided != current_guards:
            _error(409, "revision_conflict", "Exposure episode changed; refresh before preview",
                {"current_exposures": list(current_guards.values())})
    return group, policy, current


def install_github_routes(app: FastAPI) -> None:
    engine = app.state.engine
    principals = app.state.principals

    def active_rest(*, connector_id=None, principal=None, expected_revisions=None,
            action="connector.configure", authorization_target=None, allow_candidate=False):
        return _rest(engine, connector_id=connector_id, principal=principal,
            expected_revisions=expected_revisions, action=action,
            authorization_target=authorization_target, allow_candidate=allow_candidate)

    def authenticate(request: Request, authorization: str | None = Header(default=None)):
        auth_service = getattr(app.state, "oidc_auth", None)
        if auth_service is not None:
            context = auth_service.resolve_request(request)
            return context.principal_id
        if not authorization or not authorization.startswith("Bearer "):
            _error(401, "authentication_required", "Authentication required")
        supplied = authorization[7:]
        for name, principal in principals.items():
            token = principal.get("token", "")
            if supplied.isascii() and len(supplied) <= 512 and hmac.compare_digest(supplied, token):
                return name
        _error(401, "authentication_required", "Authentication required")

    def authorise(principal, action, target, *, source_scope=True):
        with engine.connect() as connection:
            row = connection.execute(sa.select(assessment_policy).where(
                assessment_policy.c.policy_id == 1)).mappings().first()
            if row is None:
                _error(503, "persistence_unavailable", "Assessment policy is unavailable")
            grants = _require_authority(row["document"], principal, action, target,
                origin="local_api", correlation_id=str(uuid.uuid4()))
            from uvm.auth.schema import AUTHORITY_CONTEXT
            from uvm.auth.service import group_scope_covered
            context = AUTHORITY_CONTEXT.get()
            if source_scope and context is not None and not group_scope_covered(connection,
                    context, [target], granting_identity_groups=[grant.get("principal_id") for grant in grants]):
                _error(403, "source_scope_forbidden", "Current exact source scope is required")
            return row

    @app.put("/api/v1/github/repositories/{repository_id}")
    def configure_repository(repository_id: str, body: dict, request: Request,
            principal: str = Depends(authenticate)):
        expected_fields = {"github_host", "owner", "name", "expected_audience_revision",
            "reader_account_ids", "team_slugs", "data_access_approved", "rationale",
            "control_evidence_ref", "included_group_ids"}
        connector_fields = expected_fields | {"connector_validation"}
        if not isinstance(body, dict) or set(body) not in (expected_fields, connector_fields):
            _error(422, "invalid_command", "Repository audience envelope is invalid")
        if (not repository_id.isdigit() or body["github_host"] != "github.com"
                or not isinstance(body["owner"], str) or not body["owner"]
                or not isinstance(body["name"], str) or not body["name"]
                or not isinstance(body["reader_account_ids"], list)
                or not isinstance(body["team_slugs"], list)
                or not isinstance(body["included_group_ids"], list)
                or not body["included_group_ids"]
                or type(body["data_access_approved"]) is not bool
                or not isinstance(body["rationale"], str) or not body["rationale"].strip()
                or not isinstance(body["control_evidence_ref"], str)
                or not body["control_evidence_ref"].strip()):
            _error(422, "invalid_command", "Repository audience values are invalid")
        authorise(principal, "github.repository.configure", repository_id, source_scope=False)
        connector_request = body.get("connector_validation")
        staged_connector_id = None
        expected_connector_revisions = None
        if connector_request is not None:
            if (not isinstance(connector_request, dict) or set(connector_request) != {
                    "connector_id", "source_id", "configuration_revision", "expected_revisions"}):
                _error(422, "invalid_command", "Connector audience revision binding is invalid")
            from uvm.connectors.api import (_fixture, _require as require_connector,
                _revisions as connector_revisions, _check_revisions as check_connector_revisions)
            from uvm.persistence.connector_schema import connectors as connector_table
            connector_binding = _fixture(connector_request["connector_id"])
            if connector_request["source_id"] != connector_binding["source_id"]:
                _error(403, "source_scope_forbidden", "Connector source scope does not match")
            with engine.begin() as connection:
                policy_row = connection.execute(sa.select(assessment_policy).where(
                    assessment_policy.c.policy_id == 1).with_for_update()).mappings().one()
                connector_lock = connection.execute(sa.select(connector_table).where(
                    connector_table.c.connector_id == connector_binding["connector_id"])
                    .with_for_update()).mappings().first()
                from uvm.auth.schema import AUTHORITY_CONTEXT
                context = AUTHORITY_CONTEXT.get()
                if connector_lock is None or connector_request["configuration_revision"] != connector_lock["configuration_revision"]:
                    _error(409, "revision_conflict", "Connector configuration changed; refresh before audience approval")
                require_connector(policy_row["document"], principal, "connector.configure", connector_binding)
                check_connector_revisions(connector_request["expected_revisions"],
                    connector_revisions(connector_lock, policy_row, context))
            staged_connector_id = connector_binding["connector_id"]
            expected_connector_revisions = connector_request["expected_revisions"]
        rest = active_rest(connector_id=staged_connector_id, principal=principal,
            expected_revisions=expected_connector_revisions,
            action="github.repository.configure", authorization_target=repository_id,
            allow_candidate=connector_request is not None)
        try:
            actual, audience_digest = _repo_audience(rest, {
                "repository_id": repository_id, "owner": body["owner"], "name": body["name"]})
        except GitHubError:
            _error(503, "github_audience_unknown", "Repository audience could not be verified")
        expected_audience = {"repository_id": repository_id, "private": True,
            "reader_account_ids": sorted(set(str(item) for item in body["reader_account_ids"])),
            "team_slugs": sorted(set(str(item) for item in body["team_slugs"]))}
        if (actual != expected_audience or not body["data_access_approved"]):
            _error(409, "github_audience_unknown",
                "Submitted audience does not exactly match current repository readers",
                {"observed_audience_sha256": audience_digest})
        now = datetime.now(UTC)
        included_group_ids = sorted({_uuid(item, "included_group_ids item")
            for item in body["included_group_ids"]})
        if len(included_group_ids) != len(body["included_group_ids"]):
            _error(422, "invalid_command", "included_group_ids must be unique")
        with engine.begin() as connection:
            policy_row = connection.execute(sa.select(assessment_policy).where(
                assessment_policy.c.policy_id == 1).with_for_update()).mappings().one()
            auth_service = getattr(request.app.state, "oidc_auth", None)
            context = auth_service.final_context(connection, request) if auth_service else None
            if context is not None and context.principal_id != principal:
                _error(403, "authority_changed", "Current identity authority changed")
            connector_lock = None
            connector_binding = None
            connector_request = body.get("connector_validation")
            if connector_request is not None:
                if (not isinstance(connector_request, dict) or set(connector_request) != {
                        "connector_id", "source_id", "configuration_revision", "expected_revisions"}):
                    _error(422, "invalid_command", "Connector audience revision binding is invalid")
                from uvm.connectors.api import (_fixture, _require as require_connector,
                    _revisions as connector_revisions, _settings as connector_settings,
                    _check_revisions as check_connector_revisions)
                from uvm.persistence.connector_schema import connectors as connector_table, connector_setup_flows
                connector_binding = _fixture(connector_request["connector_id"])
                if connector_request["source_id"] != connector_binding["source_id"]:
                    _error(403, "source_scope_forbidden", "Connector source scope does not match")
                connector_lock = connection.execute(sa.select(connector_table).where(
                    connector_table.c.connector_id == connector_binding["connector_id"])
                    .with_for_update()).mappings().first()
                if connector_lock is None or connector_request["configuration_revision"] != connector_lock["configuration_revision"]:
                    _error(409, "revision_conflict", "Connector configuration changed; refresh before audience approval")
                require_connector(policy_row["document"], principal, "connector.configure", connector_binding)
                check_connector_revisions(connector_request["expected_revisions"],
                    connector_revisions(connector_lock, policy_row, context))
                selected_settings = connector_settings(connector_lock, connection,
                    connector_binding["connector_id"])
                selected_installation = selected_settings.get("github", {}).get("installation") or {}
                setup_flow = connection.execute(sa.select(connector_setup_flows).where(
                    connector_setup_flows.c.flow_id == selected_installation.get("flow_id"),
                    connector_setup_flows.c.connector_id == connector_binding["connector_id"],
                    connector_setup_flows.c.status == "verified")).mappings().first()
                if (selected_settings.get("authentication_mode") != "github_app_v1" or not setup_flow
                        or str(repository_id) not in {str(item.get("repository_id"))
                            for item in setup_flow["repositories"]
                            if isinstance(item, dict) and item.get("installation_access") is True}):
                    _error(409, "github_audience_unknown", "Repository is outside the current verified installation")
            grants = _require_authority(policy_row["document"],
                principal, "github.repository.configure", repository_id,
                origin="local_api", correlation_id=str(uuid.uuid4()))
            from uvm.auth.schema import AUTHORITY_CONTEXT
            from uvm.auth.service import group_scope_covered
            context = AUTHORITY_CONTEXT.get() or context
            if context is not None and any(not group_scope_covered(connection, context, [group_id],
                    granting_identity_groups=[grant.get("principal_id") for grant in grants])
                    for group_id in included_group_ids):
                _error(403, "source_scope_forbidden", "Current exact source scope is required")
            included_scopes = {group_id: _capture_group_audience_binding(
                connection, group_id, actual["reader_account_ids"])
                for group_id in included_group_ids}
            existing = connection.execute(sa.select(github_repositories).where(
                github_repositories.c.repository_id == repository_id).with_for_update()).mappings().first()
            old_revision = int(existing["audience_revision"]) if existing else 0
            if body["expected_audience_revision"] != old_revision:
                _error(409, "revision_conflict", "Repository audience revision changed")
            revision = old_revision + 1
            after = {"repository_id": repository_id, "approved": True,
                "data_access_approved": True, "reader_account_ids": actual["reader_account_ids"],
                "team_slugs": actual["team_slugs"], "snapshot_sha256": audience_digest,
                "included_group_ids": included_group_ids,
                "included_scopes": included_scopes,
                "approval_actor_id": principal, "approval_evidence_ref": body["control_evidence_ref"]}
            if existing:
                before = dict(existing["audience_document"])
                connection.execute(github_repositories.update().where(
                    github_repositories.c.repository_id == repository_id).values(
                        enabled=True, audience_revision=revision,
                        audience_document=after, updated_at=now))
            else:
                before = {}
                connection.execute(github_repositories.insert().values(
                    repository_id=repository_id, github_host=body["github_host"],
                    owner=body["owner"], name=body["name"], enabled=True,
                    audience_revision=revision, audience_document=after, updated_at=now))
            connection.execute(github_repository_events.insert().values(
                event_id=str(uuid.uuid4()), repository_id=repository_id,
                revision=revision, actor_id=principal, action="audience_approved",
                before_value=before, after_value=after, rationale=body["rationale"],
                control_evidence_ref=body["control_evidence_ref"], occurred_at=now))
        return {"schema_version": 1, "repository_id": repository_id,
            "audience_revision": revision, "audience_approved": True,
            "audience_sha256": audience_digest}

    @app.post("/api/v1/github/identity-links")
    def create_identity_link(body: dict, request: Request, principal: str = Depends(authenticate)):
        fields = {"github_host", "account_id", "principal_id", "expected_link_revision",
            "control_evidence_ref", "rationale"}
        if not isinstance(body, dict) or set(body) != fields:
            _error(422, "invalid_command", "Identity link envelope is invalid")
        if (body["github_host"] != "github.com" or not str(body["account_id"]).isdigit()
                or not isinstance(body["principal_id"], str) or not body["principal_id"]
                or not isinstance(body["control_evidence_ref"], str)
                or not body["control_evidence_ref"].strip()
                or not isinstance(body["rationale"], str) or not body["rationale"].strip()
                or type(body["expected_link_revision"]) is not int):
            _error(422, "invalid_command", "Identity link values are invalid")
        authorise(principal, "github.identity.link", str(body["account_id"]), source_scope=False)
        # Resolve the active connector and current action-specific grants, but
        # do not call /user with its installation token. The user identity was
        # independently authenticated by the setup flow's OAuth user token.
        active_rest(principal=principal, action="github.identity.link",
            authorization_target=str(body["account_id"]))
        now = datetime.now(UTC)
        with engine.begin() as connection:
            policy_row = connection.execute(sa.select(assessment_policy).where(
                assessment_policy.c.policy_id == 1).with_for_update()).mappings().one()["document"]
            identity_flow = connection.execute(sa.select(connector_setup_flows).where(
                connector_setup_flows.c.actor_id == principal,
                connector_setup_flows.c.status == "verified").order_by(
                    connector_setup_flows.c.created_at.desc()).limit(1).with_for_update()
                ).mappings().first()
            verified_identity = (identity_flow["installation"] or {}) if identity_flow else {}
            if (not verified_identity.get("verified_user_id")
                    or str(verified_identity.get("verified_user_id")) != str(body["account_id"])):
                _error(403, "github_actor_unlinked",
                    "A user-authenticated GitHub setup flow for this account is required")
            account = {"id":verified_identity["verified_user_id"],
                "login":verified_identity.get("verified_user_login", "")}
            auth_service = getattr(request.app.state, "oidc_auth", None)
            context = auth_service.final_context(connection, request) if auth_service else None
            if context is not None and context.principal_id != principal:
                _error(403, "authority_changed", "Current identity authority changed")
            _require_authority(policy_row,
                principal, "github.identity.link", str(account["id"]),
                origin="local_api", correlation_id=str(uuid.uuid4()))
            existing = connection.execute(sa.select(github_identity_links).where(
                github_identity_links.c.github_host == body["github_host"],
                github_identity_links.c.account_id == str(body["account_id"])
                ).with_for_update()).mappings().first()
            old_revision = int(existing["revision"]) if existing else 0
            if body["expected_link_revision"] != old_revision:
                _error(409, "revision_conflict", "GitHub identity link revision changed")
            revision = old_revision + 1
            link_id = existing["link_id"] if existing else str(uuid.uuid4())
            before = ({"principal_id": existing["principal_id"], "enabled": existing["enabled"],
                "revision": old_revision} if existing else {})
            after = {"principal_id": body["principal_id"], "account_id": str(account["id"]),
                "account_login": account.get("login", ""), "enabled": True,
                "revision": revision}
            if existing:
                connection.execute(github_identity_links.update().where(
                    github_identity_links.c.link_id == link_id).values(
                        account_login_at_link=account.get("login", ""),
                        principal_id=body["principal_id"], revision=revision,
                        enabled=True, control_evidence_ref=body["control_evidence_ref"],
                        created_by=principal, rationale=body["rationale"], updated_at=now))
            else:
                connection.execute(github_identity_links.insert().values(
                    link_id=link_id, github_host=body["github_host"],
                    account_id=str(account["id"]), account_login_at_link=account.get("login", ""),
                    principal_id=body["principal_id"], revision=revision, enabled=True,
                    control_evidence_ref=body["control_evidence_ref"], created_by=principal,
                    rationale=body["rationale"], created_at=now, updated_at=now))
            connection.execute(github_identity_link_events.insert().values(
                event_id=str(uuid.uuid4()), link_id=link_id, revision=revision,
                actor_id=principal, action="linked", before_value=before,
                after_value=after, rationale=body["rationale"],
                control_evidence_ref=body["control_evidence_ref"], occurred_at=now))
        return {"schema_version": 1, "link_id": link_id, "link_revision": revision,
            "github_account_id": str(account["id"]), "principal_id": body["principal_id"],
            "enabled": True}

    @app.patch("/api/v1/github/identity-links/{link_id}")
    def revoke_identity_link(link_id: str, body: dict, request: Request,
            principal: str = Depends(authenticate)):
        if (not isinstance(body, dict) or set(body) != {
                "enabled", "expected_link_revision", "rationale"}
                or type(body.get("enabled")) is not bool or body["enabled"] is not False
                or type(body.get("expected_link_revision")) is not int
                or not isinstance(body.get("rationale"), str) or not body["rationale"].strip()):
            _error(422, "invalid_command", "Link revocation envelope is invalid")
        _uuid(link_id, "link_id")
        now = datetime.now(UTC)
        with engine.begin() as connection:
            row = connection.execute(sa.select(github_identity_links).where(
                github_identity_links.c.link_id == link_id).with_for_update()).mappings().first()
            if row is None:
                _error(404, "invalid_command", "GitHub identity link not found")
            policy = connection.execute(sa.select(assessment_policy).where(
                assessment_policy.c.policy_id == 1).with_for_update()).mappings().first()
            if policy is None:
                _error(503, "persistence_unavailable", "Assessment policy is unavailable")
            auth_service = getattr(request.app.state, "oidc_auth", None)
            context = auth_service.final_context(connection, request) if auth_service else None
            if context is not None and context.principal_id != principal:
                _error(403, "authority_changed", "Current identity authority changed")
            _require_authority(policy["document"], principal, "github.identity.link",
                row["account_id"], origin="local_api", correlation_id=str(uuid.uuid4()))
            if row["revision"] != body["expected_link_revision"]:
                _error(409, "revision_conflict", "GitHub identity link revision changed")
            revision = int(row["revision"]) + 1
            before = {"principal_id": row["principal_id"], "enabled": row["enabled"],
                "revision": row["revision"]}
            after = {"principal_id": row["principal_id"], "enabled": False,
                "revision": revision}
            connection.execute(github_identity_links.update().where(
                github_identity_links.c.link_id == link_id).values(
                    enabled=False, revision=revision, rationale=body["rationale"], updated_at=now))
            connection.execute(github_identity_link_events.insert().values(
                event_id=str(uuid.uuid4()), link_id=link_id, revision=revision,
                actor_id=principal, action="revoked", before_value=before,
                after_value=after, rationale=body["rationale"],
                control_evidence_ref=row["control_evidence_ref"], occurred_at=now))
            connection.execute(github_command_previews.update().where(
                github_command_previews.c.link_id == link_id,
                github_command_previews.c.state.in_(["previewed", "acknowledged"])).values(
                    state="needs_resubmission"))
        return {"schema_version": 1, "link_id": link_id,
            "link_revision": revision, "enabled": False}

    @app.post("/api/v1/github/commands/preview")
    def preview_command(body: dict, request: Request, principal: str = Depends(authenticate)):
        if not isinstance(body, dict) or set(body) != {"command", "issue_number", "repository_id"}:
            _error(422, "invalid_command", "Preview request is invalid")
        command = body["command"]
        if not isinstance(command, dict) or type(body["issue_number"]) is not int:
            _error(422, "invalid_command", "Preview command target is invalid")
        try:
            group_id = _uuid(command.get("target_id"), "target_id")
            g3_command = _g3_envelope(command, group_id)
            assessment_action = g3_command["action"]
        except (ValueError, KeyError, TypeError):
            _error(422, "invalid_command", "Preview command fields are invalid")
        now = datetime.now(UTC)
        try:
            preview_lifetime_seconds = int(os.getenv(
                "UVM_GITHUB_PREVIEW_LIFETIME_SECONDS", "900"))
        except ValueError:
            _error(503, "github_unavailable", "Preview lifetime configuration is invalid")
        if preview_lifetime_seconds < 1:
            _error(503, "github_unavailable", "Preview lifetime must be at least one second")
        expires_at = now + timedelta(seconds=preview_lifetime_seconds)
        with engine.begin() as connection:
            try:
                from uvm.connectors.runtime import runtime_secret_admitted
                preview_secret, _preview_version, _connector_policy = runtime_secret_admitted(
                    connection, "preview_secret")
            except Exception:
                _error(503, "github_unavailable", "Signed preview secret is unavailable")
            if len(preview_secret) < 32:
                _error(503, "github_unavailable", "Signed preview secret is not configured")
            group = connection.execute(sa.select(groups).where(
                groups.c.group_id == group_id)).mappings().first()
            policy, read_grants = _current_authority(connection, principal, "assessment.read", group_id,
                group["source_family"] if group else "", request) if group else None
            if group is None or policy is None:
                _error(404, "invalid_command", "Target group not found")
            try:
                _require_authority(policy["document"], principal, assessment_action,
                    group_id, group["source_family"], origin="local_api",
                    correlation_id=g3_command["command_id"])
            except HTTPException as exc:
                raise exc
            issue = connection.execute(sa.select(github_group_issues).where(
                github_group_issues.c.group_id == group_id,
                github_group_issues.c.repository_id == str(body["repository_id"]),
                github_group_issues.c.issue_number == body["issue_number"])).mappings().first()
            repo = connection.execute(sa.select(github_repositories).where(
                github_repositories.c.repository_id == str(body["repository_id"]),
                github_repositories.c.enabled.is_(True))).mappings().first()
            if issue is None or repo is None:
                _error(404, "invalid_command", "Managed issue target not found")
            _assert_group_audience_binding(connection, dict(repo), group_id)
            audience = repo["audience_document"] or {}
            if audience.get("approved") is not True or audience.get("data_access_approved") is not True:
                _error(409, "github_audience_unknown", "Repository audience is not approved")
            link = connection.execute(sa.select(github_identity_links).where(
                github_identity_links.c.principal_id == principal,
                github_identity_links.c.enabled.is_(True)).order_by(
                    github_identity_links.c.updated_at.desc()).limit(1)).mappings().first()
            if link is None:
                _error(403, "github_actor_unlinked", "A controlled GitHub account link is required")
            preview_grants = _require_authority(policy["document"], principal, "github.commands.preview",
                group_id, group["source_family"], origin="local_api",
                correlation_id=g3_command["command_id"])
            from uvm.auth.schema import AUTHORITY_CONTEXT
            from uvm.auth.service import group_scope_covered
            action_grants = _require_authority(policy["document"], principal,
                assessment_action, group_id, group["source_family"], origin="local_api",
                correlation_id=g3_command["command_id"])
            _require_source_covered_grants(connection, group_id, group["source_family"],
                read_grants, preview_grants, action_grants)
            _assert_preview_revisions(connection, group_id, command,
                int(policy["revision"]), now=now)
            allowed = {action: _matches(policy["document"], principal, action,
                group_id, group["source_family"]) for action in (
                    "remediation.confirm_portion", "remediation.confirm_group",
                    "portion.transfer", "owners.assign")}
            preview_id = str(uuid.uuid4())
            digest = _sha(command)
            snapshot = {"preview_id": preview_id, "principal_id": principal,
                "link_id": link["link_id"], "link_revision": link["revision"],
                "github_account_id": link["account_id"],
                "repository_id": str(repo["repository_id"]),
                "issue_node_id": issue["issue_node_id"],
                "issue_number": issue["issue_number"], "group_id": group_id,
                "command_digest": digest,
                "expected_revisions": g3_command["expected_revisions"],
                "expected_exposures": g3_command.get("expected_exposures", []),
                "expires_at": _instant(expires_at)}
            signature = hmac.new(preview_secret, _canonical(snapshot), hashlib.sha256).hexdigest()
            connection.execute(github_command_previews.insert().values(
                preview_id=preview_id, principal_id=principal, link_id=link["link_id"],
                link_revision=link["revision"],
                repository_id=repo["repository_id"], group_id=group_id,
                issue_number=issue["issue_number"], command=command,
                canonical_digest=digest, signature=signature, expires_at=expires_at,
                state="previewed", acknowledged_at=None, created_at=now))
        return {"schema_version": 1, **snapshot, "signature": signature,
            "command": command, "permission_hints": allowed, "errors": []}

    @app.post("/api/v1/github/commands/acknowledge")
    def acknowledge_command(body: dict, request: Request, principal: str = Depends(authenticate)):
        if not isinstance(body, dict) or set(body) != {"preview_id", "signature"}:
            _error(422, "invalid_command", "Acknowledgement request is invalid")
        preview_id = _uuid(body["preview_id"], "preview_id")
        now = datetime.now(UTC)
        with engine.begin() as connection:
            preview = connection.execute(sa.select(github_command_previews).where(
                github_command_previews.c.preview_id == preview_id).with_for_update()).mappings().first()
            if preview is None or preview["principal_id"] != principal:
                _error(404, "invalid_command", "Preview not found")
            if preview["state"] != "previewed":
                _error(409, "command_needs_resubmission", "Preview is no longer acknowledgeable")
            if preview["expires_at"] <= now:
                _error(409, "preview_expired", "Preview has expired")
            if (not isinstance(body["signature"], str)
                    or not hmac.compare_digest(body["signature"], preview["signature"])):
                _error(403, "preview_signature_invalid", "Preview signature is invalid")
            link = connection.execute(sa.select(github_identity_links).where(
                github_identity_links.c.link_id == preview["link_id"]).with_for_update()).mappings().first()
            if link is None or not link["enabled"] or link["principal_id"] != principal:
                _error(403, "github_actor_unlinked", "GitHub account link is no longer active")
            group = connection.execute(sa.select(groups).where(
                groups.c.group_id == preview["group_id"])).mappings().one()
            repo = connection.execute(sa.select(github_repositories).where(
                github_repositories.c.repository_id == preview["repository_id"])
                .with_for_update()).mappings().first()
            if repo is None:
                _error(409, "github_audience_unknown", "Repository audience approval is unavailable")
            _assert_group_audience_binding(connection, dict(repo), preview["group_id"])
            policy, read_grants = _current_authority(connection, principal, "assessment.read",
                preview["group_id"], group["source_family"], request)
            g3_command = _g3_envelope(preview["command"], preview["group_id"])
            action_grants = _require_authority(policy["document"], principal, g3_command["action"],
                preview["group_id"], group["source_family"], origin="local_api",
                correlation_id=g3_command["command_id"])
            command_action = ("github.commands.preview")
            preview_grants = _require_authority(policy["document"], principal, command_action,
                preview["group_id"], group["source_family"], origin="local_api",
                correlation_id=g3_command["command_id"])
            from uvm.auth.schema import AUTHORITY_CONTEXT
            from uvm.auth.service import group_scope_covered
            _require_source_covered_grants(connection, preview["group_id"],
                group["source_family"], read_grants, action_grants, preview_grants)
            _assert_preview_revisions(connection, preview["group_id"],
                preview["command"], int(policy["revision"]), now=now)
            connection.execute(github_command_previews.update().where(
                github_command_previews.c.preview_id == preview_id).values(
                    state="acknowledged", acknowledged_at=now))
        return {"schema_version": 1, "command_ref": preview_id,
            "expires_at": _instant(preview["expires_at"]),
            "canonical_command_digest": preview["canonical_digest"],
            "state": "acknowledged"}

    # Poll/reconciliation handlers are imported lazily so API construction
    # does not load transport workers or credentials.
    from uvm.github.lifecycle import install_github_lifecycle_routes
    install_github_lifecycle_routes(app, authenticate, authorise,
        lambda **kwargs: active_rest(**kwargs))
