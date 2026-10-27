"""Transactional queueing and snapshot construction for GitHub issue projections."""

from __future__ import annotations

import uuid
from datetime import datetime

import sqlalchemy as sa

from uvm.persistence.assessment_schema import assessment_group_state, assessment_policy
from uvm.persistence.g4_schema import (exposure_episode_members,
    exposure_episodes, github_group_issues, github_projection_intents,
    github_repositories)
from uvm.persistence.schema import exposures, groups, occurrences


def _id() -> str:
    return str(uuid.uuid4())


def build_group_projection(connection, group_id: str, *, assessment_document=None,
                            assessment_revision: int | None = None) -> dict:
    group = connection.execute(sa.select(groups).where(
        groups.c.group_id == group_id)).mappings().one()
    state = connection.execute(sa.select(assessment_group_state).where(
        assessment_group_state.c.group_id == group_id)).mappings().first()
    document = assessment_document if assessment_document is not None else (
        dict(state["document"]) if state else {})
    revision = assessment_revision or (int(state["revision"]) if state else 1)
    exposure_rows = connection.execute(sa.select(exposures.c.exposure_id,
        exposures.c.first_observed_at).where(exposures.c.group_id == group_id)
        .order_by(exposures.c.exposure_id)).mappings().all()
    episodes = []
    membership = []
    for exposure in exposure_rows:
        episode = connection.execute(sa.select(exposure_episodes).where(
            exposure_episodes.c.exposure_id == exposure["exposure_id"],
            exposure_episodes.c.is_current.is_(True))).mappings().first()
        occurrence_rows = connection.execute(sa.select(occurrences.c.occurrence_id,
            occurrences.c.component_locator, occurrences.c.first_observed_at)
            .where(occurrences.c.exposure_id == exposure["exposure_id"])
            .order_by(occurrences.c.occurrence_id)).mappings().all()
        episode_members = {}
        if episode:
            episode_members = {row["occurrence_id"]: row for row in connection.execute(
                sa.select(exposure_episode_members).where(
                    exposure_episode_members.c.episode_id == episode["episode_id"]
                )).mappings().all()}
            episodes.append({"exposure_id": exposure["exposure_id"],
                "episode_id": episode["episode_id"],
                "state_revision": int(episode["state_revision"]),
                "state": episode["state"]})
        for occurrence in occurrence_rows:
            coverage = episode_members.get(occurrence["occurrence_id"], {})
            membership.append({"membership_id": occurrence["occurrence_id"],
                "exposure_id": exposure["exposure_id"],
                "component_locator": occurrence["component_locator"],
                "first_observed_at": occurrence["first_observed_at"].isoformat().replace("+00:00", "Z")
                    if occurrence["first_observed_at"] else None,
                "episode_status": coverage.get("status", "outstanding")})
    owner_names = {}
    policy = connection.execute(sa.select(assessment_policy.c.document).where(
        assessment_policy.c.policy_id == 1)).scalar_one_or_none() or {}
    # The assessment snapshot is authoritative for identities captured before
    # the live directory was populated. The current directory may refine names
    # and types, but a portion-only ID with no captured or directory type stays
    # explicitly unknown.
    owner_types = {}
    for owner in document.get("owners", []):
        if isinstance(owner, dict) and owner.get("owner_id") and owner.get("owner_type") in {"person", "team"}:
            owner_types[owner["owner_id"]] = owner["owner_type"]
    for owner in policy.get("owner_directory", []):
        if isinstance(owner, dict) and owner.get("owner_id"):
            owner_names[owner["owner_id"]] = owner.get("display_name") or owner["owner_id"]
            if owner.get("owner_type") in {"person", "team"}:
                owner_types[owner["owner_id"]] = owner["owner_type"]
    native_authority = policy.get("native_authority", {})
    native_teams = native_authority.get("ownership_teams", {}) if isinstance(native_authority, dict) else {}
    for team_id, team in native_teams.items():
        owner_names[team_id] = team.get("display_name") or team_id
        owner_types[team_id] = "team"
    owner_views = [{**item, "display_name": owner_names.get(item.get("owner_id"), item.get("owner_id"))}
        for item in document.get("owners", [])]
    current_membership = {item["membership_id"]: item for item in membership}
    portion_views = []
    for portion in document.get("portions", []):
        if not portion.get("active", True):
            continue
        exact = [member for member in portion.get("membership_ids", [])
            if member in current_membership]
        complete = [member for member in exact if current_membership[member]["episode_status"]
            in {"confirmed", "continuity_covered"}]
        open_members = [member for member in exact if current_membership[member]["episode_status"]
            not in {"confirmed", "continuity_covered"}]
        ids = list(portion.get("owner_ids", []))
        if not ids and isinstance(portion.get("owner_ids"), list):
            ids = portion["owner_ids"]
        if not ids:
            ids = [item["owner_id"] for item in owner_views]
        portion_views.append({"portion_id": portion["portion_id"],
            "membership_ids": exact, "owners": [{"owner_id": owner_id,
                "owner_type": owner_types.get(owner_id, "unknown"),
                "display_name": owner_names.get(owner_id, owner_id)} for owner_id in ids],
            "completed_count": len(complete), "outstanding_count": len(open_members),
            "completed_membership_ids": complete,
            "outstanding_membership_ids": open_members})
    member_statuses = [item["episode_status"] for item in membership]
    all_remediated = bool(episodes) and all(item["state"] == "remediated" for item in episodes)
    partial = any(status in {"confirmed", "continuity_covered"} for status in member_statuses) \
        and not all_remediated
    return {"schema_version": 1, "group_id": group_id,
        "native_key": {"source_family": group["source_family"],
            "native_id_scheme": group["native_id_scheme"],
            "native_id_authority": group["native_id_authority"],
            "native_id_value": group["native_id_value"]},
        "assessment_revision": revision,
        "owners": owner_views,
        "portions": portion_views,
        "membership": membership, "episodes": episodes,
        "status_label": "uvm:remediated" if all_remediated else
            "uvm:partial" if partial else "uvm:open",
        "issue_state": "closed" if all_remediated else "open"}


def enqueue_group_projection(connection, group_id: str, *, recorded_at: datetime,
                             assessment_document=None,
                             assessment_revision: int | None = None) -> str | None:
    """Append the newest desired state and supersede only sends never dispatched."""
    issue = connection.execute(sa.select(github_group_issues).where(
        github_group_issues.c.group_id == group_id).with_for_update()).mappings().first()
    if issue is None:
        return None
    repo = connection.execute(sa.select(github_repositories).where(
        github_repositories.c.repository_id == issue["repository_id"])
        .with_for_update()).mappings().first()
    if repo is None:
        connection.execute(github_group_issues.update().where(
            github_group_issues.c.group_id == group_id).values(
                state="audience_blocked", discrepancy_codes=["repository_unconfigured"],
                updated_at=recorded_at))
        return None
    revision = int(issue["desired_revision"]) + 1
    payload = build_group_projection(connection, group_id,
        assessment_document=assessment_document, assessment_revision=assessment_revision)
    connection.execute(github_projection_intents.update().where(
        github_projection_intents.c.group_id == group_id,
        github_projection_intents.c.state == "pending").values(
            state="superseded", updated_at=recorded_at))
    unresolved = connection.execute(sa.select(
        github_projection_intents.c.projection_id).where(
            github_projection_intents.c.group_id == group_id,
            github_projection_intents.c.state.in_(["dispatching", "uncertain"])).limit(1)
        ).first() is not None
    projection_id = _id()
    connection.execute(github_projection_intents.insert().values(
        projection_id=projection_id, group_id=group_id,
        repository_id=issue["repository_id"], issue_node_id=issue["issue_node_id"],
        issue_number=issue["issue_number"], desired_revision=revision,
        payload=payload, state="pending", operation_id=None, attempted_at=None,
        created_at=recorded_at, updated_at=recorded_at))
    audience = repo["audience_document"] or {}
    if not (audience.get("approved") is True
            and audience.get("data_access_approved") is True
            and audience.get("repository_id") == repo["repository_id"]):
        state = "audience_blocked"
        discrepancy = ["repository_audience_unapproved"]
    elif unresolved:
        state = "uncertain"
        discrepancy = ["external_write_uncertain"]
    else:
        state = "pending"
        discrepancy = []
    connection.execute(github_group_issues.update().where(
        github_group_issues.c.group_id == group_id).values(
            desired_revision=revision, state=state,
            discrepancy_codes=discrepancy, updated_at=recorded_at))
    return projection_id
