"""Durable GitHub issue creation, REST inbox polling and ordered projections."""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import re
import threading
import time
import uuid
from datetime import datetime, timezone
from urllib.parse import quote

import sqlalchemy as sa
from fastapi import Depends, FastAPI, HTTPException, Request

from uvm.assessment.api import _lock_group_membership, _require_authority, _uuid
from uvm.assessment.episodes import ensure_current_episodes
from uvm.github.client import GitHubError, GitHubOutcomeUnknown, GitHubREST, repo_path
from uvm.github.webhooks import validate_delivery_payload
from uvm.connectors.crypto import SecretUnavailable
from uvm.persistence.connector_schema import connectors
from uvm.persistence.assessment_schema import assessment_policy
from uvm.persistence.g4_schema import (github_command_previews,
    github_create_reservations, github_external_events, github_group_issues,
    github_identity_links, github_inbox_commands, github_poll_state,
    github_webhook_deliveries,
    github_projection_intents, github_projection_steps, github_repositories)
from uvm.persistence.github_lifecycle import build_group_projection, enqueue_group_projection
from uvm.persistence.observation_schema import source_observations
from uvm.persistence.schema import exposures, groups, occurrences

UTC = timezone.utc
_LOG = logging.getLogger("uvm.github.lifecycle")


def _error(status, code, message, details=None):
    raise HTTPException(status, {"code": code, "message": message,
        "details": details or {}})


def _now():
    return datetime.now(UTC)


def _iso(value):
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z") if value else None


def _time(value):
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(UTC) if value else None


def _canon(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
        ensure_ascii=True, allow_nan=False).encode()


def _sha(value):
    return hashlib.sha256(_canon(value)).hexdigest()


def _require_tx(connection, principal, action, target, source_family=None):
    row = connection.execute(sa.select(assessment_policy).where(
        assessment_policy.c.policy_id == 1).with_for_update()).mappings().first()
    if row is None:
        _error(503, "persistence_unavailable", "Assessment policy unavailable")
    return _require_authority(row["document"], principal, action, target, source_family,
        origin="local_api", correlation_id=str(uuid.uuid4()))


def _repo(connection, repository_id):
    row = connection.execute(sa.select(github_repositories).where(
        github_repositories.c.repository_id == str(repository_id),
        github_repositories.c.enabled.is_(True))).mappings().first()
    if row is None:
        _error(404, "invalid_command", "GitHub repository is not configured")
    return dict(row)


def _audience(rest, repo):
    from uvm.github.api import _repo_audience
    try:
        actual, digest = _repo_audience(rest, repo)
    except GitHubError:
        _error(503, "github_audience_unknown", "Repository audience cannot be revalidated")
    saved = repo["audience_document"] or {}
    expected = {"repository_id": str(repo["repository_id"]), "private": True,
        "reader_account_ids": sorted(saved.get("reader_account_ids", [])),
        "team_slugs": sorted(saved.get("team_slugs", []))}
    if actual != expected or saved.get("snapshot_sha256") != digest:
        _error(409, "github_audience_unknown", "Repository audience changed")


def _labels(rest, repo):
    path = repo_path(repo["owner"], repo["name"]) + "/labels"
    for name, color, description in (("uvm:open", "d73a4a", "UVM open exposure"),
        ("uvm:partial", "fbca04", "UVM partially remediated exposure"),
        ("uvm:remediated", "0e8a16", "UVM remediated exposure")):
        try:
            rest.get(path + "/" + name.replace("/", "%2F"))
        except GitHubError as exc:
            if exc.status != 404:
                raise
            try:
                rest.write("POST", path, {"name": name, "color": color,
                    "description": description})
            except GitHubError as create_error:
                if create_error.status != 422:
                    raise


def _create_markers(operation_id, digest, group_id):
    return (f"<!-- uvm-managed-group:{group_id} -->",
        f"<!-- uvm-create-operation:{operation_id} -->",
        f"<!-- uvm-create-digest:{digest} -->")


def _issue_body(payload, operation_id, digest):
    lines = [f"### UVM projection revision 1", "",
        f"Native ID: `{payload['native_key']['source_family']}` / "
        f"`{payload['native_key']['native_id_value']}`", "",
        "| Instance | Exposure | First observed | Remediation |", "|---|---|---|---|"]
    for item in payload["membership"]:
        lines.append(f"| `{item['membership_id']}` | `{item['exposure_id']}` | "
            f"{item['first_observed_at'] or 'Unknown'} | {item['episode_status']} |")
    owners = ", ".join(f"{item.get('display_name', item['owner_id'])} "
        f"({item['owner_type']}: `{item['owner_id']}`)" for item in payload["owners"])
    lines.append("\nOwners: " + (owners or "Unassigned"))
    lines.extend(["", "### Active portions"])
    if payload["portions"]:
        for portion in payload["portions"]:
            owners = ", ".join(f"{owner['display_name']} ({owner['owner_type']}: `{owner['owner_id']}`)"
                for owner in portion["owners"]) or "Unassigned"
            lines.extend([f"- Portion `{portion['portion_id']}`: {portion['completed_count']} of "
                f"{len(portion['membership_ids'])} members covered; {portion['outstanding_count']} outstanding.",
                f"  Owners: {owners}",
                "  Members: " + ", ".join(f"`{member}`" for member in portion["membership_ids"])])
    else:
        lines.append("No active portions")
    lines.extend(_create_markers(operation_id, digest, payload["group_id"]))
    return "\n".join(lines)


def _find_create(rest, repo, reservation):
    issues = rest.get_all(repo_path(repo["owner"], repo["name"])
        + "/issues?state=all&per_page=100")
    markers = _create_markers(reservation["operation_id"],
        reservation["request_digest"], reservation["group_id"])
    return [item for item in issues if "pull_request" not in item
        and all(marker in (item.get("body") or "") for marker in markers)]


def _finish_create(engine, reservation, repo, issue, now):
    with engine.begin() as connection:
        stored = connection.execute(sa.select(github_create_reservations).where(
            github_create_reservations.c.group_id == reservation["group_id"])
            .with_for_update()).mappings().one()
        repo_revision = connection.execute(sa.select(
            github_repositories.c.audience_revision).where(
                github_repositories.c.repository_id == repo["repository_id"])).scalar_one()
        connection.execute(github_create_reservations.update().where(
            github_create_reservations.c.group_id == reservation["group_id"]).values(
                state="applied", issue_node_id=issue["node_id"],
                issue_number=issue["number"], issue_url=issue["html_url"], updated_at=now))
        mapping = connection.execute(sa.select(github_group_issues).where(
            github_group_issues.c.group_id == reservation["group_id"])
            .with_for_update()).mappings().first()
        values = {"repository_id": repo["repository_id"],
            "issue_node_id": issue["node_id"], "issue_number": issue["number"],
            "issue_url": issue["html_url"], "state": "pending",
            "desired_revision": int(mapping["desired_revision"]) if mapping else 0,
            "applied_revision": int(mapping["applied_revision"]) if mapping else 0,
            "audience_revision": repo_revision, "last_reconciled_at": None,
            "discrepancy_codes": ["projection_pending"],
            "document": {"creation_effect": {"issue_created": True,
                "issue_number": issue["number"], "creation_payload_digest": stored["request_digest"]}},
            "updated_at": now}
        if mapping:
            connection.execute(github_group_issues.update().where(
                github_group_issues.c.group_id == reservation["group_id"]).values(**values))
        else:
            connection.execute(github_group_issues.insert().values(
                group_id=reservation["group_id"], **values))
        # The issue POST creates a remote object; it does not prove that the
        # current group state has been projected. Capture whatever state won
        # while creation was in flight as a fresh monotonic projection intent.
        enqueue_group_projection(connection, reservation["group_id"], recorded_at=now)


def _mark_create(engine, group_id, state, code):
    with engine.begin() as connection:
        connection.execute(github_create_reservations.update().where(
            github_create_reservations.c.group_id == group_id).values(
                state=state, updated_at=_now()))
        connection.execute(github_group_issues.update().where(
            github_group_issues.c.group_id == group_id).values(
                state=state, discrepancy_codes=[code], updated_at=_now()))


def _create_or_recover(engine, rest, repo, group_id):
    now = _now()
    with engine.begin() as connection:
        group = connection.execute(sa.select(groups).where(
            groups.c.group_id == group_id).with_for_update()).mappings().first()
        if group is None:
            _error(404, "invalid_command", "Group not found")
        _lock_group_membership(connection, group_id)
        ensure_current_episodes(connection, group_id, now=now)
        mapping = connection.execute(sa.select(github_group_issues).where(
            github_group_issues.c.group_id == group_id).with_for_update()).mappings().first()
        if mapping and mapping["issue_number"]:
            return {"status": "mapped", "issue_number": mapping["issue_number"],
                "issue_url": mapping["issue_url"]}
        reservation = connection.execute(sa.select(github_create_reservations).where(
            github_create_reservations.c.group_id == group_id).with_for_update()).mappings().first()
        new_owner = reservation is None
        if reservation is None:
            payload = build_group_projection(connection, group_id)
            operation_id = str(uuid.uuid4())
            digest = _sha(payload)
            request_payload = {"title": f"UVM: {group['source_family']} {group['native_id_value']}",
                "body": _issue_body(payload, operation_id, digest),
                "labels": [payload["status_label"]]}
            connection.execute(github_create_reservations.insert().values(
                group_id=group_id, repository_id=repo["repository_id"],
                operation_id=operation_id,
                marker=f"<!-- uvm-create-operation:{operation_id} -->",
                request_digest=digest, request_payload=request_payload,
                state="dispatching", owner_token=str(uuid.uuid4()),
                dispatch_started_at=now, created_at=now, updated_at=now))
            if mapping is None:
                connection.execute(github_group_issues.insert().values(
                    group_id=group_id, repository_id=repo["repository_id"],
                    issue_node_id=None, issue_number=None, issue_url=None,
                    state="pending", desired_revision=0, applied_revision=0,
                    audience_revision=repo["audience_revision"],
                    last_reconciled_at=None, discrepancy_codes=[], document={}, updated_at=now))
            reservation = {"group_id": group_id, "repository_id": repo["repository_id"],
                "operation_id": operation_id, "request_digest": digest,
                "request_payload": request_payload, "state": "dispatching"}
        else:
            reservation = dict(reservation)
            if reservation["repository_id"] != repo["repository_id"]:
                return {"status": "conflict", "reason": "repository_mismatch"}
    if not new_owner:
        try:
            matches = _find_create(rest, repo, reservation)
        except GitHubError:
            _mark_create(engine, group_id, "uncertain", "create_reconciliation_unavailable")
            return {"status": "uncertain"}
        if len(matches) > 1:
            _mark_create(engine, group_id, "conflict", "multiple_managed_issues")
            return {"status": "conflict", "matching_issue_count": len(matches)}
        if len(matches) == 1:
            _finish_create(engine, reservation, repo, matches[0], _now())
            return {"status": "adopted", "issue_number": matches[0]["number"],
                "issue_url": matches[0]["html_url"]}
        _mark_create(engine, group_id, "uncertain", "create_outcome_unresolved")
        return {"status": "uncertain", "matching_issue_count": 0}
    try:
        _labels(rest, repo)
        _, created, _ = rest.write("POST", repo_path(repo["owner"], repo["name"])
            + "/issues", reservation["request_payload"])
        readback = rest.get(repo_path(repo["owner"], repo["name"])
            + f"/issues/{created['number']}")
    except GitHubOutcomeUnknown:
        _mark_create(engine, group_id, "uncertain", "create_response_unknown")
        return {"status": "uncertain"}
    except GitHubError as exc:
        if exc.status >= 500 or exc.status in {408, 429}:
            _mark_create(engine, group_id, "uncertain", "create_response_unknown")
            return {"status": "uncertain"}
        _mark_create(engine, group_id, "conflict", "create_rejected")
        return {"status": "conflict", "http_status": exc.status}
    markers = _create_markers(reservation["operation_id"],
        reservation["request_digest"], group_id)
    if "pull_request" in readback or not all(
            marker in (readback.get("body") or "") for marker in markers):
        _mark_create(engine, group_id, "conflict", "create_readback_mismatch")
        return {"status": "conflict"}
    _finish_create(engine, reservation, repo, readback, _now())
    return {"status": "created", "issue_number": readback["number"],
        "issue_url": readback["html_url"]}


def _projection_marker(group_id, revision):
    return f"<!-- uvm-projection:{group_id}:{revision} -->"


def _projection_markdown(payload, revision):
    rows = [f"### UVM projection revision {revision}", "",
        "| Instance | Exposure | First observed | Remediation |", "|---|---|---|---|"]
    rows.extend(f"| `{item['membership_id']}` | `{item['exposure_id']}` | "
        f"{item['first_observed_at'] or 'Unknown'} | {item['episode_status']} |"
        for item in payload["membership"])
    owners = ", ".join(f"{item.get('display_name', item['owner_id'])} "
        f"({item['owner_type']}: `{item['owner_id']}`)" for item in payload["owners"]) or "Unassigned"
    rows.extend(["", "Owners: " + owners, "", "### Active portions"])
    for portion in payload["portions"]:
        portion_owners = ", ".join(f"{owner['display_name']} ({owner['owner_type']}: `{owner['owner_id']}`)"
            for owner in portion["owners"]) or "Unassigned"
        rows.extend([f"- Portion `{portion['portion_id']}`: {portion['completed_count']} of "
            f"{len(portion['membership_ids'])} members covered; {portion['outstanding_count']} outstanding.",
            f"  Owners: {portion_owners}", "  Members: " + ", ".join(
                f"`{member}`" for member in portion["membership_ids"])])
    if not payload["portions"]:
        rows.append("No active portions")
    rows.append(_projection_marker(payload["group_id"], revision))
    return "\n".join(rows)


def _projection_integrity_discrepancies(rest, repo, issue, group_id,
                                       projection, writer_id):
    """Verify the retained applied revision against its complete native comment."""
    root = repo_path(repo["owner"], repo["name"])
    path = root + f"/issues/{issue['issue_number']}"
    current = rest.get(path)
    comments = rest.get_all(path + "/comments?per_page=100")
    revision = int(projection["desired_revision"])
    marker = _projection_marker(group_id, revision)
    expected_body = _projection_markdown(projection["payload"], revision)
    marked = [item for item in comments if marker in (item.get("body") or "")]
    exact = [item for item in marked if item.get("body") == expected_body
        and writer_id is not None
        and str((item.get("user") or {}).get("id")) == str(writer_id)]
    discrepancies = []
    if len(marked) != 1 or len(exact) != 1:
        discrepancies.append("projection_comment_integrity")
    label_names = {item.get("name") for item in current.get("labels", [])}
    if current.get("state") != projection["payload"]["issue_state"]:
        discrepancies.append("native_issue_state_changed")
    if projection["payload"]["status_label"] not in label_names:
        discrepancies.append("native_managed_label_changed")
    return discrepancies


def _unresolved_steps(connection, group_id):
    return connection.execute(sa.select(github_projection_steps.c.step_id,
        github_projection_steps.c.projection_id, github_projection_steps.c.step_key,
        github_projection_steps.c.state).join(github_projection_intents,
        github_projection_intents.c.projection_id == github_projection_steps.c.projection_id)
        .where(github_projection_intents.c.group_id == group_id,
            github_projection_steps.c.state.in_(["dispatching", "uncertain"]))
        .order_by(github_projection_intents.c.desired_revision.desc()).limit(1)
        ).mappings().all()


def _projection_map_version(row):
    return tuple(row[key] for key in ("desired_revision", "applied_revision",
        "issue_number", "issue_node_id", "audience_revision", "state",
        "discrepancy_codes"))


def _reconcile_polled_mapping(engine, rest, repo, original, root):
    """Read remote projection, then commit only against its still-current DB version."""
    group_id = original["group_id"]
    with engine.begin() as connection:
        connection.execute(sa.select(assessment_policy.c.policy_id).where(
            assessment_policy.c.policy_id == 1).with_for_update()).first()
        mapping = connection.execute(sa.select(github_group_issues).where(
            github_group_issues.c.group_id == group_id).with_for_update()
            ).mappings().first()
        if mapping is None or mapping["issue_number"] is None:
            return False
        mapping = dict(mapping)
        current_repo = connection.execute(sa.select(github_repositories).where(
            github_repositories.c.repository_id == repo["repository_id"])
            .with_for_update()).mappings().first()
        try:
            from uvm.github.api import _assert_group_audience_binding
            if current_repo is None:
                raise HTTPException(409, "repository approval unavailable")
            _assert_group_audience_binding(connection, dict(current_repo), group_id)
        except HTTPException:
            codes = ["included_scope_changed"]
            if _unresolved_steps(connection, group_id):
                codes.append("external_write_uncertain")
            connection.execute(github_group_issues.update().where(
                github_group_issues.c.group_id == group_id).values(
                    state="audience_blocked", discrepancy_codes=codes, updated_at=_now()))
            return False
        snapshot = mapping
        unresolved_snapshot = _unresolved_steps(connection, group_id)
        applied = None
        if int(mapping["applied_revision"]) > 0:
            applied = connection.execute(sa.select(github_projection_intents).where(
                github_projection_intents.c.group_id == group_id,
                github_projection_intents.c.desired_revision == mapping["applied_revision"],
                github_projection_intents.c.state == "applied").limit(1)
                ).mappings().first()

    issue_error = False
    event_error = False
    discrepancies = []
    events = []
    try:
        issue = rest.get(root + f"/issues/{mapping['issue_number']}")
        if applied:
            with engine.connect() as connection:
                writer_request = connection.execute(sa.select(
                    github_projection_steps.c.request).where(
                    github_projection_steps.c.projection_id == applied["projection_id"],
                    github_projection_steps.c.step_key == "comment_create")
                    ).scalar_one_or_none()
            discrepancies.extend(_projection_integrity_discrepancies(rest, dict(repo),
                {**dict(issue), "issue_number": mapping["issue_number"]}, group_id,
                dict(applied), (writer_request or {}).get("expected_writer_id")))
        elif int(mapping["applied_revision"]) > 0:
            discrepancies.append("applied_projection_missing")
    except (GitHubError, KeyError, TypeError):
        issue_error = True
    if not issue_error:
        try:
            events = rest.get_all(root + f"/issues/{mapping['issue_number']}/events?per_page=100")
        except GitHubError:
            event_error = True

    # Serialize the conclusion with assessment projection queueing and native
    # step dispatch. A readback from an older desired revision, a changed
    # inclusion binding, or a newly unresolved write cannot settle this row.
    with engine.begin() as connection:
        connection.execute(sa.select(assessment_policy.c.policy_id).where(
            assessment_policy.c.policy_id == 1).with_for_update()).first()
        current = connection.execute(sa.select(github_group_issues).where(
            github_group_issues.c.group_id == group_id).with_for_update()
            ).mappings().first()
        current_repo = connection.execute(sa.select(github_repositories).where(
            github_repositories.c.repository_id == repo["repository_id"])
            .with_for_update()).mappings().first()
        try:
            from uvm.github.api import _assert_group_audience_binding
            if current_repo is None:
                raise HTTPException(409, "repository approval unavailable")
            _assert_group_audience_binding(connection, dict(current_repo), group_id)
        except HTTPException:
            codes = ["included_scope_changed"]
            if _unresolved_steps(connection, group_id):
                codes.append("external_write_uncertain")
            connection.execute(github_group_issues.update().where(
                github_group_issues.c.group_id == group_id).values(
                    state="audience_blocked", discrepancy_codes=codes, updated_at=_now()))
            return False
        if current is None:
            return False
        current = dict(current)
        unresolved_current = _unresolved_steps(connection, group_id)
        snapshot_steps = [tuple(row[key] for key in
            ("step_id", "projection_id", "step_key", "state"))
            for row in unresolved_snapshot]
        current_steps = [tuple(row[key] for key in
            ("step_id", "projection_id", "step_key", "state"))
            for row in unresolved_current]
        changed = (_projection_map_version(current) != _projection_map_version(snapshot)
            or current_steps != snapshot_steps)
        if changed:
            if unresolved_current:
                connection.execute(github_group_issues.update().where(
                    github_group_issues.c.group_id == group_id).values(
                        state="uncertain", discrepancy_codes=["external_write_uncertain"],
                        updated_at=_now()))
            return False
        if issue_error:
            codes = (["external_write_uncertain"] if unresolved_current else
                ["projection_readback_unavailable"])
            connection.execute(github_group_issues.update().where(
                github_group_issues.c.group_id == group_id).values(
                    state="uncertain" if unresolved_current else "pending",
                    discrepancy_codes=codes, updated_at=_now()))
            return False

        if unresolved_current:
            discrepancies.append("external_write_uncertain")
        has_unsent = int(current["desired_revision"]) > int(current["applied_revision"])
        if has_unsent:
            discrepancies.append("projection_pending")
        native_drift = False
        for event in events:
            event_id = str(event.get("id") or _sha(event))
            event_type = str(event.get("event", "unknown"))
            if event_type in {"assigned", "unassigned"}:
                native_drift = True
            exists = connection.execute(sa.select(github_external_events.c.record_id).where(
                github_external_events.c.repository_id == repo["repository_id"],
                github_external_events.c.github_event_id == event_id)).first()
            if exists is None:
                connection.execute(github_external_events.insert().values(
                    record_id=str(uuid.uuid4()), repository_id=repo["repository_id"],
                    github_event_id=event_id, issue_number=mapping["issue_number"],
                    event_type=event_type,
                    actor_account_id=str((event.get("actor") or {}).get("id") or "") or None,
                    raw_payload=event, payload_digest=_sha(event),
                    created_at=_time(event.get("created_at")), received_at=_now(),
                    outcome=("requires_acknowledgement" if event_type in
                        {"assigned", "unassigned"} else "retained_external_observation")))
        if native_drift:
            discrepancies.append("native_owner_drift")
        substantive = [code for code in discrepancies if code != "projection_pending"]
        state = ("uncertain" if unresolved_current else
            "conflict" if substantive else
            "pending" if has_unsent else "applied")
        connection.execute(github_group_issues.update().where(
            github_group_issues.c.group_id == group_id).values(
                state=state, discrepancy_codes=sorted(set(discrepancies)),
                updated_at=_now()))
        return not unresolved_current and not event_error


def _project_one_owned(engine, rest, group_id):
    now = _now()
    verify_snapshot = None
    with engine.begin() as connection:
        from uvm.assessment.policy_lock import lock_policy
        lock_policy(connection, shared=True)
        policy_revision = connection.execute(sa.select(assessment_policy.c.revision).where(
            assessment_policy.c.policy_id == 1).with_for_update()).first()
        policy_revision = int(policy_revision.revision) if policy_revision else 0
        issue = connection.execute(sa.select(github_group_issues).where(
            github_group_issues.c.group_id == group_id).with_for_update()).mappings().first()
        if issue is None or issue["issue_number"] is None:
            return {"status": "unlinked", "sent": False}
        repo = connection.execute(sa.select(github_repositories).where(
            github_repositories.c.repository_id == issue["repository_id"])
            .with_for_update()).mappings().one()
        from uvm.github.api import _assert_group_audience_binding
        try:
            _assert_group_audience_binding(connection, dict(repo), group_id)
        except HTTPException:
            connection.execute(github_group_issues.update().where(
                github_group_issues.c.group_id == group_id).values(
                    state="audience_blocked", discrepancy_codes=["included_scope_changed"],
                    updated_at=now))
            return {"status": "audience_blocked", "sent": False}
        audience = repo["audience_document"] or {}
        if audience.get("approved") is not True or audience.get("data_access_approved") is not True:
            connection.execute(github_group_issues.update().where(
                github_group_issues.c.group_id == group_id).values(
                    state="audience_blocked", discrepancy_codes=["repository_audience_unapproved"],
                    updated_at=now))
            return {"status": "audience_blocked", "sent": False}
        unresolved = connection.execute(sa.select(github_projection_intents).where(
            github_projection_intents.c.group_id == group_id,
            github_projection_intents.c.state.in_(["dispatching", "uncertain"])
            ).order_by(github_projection_intents.c.desired_revision.desc()).limit(1)
            .with_for_update()).mappings().first()
        if unresolved:
            connection.execute(github_group_issues.update().where(
                github_group_issues.c.group_id == group_id).values(
                    state="uncertain", discrepancy_codes=["external_write_uncertain"],
                    updated_at=now))
            intent, repo, issue = dict(unresolved), dict(repo), dict(issue)
            recovering = True
        else:
            intent = connection.execute(sa.select(github_projection_intents).where(
            github_projection_intents.c.group_id == group_id,
            github_projection_intents.c.state == "pending").order_by(
            github_projection_intents.c.desired_revision.desc()).limit(1)
            .with_for_update()).mappings().first()
            if intent is None:
                latest = connection.execute(sa.select(github_projection_intents).where(
                    github_projection_intents.c.group_id == group_id).order_by(
                    github_projection_intents.c.desired_revision.desc()).limit(1)
                    ).mappings().first()
                if latest is None or int(issue["applied_revision"]) < int(latest["desired_revision"]):
                    return {"status": "pending", "sent": False}
                writer_request = connection.execute(sa.select(
                    github_projection_steps.c.request).where(
                    github_projection_steps.c.projection_id == latest["projection_id"],
                    github_projection_steps.c.step_key == "comment_create")).scalar_one_or_none()
                writer_id = (writer_request or {}).get("expected_writer_id")
                intent, repo, issue, latest = dict(latest), dict(repo), dict(issue), dict(latest)
                from uvm.connectors.api import _settings as connector_settings
                connector_snapshot = None
                configured = connection.execute(sa.select(connectors).where(
                    connectors.c.configuration_revision > 0)).mappings().all()
                matched = []
                for candidate in configured:
                    candidate_settings = connector_settings(candidate, connection,
                        str(candidate["connector_id"]))
                    if str(repo["repository_id"]) in {str(value) for value in
                            (candidate_settings.get("github") or {}).get("repository_ids", [])}:
                        matched.append(candidate)
                if len(matched) == 1:
                    candidate = matched[0]
                    connector_snapshot = {"connector_id": str(candidate["connector_id"]),
                        "configuration_revision": int(candidate["configuration_revision"]),
                        "active_configuration_revision": candidate["active_configuration_revision"],
                        "connector_revision": int(candidate["connector_revision"]),
                        "lifecycle": candidate["lifecycle"],
                        "recovery_epoch_id": (candidate["recovery"].get("recovery_epoch_id") or ""),
                        "recovery_state": candidate["recovery"].get("state")}
                verify_snapshot = {"policy_revision": policy_revision,
                    "audience_revision": int(repo["audience_revision"]),
                    "desired_revision": int(issue["desired_revision"]),
                    "applied_revision": int(issue["applied_revision"]),
                    "projection_id": latest["projection_id"],
                    "projection_revision": int(latest["desired_revision"]),
                    "connector": connector_snapshot,
                    "writer_id": writer_id}
            else:
                captured_steps = connection.execute(sa.select(github_projection_steps.c.step_id).where(
                    github_projection_steps.c.projection_id == intent["projection_id"])
                    .limit(1)).first()
                connection.execute(github_projection_intents.update().where(
                    github_projection_intents.c.group_id == group_id,
                    github_projection_intents.c.state == "pending",
                    github_projection_intents.c.desired_revision < intent["desired_revision"])
                    .values(state="superseded", updated_at=now))
                operation_id = str(uuid.uuid4())
                connection.execute(github_projection_intents.update().where(
                    github_projection_intents.c.projection_id == intent["projection_id"])
                    .values(state="dispatching", operation_id=operation_id,
                        attempted_at=now, updated_at=now))
                connection.execute(github_group_issues.update().where(
                    github_group_issues.c.group_id == group_id).values(
                        state="pending", updated_at=now))
                intent, repo, issue = dict(intent), dict(repo), dict(issue)
                # Pending may mean preflight safely deferred before any write, or
                # a known partial projection whose settled steps are reusable.
                # Only unresolved step rows block or invoke uncertain recovery.
                recovering = captured_steps is not None

    from uvm.github.api import _repo_audience
    try:
        if verify_snapshot is not None:
            discrepancies = _projection_integrity_discrepancies(
                rest, repo, issue, group_id, intent, verify_snapshot["writer_id"])
            verified_state = "conflict" if discrepancies else "applied"
            with engine.begin() as connection:
                from uvm.assessment.policy_lock import lock_policy
                lock_policy(connection, shared=True)
                current_policy = connection.execute(sa.select(assessment_policy.c.revision).where(
                    assessment_policy.c.policy_id == 1)).scalar_one()
                current_issue = connection.execute(sa.select(github_group_issues).where(
                    github_group_issues.c.group_id == group_id).with_for_update()).mappings().one_or_none()
                current_repo = connection.execute(sa.select(github_repositories).where(
                    github_repositories.c.repository_id == repo["repository_id"])
                    .with_for_update()).mappings().one_or_none()
                current_intent = connection.execute(sa.select(github_projection_intents).where(
                    github_projection_intents.c.projection_id == verify_snapshot["projection_id"])
                    .with_for_update()).mappings().one_or_none()
                current_connector = None
                connector_snapshot = verify_snapshot["connector"]
                if connector_snapshot is not None:
                    current_connector = connection.execute(sa.select(connectors).where(
                        connectors.c.connector_id == connector_snapshot["connector_id"])
                        ).mappings().one_or_none()
                if (int(current_policy) != verify_snapshot["policy_revision"] or current_issue is None
                        or current_repo is None or current_intent is None
                        or int(current_issue["desired_revision"]) != verify_snapshot["desired_revision"]
                        or int(current_issue["applied_revision"]) != verify_snapshot["applied_revision"]
                        or int(current_repo["audience_revision"]) != verify_snapshot["audience_revision"]
                        or int(current_intent["desired_revision"]) != verify_snapshot["projection_revision"]
                        or current_intent["state"] != "applied"
                        or (connector_snapshot is not None and (current_connector is None
                            or int(current_connector["configuration_revision"]) != connector_snapshot["configuration_revision"]
                            or current_connector["active_configuration_revision"] != connector_snapshot["active_configuration_revision"]
                            or int(current_connector["connector_revision"]) != connector_snapshot["connector_revision"]
                            or current_connector["lifecycle"] != connector_snapshot["lifecycle"]
                            or (current_connector["recovery"].get("recovery_epoch_id") or "") != connector_snapshot["recovery_epoch_id"]
                            or current_connector["recovery"].get("state") != connector_snapshot["recovery_state"]))):
                    return {"status": "pending", "sent": False,
                        "reason": "verification_snapshot_changed"}
                connection.execute(github_group_issues.update().where(
                    github_group_issues.c.group_id == group_id).values(
                        state=verified_state, discrepancy_codes=discrepancies,
                        last_reconciled_at=_now(), updated_at=_now()))
            return {"status": verified_state, "sent": False,
                "discrepancy_codes": discrepancies}
        actual_audience, digest = _repo_audience(rest, repo)
        saved = repo["audience_document"] or {}
        expected_audience = {"repository_id": str(repo["repository_id"]), "private": True,
            "reader_account_ids": sorted(saved.get("reader_account_ids", [])),
            "team_slugs": sorted(saved.get("team_slugs", []))}
        if actual_audience != expected_audience or saved.get("snapshot_sha256") != digest:
            raise GitHubError(403, "audience changed")
        issue_path = repo_path(repo["owner"], repo["name"]) + f"/issues/{issue['issue_number']}"
        current, _ = rest.get_with_headers(issue_path)
        comments = rest.get_all(issue_path + "/comments?per_page=100")
        marker = _projection_marker(group_id, int(intent["desired_revision"]))
        comment_request = None
        with engine.connect() as db:
            comment_request = db.execute(sa.select(github_projection_steps.c.request).where(
                github_projection_steps.c.projection_id == intent["projection_id"],
                github_projection_steps.c.step_key == "comment_create")).scalar_one_or_none()
        expected_body = _projection_markdown(intent["payload"], int(intent["desired_revision"]))
        writer_id = (comment_request or {}).get("expected_writer_id")
        marked = [item for item in comments if marker in (item.get("body") or "")]
        exact = [item for item in marked if item.get("body") == expected_body
            and str((item.get("user") or {}).get("id")) == str(writer_id)] if writer_id else []
        if marked and (len(marked) != 1 or len(exact) != 1):
            _set_projection_comment_conflict(engine, intent["projection_id"], group_id)
            return {"status": "conflict", "sent": False,
                "reason": "projection_comment_tampered_or_duplicate"}
        marker_exists = len(exact) == 1
        with engine.connect() as db:
            unresolved_any = db.execute(sa.select(github_projection_steps.c.step_id).where(
                github_projection_steps.c.projection_id == intent["projection_id"],
                github_projection_steps.c.state.in_(["dispatching", "uncertain"])).limit(1)).first()
            unresolved_comment = db.execute(sa.select(github_projection_steps.c.step_id).where(
                github_projection_steps.c.projection_id == intent["projection_id"],
                github_projection_steps.c.step_key == "comment_create",
                github_projection_steps.c.state.in_(["dispatching", "uncertain"]))).first()
        if recovering and intent.get("in_flight_step") != "comment_create" and unresolved_any:
            return {"status": "uncertain", "sent": False,
                "reason": "external_step_outcome_unresolved",
                "step": intent.get("in_flight_step")}
        if recovering and unresolved_comment and not marker_exists:
            return {"status": "uncertain", "sent": False,
                "reason": "projection_marker_not_observed"}
        if not recovering and marked:
            raise GitHubOutcomeUnknown("projection marker exists for a new write reservation")
        if not marker_exists:
            bot_login = getattr(rest, "app_bot_login", None)
            viewer = (rest.get("users/" + quote(bot_login, safe="[]-"))
                if bot_login else rest.get("/user"))
            # Capture the attributable writer before dispatch; a fresh step has
            # no retained request row to supply this ID during immediate
            # readback, while a recovered step already has the same value.
            writer_id = str(viewer["id"])
            _send_projection_step(engine, intent, group_id, "comment_create",
                {"method": "POST", "path": issue_path + "/comments",
                    "body": {"body": _projection_markdown(intent["payload"],
                        int(intent["desired_revision"]))},
                    "expected_writer_id": writer_id}, rest)
        elif recovering and unresolved_comment:
            _settle_projection_step(engine, intent["projection_id"],
                "comment_create", "applied", {"recovered_by_exact_comment": True})
        reserved = {"uvm:open", "uvm:partial", "uvm:remediated"}
        current = rest.get(issue_path)
        current_labels = {item["name"] for item in current.get("labels", [])}
        desired_label = intent["payload"]["status_label"]
        # GitHub rejects If-Match on issue writes. Change only UVM-owned labels
        # through additive/removal endpoints so concurrent human labels survive.
        for stale_label in sorted((current_labels & reserved) - {desired_label}):
            _send_projection_step(engine, intent, group_id,
                "label_delete:" + stale_label,
                {"method": "DELETE", "path": issue_path + "/labels/" + quote(stale_label, safe=""),
                    "body": None}, rest, allow_404=True)
        if desired_label not in current_labels:
            _send_projection_step(engine, intent, group_id, "label_add:" + desired_label,
                {"method": "POST", "path": issue_path + "/labels",
                    "body": {"labels": [desired_label]}}, rest)
        current = rest.get(issue_path)
        if current.get("state") != intent["payload"]["issue_state"]:
            _send_projection_step(engine, intent, group_id, "issue_state",
                {"method": "PATCH", "path": issue_path,
                    "body": {"state": intent["payload"]["issue_state"]}}, rest)
        verified = rest.get(issue_path)
        verify_comments = rest.get_all(issue_path + "/comments?per_page=100")
        label_names = {item["name"] for item in verified.get("labels", [])}
        if (verified.get("state") != intent["payload"]["issue_state"]
                or intent["payload"]["status_label"] not in label_names
                or len([item for item in verify_comments if marker in (item.get("body") or "")]) != 1
                or len([item for item in verify_comments if item.get("body") == expected_body
                    and str((item.get("user") or {}).get("id")) == str(writer_id)]) != 1):
            raise GitHubOutcomeUnknown("projection readback is incomplete")
    except GitHubOutcomeUnknown:
        _set_projection_state(engine, intent["projection_id"], group_id,
            "uncertain", "external_write_uncertain")
        return {"status": "uncertain", "sent": True}
    except HTTPException:
        _block_projection_audience(engine, intent["projection_id"], group_id)
        return {"status": "audience_blocked", "sent": False}
    except SecretUnavailable:
        return {"status": "stale", "sent": False,
            "reason": "connector_dispatch_fenced"}
    except GitHubError as exc:
        with engine.connect() as db:
            unresolved = db.execute(sa.select(github_projection_steps.c.step_id).where(
                github_projection_steps.c.projection_id == intent["projection_id"],
                github_projection_steps.c.state.in_(["dispatching", "uncertain"])).limit(1)).first()
        if not unresolved:
            _block_projection_audience(engine, intent["projection_id"], group_id)
            return {"status": "audience_blocked", "sent": False,
                "reason": "preflight_read_failed", "http_status": exc.status}
        _LOG.warning("github_projection_rejected status=%s message=%s",
            exc.status, json.dumps({key: (exc.body or {}).get(key) for key in
                ("message", "errors", "documentation_url", "status")}, sort_keys=True))
        if exc.status >= 500 or exc.status in {408, 412, 429}:
            _set_projection_state(engine, intent["projection_id"], group_id,
                "uncertain", "external_write_uncertain")
            return {"status": "uncertain", "sent": True}
        _set_projection_state(engine, intent["projection_id"], group_id,
            "failed", "projection_rejected")
        return {"status": "failed", "sent": True, "http_status": exc.status}
    _set_projection_state(engine, intent["projection_id"], group_id,
        "applied", None, applied_revision=intent["desired_revision"])
    return {"status": "applied", "sent": True,
        "desired_revision": intent["desired_revision"]}


def _settle_projection_step(engine, projection_id, step_key, state, response):
    now = _now()
    with engine.begin() as connection:
        connection.execute(github_projection_steps.update().where(
            github_projection_steps.c.projection_id == projection_id,
            github_projection_steps.c.step_key == step_key).values(
                state=state, response=response, settled_at=now))
        connection.execute(github_projection_intents.update().where(
            github_projection_intents.c.projection_id == projection_id).values(
                in_flight_step=None, updated_at=now))


def _send_projection_step(engine, intent, group_id, step_key, request, rest,
                          allow_404=False):
    now = _now()
    digest = _sha(request)
    with engine.begin() as connection:
        from uvm.operations.backup_settings import intent_quarantined
        if intent_quarantined(connection, intent["projection_id"]):
            raise GitHubOutcomeUnknown("projection is held for recovery reconciliation")

        # Poll finalization takes this same row lock before committing remote
        # readback conclusions. A new native write therefore either appears in
        # its revalidation or starts strictly after that conclusion commits.
        connection.execute(sa.select(github_group_issues.c.group_id).where(
            github_group_issues.c.group_id == group_id).with_for_update()).first()
        previous = connection.execute(sa.select(github_projection_steps).where(
            github_projection_steps.c.projection_id == intent["projection_id"],
            github_projection_steps.c.step_key == step_key).with_for_update()
            ).mappings().first()
        if previous is not None:
            if previous["request_digest"] != digest:
                raise GitHubOutcomeUnknown("captured GitHub operation content changed")
            if previous["state"] == "applied":
                return previous["response"]
            # A second dispatch is forbidden after a crash or lost response.
            if previous["state"] in {"dispatching", "uncertain"}:
                raise GitHubOutcomeUnknown(f"{step_key} outcome remains unresolved")
            raise GitHubError(409, "prior external projection step failed")
        connection.execute(github_projection_steps.insert().values(
            step_id=str(uuid.uuid4()), projection_id=intent["projection_id"],
            group_id=group_id, step_key=step_key, request_digest=digest,
            request=request, state="dispatching", response=None,
            attempted_at=now, settled_at=None, created_at=now))
        connection.execute(github_projection_intents.update().where(
            github_projection_intents.c.projection_id == intent["projection_id"])
            .values(in_flight_step=step_key, updated_at=now))
    try:
        response = rest.write(request["method"], request["path"], request["body"])
    except GitHubError as exc:
        uncertain = exc.status >= 500 or exc.status in {408, 412, 429}
        if allow_404 and exc.status == 404:
            _settle_projection_step(engine, intent["projection_id"], step_key,
                "applied", {"already_absent": True})
            return {"already_absent": True}
        now = _now()
        with engine.begin() as connection:
            connection.execute(github_projection_steps.update().where(
                github_projection_steps.c.projection_id == intent["projection_id"],
                github_projection_steps.c.step_key == step_key).values(
                    state="uncertain" if uncertain else "failed",
                    response={"http_status": exc.status}, settled_at=now))
            connection.execute(github_projection_intents.update().where(
                github_projection_intents.c.projection_id == intent["projection_id"])
                .values(state="uncertain" if uncertain else "failed",
                    in_flight_step=step_key if uncertain else None, updated_at=now))
            connection.execute(github_group_issues.update().where(
                github_group_issues.c.group_id == group_id).values(
                    state="uncertain" if uncertain else "failed",
                    discrepancy_codes=["external_write_uncertain" if uncertain
                        else "projection_rejected"], updated_at=now))
        raise
    except GitHubOutcomeUnknown:
        now = _now()
        with engine.begin() as connection:
            connection.execute(github_projection_steps.update().where(
                github_projection_steps.c.projection_id == intent["projection_id"],
                github_projection_steps.c.step_key == step_key).values(
                    state="uncertain", settled_at=now))
            connection.execute(github_projection_intents.update().where(
                github_projection_intents.c.projection_id == intent["projection_id"])
                .values(state="uncertain", in_flight_step=step_key, updated_at=now))
            connection.execute(github_group_issues.update().where(
                github_group_issues.c.group_id == group_id).values(
                    state="uncertain", discrepancy_codes=["external_write_uncertain"],
                    updated_at=now))
        raise
    _settle_projection_step(engine, intent["projection_id"], step_key,
        "applied", response if isinstance(response, (dict, list, str, int, float, bool)) else None)
    return response


def _project_one(engine, rest, group_id):
    # A PostgreSQL session advisory lock spans remote calls as well as local
    # transactions. If a worker dies, the server releases it; durable step
    # records still prevent replaying an uncertain external write.
    raw = engine.raw_connection()
    try:
        cursor = raw.cursor()
        cursor.execute("SELECT pg_advisory_lock(hashtextextended(%s, 0))", (group_id,))
        try:
            return _project_one_owned(engine, rest, group_id)
        finally:
            cursor.execute("SELECT pg_advisory_unlock(hashtextextended(%s, 0))", (group_id,))
            cursor.close()
    finally:
        raw.close()


def _set_projection_state(engine, projection_id, group_id, state, discrepancy,
                          applied_revision=None):
    now = _now()
    with engine.begin() as connection:
        connection.execute(github_projection_intents.update().where(
            github_projection_intents.c.projection_id == projection_id).values(
                state=state, updated_at=now))
        latest = connection.execute(sa.select(github_group_issues.c.desired_revision,
            github_group_issues.c.applied_revision).where(
                github_group_issues.c.group_id == group_id).with_for_update()).one()
        values = {"state": state,
            "discrepancy_codes": [discrepancy] if discrepancy else [], "updated_at": now}
        if applied_revision is not None:
            applied = max(int(latest.applied_revision), int(applied_revision))
            desired = int(latest.desired_revision)
            values.update(applied_revision=applied,
                state="applied" if desired <= applied else "pending",
                discrepancy_codes=[] if desired <= applied else ["projection_pending"],
                last_reconciled_at=now)
        connection.execute(github_group_issues.update().where(
            github_group_issues.c.group_id == group_id).values(**values))


def _set_projection_comment_conflict(engine, projection_id, group_id):
    now = _now()
    with engine.begin() as connection:
        unresolved = connection.execute(sa.select(github_projection_steps.c.step_id).where(
            github_projection_steps.c.projection_id == projection_id,
            github_projection_steps.c.state.in_(["dispatching", "uncertain"])).limit(1)).first()
        connection.execute(github_projection_intents.update().where(
            github_projection_intents.c.projection_id == projection_id).values(
                state="uncertain" if unresolved else "failed", updated_at=now))
        connection.execute(github_group_issues.update().where(
            github_group_issues.c.group_id == group_id).values(
                state="conflict", discrepancy_codes=(
                    ["projection_comment_conflict", "external_write_uncertain"]
                    if unresolved else ["projection_comment_conflict"]), updated_at=now))


def _block_projection_audience(engine, projection_id, group_id):
    now = _now()
    with engine.begin() as connection:
        unresolved = connection.execute(sa.select(github_projection_steps.c.step_id).where(
            github_projection_steps.c.projection_id == projection_id,
            github_projection_steps.c.state.in_(["dispatching", "uncertain"])).limit(1)).first()
        if not unresolved:
            # Audience reads are not external writes. A failure here may safely
            # defer a reservation, but must never rename a dispatched step.
            connection.execute(github_projection_intents.update().where(
                github_projection_intents.c.projection_id == projection_id,
                github_projection_intents.c.state == "dispatching").values(
                    state="pending", in_flight_step=None, updated_at=now))
        connection.execute(github_group_issues.update().where(
            github_group_issues.c.group_id == group_id).values(
                state="audience_blocked", discrepancy_codes=["repository_audience_unknown"],
                updated_at=now))


_COMMAND_RE = re.compile(r"^/uvm v1\s*\n```json\s*\n(.*?)\n```\s*$", re.DOTALL)


def _parse_submission(body):
    match = _COMMAND_RE.fullmatch((body or "").strip())
    if not match:
        return None
    try:
        value = json.loads(match.group(1))
    except json.JSONDecodeError:
        return None
    if (not isinstance(value, dict) or set(value) != {"preview_id", "signature", "command"}
            or not isinstance(value.get("signature"), str)
            or not isinstance(value.get("command"), dict)):
        return None
    return value


def _poll_comment_disposition(raw: dict, captured_comment_ids: set[str],
                             current_group_ids: set[str]) -> str:
    """Classify safely before opening per-comment inbox transactions."""
    if str(raw.get("id", "")) in captured_comment_ids:
        return "process"
    submission = _parse_submission(raw.get("body"))
    if submission is None:
        return "ignored"
    try:
        group_id = _uuid(submission["command"].get("target_id"), "target_id")
    except HTTPException:
        return "process"
    return "process" if str(group_id) in current_group_ids else "unknown_group"


def _finish_inbox(engine, inbox_id, state, outcome):
    with engine.begin() as connection:
        connection.execute(github_inbox_commands.update().where(
            github_inbox_commands.c.inbox_id == inbox_id).values(
                state=state, outcome=outcome,
                processed_at=None if state == "pending" else _now()))


def _process_comment(engine, app, repo, raw):
    captured_text = raw.get("body") or ""
    submission = _parse_submission(captured_text)
    repo_id, comment_id = str(repo["repository_id"]), str(raw["id"])
    actor_id = str((raw.get("user") or {}).get("id", ""))
    issue_match = re.search(r"/issues/(\d+)$", raw.get("issue_url", ""))
    issue_number = int(issue_match.group(1)) if issue_match else 0
    body_digest = hashlib.sha256(captured_text.encode()).hexdigest()
    now = _now()
    with engine.begin() as connection:
        existing = connection.execute(sa.select(github_inbox_commands).where(
            github_inbox_commands.c.repository_id == repo_id,
            github_inbox_commands.c.comment_id == comment_id).with_for_update()).mappings().first()
        if existing:
            existing = dict(existing)
            if existing["body_digest"] != body_digest:
                event_key = f"comment-edit:{comment_id}:{body_digest}"
                event = connection.execute(sa.select(github_external_events.c.record_id).where(
                    github_external_events.c.repository_id == repo_id,
                    github_external_events.c.github_event_id == event_key)).first()
                if event is None:
                    connection.execute(github_external_events.insert().values(
                        record_id=str(uuid.uuid4()), repository_id=repo_id,
                        github_event_id=event_key, issue_number=issue_number,
                        event_type="comment_body_changed_after_capture",
                        actor_account_id=actor_id or None, raw_payload=raw,
                        payload_digest=body_digest,
                        created_at=_time(raw.get("updated_at")), received_at=now,
                        outcome="retained_original_submission"))
            if existing["state"] != "pending":
                return existing["state"]
            # A captured inbox item always executes the immutable first body.
            captured_text = existing["body"]
            submission = _parse_submission(captured_text)
            preview_id = existing["preview_id"]
            inbox_id = existing["inbox_id"]
            group_id = existing["group_id"]
            submitted_at = _time((existing["raw_comment"] or {}).get("created_at"))
        else:
            if submission is None:
                return "ignored"
            command = submission["command"]
            try:
                group_id = _uuid(command.get("target_id"), "target_id")
                preview_id = _uuid(submission["preview_id"], "preview_id")
            except HTTPException:
                return "invalid"
            if connection.execute(sa.select(groups.c.group_id).where(
                    groups.c.group_id == group_id)).scalar_one_or_none() is None:
                return "unknown_group"
            link = connection.execute(sa.select(github_identity_links).where(
                github_identity_links.c.github_host == "github.com",
                github_identity_links.c.account_id == actor_id,
                github_identity_links.c.enabled.is_(True)).order_by(
                    github_identity_links.c.updated_at.desc()).limit(1)).mappings().first()
            preview = connection.execute(sa.select(github_command_previews).where(
                github_command_previews.c.preview_id == preview_id)).mappings().first()
            submitted_at = _time(raw.get("created_at"))
            edited_before_capture = (_time(raw.get("updated_at")) != _time(raw.get("created_at")))
            if edited_before_capture:
                state = "needs_resubmission"
                initial_outcome = {"code": "comment_edited_before_capture"}
            elif link is None:
                state = "denied"
                initial_outcome = {"code": "github_actor_unlinked"}
            elif preview is None:
                state = "needs_resubmission"
                initial_outcome = {"code": "preview_not_found"}
            elif preview["state"] not in {"acknowledged", "executed"}:
                state = "needs_resubmission"
                initial_outcome = {"code": "preview_not_acknowledged"}
            elif submitted_at is None or submitted_at > preview["expires_at"]:
                state = "needs_resubmission"
                initial_outcome = {"code": "preview_expired_before_submission"}
            elif preview["principal_id"] != link["principal_id"] or preview["link_id"] != link["link_id"]:
                state = "denied"
                initial_outcome = {"code": "github_actor_unlinked"}
            elif preview["repository_id"] != repo_id or preview["issue_number"] != issue_number:
                state = "needs_resubmission"
                initial_outcome = {"code": "preview_target_mismatch"}
            elif preview["canonical_digest"] != _sha(command):
                state = "needs_resubmission"
                initial_outcome = {"code": "preview_command_mismatch"}
            elif not hmac.compare_digest(preview["signature"], submission["signature"]):
                state = "needs_resubmission"
                initial_outcome = {"code": "preview_signature_invalid"}
            else:
                state = "pending"
                initial_outcome = None
            inbox_id = str(uuid.uuid4())
            connection.execute(github_inbox_commands.insert().values(
                inbox_id=inbox_id, repository_id=repo_id, group_id=group_id,
                issue_number=issue_number, comment_id=comment_id, account_id=actor_id,
                link_id=link["link_id"] if link else None,
                preview_id=preview_id if preview is not None else None,
                preview_reference=str(submission["preview_id"]),
                connector_command_id=None,
                body=captured_text, body_digest=body_digest, raw_comment=raw,
                state=state, outcome=initial_outcome, first_seen_at=now,
                processed_at=now if state != "pending" else None))
            if state != "pending":
                return state

    command = submission["command"]
    with engine.connect() as connection:
        link = connection.execute(sa.select(github_identity_links).where(
            github_identity_links.c.link_id == (existing["link_id"] if existing else
                sa.select(github_identity_links.c.link_id).where(
                    github_identity_links.c.github_host == "github.com",
                    github_identity_links.c.account_id == actor_id).scalar_subquery()),
            github_identity_links.c.enabled.is_(True))).mappings().first()
        preview = connection.execute(sa.select(github_command_previews).where(
            github_command_previews.c.preview_id == preview_id)).mappings().first()
    invalid_code = None
    if link is None or preview is None or not link["enabled"] or link["account_id"] != actor_id:
        invalid_code = "github_actor_unlinked"
    elif link["principal_id"] != preview["principal_id"] or link["revision"] != preview["link_revision"] or link["link_id"] != preview["link_id"]:
        invalid_code = "github_actor_link_revision_changed"
    elif preview["state"] not in {"acknowledged", "executed"}:
        invalid_code = "preview_not_acknowledged"
    elif preview["canonical_digest"] != _sha(command):
        invalid_code = "preview_command_mismatch"
    elif not hmac.compare_digest(preview["signature"], submission["signature"]):
        invalid_code = "preview_signature_invalid"
    elif submitted_at is None or submitted_at > preview["expires_at"]:
        invalid_code = "preview_expired_before_submission"
    if invalid_code:
        _finish_inbox(engine, inbox_id, "denied", {"code": invalid_code})
        return "denied"
    try:
        from uvm.github.api import _g3_envelope
        envelope = _g3_envelope(command, group_id)
        # Signed command identity is stable across reposts; transport comment
        # identity is retained separately for inbox deduplication.
        namespace = uuid.UUID("0dfaa145-d9c6-4333-ae3c-dc590fbf0e35")
        signed_command_id = command["command_id"]
        connector_key = f"github.com:{actor_id}:{repo_id}:{issue_number}:{signed_command_id}"
        envelope["command_id"] = str(uuid.uuid5(namespace, connector_key))
        trusted_context = {"link_id": link["link_id"],
            "link_revision": link["revision"], "account_id": actor_id,
            "preview_id": preview_id, "repository_id": repo_id,
            "issue_number": issue_number, "command_digest": preview["canonical_digest"],
            "signature": submission["signature"], "submission_at": submitted_at}
        with engine.begin() as connection:
            connection.execute(github_inbox_commands.update().where(
                github_inbox_commands.c.inbox_id == inbox_id).values(
                    connector_command_id=envelope["command_id"]))
        result = app.state.g4_assessment_executor(envelope, link["principal_id"], trusted_context)
    except (HTTPException, ValueError) as exc:
        if isinstance(exc, HTTPException):
            detail = exc.detail if isinstance(exc.detail, dict) else {}
            status = exc.status_code
            code = detail.get("code", "assessment_command_failed")
            _LOG.warning("github_inbound_assessment_denied status=%s code=%s message=%s",
                status, code, str(detail.get("message", ""))[:160])
        else:
            status, code, detail = 422, "invalid_command", {}
        state = ("pending" if status >= 500 or status in {408, 429}
            else "denied" if status == 403 else "conflict" if status == 409 else "error")
        _finish_inbox(engine, inbox_id, state, {"code": code,
            "status": status, "details": detail.get("details", {}),
            "retryable": state == "pending"})
        return state
    _finish_inbox(engine, inbox_id, "applied", result)
    with engine.begin() as connection:
        connection.execute(github_command_previews.update().where(
            github_command_previews.c.preview_id == preview_id).values(state="executed"))
    return "applied"


def install_github_lifecycle_routes(app: FastAPI, authenticate, authorise, rest_factory):
    engine = app.state.engine

    def final_identity(connection, request, principal):
        if request is None:
            from uvm.auth.schema import AUTHORITY_CONTEXT
            context = AUTHORITY_CONTEXT.get()
            if context is not None and context.principal_id != principal:
                _error(403, "authority_changed", "Current identity authority changed")
            return context
        auth_service = getattr(request.app.state, "oidc_auth", None)
        context = auth_service.final_context(connection, request) if auth_service else None
        if context is not None and context.principal_id != principal:
            _error(403, "authority_changed", "Current identity authority changed")
        return context

    def permitted(principal, connection, group_id, action, request):
        group = connection.execute(sa.select(groups).where(
            groups.c.group_id == group_id)).mappings().first()
        if group is None:
            _error(404, "invalid_command", "Group not found")
        read_grants = _require_tx(connection, principal, "assessment.read", group_id,
            group["source_family"])
        grants = _require_tx(connection, principal, action, group_id,
            group["source_family"])
        final_identity(connection, request, principal)
        from uvm.auth.schema import AUTHORITY_CONTEXT
        from uvm.auth.service import group_scope_covered
        # The exact source ceiling must belong to an identity group that also
        # grants both the read and requested writer role.
        context = AUTHORITY_CONTEXT.get()
        if context is not None:
            for candidates in (read_grants, grants):
                if not any(group_scope_covered(connection, context, [group_id],
                        granting_identity_groups=[item.get("principal_id")]) for item in candidates):
                    _error(403, "source_scope_forbidden", "Current exact source scope is required")
        return group

    def authorize_poll_repository(connection, repo, principal, request=None):
        """Shared current connector, audience-scope and actor guard for G4 poll work."""
        from uvm.auth.schema import AUTHORITY_CONTEXT
        from uvm.auth.service import group_scope_covered
        included_scopes = (repo.get("audience_document") or {}).get("included_scopes", {})
        included_group_ids = tuple(included_scopes)
        source_families = set(connection.execute(sa.select(
            source_observations.c.source_family).select_from(
            source_observations.join(occurrences,
                source_observations.c.occurrence_id == occurrences.c.occurrence_id).join(
                exposures, occurrences.c.exposure_id == exposures.c.exposure_id))
            .where(exposures.c.group_id.in_(included_group_ids))).scalars()) if included_group_ids else set()
        if not included_group_ids or not source_families:
            _error(403, "source_scope_forbidden", "Current exact source scope is required")
        for source_family in sorted(source_families):
            scoped_groups = tuple(group_id for group_id in included_group_ids
                if connection.execute(sa.select(sa.func.count()).select_from(
                    source_observations.join(occurrences,
                        source_observations.c.occurrence_id == occurrences.c.occurrence_id).join(
                        exposures, occurrences.c.exposure_id == exposures.c.exposure_id))
                    .where(exposures.c.group_id == group_id,
                        source_observations.c.source_family == source_family)).scalar_one() > 0)
            for action in ("github.poll", "assessment.read"):
                grants = _require_tx(connection, principal, action,
                    str(repo["repository_id"]), source_family=source_family)
                context = AUTHORITY_CONTEXT.get()
                if context is not None and not group_scope_covered(connection, context,
                        scoped_groups,
                        granting_identity_groups=[item.get("principal_id") for item in grants]):
                    _error(403, "source_scope_forbidden", "Current exact source scope is required")
        final_identity(connection, request, principal)
        return repo

    @app.post("/api/v1/github/groups/{group_id}/create")
    def create_issue(group_id: str, body: dict, request: Request, principal: str = Depends(authenticate)):
        group_id = _uuid(group_id, "group_id")
        if not isinstance(body, dict) or set(body) != {"repository_id"}:
            _error(422, "invalid_command", "Issue creation request is invalid")
        with engine.begin() as connection:
            permitted(principal, connection, group_id, "github.issue.sync", request)
            repo = _repo(connection, body["repository_id"])
            from uvm.github.api import _assert_group_audience_binding
            _assert_group_audience_binding(connection, repo, group_id)
        rest = rest_factory(principal=principal, action="github.issue.sync",
            authorization_target=group_id)
        _audience(rest, repo)
        outcome = _create_or_recover(engine, rest, repo, group_id)
        return {"schema_version": 1, "group_id": group_id, **outcome}

    @app.post("/api/v1/github/groups/{group_id}/reconcile")
    def reconcile_group(group_id: str, request: Request, principal: str = Depends(authenticate)):
        group_id = _uuid(group_id, "group_id")
        with engine.begin() as connection:
            permitted(principal, connection, group_id, "github.issue.sync", request)
            issue = connection.execute(sa.select(github_group_issues).where(
                github_group_issues.c.group_id == group_id)).mappings().first()
            if issue is None:
                _error(404, "github_issue_unlinked", "Group has no managed issue")
            repo = _repo(connection, issue["repository_id"])
        rest = rest_factory(principal=principal, action="github.issue.sync",
            authorization_target=group_id)
        return {"schema_version": 1, "group_id": group_id,
            **_project_one(engine, rest, group_id)}

    @app.post("/api/v1/github/webhooks/{repository_id}", status_code=202)
    async def receive_webhook(repository_id: str, request: Request):
        from uvm.github.webhooks import MAX_WEBHOOK_BYTES, parse_delivery, verify_signature
        if request.headers.get("content-type", "").split(";", 1)[0].strip().lower() != "application/json":
            _error(415, "unsupported_media_type", "Webhook content type must be application/json")
        body_parts, size = [], 0
        async for part in request.stream():
            size += len(part)
            if size > MAX_WEBHOOK_BYTES:
                _error(413, "payload_too_large", "Webhook payload exceeds the configured limit")
            body_parts.append(part)
        body = b"".join(body_parts)
        signature = request.headers.get("x-hub-signature-256", "")
        with engine.begin() as connection:
            # Hold the current connector, secret and authority fence until the
            # durable delivery admission is recorded. Slow request bodies are
            # consumed before taking these locks, so disable/revoke can win
            # until this admission boundary and never just after a stale read.
            try:
                from uvm.connectors.runtime import runtime_secret_admitted
                secret, secret_version, _policy = runtime_secret_admitted(
                    connection, "webhook_secret")
            except (OSError, RuntimeError):
                configured = connection.execute(sa.select(sa.func.count()).select_from(
                    connectors).where(connectors.c.configuration_revision > 0)).scalar_one()
                if configured:
                    _error(503, "webhook_secret_unavailable", "Webhook secret is unavailable")
                try:
                    from uvm.github.webhooks import read_webhook_secret
                    secret, secret_version = read_webhook_secret(), "legacy-token-file"
                except (OSError, RuntimeError):
                    _error(503, "webhook_secret_unavailable", "Webhook secret is unavailable")
            if not verify_signature(body, signature, secret):
                _error(401, "invalid_webhook_signature", "Webhook signature is invalid")
            try:
                payload, action = parse_delivery(body,
                    request.headers.get("x-github-delivery", ""),
                    request.headers.get("x-github-event", ""))
            except ValueError as exc:
                code = str(exc)
                _error(422, code, "Webhook envelope is invalid")
            if str(payload["repository"].get("id")) != str(repository_id):
                _error(422, "repository_mismatch", "Webhook repository does not match the configured route")
            repo = connection.execute(sa.select(github_repositories).where(
                github_repositories.c.repository_id == str(repository_id),
                github_repositories.c.enabled.is_(True))).mappings().first()
            if repo is None:
                _error(404, "repository_not_enabled", "GitHub repository is not enabled")
            delivery_id = str(uuid.UUID(request.headers["x-github-delivery"]))
            digest = hashlib.sha256(body).hexdigest()
            existing = connection.execute(sa.select(github_webhook_deliveries).where(
                github_webhook_deliveries.c.repository_id == str(repository_id),
                github_webhook_deliveries.c.delivery_id == delivery_id).with_for_update()).mappings().first()
            if existing:
                if existing["body_digest"] != digest:
                    _error(409, "delivery_id_conflict", "Delivery identity was reused with different content")
                return {"schema_version": 1, "delivery_id": delivery_id,
                    "status": existing["state"], "duplicate": True}
            from sqlalchemy.dialects.postgresql import insert as pg_insert
            insert = pg_insert(github_webhook_deliveries).values(
                delivery_id=delivery_id, repository_id=str(repository_id),
                event_type=request.headers["x-github-event"], action=action,
                payload=payload, body_digest=digest, secret_version=secret_version,
                state="accepted", outcome=None, received_at=_now(), processed_at=None
            ).on_conflict_do_nothing(index_elements=[github_webhook_deliveries.c.delivery_id])
            inserted = connection.execute(insert.returning(
                github_webhook_deliveries.c.delivery_id)).scalar_one_or_none()
            if inserted is None:
                existing = connection.execute(sa.select(github_webhook_deliveries).where(
                    github_webhook_deliveries.c.repository_id == str(repository_id),
                    github_webhook_deliveries.c.delivery_id == delivery_id).with_for_update()
                    ).mappings().first()
                if existing is None:
                    _error(409, "delivery_id_conflict",
                        "Delivery identity is already bound to another repository")
                if existing["body_digest"] != digest:
                    _error(409, "delivery_id_conflict", "Delivery identity was reused with different content")
                return {"schema_version": 1, "delivery_id": delivery_id,
                    "status": existing["state"], "duplicate": True}
        return {"schema_version": 1, "delivery_id": delivery_id,
            "status": "accepted", "duplicate": False}

    def _poll_repository(body: dict, principal: str, request: Request = None):
        if not isinstance(body, dict) or set(body) != {"repository_id"}:
            _error(422, "invalid_command", "Poll request is invalid")
        with engine.begin() as connection:
            repo = _repo(connection, body["repository_id"])
            # Polling may discover commands, so require current connector and
            # exact repository/source authority before GitHub access.
            authorize_poll_repository(connection, repo, principal, request)
        rest = rest_factory(principal=principal, action="github.poll",
            authorization_target=repo["repository_id"])
        _audience(rest, repo)
        root = repo_path(repo["owner"], repo["name"])
        comments = rest.get_all(root + "/issues/comments?per_page=100")
        comment_ids = [str(comment.get("id", "")) for comment in comments]
        with engine.connect() as connection:
            captured_comment_ids = set(connection.execute(sa.select(
                github_inbox_commands.c.comment_id).where(
                    github_inbox_commands.c.repository_id == str(repo["repository_id"]),
                    github_inbox_commands.c.comment_id.in_(comment_ids)
                )).scalars()) if comment_ids else set()
            current_group_ids = {str(group_id) for group_id in connection.execute(
                sa.select(groups.c.group_id)).scalars()}
        results = []
        processed_comments = set()
        for comment in comments:
            comment_id = str(comment.get("id"))
            processed_comments.add(comment_id)
            disposition = _poll_comment_disposition(comment, captured_comment_ids,
                current_group_ids)
            if disposition == "ignored":
                continue
            result = ("unknown_group" if disposition == "unknown_group"
                else _process_comment(engine, app, repo, comment))
            if result != "ignored":
                record = None
                if result != "unknown_group":
                    with engine.connect() as connection:
                        record = connection.execute(sa.select(github_inbox_commands.c.outcome).where(
                            github_inbox_commands.c.repository_id == repo["repository_id"],
                            github_inbox_commands.c.comment_id == comment_id)).first()
                results.append({"comment_id": str(comment.get("id")), "state": result,
                    "outcome": record[0] if record else None})
        # Captured commands outlive mutable GitHub comment contents and may no
        # longer appear in the current poll response. Retry from the immutable
        # retained capture independently of remote comment enumeration.
        with engine.connect() as connection:
            pending = connection.execute(sa.select(github_inbox_commands).where(
                github_inbox_commands.c.repository_id == repo["repository_id"],
                github_inbox_commands.c.state == "pending").order_by(
                    github_inbox_commands.c.first_seen_at,
                    github_inbox_commands.c.comment_id)).mappings().all()
        for captured in pending:
            if str(captured["comment_id"]) in processed_comments:
                continue
            result = _process_comment(engine, app, repo, captured["raw_comment"])
            with engine.connect() as connection:
                outcome = connection.execute(sa.select(github_inbox_commands.c.outcome).where(
                    github_inbox_commands.c.inbox_id == captured["inbox_id"])).scalar_one_or_none()
            results.append({"comment_id": str(captured["comment_id"]),
                "state": result, "outcome": outcome, "resumed_from_capture": True})
        with engine.connect() as connection:
            mappings = connection.execute(sa.select(github_group_issues).where(
                github_group_issues.c.repository_id == repo["repository_id"])
                ).mappings().all()
        complete_reconcile = True
        for mapping in mappings:
            if not _reconcile_polled_mapping(engine, rest, repo, dict(mapping), root):
                complete_reconcile = False
        now = _now()
        with engine.begin() as connection:
            prior = connection.execute(sa.select(github_poll_state).where(
                github_poll_state.c.repository_id == repo["repository_id"])
                .with_for_update()).mappings().first()
            values = {"comments_checkpoint": str(max((int(item.get("id", 0)) for item in comments), default=0)),
                "events_checkpoint": "full-reconcile" if complete_reconcile else "incomplete",
                "last_full_reconcile_at": now if complete_reconcile else (prior["last_full_reconcile_at"] if prior else None),
                "last_poll_at": now, "updated_at": now}
            if not complete_reconcile:
                values["comments_checkpoint"] = (
                    prior["comments_checkpoint"] if prior else "0")
            if not complete_reconcile:
                values["comments_checkpoint"] = (prior["comments_checkpoint"]
                    if prior else "0")
            if prior:
                connection.execute(github_poll_state.update().where(
                    github_poll_state.c.repository_id == repo["repository_id"]).values(**values))
            else:
                connection.execute(github_poll_state.insert().values(
                    repository_id=repo["repository_id"], **values))
        return {"schema_version": 1, "repository_id": repo["repository_id"],
            "comments_seen": len(comments), "managed_commands": results,
            "reconcile_complete": complete_reconcile,
            "last_full_reconcile_at": _iso(now if complete_reconcile else
                prior["last_full_reconcile_at"] if prior else None)}

    @app.post("/api/v1/github/poll")
    def poll(body: dict, principal: str = Depends(authenticate), request: Request = None):
        if not isinstance(body, dict) or set(body) != {"repository_id"}:
            _error(422, "invalid_command", "Poll request is invalid")
        repository_id = str(body["repository_id"])
        lock_connection = engine.connect()
        locked = False
        try:
            locked = lock_connection.execute(sa.text(
                "SELECT pg_try_advisory_lock(hashtextextended(:key, 0))"),
                {"key": "uvm-github-poll:" + repository_id}).scalar_one()
            if not locked:
                _error(409, "github_reconciliation_in_progress", "Repository reconciliation is already running")
            return _poll_repository(body, principal, request)
        finally:
            if locked:
                try:
                    lock_connection.execute(sa.text(
                        "SELECT pg_advisory_unlock(hashtextextended(:key, 0))"),
                        {"key": "uvm-github-poll:" + repository_id})
                except Exception:
                    pass
            lock_connection.close()

    webhook_principal = os.getenv("UVM_GITHUB_WEBHOOK_PRINCIPAL") or os.getenv("UVM_GITHUB_POLL_PRINCIPAL")
    webhook_stop = threading.Event()
    webhook_thread = None

    def process_webhook_delivery(repository_id, delivery_id):
        auth_service = getattr(app.state, "oidc_auth", None)
        if auth_service is None or not webhook_principal:
            raise RuntimeError("GitHub webhook processing requires a configured service principal")
        from uvm.auth.schema import AUTHORITY_CONTEXT
        context = auth_service.service_context_for_principal(webhook_principal)
        if context is None:
            raise RuntimeError("GitHub webhook service principal is not currently authorised")
        token = AUTHORITY_CONTEXT.set(context)
        lock_connection = engine.connect()
        locked = False
        try:
            locked = lock_connection.execute(sa.text(
                "SELECT pg_try_advisory_lock(hashtextextended(:key, 0))"),
                {"key": "uvm-github-poll:" + str(repository_id)}).scalar_one()
            if not locked:
                return False
            # Snapshot and admit under the common authority-first lock order,
            # then release all DB locks before connector resolution or remote
            # reads. A duplicate delivery can now observe `processing` without
            # waiting on a worker that is acquiring the policy/connector fence.
            from uvm.assessment.policy_lock import lock_policy
            with engine.begin() as connection:
                lock_policy(connection)
                repo = connection.execute(sa.select(github_repositories).where(
                    github_repositories.c.repository_id == str(repository_id),
                    github_repositories.c.enabled.is_(True)).with_for_update()).mappings().first()
                delivery = connection.execute(sa.select(github_webhook_deliveries).where(
                    github_webhook_deliveries.c.repository_id == str(repository_id),
                    github_webhook_deliveries.c.delivery_id == delivery_id).with_for_update()).mappings().first()
                if repo is None or delivery is None or delivery["state"] == "processed":
                    return True
                repo, delivery = dict(repo), dict(delivery)
                try:
                    retained_action = validate_delivery_payload(
                        delivery.get("payload"), delivery.get("event_type"))
                    if retained_action != delivery.get("action"):
                        raise ValueError("malformed_envelope")
                except (KeyError, TypeError, ValueError):
                    connection.execute(github_webhook_deliveries.update().where(
                        github_webhook_deliveries.c.repository_id == str(repository_id),
                        github_webhook_deliveries.c.delivery_id == delivery_id).values(
                            state="processed", outcome={"code": "malformed_retained_payload"},
                            processed_at=_now()))
                    _LOG.warning("github_webhook_retained_payload_rejected repository_id=%s delivery_id=%s",
                        repository_id, delivery_id)
                    return True
                audience = repo.get("audience_document") or {}
                if (audience.get("approved") is not True
                        or audience.get("data_access_approved") is not True
                        or audience.get("repository_id") != str(repository_id)):
                    _LOG.error("github_webhook_audience_denied repository_id=%s approved=%s data_access_approved=%s audience_repository_id=%s",
                        repository_id, audience.get("approved"),
                        audience.get("data_access_approved"), audience.get("repository_id"))
                    raise PermissionError("current repository audience is not approved")
                authorize_poll_repository(connection, repo, webhook_principal)
                connection.execute(github_webhook_deliveries.update().where(
                    github_webhook_deliveries.c.delivery_id == delivery_id,
                    github_webhook_deliveries.c.repository_id == str(repository_id)).values(
                        state="processing"))
            rest = rest_factory(principal=webhook_principal, action="github.poll",
                authorization_target=str(repository_id))
            _audience(rest, repo)
            payload = delivery["payload"]
            event_type, action = delivery["event_type"], delivery["action"]
            outcome = {"event": event_type, "action": action}
            if event_type == "issue_comment" and action in {"created", "edited", "deleted"}:
                comment, issue = payload["comment"], payload["issue"]
                raw_comment = {"id": str(comment["id"]), "body": comment.get("body") or "",
                    "user": comment.get("user") or {}, "created_at": comment.get("created_at"),
                    "updated_at": comment.get("updated_at"), "issue_url": issue.get("html_url", "")}
                if action == "created":
                    state = _process_comment(engine, app, repo, raw_comment)
                else:
                    with engine.connect() as connection:
                        captured = connection.execute(sa.select(github_inbox_commands.c.inbox_id)
                            .where(github_inbox_commands.c.repository_id == str(repository_id),
                                github_inbox_commands.c.comment_id == str(comment["id"]))).first()
                    state = (_process_comment(engine, app, repo, raw_comment)
                        if captured else "ignored_unlinked_event")
                    if captured and action == "deleted":
                        event_key = f"comment-delete:{comment['id']}:{delivery_id}"
                        with engine.begin() as connection:
                            exists = connection.execute(sa.select(
                                github_external_events.c.record_id).where(
                                github_external_events.c.repository_id == str(repository_id),
                                github_external_events.c.github_event_id == event_key)).first()
                            if exists is None:
                                issue_match = re.search(r"/issues/(\d+)$", issue.get("html_url", ""))
                                connection.execute(github_external_events.insert().values(
                                    record_id=str(uuid.uuid4()), repository_id=str(repository_id),
                                    github_event_id=event_key,
                                    issue_number=int(issue_match.group(1)) if issue_match else 0,
                                    event_type="comment_deleted_after_capture",
                                    actor_account_id=str((comment.get("user") or {}).get("id") or "") or None,
                                    raw_payload=payload,
                                    payload_digest=hashlib.sha256(_canon(payload)).hexdigest(),
                                    created_at=_time(comment.get("updated_at")) or _now(),
                                    received_at=_now(), outcome="retained_original_submission"))
                outcome["command_state"] = state
                if state == "pending":
                    with engine.begin() as connection:
                        connection.execute(github_webhook_deliveries.update().where(
                            github_webhook_deliveries.c.repository_id == str(repository_id),
                            github_webhook_deliveries.c.delivery_id == delivery_id).values(
                                state="accepted", outcome={"code": "processing_deferred",
                                    "command_state": "pending"}, processed_at=None))
                    return False
                if (state == "applied" and os.getenv("UVM_G7_DISPOSABLE_MODE") == "1"
                        and os.getenv("UVM_GITHUB_WEBHOOK_CRASH_AFTER_COMMAND_COMMIT") == "1"):
                    marker = "/opt/uvm/state/g7-webhook-crash-after-command-commit"
                    try:
                        descriptor = os.open(marker, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
                    except FileExistsError:
                        pass
                    else:
                        os.close(descriptor)
                        # This fixture-only failpoint proves inbox/audit commit
                        # survives a process exit before delivery completion.
                        _LOG.error("g7_fixture_crash_after_command_commit repository_id=%s delivery_id=%s",
                            repository_id, delivery_id)
                        os._exit(86)
                with engine.connect() as connection:
                    record = connection.execute(sa.select(github_inbox_commands.c.inbox_id,
                        github_inbox_commands.c.outcome).where(
                        github_inbox_commands.c.repository_id == str(repository_id),
                        github_inbox_commands.c.comment_id == str(comment["id"]))).first()
                if record:
                    outcome.update({"inbox_id": record[0], "command_outcome": record[1]})
            else:
                rest = rest_factory(principal=webhook_principal, action="github.poll",
                    authorization_target=str(repository_id))
                _audience(rest, repo)
                if event_type == "issues":
                    root = repo_path(repo["owner"], repo["name"])
                    with engine.connect() as connection:
                        mappings = connection.execute(sa.select(github_group_issues).where(
                            github_group_issues.c.repository_id == str(repository_id))).mappings().all()
                    reconcile_results = [_reconcile_polled_mapping(engine, rest, repo,
                        dict(mapping), root) for mapping in mappings]
                    complete = all(reconcile_results)
                    outcome["reconcile_complete"] = complete
                else:
                    outcome["connectivity"] = "verified"
            with engine.begin() as connection:
                connection.execute(github_webhook_deliveries.update().where(
                    github_webhook_deliveries.c.repository_id == str(repository_id),
                    github_webhook_deliveries.c.delivery_id == delivery_id).values(
                        state="processed", outcome=outcome, processed_at=_now()))
            return True
        except Exception as exc:
            denial_reason = None
            if isinstance(exc, HTTPException) and exc.status_code == 403:
                detail = exc.detail if isinstance(exc.detail, dict) else {}
                denial_reason = str(detail.get("code") or "forbidden")
            elif isinstance(exc, HTTPException) and exc.status_code == 409:
                detail = exc.detail if isinstance(exc.detail, dict) else {}
                if detail.get("code") == "github_audience_unknown":
                    denial_reason = "github_audience_changed"
            elif isinstance(exc, PermissionError):
                denial_reason = "repository_audience_not_approved"
            _LOG.warning("github_webhook_delivery_deferred repository_id=%s delivery_id=%s code=%s",
                repository_id, delivery_id, type(exc).__name__)
            with engine.begin() as connection:
                connection.execute(github_webhook_deliveries.update().where(
                    github_webhook_deliveries.c.repository_id == str(repository_id),
                    github_webhook_deliveries.c.delivery_id == delivery_id).values(
                        state="processed" if denial_reason else "accepted",
                        outcome=({"code": "authority_denied", "reason": denial_reason}
                            if denial_reason else {"code": "processing_deferred"}),
                        processed_at=_now() if denial_reason else None))
            return False
        finally:
            AUTHORITY_CONTEXT.reset(token)
            if locked:
                try:
                    lock_connection.execute(sa.text(
                        "SELECT pg_advisory_unlock(hashtextextended(:key, 0))"),
                        {"key": "uvm-github-poll:" + str(repository_id)})
                except Exception:
                    pass
            lock_connection.close()

    def webhook_worker_loop():
        while not webhook_stop.wait(1):
            try:
                with engine.connect() as connection:
                    pending = connection.execute(sa.select(
                        github_webhook_deliveries.c.repository_id,
                        github_webhook_deliveries.c.delivery_id).where(
                        github_webhook_deliveries.c.state.in_(["accepted", "processing"])
                        ).order_by(github_webhook_deliveries.c.received_at).limit(20)).all()
                for repository_id, delivery_id in pending:
                    process_webhook_delivery(repository_id, delivery_id)
            except Exception:
                _LOG.exception("github_webhook_worker_failed")

    def start_webhook_worker():
        nonlocal webhook_thread
        if not webhook_principal:
            _LOG.warning("github_webhook_worker_disabled_no_service_principal")
            return
        webhook_thread = threading.Thread(target=webhook_worker_loop,
            name="uvm-github-webhook-worker", daemon=True)
        webhook_thread.start()

    def stop_webhook_worker():
        webhook_stop.set()
        if webhook_thread and webhook_thread.is_alive():
            webhook_thread.join(timeout=5)

    app.router.on_startup.append(start_webhook_worker)
    app.router.on_shutdown.append(stop_webhook_worker)

    # Optional process scheduler uses the exact same permission-checked REST
    # poll path as the manual endpoint. Deployments enable it with a dedicated
    # configured principal that has github.poll and assessment.read. A DB
    # advisory lock prevents multiple API workers from polling a repository at
    # once; failures are logged and never move the full-reconcile checkpoint.
    poll_interval = int(os.getenv("UVM_GITHUB_POLL_INTERVAL_SECONDS", "86400"))
    poll_principal = os.getenv("UVM_GITHUB_POLL_PRINCIPAL")
    stop_polling = threading.Event()
    poll_thread = None

    def scheduled_poll_loop():
        while not stop_polling.wait(poll_interval):
            auth_context_token = None
            try:
                auth_service = getattr(app.state, "oidc_auth", None)
                with engine.connect() as connection:
                    repositories = connection.execute(sa.select(
                        github_repositories.c.repository_id).where(
                        github_repositories.c.enabled.is_(True))).scalars().all()
                for repository_id in repositories:
                    if stop_polling.is_set():
                        break
                    lock_connection = engine.connect()
                    try:
                        locked = lock_connection.execute(sa.text(
                            "SELECT pg_try_advisory_lock(hashtextextended(:key, 0))"),
                            {"key": "uvm-github-poll:" + str(repository_id)}).scalar_one()
                        if not locked:
                            continue
                        auth_context_token = None
                        if auth_service is not None:
                            from uvm.auth.schema import AUTHORITY_CONTEXT
                            background_context = auth_service.service_context_for_principal(poll_principal)
                            if background_context is None:
                                raise RuntimeError("scheduled GitHub polling requires a configured service principal")
                            auth_context_token = AUTHORITY_CONTEXT.set(background_context)
                        outcome = _poll_repository({"repository_id": str(repository_id)}, poll_principal)
                        _LOG.warning("scheduled_github_poll_complete repository_id=%s reconcile_complete=%s",
                            repository_id, outcome.get("reconcile_complete"))
                        marker_path = os.getenv("UVM_GITHUB_POLL_COMPLETION_MARKER")
                        if marker_path:
                            from pathlib import Path
                            Path(marker_path).write_text(json.dumps({
                                "repository_id": str(repository_id),
                                "reconcile_complete": bool(outcome.get("reconcile_complete")),
                                "completed_at": _iso(_now())}, sort_keys=True) + "\n",
                                encoding="utf-8")
                    finally:
                        if auth_context_token is not None:
                            AUTHORITY_CONTEXT.reset(auth_context_token)
                            auth_context_token = None
                        try:
                            lock_connection.execute(sa.text(
                                "SELECT pg_advisory_unlock(hashtextextended(:key, 0))"),
                                {"key": "uvm-github-poll:" + str(repository_id)})
                        except Exception:
                            pass
                        lock_connection.close()
            except Exception:
                _LOG.exception("scheduled_github_poll_failed")
            finally:
                if auth_context_token is not None:
                    AUTHORITY_CONTEXT.reset(auth_context_token)

    def start_scheduled_polling():
        nonlocal poll_thread
        if poll_interval <= 0 or not poll_principal:
            _LOG.info("scheduled_github_poll_disabled")
            return
        _LOG.warning("scheduled_github_poll_started pid=%d interval_seconds=%s",
            os.getpid(), poll_interval)
        poll_thread = threading.Thread(target=scheduled_poll_loop,
            name="uvm-github-daily-poll", daemon=True)
        poll_thread.start()

    def stop_scheduled_polling():
        stop_polling.set()
        if poll_thread and poll_thread.is_alive():
            poll_thread.join(timeout=5)

    app.router.on_startup.append(start_scheduled_polling)
    app.router.on_shutdown.append(stop_scheduled_polling)
