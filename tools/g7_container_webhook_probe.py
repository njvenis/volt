#!/usr/bin/env python3
"""Exercise the public webhook HMAC admission boundary in a disposable image."""
from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import subprocess
import urllib.error
import urllib.request
import uuid
from pathlib import Path


def post(origin: str, repository_id: str, delivery_id: str, body: bytes,
         signature: str | None) -> dict:
    headers = {"Content-Type": "application/json", "X-GitHub-Event": "ping",
        "X-GitHub-Delivery": delivery_id}
    if signature is not None:
        headers["X-Hub-Signature-256"] = signature
    request = urllib.request.Request(
        f"{origin}/api/v1/github/webhooks/{repository_id}", data=body,
        headers=headers, method="POST")
    try:
        response = urllib.request.urlopen(request, timeout=8)
    except urllib.error.HTTPError as error:
        response = error
    raw = response.read()
    try:
        payload = json.loads(raw)
    except (ValueError, UnicodeDecodeError):
        payload = None
    result = {"status": response.status, "body": payload,
        "response_sha256": hashlib.sha256(raw).hexdigest()}
    response.close()
    return result


def psql(container: str, sql: str) -> str:
    command = ["docker", "exec", "-i", container, "/bin/bash", "-lc",
        'export PGPASSWORD="$(cat /run/secrets/uvm_db_password)"; '
        'exec psql -X -q -v ON_ERROR_STOP=1 -h 127.0.0.1 -U uvm_app -d uvm -At -F "|"']
    return subprocess.run(command, input=sql, text=True, check=True,
        capture_output=True).stdout.strip()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--container", required=True)
    parser.add_argument("--origin", required=True)
    parser.add_argument("--repository-id", default="987654321")
    parser.add_argument("--secret-file", required=True, type=Path)
    parser.add_argument("--evidence", required=True, type=Path)
    parser.add_argument("--replay-of", type=Path,
        help="Replay a delivery recorded by an earlier run, without seeding fixture rows")
    args = parser.parse_args()
    args.evidence.mkdir(parents=True, exist_ok=True)
    secret = args.secret_file.read_bytes().strip()
    if len(secret) < 32:
        raise SystemExit("fixture webhook secret is too short")
    repo = args.repository_id
    if args.replay_of:
        prior = json.loads(args.replay_of.read_text())
        delivery_id = prior["delivery_id"]
        payload = {"zen": "G7 local webhook admission fixture", "repository": {"id": int(repo)}}
        body = json.dumps(payload, separators=(",", ":"), ensure_ascii=True).encode()
        valid = "sha256=" + hmac.new(secret, body, hashlib.sha256).hexdigest()
        replay = post(args.origin, repo, delivery_id, body, valid)
        readback = psql(args.container,
            "SELECT delivery_id || '|' || state || '|' || secret_version "
            "FROM github_webhook_deliveries "
            f"WHERE repository_id='{repo}' AND delivery_id='{delivery_id}';\n")
        checks = {"accepted_replay_detected": replay["status"] == 202
            and replay.get("body", {}).get("duplicate") is True,
            "same_durable_delivery_retained": readback == f"{delivery_id}|accepted|v1"}
        result = {"environment": "local disposable pinned Docker image",
            "delivery_id": delivery_id, "replay": replay, "readback": readback,
            "assertions": checks}
        (args.evidence / "webhook-replay-after-replacement.json").write_text(
            json.dumps(result, sort_keys=True, separators=(",", ":")) + "\n")
        if not all(checks.values()):
            raise SystemExit("cross-replacement webhook replay failed: " + json.dumps(checks, sort_keys=True))
        print(json.dumps(result, sort_keys=True))
        return 0
    now = "2026-01-01T00:00:00+00:00"
    audience = json.dumps({"approved": True, "data_access_approved": True,
        "repository_id": repo, "reader_account_ids": [], "team_slugs": []},
        sort_keys=True, separators=(",", ":"))
    seed_sql = ("INSERT INTO github_repositories (repository_id,github_host,owner,name,enabled,"
        "audience_revision,audience_document,updated_at) VALUES ("
        f"'{repo}','github.com','g7-fixture','webhook-boundary',true,1,'{audience}'::jsonb,'{now}'::timestamptz);\n")
    psql(args.container, seed_sql)
    payload = {"zen": "G7 local webhook admission fixture",
        "repository": {"id": int(repo)}}
    body = json.dumps(payload, separators=(",", ":"), ensure_ascii=True).encode()
    valid = "sha256=" + hmac.new(secret, body, hashlib.sha256).hexdigest()
    forged = "sha256=" + "0" * 64
    invalid_ids = {name: str(uuid.uuid4()) for name in
        ("missing_signature", "forged_signature", "stale_signature", "wrong_route")}
    requests = {
        "missing_signature": post(args.origin, repo, invalid_ids["missing_signature"], body, None),
        "forged_signature": post(args.origin, repo, invalid_ids["forged_signature"], body, forged),
        "stale_signature": post(args.origin, repo, invalid_ids["stale_signature"], body,
            "sha256=" + hmac.new(b"stale-local-fixture-secret", body, hashlib.sha256).hexdigest()),
        "wrong_route": post(args.origin, str(int(repo) + 1), invalid_ids["wrong_route"], body, valid),
    }
    delivery_id = str(uuid.uuid4())
    requests["valid_first"] = post(args.origin, repo, delivery_id, body, valid)
    requests["valid_replay"] = post(args.origin, repo, delivery_id, body, valid)
    readback = psql(args.container,
        "SELECT delivery_id || '|' || state || '|' || secret_version "
        "FROM github_webhook_deliveries "
        f"WHERE repository_id='{repo}' AND delivery_id='{delivery_id}';\n")
    invalid_list = ",".join("'" + invalid_ids[name] + "'" for name in invalid_ids)
    invalid_count = psql(args.container,
        "SELECT count(*) FROM github_webhook_deliveries "
        f"WHERE delivery_id IN ({invalid_list});\n")
    outcomes = {
        "missing_signature_denied": requests["missing_signature"]["status"] == 401,
        "forged_signature_denied": requests["forged_signature"]["status"] == 401,
        "stale_signature_denied": requests["stale_signature"]["status"] == 401,
        "wrong_route_denied": (requests["wrong_route"]["status"] == 400
            and requests["wrong_route"].get("body", {}).get("error", {}).get("code") == "invalid_request"),
        "valid_delivery_accepted": (requests["valid_first"]["status"] == 202
            and requests["valid_first"].get("body", {}).get("status") == "accepted"
            and requests["valid_first"].get("body", {}).get("duplicate") is False),
        "valid_replay_detected": (requests["valid_replay"]["status"] == 202
            and requests["valid_replay"].get("body", {}).get("duplicate") is True),
        "durable_readback_matches": readback == f"{delivery_id}|accepted|v1",
        "denied_requests_have_no_durable_effects": invalid_count == "0",
    }
    requests["durable_readback"] = {"delivery_id": delivery_id,
        "value": readback, "invalid_delivery_ids": invalid_ids, "invalid_delivery_row_count": invalid_count}
    report = {"environment": "local disposable pinned Docker image",
        "fixture": "isolated g7_acceptance-style repository row; no GitHub API contacted",
        "repository_id": repo, "delivery_id": delivery_id,
        "responses": requests, "assertions": outcomes}
    (args.evidence / "webhook-public-admission.json").write_text(
        json.dumps(report, sort_keys=True, separators=(",", ":")) + "\n")
    if not all(outcomes.values()):
        raise SystemExit("webhook admission assertions failed: " + json.dumps(outcomes, sort_keys=True))
    print(json.dumps({"assertions": outcomes, "delivery_id": delivery_id}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
