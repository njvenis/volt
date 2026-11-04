#!/usr/bin/env python3
"""Fail-closed identity check for a retained RC2 candidate workflow run."""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import urllib.error
import urllib.request


def api(path: str, token: str) -> dict:
    request = urllib.request.Request(
        "https://api.github.com/" + path,
        headers={"Accept": "application/vnd.github+json", "Authorization": f"Bearer {token}",
                 "X-GitHub-Api-Version": "2022-11-28"},
    )
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            value = json.load(response)
    except (urllib.error.URLError, urllib.error.HTTPError, OSError, ValueError):
        raise RuntimeError("GitHub candidate identity lookup failed closed") from None
    if not isinstance(value, dict):
        raise RuntimeError("GitHub candidate identity response is malformed")
    return value


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--source", required=True)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--workflow", default=".github/workflows/release.yml")
    args = parser.parse_args()
    token = os.environ.get("GH_TOKEN", "")
    if not token or not re.fullmatch(r"[0-9]+", args.run_id):
        parser.error("a numeric candidate run ID and GitHub token are required")
    if not re.fullmatch(r"[0-9a-f]{40}", args.source):
        parser.error("candidate source must be a full commit SHA")
    try:
        prefix = f"repos/{args.repository}/actions"
        run = api(f"{prefix}/runs/{args.run_id}", token)
        if (run.get("id") != int(args.run_id) or run.get("repository", {}).get("full_name") != args.repository
                or run.get("workflow_path") != args.workflow or run.get("event") != "workflow_dispatch"
                or run.get("head_branch") != "main" or run.get("head_sha") != args.source
                or run.get("status") != "completed" or run.get("conclusion") != "success"):
            raise RuntimeError("candidate run must be a successful, completed main dispatch for this exact source and workflow")
        artifacts = api(f"{prefix}/runs/{args.run_id}/artifacts", token).get("artifacts")
        expected_name = f"volt-rc2-candidate-{args.source}"
        matches = [item for item in artifacts or [] if item.get("name") == expected_name and not item.get("expired")]
        if len(matches) != 1 or not isinstance(matches[0].get("digest"), str):
            raise RuntimeError("candidate run must contain exactly one retained candidate artifact with a digest")
        print(json.dumps({"run_id": int(args.run_id), "repository": args.repository,
                          "workflow_path": args.workflow, "source_commit": args.source,
                          "artifact_name": expected_name, "artifact_id": matches[0]["id"],
                          "artifact_digest": matches[0]["digest"]}, sort_keys=True))
        return 0
    except RuntimeError as exc:
        print(str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
