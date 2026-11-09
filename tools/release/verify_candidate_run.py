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


def workflow_path_matches(value: object, workflow: str) -> bool:
    if not isinstance(value, str):
        return False
    path, separator, ref = value.partition("@")
    return path == workflow and (not separator or ref in {"main", "refs/heads/main"})


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--source", required=True)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--workflow", default=".github/workflows/release.yml")
    parser.add_argument("--artifact-id")
    parser.add_argument("--artifact-digest")
    parser.add_argument("--controller-source")
    args = parser.parse_args()
    token = os.environ.get("GH_TOKEN", "")
    if not token or not re.fullmatch(r"[0-9]+", args.run_id):
        parser.error("a numeric candidate run ID and GitHub token are required")
    if not re.fullmatch(r"[0-9a-f]{40}", args.source):
        parser.error("candidate source must be a full commit SHA")
    if args.controller_source is not None and not re.fullmatch(r"[0-9a-f]{40}", args.controller_source):
        parser.error("controller source must be a full commit SHA")
    if (args.artifact_id is None) != (args.artifact_digest is None):
        parser.error("expected artifact ID and digest must be supplied together")
    if args.artifact_id is not None and (not re.fullmatch(r"[0-9]+", args.artifact_id)
                                         or not re.fullmatch(r"sha256:[0-9a-f]{64}", args.artifact_digest)):
        parser.error("expected artifact identity is malformed")
    try:
        prefix = f"repos/{args.repository}/actions"
        run = api(f"{prefix}/runs/{args.run_id}", token)
        if (run.get("id") != int(args.run_id) or run.get("repository", {}).get("full_name") != args.repository
                or not workflow_path_matches(run.get("path"), args.workflow) or run.get("event") != "workflow_dispatch"
                or run.get("head_branch") != "main" or run.get("head_sha") != args.source
                or run.get("status") != "completed" or run.get("conclusion") != "success"):
            raise RuntimeError("candidate run must be a successful, completed main dispatch for this exact source and workflow")
        artifacts = api(f"{prefix}/runs/{args.run_id}/artifacts", token).get("artifacts")
        expected_name = f"volt-rc2-candidate-{args.source}"
        matches = [item for item in artifacts or [] if item.get("name") == expected_name and not item.get("expired")]
        if (len(matches) != 1 or type(matches[0].get("id")) is not int
                or not isinstance(matches[0].get("digest"), str)
                or not re.fullmatch(r"sha256:[0-9a-f]{64}", matches[0]["digest"])):
            raise RuntimeError("candidate run must contain exactly one retained candidate artifact with a digest")
        if args.artifact_id is not None and (matches[0]["id"] != int(args.artifact_id)
                                             or matches[0]["digest"] != args.artifact_digest):
            raise RuntimeError("candidate artifact ID or digest differs from the explicitly approved identity")
        print(json.dumps({"run_id": int(args.run_id), "repository": args.repository,
                          "workflow_path": run["path"], "source_commit": args.source,
                          "controller_commit": args.controller_source or args.source,
                          "artifact_name": expected_name, "artifact_id": matches[0]["id"],
                          "artifact_digest": matches[0]["digest"]}, sort_keys=True))
        return 0
    except RuntimeError as exc:
        print(str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
