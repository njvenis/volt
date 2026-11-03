#!/usr/bin/env python3
"""Fail-closed approval guard for publication-side effects."""
import argparse
import json
import sys
from pathlib import Path


def has_required_reviewers(data: dict) -> bool:
    rules = data.get("protection_rules")
    if not isinstance(rules, list):
        return False
    return any(
        rule.get("type") == "required_reviewers"
        and isinstance(rule.get("reviewers"), list)
        and len(rule["reviewers"]) > 0
        for rule in rules if isinstance(rule, dict)
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--approved", required=True, choices=("true", "false"))
    parser.add_argument("--environment-json", required=True, type=Path)
    parser.add_argument("--approval-reference", required=True)
    args = parser.parse_args()
    if args.approved != "true":
        parser.error("maintainer must explicitly set publish_approved=true")
    if not args.approval_reference.strip():
        parser.error("approval reference is required")
    try:
        data = json.loads(args.environment_json.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        parser.error(f"cannot verify publication environment protection: {exc}")
    if not has_required_reviewers(data):
        parser.error("volt-rc1-publication must have at least one required human reviewer configured")
    print("publication guard accepted explicit maintainer input and configured required reviewer protection")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
