#!/usr/bin/env python3
"""Typed checks for the exact GitHub Actions provenance producer used by VOLT."""
from __future__ import annotations

REPOSITORY = "https://github.com/njvenis/volt"
WORKFLOW_REF = "njvenis/volt/.github/workflows/release.yml@refs/heads/main"
BUILD_TYPE = "https://github.com/Attestations/GitHubActionsWorkflow@v1"


def validate(predicate: object, source_commit: str) -> None:
    if not isinstance(source_commit, str) or len(source_commit) != 40 or any(c not in "0123456789abcdef" for c in source_commit):
        raise ValueError("expected VOLT source commit is malformed")
    if not isinstance(predicate, dict):
        raise ValueError("SLSA provenance predicate must be an object")
    build = predicate.get("buildDefinition")
    if not isinstance(build, dict) or build.get("buildType") != BUILD_TYPE:
        raise ValueError("provenance build type is not the approved GitHub Actions workflow")
    external = build.get("externalParameters")
    if not isinstance(external, dict):
        raise ValueError("provenance external parameters are missing")
    workflow = external.get("workflow")
    source = external.get("source")
    if not isinstance(workflow, dict) or workflow.get("repository") != REPOSITORY or workflow.get("ref") != WORKFLOW_REF:
        raise ValueError("provenance workflow repository/ref disagrees with the approved VOLT publisher")
    if not isinstance(source, dict) or source.get("uri") != REPOSITORY or source.get("ref") != source_commit:
        raise ValueError("provenance source URI/ref disagrees with the expected VOLT commit")
    dependencies = build.get("resolvedDependencies")
    if not isinstance(dependencies, list):
        raise ValueError("provenance resolved dependencies are missing")
    volt_dependencies = [dep for dep in dependencies if isinstance(dep, dict) and dep.get("uri") == "git+" + REPOSITORY]
    if len(volt_dependencies) != 1:
        raise ValueError("provenance must resolve exactly one VOLT source dependency")
    digest = volt_dependencies[0].get("digest")
    if not isinstance(digest, dict) or digest.get("gitCommit") != source_commit or set(digest) != {"gitCommit"}:
        raise ValueError("provenance resolved VOLT dependency disagrees with the expected commit")
