"""Exact route/method allowlist for same-image recovery readback mode."""
from __future__ import annotations


def recovery_request_decision(method: str, path: str) -> str:
    allowed = (path in {"/", "/openapi.json", "/healthz", "/api/v1/auth/session",
            "/api/v1/operations/backup-settings"}
        or path.startswith("/assets/")
        or path.startswith("/api/v1/operations/backup-settings/")
        or path.startswith("/api/v1/operations/observer-settings/")
        or path.startswith("/api/v1/assessment/groups/")
        or path in {"/api/v1/assessment/groups", "/api/v1/assessment/audit"})
    if not allowed:
        return "not_found"
    if method.upper() not in {"GET", "HEAD"}:
        return "method_not_allowed"
    return "allow"


def recovery_control_request_decision(path: str) -> str:
    if path == "/healthz" or path.startswith("/recovery-control/v1/"):
        return "allow"
    return "not_found"
