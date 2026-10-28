"""Fail-closed DefectDojo request fence used only during recovery readback."""
from __future__ import annotations

import re
import os


_ALLOWED = (
    re.compile(r"^/api/v2/(?:findings|engagements|tests|files)/(?:\d+)?/?$"),
    re.compile(r"^/media/[A-Za-z0-9._/-]+$"),
    re.compile(r"^/healthz/?$"),
)


def recovery_request_decision(method: str, path: str) -> str:
    if not any(pattern.fullmatch(path) for pattern in _ALLOWED):
        return "not_found"
    if method not in {"GET", "HEAD"}:
        return "method_not_allowed"
    return "allow"


class ReadOnlyRecoveryMiddleware:
    """Allow only enumerated public readback routes with GET or HEAD."""

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if os.environ.get("UVM_G7_VERIFICATION_ONLY") != "1":
            return self.get_response(request)
        decision = recovery_request_decision(request.method, request.path_info)
        if decision != "allow":
            from django.http import HttpResponse
            status = 404 if decision == "not_found" else 405
            response = HttpResponse(status=status)
            if status == 405:
                response["Allow"] = "GET, HEAD"
            return response
        return self.get_response(request)
