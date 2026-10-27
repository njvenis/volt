"""Shared whole-report read boundary for report and Findings projections."""

from __future__ import annotations

from collections.abc import Callable

import sqlalchemy as sa

from uvm.persistence.metrics_schema import report_requests


def report_scope_read(connection, report_id: str, principal: str, policy: dict,
        action: str, matches: Callable[[object, dict, str, str, str], bool]):
    """Return an issued report and whether its complete frozen scope is readable.

    Pass the live connection into the matcher so scoped grants can resolve
    current workload attributes and exact source coverage for each group.
    """
    row = connection.execute(sa.select(report_requests).where(
        report_requests.c.report_id == report_id)).mappings().first()
    if row is None:
        return None, False
    scope = row["scope"].get("group_ids", [])
    allowed = bool(scope) and all(matches(connection, policy, principal, action, group_id)
        for group_id in scope)
    return row, allowed
