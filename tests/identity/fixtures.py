"""Synthetic identity fixtures.

All accounts, hosts, QIDs and CVEs are synthetic fixture values.
Qualys QID is treated as a globally meaningful identifier (shared authority
namespace across accounts); the account-local scheme carries the account in
the authority namespace, per the approved G1 design.
"""

from __future__ import annotations

import hashlib
import uuid
from datetime import datetime, timezone

from uvm.identity import (
    MISSING_NOT_APPLICABLE,
    MISSING_NOT_SUPPLIED,
    MissingField,
    SourceObservationV1,
    RuleV1,
)

UTC = timezone.utc
T0 = datetime(2026, 9, 1, 8, 0, 0, tzinfo=UTC)
T1 = datetime(2026, 9, 8, 8, 0, 0, tzinfo=UTC)
T2 = datetime(2026, 9, 15, 8, 0, 0, tzinfo=UTC)


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


_counter = 0
_FIXTURE_NAMESPACE = uuid.NAMESPACE_URL


def synthetic_id(name: str) -> str:
    """Deterministic synthetic UVM UUID for tests (deterministic replay)."""
    return str(uuid.uuid5(_FIXTURE_NAMESPACE, f"uvm-synthetic:{name}"))


def next_id(prefix: str) -> str:
    """Deterministic synthetic UVM UUID (the approved G1 contracts make
    every UVM ID an immutable UUID; the prefix is only the name basis)."""
    global _counter
    _counter += 1
    return synthetic_id(f"{prefix}-{_counter}")


def make_observation(
    *,
    observation_id: str | None = None,
    source_family: str = "qualys",
    source_account_id: str = "acc-1",
    run_id: str = "run-1",
    source_record_ordinal: int = 1,
    collection_status: str = "success",
    collected_at: datetime = T1,
    observed_at: datetime | None = T0,
    native_id_scheme: str | None = "qualys-qid",
    native_id_authority: str | None = "global",
    native_id_value: str | None = "101",
    asset_locator: str | None = "host-a",
    component_locator: str | None = "comp-a",
    source_record_locator: str | None = None,
    source_rating: str | None = None,
    source_first_seen_at: datetime | None = None,
    report_id: str | None = None,
    coverage_scope: str | None = None,
    vulnerability_refs: tuple[str, ...] | None = ("CVE-2026-0001",),
    missing: tuple[MissingField, ...] = (),
    raw_bytes: str | None = None,
) -> SourceObservationV1:
    """Build a valid SourceObservationV1; None optionals must be covered by
    ``missing`` or the DTO validation raises (explicit nulls only).
    ``raw_bytes`` overrides the synthetic raw-evidence digest input."""
    oid = observation_id or next_id("obs")
    m = list(missing)
    m.append(MissingField("vulnerability_refs", MISSING_NOT_APPLICABLE))
    m.append(MissingField("vulnerability_refs", MISSING_NOT_APPLICABLE))
    if observed_at is None:
        m.append(MissingField("observed_at", "not_supplied"))
    if native_id_scheme is None:
        m.append(MissingField("native_id_scheme", "not_supplied"))
    if native_id_authority is None:
        m.append(MissingField("native_id_authority", "not_supplied"))
    if native_id_value is None:
        m.append(MissingField("native_id_value", "not_supplied"))
    if asset_locator is None:
        m.append(MissingField("asset_locator", "not_supplied"))
    if component_locator is None:
        m.append(MissingField("component_locator", MISSING_NOT_APPLICABLE))
    if source_record_locator is None:
        m.append(MissingField("source_record_locator", MISSING_NOT_SUPPLIED))
    if source_rating is None:
        m.append(MissingField("source_rating", MISSING_NOT_SUPPLIED))
    if source_first_seen_at is None:
        m.append(MissingField("source_first_seen_at", MISSING_NOT_SUPPLIED))
    if report_id is None:
        m.append(MissingField("report_id", MISSING_NOT_SUPPLIED))
    if coverage_scope is None:
        m.append(MissingField("coverage_scope", MISSING_NOT_SUPPLIED))
    return SourceObservationV1(
        schema_version=1,
        observation_id=oid,
        revision=1,
        source_family=source_family,
        source_account_id=source_account_id,
        run_id=run_id,
        source_record_ordinal=source_record_ordinal,
        collection_status=collection_status,
        collected_at=collected_at,
        raw_evidence_ref=f"ref/{oid}",
        raw_evidence_sha256=_digest(raw_bytes or f"{source_account_id}/{run_id}/{source_record_ordinal}"),
        missing_fields=tuple(m),
        observed_at=observed_at,
        native_id_scheme=native_id_scheme,
        native_id_authority=native_id_authority,
        native_id_value=native_id_value,
        asset_locator=asset_locator,
        component_locator=component_locator,
        source_record_locator=source_record_locator,
        source_rating=source_rating,
        source_first_seen_at=source_first_seen_at,
        report_id=report_id,
        coverage_scope=coverage_scope,
        vulnerability_refs=vulnerability_refs,
    )


RULE = RuleV1(
    rule_id="rule-workload-v1",
    rule_version=1,
    workload_match_fields=("provisioning_key", "service_key"),
)
